<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Carry users over from Wordfence Login Security, the two-factor half of the
 * Wordfence plugin.
 *
 * Wordfence keeps authenticator secrets and recovery codes in the clear in its
 * own network-wide table, and passkeys in another. Both are read directly and
 * never written to.
 *
 * Wordfence asks for its code inside the authenticate filter and in its own
 * AJAX step on the login form, both before Sigil's challenge on wp_login, and
 * it has no switch to stand down. So while both are active, Wordfence's two
 * checks are skipped for the interactive sign-ins of users whose Wordfence
 * setup Sigil fully covers, and Sigil asks instead.
 */
final class Wordfence_Import {

	private const SECRETS  = 'wfls_2fa_secrets';
	private const PASSKEYS = 'wfls_passkeys';
	private const SETTINGS = 'wfls_settings';

	// Wordfence's recovery codes are eight random bytes, shown as sixteen hex
	// characters.
	private const RECOVERY_BYTES = 8;

	public static function is_active(): bool {
		return defined( 'WORDFENCE_LS_VERSION' ) || class_exists( '\WordfenceLS\Controller_WordfenceLS', false );
	}

	public static function has_data(): bool {
		return array() !== self::candidates( 1 );
	}

	/**
	 * @return list<int>
	 */
	public static function candidates( int $limit = 0 ): array {
		global $wpdb;

		$ids = array();
		foreach ( array( self::SECRETS, self::PASSKEYS ) as $name ) {
			$table = $wpdb->base_prefix . $name;
			if ( ! Import::table_exists( $table ) ) {
				continue;
			}

			// Wordfence's own table under the network prefix; nothing user-supplied.
			// Joined to the users table because rows can outlive an account that
			// was deleted while Wordfence was inactive.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			foreach ( (array) $wpdb->get_col( "SELECT DISTINCT w.user_id FROM {$table} AS w INNER JOIN {$wpdb->users} AS u ON u.ID = w.user_id" . ( $limit > 0 ? ' LIMIT ' . (int) $limit : '' ) ) as $id ) {
				$ids[ (int) $id ] = true;
			}
		}

		$ids = array_keys( $ids );
		sort( $ids );

		return $ids;
	}

	/**
	 * @param list<int>|null $user_ids
	 * @return array{users: list<array<string, mixed>>, counts: array<string, int>}
	 */
	public static function run( ?array $user_ids, bool $dry_run ): array {
		return Import::run( self::class, $user_ids, $dry_run );
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function import_user( int $user_id, bool $dry_run ): array {
		$result = Import::blank_result( $user_id );

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User ) {
			$result['status']          = 'needs_attention';
			$result['needs_attention'] = true;
			$result['flags'][]         = 'user_not_found';
			return $result;
		}
		$result['login'] = $user->user_login;

		$secret  = self::secret_row( $user_id );
		$records = self::passkey_records( $user_id );

		// An enrolment Wordfence is not asking for, because its two-factor or
		// passkeys are switched off site-wide, was not protecting anyone, so it
		// does not become a second factor here either.
		if ( null !== $secret && ! self::setting_on( 'enable-2fa' ) ) {
			$result['flags'][] = 'wordfence_2fa_off';
			$secret            = null;
		}
		if ( array() !== $records && ! self::setting_on( 'enable-passkeys' ) ) {
			$result['flags'][] = 'wordfence_passkeys_off';
			$records           = array();
		}

		if ( null === $secret && array() === $records ) {
			$result['status'] = 'not_using';
			return $result;
		}

		$sigil    = Store::methods( $user_id );
		$writes   = array();
		$passkeys = array();
		$lost     = false;

		if ( null !== $secret ) {
			if ( isset( $sigil['totp'] ) ) {
				$result['already'][] = 'totp';
			} else {
				// Wordfence refuses a code from a step at or before the last one it
				// accepted, recorded as vtime. So does Sigil, once it knows the step.
				$data = Import::totp_record( Import::base32_encode( (string) $secret->secret ), intdiv( (int) $secret->vtime, 30 ) );
				if ( null === $data ) {
					$result['flags'][] = 'totp_secret_unusable';
					$lost              = true;
				} else {
					$writes['totp'] = $data;
				}
			}

			$recovery = (string) $secret->recovery;
			if ( isset( $sigil['backup'] ) ) {
				$result['already'][] = 'backup';
			} elseif ( strlen( $recovery ) < self::RECOVERY_BYTES ) {
				$result['flags'][] = 'backup_codes_none_left';
			} else {
				$writes['backup'] = self::backup_record( $recovery );
			}
		}

		if ( array() !== $records ) {
			$carried  = self::passkey_rows( $user_id, $records, $result['flags'] );
			$passkeys = $carried['rows'];
			$lost     = $carried['lost'] || $lost;
			if ( $carried['already'] ) {
				$result['already'][] = 'passkey';
			}
		}

		$will_have_signin = array() !== Import::usable_sign_in_methods( $user_id ) || isset( $writes['totp'] ) || array() !== $passkeys;

		if ( ! $will_have_signin || ( $lost && ! isset( $sigil['email'] ) ) ) {
			// Half a setup would have Sigil challenge this person with whatever came
			// across, and Wordfence would never get to ask for the method they actually
			// use. Nothing is written; Wordfence keeps them until they have set up
			// something in Sigil.
			$writes   = array();
			$passkeys = array();

			$result['status']          = 'needs_attention';
			$result['needs_attention'] = true;
		}

		$will_have = array_merge( array_keys( $sigil ), array_keys( $writes ), array() !== $passkeys ? array( 'passkey' ) : array() );
		foreach ( array( 'passkey', 'totp' ) as $id ) {
			if ( in_array( $id, $will_have, true ) ) {
				$result['preferred'] = $id;
				break;
			}
		}

		return Import::apply( $result, $user_id, $writes, $passkeys, $dry_run );
	}

	private static function secret_row( int $user_id ): ?object {
		global $wpdb;

		$table = $wpdb->base_prefix . self::SECRETS;
		if ( ! Import::table_exists( $table ) ) {
			return null;
		}

		// Wordfence's own table under the network prefix; the user id is prepared.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT secret, recovery, vtime FROM {$table} WHERE user_id = %d ORDER BY id DESC LIMIT 1", $user_id ) );

		return $row instanceof \stdClass ? $row : null;
	}

	/**
	 * Wordfence stores its recovery codes as raw bytes, so they are hashed here
	 * the way Sigil hashes its own: each code as the sixteen upper-case hex
	 * characters Sigil's check normalises what the user types to.
	 *
	 * @return array{codes: list<array{hash: string, used: bool}>, length: int}
	 */
	private static function backup_record( string $recovery ): array {
		$codes = array();
		foreach ( str_split( $recovery, self::RECOVERY_BYTES ) as $raw ) {
			if ( self::RECOVERY_BYTES !== strlen( $raw ) ) {
				continue;
			}
			$codes[] = array(
				'hash' => wp_hash_password( strtoupper( bin2hex( $raw ) ) ),
				'used' => false,
			);
		}

		return array(
			'codes'  => $codes,
			'length' => self::RECOVERY_BYTES * 2,
		);
	}

	/**
	 * @return list<object>
	 */
	private static function passkey_records( int $user_id ): array {
		global $wpdb;

		$table = $wpdb->base_prefix . self::PASSKEYS;
		if ( ! Import::table_exists( $table ) ) {
			return array();
		}

		// Wordfence's own table under the network prefix; the user id is prepared.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT credential_id, public_key, sign_count, transports, label FROM {$table} WHERE user_id = %d ORDER BY id ASC", $user_id ) );

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * @param list<object>  $records
	 * @param list<string>  $flags
	 * @return array{rows: list<array{credential_id: string, public_key: string, sign_count: int, label: string, transports: string}>, lost: bool, already: bool}
	 */
	private static function passkey_rows( int $user_id, array $records, array &$flags ): array {
		$out = array(
			'rows'    => array(),
			'lost'    => false,
			'already' => false,
		);

		$source_rp = self::passkey_rp_id();
		if ( Providers\Passkey::rp_id() !== $source_rp ) {
			$flags[]     = 'passkey_rp_mismatch:' . ( '' !== $source_rp ? $source_rp : '?' );
			$out['lost'] = true;
			return $out;
		}

		foreach ( $records as $record ) {
			$credential_id = (string) $record->credential_id;

			$owner = Import::passkey_owner( $credential_id, $user_id );
			if ( 'mine' === $owner ) {
				$out['already'] = true;
				continue;
			}
			if ( 'other' === $owner ) {
				$flags[]     = 'passkey_other_user';
				$out['lost'] = true;
				continue;
			}

			$row = Import::passkey_row( $credential_id, (string) $record->public_key, (int) $record->sign_count, (string) $record->label, (string) $record->transports );
			if ( is_string( $row ) ) {
				$flags[]     = $row;
				$out['lost'] = true;
				continue;
			}
			$out['rows'][] = $row;
		}

		$flags = array_values( array_unique( $flags ) );

		return $out;
	}

	/**
	 * A Wordfence on/off setting. A missing row means a site upgraded from
	 * before the setting existed, where Wordfence treats it as on.
	 */
	private static function setting_on( string $name ): bool {
		$value = self::setting( $name );
		if ( null === $value ) {
			return true;
		}
		if ( is_numeric( $value ) ) {
			return 0.0 !== (float) $value;
		}

		return '' !== $value && ! preg_match( '/^(?:f(?:alse)?|no?|off)$/i', $value );
	}

	private static function setting( string $name ): ?string {
		global $wpdb;

		$table = $wpdb->base_prefix . self::SETTINGS;
		if ( ! Import::table_exists( $table ) ) {
			return null;
		}

		// Wordfence's own table under the network prefix; the name is prepared.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$value = $wpdb->get_var( $wpdb->prepare( "SELECT value FROM {$table} WHERE name = %s", $name ) );

		return is_string( $value ) ? $value : null;
	}

	/**
	 * The relying party Wordfence registered its passkeys under: the override
	 * an administrator set, or the one it recorded at the last registration.
	 * Wordfence keeps neither per credential.
	 */
	private static function passkey_rp_id(): string {
		foreach ( array( 'passkey-relying-party-override', 'last-passkey-rp' ) as $name ) {
			$value = self::setting( $name );
			if ( null !== $value && '' !== $value ) {
				return strtolower( $value );
			}
		}

		return '';
	}

	/**
	 * Whether Sigil can take this person's sign-in over from Wordfence: Sigil
	 * has a method for them and nothing they used in Wordfence was left behind.
	 */
	public static function covers( \WP_User $user ): bool {
		return Providers::instance()->has_usable( (int) $user->ID ) && ! self::import_user( (int) $user->ID, true )['needs_attention'];
	}

	/**
	 * On the form post, take Wordfence's authenticate check out for a user Sigil
	 * covers, so Sigil's challenge on wp_login is the only one. Runs just before
	 * it, once the password has been checked.
	 *
	 * @param mixed $user
	 * @return mixed
	 */
	public static function stand_down( $user ) {
		if ( ! $user instanceof \WP_User || App_Passwords::is_api_request() || ! self::is_active() || ! self::covers( $user ) ) {
			return $user;
		}

		global $wp_filter;
		if ( isset( $wp_filter['authenticate']->callbacks[25] ) ) {
			foreach ( $wp_filter['authenticate']->callbacks[25] as $callback ) {
				if ( is_array( $callback['function'] ) && $callback['function'][0] instanceof \WordfenceLS\Controller_WordfenceLS ) {
					remove_filter( 'authenticate', $callback['function'], 25 );
				}
			}
		}

		return $user;
	}

	/**
	 * Wordfence's login form posts the credentials to its own AJAX action first
	 * and shows its code prompt when that says so. For a user Sigil covers,
	 * answer that step the way Wordfence answers for someone without its
	 * two-factor, and let the form submit to Sigil's challenge.
	 *
	 * The password is checked here through the full authenticate chain, so this
	 * is never an oracle that skips another plugin's lockout. Anyone else falls
	 * through to Wordfence untouched.
	 */
	public static function ajax_stand_down(): void {
		// Wordfence's own login step, which carries no nonce; the credentials are
		// checked by wp_authenticate() below.
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$login    = isset( $_POST['log'] ) && is_string( $_POST['log'] ) ? sanitize_user( wp_unslash( $_POST['log'] ) ) : '';
		$password = isset( $_POST['pwd'] ) && is_string( $_POST['pwd'] ) ? wp_unslash( $_POST['pwd'] ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		if ( '' === $login || '' === $password ) {
			return;
		}

		$user = is_email( $login ) ? get_user_by( 'email', $login ) : get_user_by( 'login', $login );
		if ( ! $user instanceof \WP_User || ! self::covers( $user ) ) {
			return;
		}

		$result = wp_authenticate( $login, $password );
		if ( $result instanceof \WP_User ) {
			wp_send_json( array( 'login' => 1 ) );
		}

		wp_send_json( array( 'error' => __( '<strong>Error:</strong> The username or password you entered is incorrect.', 'sigil-2fa' ) ) );
	}

	public static function flag_label( string $flag ): string {
		switch ( $flag ) {
			case 'wordfence_2fa_off':
				return __( 'Wordfence two-factor is switched off for the site, so the authenticator it holds was not protecting the account and was not imported', 'sigil-2fa' );
			case 'wordfence_passkeys_off':
				return __( 'Wordfence passkeys are switched off for the site, so they were not imported', 'sigil-2fa' );
		}

		return Import::flag_label( $flag );
	}
}
