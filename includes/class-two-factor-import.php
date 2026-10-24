<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Carry users over from the WordPress "Two Factor" plugin.
 *
 * Reads that plugin's user meta directly, so it works whether or not Two
 * Factor is still active, and never writes to or deletes any of it: if
 * something goes wrong, deactivating Sigil and reactivating Two Factor puts
 * everyone back where they were.
 *
 * The rule throughout is that nobody leaves with less than they had. A method
 * Two Factor was actually using comes across when Sigil can verify it; when it
 * cannot, the account gets email codes instead and is named in the report, so
 * an administrator sees every account whose sign-in changed.
 */
final class Two_Factor_Import {

	private const META_ENABLED = '_two_factor_enabled_providers';
	private const META_PRIMARY = '_two_factor_provider';
	private const META_TOTP    = '_two_factor_totp_key';
	private const META_TOTP_TS = '_two_factor_totp_last_successful_login';
	private const META_BACKUP  = '_two_factor_backup_codes';
	private const OPTION_SITE  = 'two_factor_enabled_providers';

	private const EMAIL    = 'Two_Factor_Email';
	private const TOTP     = 'Two_Factor_Totp';
	private const BACKUP   = 'Two_Factor_Backup_Codes';
	private const WEBAUTHN = 'TwoFactor_Provider_WebAuthn';
	// Two Factor's old U2F provider. The WebAuthn provider plugin adopts the
	// keys it left behind, and enables itself for anyone who had it.
	private const U2F = 'Two_Factor_FIDO_U2F';

	// Two Factor's own provider order, which decides the primary method when
	// the user never picked one. The WebAuthn provider registers after the
	// built-in ones.
	private const ORDER = array( self::EMAIL, self::TOTP, self::BACKUP, self::WEBAUTHN );

	private const MAP = array(
		self::EMAIL    => 'email',
		self::TOTP     => 'totp',
		self::BACKUP   => 'backup',
		self::WEBAUTHN => 'passkey',
		self::U2F      => 'passkey',
	);

	private const META_U2F         = '_two_factor_fido_u2f_registered_key';
	private const WEBAUTHN_KEYS    = '2fa_webauthn_credentials';
	private const WEBAUTHN_HANDLES = '2fa_webauthn_users';

	// Sigil's backup-code check strips to eight characters before comparing,
	// so codes of any other length could never be accepted.
	private const BACKUP_LENGTH = 8;

	public static function is_active(): bool {
		return class_exists( 'Two_Factor_Core', false ) || defined( 'TWO_FACTOR_VERSION' );
	}

	/**
	 * Keep Two Factor out of the way where Sigil is already doing its job.
	 *
	 * Sigil challenges at wp_login priority 10 and exits, so Two Factor's
	 * handler at PHP_INT_MAX never runs for its users. Saying so through the
	 * switch Two Factor 0.17 provides stops it holding back the session cookie
	 * Sigil issues after its own challenge.
	 *
	 * It stands down only for interactive sign-ins by someone whose Two Factor
	 * setup Sigil fully covers. API requests never reach wp_login, so there
	 * Two Factor keeps refusing the account password. Someone whose methods
	 * did not all come across stays with Two Factor until an administrator has
	 * sorted them out.
	 *
	 * @param bool  $required
	 * @param mixed $user
	 */
	public static function filter_two_factor_required( $required, $user ): bool {
		if ( ! $user instanceof \WP_User || App_Passwords::is_api_request() ) {
			return (bool) $required;
		}

		if ( ! Providers::instance()->has_usable( (int) $user->ID ) ) {
			return (bool) $required;
		}

		if ( self::import_user( (int) $user->ID, true )['needs_attention'] ) {
			return (bool) $required;
		}

		return false;
	}

	/**
	 * Every user carrying any Two Factor data worth looking at.
	 *
	 * @return list<int>
	 */
	public static function candidates(): array {
		$ids = array();

		foreach ( array( self::META_ENABLED, self::META_TOTP, self::META_BACKUP ) as $key ) {
			$args = array(
				'meta_key' => $key, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'fields'   => 'ID',
				'number'   => -1,
			);
			if ( is_multisite() ) {
				$args['blog_id'] = 0;
			}

			foreach ( get_users( $args ) as $id ) {
				$ids[ (int) $id ] = true;
			}
		}

		$ids = array_keys( $ids );
		sort( $ids );

		return $ids;
	}

	public static function has_data(): bool {
		$args = array(
			'meta_key' => self::META_ENABLED, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
			'fields'   => 'ID',
			'number'   => 1,
		);
		if ( is_multisite() ) {
			$args['blog_id'] = 0;
		}

		return array() !== get_users( $args );
	}

	/**
	 * Import every candidate, or the ones given.
	 *
	 * @param list<int>|null $user_ids
	 * @return array{users: list<array<string, mixed>>, counts: array<string, int>}
	 */
	public static function run( ?array $user_ids, bool $dry_run ): array {
		return Import::run( self::class, $user_ids, $dry_run );
	}

	/**
	 * @return array{
	 *   user_id: int,
	 *   login: string,
	 *   status: string,
	 *   imported: list<string>,
	 *   already: list<string>,
	 *   preferred: string,
	 *   needs_attention: bool,
	 *   flags: list<string>
	 * }
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

		$stored = self::stored_providers( $user_id );
		if ( array() === $stored ) {
			// Leftover secrets or codes with nothing switched on were not a
			// second factor in Two Factor, so they do not become one here.
			$result['status'] = 'not_using';
			if ( '' !== self::totp_key( $user_id ) || array() !== self::backup_hashes( $user_id ) ) {
				$result['flags'][] = 'data_without_enabled_method';
			}
			return $result;
		}

		$enabled   = self::effective_providers( $stored );
		$had_email = in_array( self::EMAIL, $enabled, true );
		$sigil     = Store::methods( $user_id );
		$writes    = array();
		$passkeys  = array();

		// Set when Two Factor was using something Sigil cannot carry over.
		$lost = false;
		// Set when Two Factor would actually have challenged this person.
		$had_working = $had_email;

		foreach ( array_diff( $enabled, array_keys( self::MAP ) ) as $unknown ) {
			if ( 'Two_Factor_Dummy' !== $unknown ) {
				$result['flags'][] = 'unsupported_method:' . sanitize_key( $unknown );
				$lost              = true;
				$had_working       = true;
			}
		}

		if ( in_array( self::TOTP, $enabled, true ) ) {
			$key = self::totp_key( $user_id );
			if ( '' === $key ) {
				// Two Factor lists TOTP for anyone who opened its settings, but it
				// only ever challenged with it once a secret was saved.
				$result['flags'][] = 'totp_never_configured';
			} elseif ( isset( $sigil['totp'] ) ) {
				$result['already'][] = 'totp';
				$had_working         = true;
			} else {
				$had_working = true;
				// Two Factor records the time of the last accepted code. Carrying it
				// across stops that same code being replayed into Sigil inside its
				// window.
				$last = get_user_meta( $user_id, self::META_TOTP_TS, true );
				$data = Import::totp_record( $key, is_numeric( $last ) ? intdiv( (int) $last, 30 ) : 0 );
				if ( null === $data ) {
					$result['flags'][] = 'totp_secret_unusable';
					$lost              = true;
				} else {
					$writes['totp'] = $data;
				}
			}
		}

		if ( in_array( self::WEBAUTHN, $enabled, true ) || in_array( self::U2F, $enabled, true ) ) {
			$keys = self::webauthn_keys( $user_id, $result['flags'] );
			if ( null === $keys ) {
				// The WebAuthn provider only challenges once a key is registered.
				$result['flags'][] = 'passkey_never_registered';
			} else {
				$had_working = true;
				$lost        = $keys['lost'] || $lost;
				$passkeys    = $keys['rows'];
				if ( $keys['already'] ) {
					$result['already'][] = 'passkey';
				}
			}
		}

		if ( in_array( self::BACKUP, $enabled, true ) ) {
			$hashes = self::backup_hashes( $user_id );
			if ( isset( $sigil['backup'] ) ) {
				$result['already'][] = 'backup';
			} elseif ( array() === $hashes ) {
				$result['flags'][] = 'backup_codes_none_left';
			} else {
				$had_working = true;
				$codes       = self::backup_record( $hashes, $user );
				if ( null === $codes ) {
					$result['flags'][] = 'backup_codes_unverifiable';
				} else {
					$writes['backup'] = $codes;
				}
			}
		}

		// Email codes only ever come across for someone who already had them.
		// Handing them to anyone else would quietly swap the method they chose
		// for a weaker one.
		if ( $had_email ) {
			if ( isset( $sigil['email'] ) ) {
				$result['already'][] = 'email';
			} elseif ( ! is_email( $user->user_email ) ) {
				$result['flags'][] = 'email_address_invalid';
				$lost              = true;
			} else {
				$writes['email'] = array( 'enrolled_at' => time() );
			}
		}

		$will_have_email  = isset( $sigil['email'] ) || isset( $writes['email'] );
		$will_have_signin = array() !== Import::usable_sign_in_methods( $user_id ) || isset( $writes['totp'] ) || isset( $writes['email'] ) || array() !== $passkeys;

		if ( ( $lost && ! $will_have_email ) || ( $had_working && ! $will_have_signin ) ) {
			$result['status']          = 'needs_attention';
			$result['needs_attention'] = true;
		} elseif ( ! $had_working ) {
			$result['status'] = 'not_using';
		}

		$will_have = array_merge( array_keys( $sigil ), array_keys( $writes ), array() !== $passkeys ? array( 'passkey' ) : array() );

		$result['preferred'] = self::preferred( $user_id, $enabled, $will_have );

		return Import::apply( $result, $user_id, $writes, $passkeys, $dry_run );
	}

	/**
	 * The keys the WebAuthn provider plugin holds for this user, as Sigil rows.
	 *
	 * Null when there are none, so the provider was never really in use. Keys it
	 * cannot carry are named in $flags and set 'lost'.
	 *
	 * @param list<string> $flags
	 * @return array{rows: list<array{credential_id: string, public_key: string, sign_count: int, label: string, transports: string}>, lost: bool, already: bool}|null
	 */
	private static function webauthn_keys( int $user_id, array &$flags ): ?array {
		global $wpdb;

		$keys    = $wpdb->base_prefix . self::WEBAUTHN_KEYS;
		$handles = $wpdb->base_prefix . self::WEBAUTHN_HANDLES;

		$records = array();
		if ( Import::table_exists( $keys ) && Import::table_exists( $handles ) ) {
			// Both names are the provider plugin's own tables under the network
			// prefix; only the user id is a value, and it is prepared.
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$records = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT k.credential_id, k.public_key, k.counter, k.name, k.u2f FROM {$keys} AS k INNER JOIN {$handles} AS h ON h.user_handle = k.user_handle WHERE h.user_id = %d ORDER BY k.id ASC",
					$user_id
				)
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$records = is_array( $records ) ? $records : array();
		}

		// Keys from Two Factor's old U2F provider that the WebAuthn plugin has not
		// adopted into its table yet. It would adopt them on the next sign-in as
		// U2F keys, which Sigil cannot verify either.
		$legacy = array() === $records ? get_user_meta( $user_id, self::META_U2F, false ) : array();

		if ( array() === $records && array() === $legacy ) {
			return null;
		}

		$out = array(
			'rows'    => array(),
			'lost'    => false,
			'already' => false,
		);

		if ( array() !== $legacy ) {
			$flags[]     = 'passkey_u2f';
			$out['lost'] = true;
			return $out;
		}

		$source_rp = self::webauthn_rp_id();
		if ( Providers\Passkey::rp_id() !== $source_rp ) {
			$flags[]     = 'passkey_rp_mismatch:' . $source_rp;
			$out['lost'] = true;
			return $out;
		}

		foreach ( $records as $record ) {
			if ( ! empty( $record->u2f ) ) {
				// Signed with the U2F AppID rather than the RP ID. Verifying those
				// needs the appid extension, which Sigil's WebAuthn library has not
				// got.
				$flags[]     = 'passkey_u2f';
				$out['lost'] = true;
				continue;
			}

			$credential_id = Import::base64url_decode( (string) $record->credential_id );
			$owner         = Import::passkey_owner( $credential_id, $user_id );
			if ( 'mine' === $owner ) {
				$out['already'] = true;
				continue;
			}
			if ( 'other' === $owner ) {
				$flags[]     = 'passkey_other_user';
				$out['lost'] = true;
				continue;
			}

			$row = Import::passkey_row( $credential_id, Import::base64url_decode( (string) $record->public_key ), (int) $record->counter, (string) $record->name, '' );
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
	 * The relying party the WebAuthn provider registers keys under: the cookie
	 * domain when one is set, otherwise the host of its AppID URL.
	 */
	private static function webauthn_rp_id(): string {
		if ( defined( 'COOKIE_DOMAIN' ) && is_string( COOKIE_DOMAIN ) && '' !== COOKIE_DOMAIN ) {
			return strtolower( ltrim( COOKIE_DOMAIN, '.' ) );
		}

		$parts = wp_parse_url( home_url() );
		$host  = is_array( $parts ) && isset( $parts['host'] ) ? (string) $parts['host'] : '';
		$url   = 'https://' . $host . ( empty( $parts['port'] ) ? '' : ':' . (int) $parts['port'] );

		// The provider plugin's own filter, read so a site that moved its AppID is caught.
		$app_id = (string) apply_filters( 'webauthn_app_id', $url ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
		$rp     = wp_parse_url( $app_id, PHP_URL_HOST );

		return is_string( $rp ) ? strtolower( $rp ) : '';
	}

	/**
	 * @return list<string>
	 */
	private static function stored_providers( int $user_id ): array {
		$raw = get_user_meta( $user_id, self::META_ENABLED, true );
		if ( ! is_array( $raw ) ) {
			return array();
		}

		return array_values( array_unique( array_filter( $raw, 'is_string' ) ) );
	}

	/**
	 * The stored list as Two Factor would honour it, after the site-wide
	 * provider setting it added in 0.16.
	 *
	 * When none of what the user stored is still allowed, Two Factor forces
	 * email codes on rather than letting them in on a password, and so does
	 * this.
	 *
	 * @param list<string> $stored
	 * @return list<string>
	 */
	private static function effective_providers( array $stored ): array {
		$site = get_option( self::OPTION_SITE, null );
		if ( ! is_array( $site ) ) {
			return $stored;
		}

		$allowed = array_values( array_intersect( $stored, $site ) );
		if ( array() === $allowed ) {
			return array( self::EMAIL );
		}

		return $allowed;
	}

	private static function totp_key( int $user_id ): string {
		$raw = get_user_meta( $user_id, self::META_TOTP, true );

		return is_string( $raw ) ? $raw : '';
	}

	/**
	 * @return list<string>
	 */
	private static function backup_hashes( int $user_id ): array {
		$raw = get_user_meta( $user_id, self::META_BACKUP, true );
		if ( ! is_array( $raw ) ) {
			return array();
		}

		return array_values( array_filter( $raw, 'is_string' ) );
	}

	/**
	 * Two Factor hashes backup codes with wp_hash_password(), the same call
	 * Sigil uses, so the hashes carry over unchanged and wp_check_password()
	 * verifies them. Only formats that function recognises are accepted, and
	 * only when the codes are the eight characters Sigil's check expects.
	 *
	 * @param list<string> $hashes
	 * @return array{codes: list<array{hash: string, used: bool}>}|null
	 */
	private static function backup_record( array $hashes, \WP_User $user ): ?array {
		// Two Factor's own filter, read so a site that changed its code length is caught.
		$length = (int) apply_filters( 'two_factor_backup_code_length', self::BACKUP_LENGTH, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
		if ( self::BACKUP_LENGTH !== $length ) {
			return null;
		}

		$codes = array();
		foreach ( $hashes as $hash ) {
			if ( ! Import::is_password_hash( $hash ) ) {
				return null;
			}
			$codes[] = array(
				'hash' => $hash,
				'used' => false,
			);
		}

		return array( 'codes' => $codes );
	}

	/**
	 * The method Two Factor would have asked for first, as a Sigil id.
	 *
	 * @param list<string> $enabled
	 * @param list<string> $will_have Sigil method ids the account ends up with.
	 */
	private static function preferred( int $user_id, array $enabled, array $will_have ): string {
		$primary = get_user_meta( $user_id, self::META_PRIMARY, true );
		$order   = self::ORDER;
		if ( is_string( $primary ) && in_array( $primary, $enabled, true ) ) {
			array_unshift( $order, $primary );
		}

		foreach ( $order as $provider ) {
			$id = self::MAP[ $provider ] ?? '';
			// A list of single-use codes is a way back in, not a way to sign in
			// every day, so it is never made the first thing offered.
			if ( '' === $id || 'backup' === $id || ! in_array( $id, $will_have, true ) ) {
				continue;
			}
			if ( in_array( $provider, $enabled, true ) || 'email' === $id ) {
				return $id;
			}
		}

		return '';
	}

	public static function flag_label( string $flag ): string {
		switch ( explode( ':', $flag, 2 )[0] ) {
			case 'totp_never_configured':
				return __( 'Authenticator app was switched on but never set up in Two Factor', 'sigil-2fa' );
			case 'passkey_never_registered':
				return __( 'WebAuthn was switched on but no security key or passkey was ever registered', 'sigil-2fa' );
			case 'data_without_enabled_method':
				return __( 'Two Factor data exists but no method was switched on, so nothing was imported', 'sigil-2fa' );
		}

		return Import::flag_label( $flag );
	}
}
