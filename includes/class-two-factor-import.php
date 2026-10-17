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

	private const EMAIL  = 'Two_Factor_Email';
	private const TOTP   = 'Two_Factor_Totp';
	private const BACKUP = 'Two_Factor_Backup_Codes';

	// Two Factor's own provider order, which decides the primary method when
	// the user never picked one.
	private const ORDER = array( self::EMAIL, self::TOTP, self::BACKUP );

	private const MAP = array(
		self::EMAIL  => 'email',
		self::TOTP   => 'totp',
		self::BACKUP => 'backup',
	);

	// Sigil's backup-code check strips to eight characters before comparing,
	// so codes of any other length could never be accepted.
	private const BACKUP_LENGTH = 8;

	private const MIN_SECRET_BYTES = 16;

	private const REPORT_TRANSIENT = 'sigil_tf_report_';

	public static function is_two_factor_active(): bool {
		return class_exists( 'Two_Factor_Core', false ) || defined( 'TWO_FACTOR_VERSION' );
	}

	/**
	 * Keep Two Factor out of the way for anyone Sigil already protects.
	 *
	 * Sigil challenges at wp_login priority 10 and exits, so Two Factor's
	 * handler at PHP_INT_MAX never runs for those users. This makes that
	 * explicit through the switch Two Factor 0.17 provides, so neither plugin
	 * asks twice and Two Factor does not hold back the session cookie Sigil
	 * issues after its own challenge.
	 *
	 * @param bool  $required
	 * @param mixed $user
	 */
	public static function filter_two_factor_required( $required, $user ): bool {
		if ( $user instanceof \WP_User && Providers::instance()->has_usable( (int) $user->ID ) ) {
			return false;
		}

		return (bool) $required;
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
				'meta_key' => $key, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_query_meta_key
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

	/**
	 * Import every candidate, or the ones given.
	 *
	 * @param list<int>|null $user_ids
	 * @return array{users: list<array<string, mixed>>, counts: array<string, int>}
	 */
	public static function run( ?array $user_ids, bool $dry_run ): array {
		$user_ids = null === $user_ids ? self::candidates() : $user_ids;

		$users  = array();
		$counts = array(
			'users'          => 0,
			'not_using'      => 0,
			'email'          => 0,
			'totp'           => 0,
			'backup'         => 0,
			'already'        => 0,
			'email_fallback' => 0,
			'flagged'        => 0,
			'failed'         => 0,
		);

		// One bulk migration is not a hundred separate security events. The
		// account holder alert exists to expose an attacker adding a factor, and
		// a mail to every user saying their methods changed would bury the one
		// that mattered on any other day.
		add_filter( 'sigil_send_change_alert', '__return_false', 99 );

		foreach ( $user_ids as $user_id ) {
			$result  = self::import_user( (int) $user_id, $dry_run );
			$users[] = $result;

			++$counts['users'];
			if ( 'not_using' === $result['status'] ) {
				++$counts['not_using'];
			}
			if ( 'failed' === $result['status'] ) {
				++$counts['failed'];
			}
			foreach ( array( 'email', 'totp', 'backup' ) as $method ) {
				if ( in_array( $method, $result['imported'], true ) ) {
					++$counts[ $method ];
				}
			}
			if ( array() !== $result['already'] ) {
				++$counts['already'];
			}
			if ( $result['email_fallback'] ) {
				++$counts['email_fallback'];
			}
			if ( array() !== $result['flags'] ) {
				++$counts['flagged'];
			}
		}

		remove_filter( 'sigil_send_change_alert', '__return_false', 99 );

		return array(
			'users'  => $users,
			'counts' => $counts,
		);
	}

	/**
	 * @return array{
	 *   user_id: int,
	 *   login: string,
	 *   status: string,
	 *   imported: list<string>,
	 *   already: list<string>,
	 *   preferred: string,
	 *   email_fallback: bool,
	 *   flags: list<string>
	 * }
	 */
	public static function import_user( int $user_id, bool $dry_run ): array {
		$result = array(
			'user_id'        => $user_id,
			'login'          => '',
			'status'         => 'ok',
			'imported'       => array(),
			'already'        => array(),
			'preferred'      => '',
			'email_fallback' => false,
			'flags'          => array(),
		);

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User ) {
			$result['status']  = 'failed';
			$result['flags'][] = 'user_not_found';
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

		$enabled = self::effective_providers( $stored );
		foreach ( array_diff( $stored, array_keys( self::MAP ) ) as $unknown ) {
			if ( 'Two_Factor_Dummy' !== $unknown ) {
				$result['flags'][] = 'unsupported_method:' . sanitize_key( $unknown );
			}
		}

		$sigil      = Store::methods( $user_id );
		$writes     = array();
		$want_email = in_array( self::EMAIL, $enabled, true );

		if ( in_array( self::TOTP, $enabled, true ) ) {
			$key = self::totp_key( $user_id );
			if ( isset( $sigil['totp'] ) ) {
				$result['already'][] = 'totp';
			} elseif ( '' === $key ) {
				// Two Factor lists TOTP for anyone who opened its settings, but it
				// only ever challenged with it once a secret was saved.
				$result['flags'][] = 'totp_never_configured';
				$want_email        = true;
			} else {
				$data = self::totp_record( $key, $user_id );
				if ( null === $data ) {
					$result['flags'][] = 'totp_secret_unusable';
					$want_email        = true;
				} else {
					$writes['totp'] = $data;
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
				$codes = self::backup_record( $hashes, $user );
				if ( null === $codes ) {
					$result['flags'][] = 'backup_codes_unverifiable';
				} else {
					$writes['backup'] = $codes;
				}
			}
		}

		// Whatever happened above, the account must leave with something it can
		// sign in with that is not a one-off list of codes.
		$usable = self::usable_sign_in_methods( $user_id );
		if ( array() === $usable && ! isset( $writes['totp'] ) ) {
			$want_email = true;
		}

		if ( $want_email ) {
			if ( isset( $sigil['email'] ) ) {
				$result['already'][] = 'email';
			} elseif ( ! is_email( $user->user_email ) ) {
				$result['flags'][] = 'email_address_invalid';
			} else {
				$writes['email'] = array( 'enrolled_at' => time() );
				if ( ! in_array( self::EMAIL, $enabled, true ) ) {
					$result['email_fallback'] = true;
				}
			}
		}

		if ( array() === $writes && array() === $usable && ! isset( $sigil['backup'] ) ) {
			$result['status'] = 'failed';
		}

		$result['preferred'] = self::preferred( $user_id, $enabled, $sigil, $writes );

		if ( ! $dry_run && array() !== $writes ) {
			do_action( 'sigil_before_methods_change', $user_id );

			foreach ( $writes as $provider_id => $data ) {
				Store::set_method( $user_id, $provider_id, $data );
			}

			$written = Store::methods( $user_id );
			foreach ( array_keys( $writes ) as $provider_id ) {
				if ( ! isset( $written[ $provider_id ] ) ) {
					$result['status']  = 'failed';
					$result['flags'][] = 'write_failed:' . $provider_id;
					unset( $writes[ $provider_id ] );
				}
			}

			/** This action is documented in includes/class-enrolment.php */
			do_action( 'sigil_methods_changed', $user_id );
		}

		if ( ! $dry_run && '' !== $result['preferred'] && '' === Providers::preference( $user_id ) ) {
			Providers::set_preference( $user_id, $result['preferred'] );
		}

		$result['imported'] = array_keys( $writes );

		return $result;
	}

	/**
	 * Methods Sigil can already challenge this account with, other than backup
	 * codes. Asked of the providers rather than read from the stored list, so a
	 * passkey row whose credentials are gone does not count.
	 *
	 * @return list<string>
	 */
	private static function usable_sign_in_methods( int $user_id ): array {
		$ids = array();
		foreach ( Providers::instance()->enrolled_for( $user_id ) as $provider ) {
			if ( 'backup' !== $provider->id() ) {
				$ids[] = $provider->id();
			}
		}

		return $ids;
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
	 * @return array{secret: string, last_step: int}|null
	 */
	private static function totp_record( string $key, int $user_id ): ?array {
		$secret = strtoupper( preg_replace( '/[\s=]+/', '', $key ) ?? '' );
		if ( ! preg_match( '/^[A-Z2-7]+$/', $secret ) ) {
			return null;
		}

		// 5 bits per character; anything under 16 bytes is refused by Sigil's
		// own validator and would never accept a code.
		if ( intdiv( strlen( $secret ) * 5, 8 ) < self::MIN_SECRET_BYTES ) {
			return null;
		}

		$encrypted = Crypto::encrypt( $secret );
		if ( '' === $encrypted || ! hash_equals( $secret, Crypto::decrypt( $encrypted ) ) ) {
			return null;
		}

		// Two Factor records the time of the last accepted code. Carrying it
		// across stops that same code being replayed into Sigil inside its
		// window.
		$last = get_user_meta( $user_id, self::META_TOTP_TS, true );
		$step = is_numeric( $last ) ? intdiv( (int) $last, 30 ) : 0;

		return array(
			'secret'    => base64_encode( $encrypted ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- binary ciphertext stored the same way the TOTP provider does.
			'last_step' => max( 0, $step ),
		);
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
		$length = (int) apply_filters( 'two_factor_backup_code_length', self::BACKUP_LENGTH, $user );
		if ( self::BACKUP_LENGTH !== $length ) {
			return null;
		}

		$codes = array();
		foreach ( $hashes as $hash ) {
			if ( ! self::is_password_hash( $hash ) ) {
				return null;
			}
			$codes[] = array(
				'hash' => $hash,
				'used' => false,
			);
		}

		return array( 'codes' => $codes );
	}

	private static function is_password_hash( string $hash ): bool {
		// phpass portable, WordPress 6.8+ bcrypt, and native password_hash().
		if ( 0 === strpos( $hash, '$P$' ) || 0 === strpos( $hash, '$H$' ) ) {
			return 34 === strlen( $hash );
		}
		if ( 0 === strpos( $hash, '$wp' ) ) {
			return null !== password_get_info( substr( $hash, 3 ) )['algo'];
		}

		return null !== password_get_info( $hash )['algo'];
	}

	/**
	 * The method Two Factor would have asked for first, as a Sigil id.
	 *
	 * @param list<string>                        $enabled
	 * @param array<string, array<string, mixed>> $sigil
	 * @param array<string, array<string, mixed>> $writes
	 */
	private static function preferred( int $user_id, array $enabled, array $sigil, array $writes ): string {
		$will_have = array_merge( array_keys( $sigil ), array_keys( $writes ) );

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

	/**
	 * @param array{users: list<array<string, mixed>>, counts: array<string, int>} $report
	 */
	public static function remember_report( int $user_id, array $report, bool $dry_run ): void {
		$report['dry_run'] = $dry_run;
		set_transient( self::REPORT_TRANSIENT . $user_id, $report, 15 * MINUTE_IN_SECONDS );
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public static function recall_report( int $user_id ): ?array {
		$report = get_transient( self::REPORT_TRANSIENT . $user_id );

		return is_array( $report ) ? $report : null;
	}

	public static function flag_label( string $flag ): string {
		$parts = explode( ':', $flag, 2 );

		switch ( $parts[0] ) {
			case 'totp_never_configured':
				return __( 'Authenticator app was switched on but never set up in Two Factor', 'sigil-2fa' );
			case 'totp_secret_unusable':
				return __( 'Authenticator secret could not be read, so it was not imported', 'sigil-2fa' );
			case 'backup_codes_unverifiable':
				return __( 'Backup codes are in a format Sigil cannot check, so they were not imported', 'sigil-2fa' );
			case 'backup_codes_none_left':
				return __( 'Backup codes were switched on but none were left', 'sigil-2fa' );
			case 'email_address_invalid':
				return __( 'Account has no valid email address, so email codes could not be set up', 'sigil-2fa' );
			case 'data_without_enabled_method':
				return __( 'Two Factor data exists but no method was switched on, so nothing was imported', 'sigil-2fa' );
			case 'unsupported_method':
				/* translators: %s: Two Factor provider name */
				return sprintf( __( 'Method %s has no Sigil equivalent', 'sigil-2fa' ), $parts[1] ?? '' );
			case 'write_failed':
				/* translators: %s: Sigil method id */
				return sprintf( __( 'Saving %s failed', 'sigil-2fa' ), $parts[1] ?? '' );
			case 'user_not_found':
				return __( 'User not found', 'sigil-2fa' );
		}

		return $flag;
	}
}
