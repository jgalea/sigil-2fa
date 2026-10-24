<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * What every importer shares: the run over a list of users, the report kept
 * for the settings screen, and the writes into Sigil.
 *
 * Each source decides for itself what a user had and what can come across;
 * this class only turns those decisions into stored methods, and reads back
 * what landed so the report never claims a write that failed.
 */
final class Import {

	private const REPORT_TRANSIENT = 'sigil_import_report_';

	private const MIN_SECRET_BYTES = 16;

	// The width of Sigil's credential_id column.
	private const MAX_CREDENTIAL_ID_BYTES = 255;

	/**
	 * @return array<string, array{label: string, class: class-string}>
	 */
	public static function sources(): array {
		return array(
			'two-factor' => array(
				'label' => 'Two Factor',
				'class' => Two_Factor_Import::class,
			),
			'wordfence'  => array(
				'label' => 'Wordfence',
				'class' => Wordfence_Import::class,
			),
		);
	}

	/**
	 * Import every candidate the source finds, or the users given.
	 *
	 * @param class-string   $importer
	 * @param list<int>|null $user_ids
	 * @return array{users: list<array<string, mixed>>, counts: array<string, int>}
	 */
	public static function run( string $importer, ?array $user_ids, bool $dry_run ): array {
		$user_ids = null === $user_ids ? $importer::candidates() : $user_ids;

		$users  = array();
		$counts = array(
			'users'     => 0,
			'not_using' => 0,
			'email'     => 0,
			'totp'      => 0,
			'backup'    => 0,
			'passkey'   => 0,
			'already'   => 0,
			'attention' => 0,
			'flagged'   => 0,
		);

		// One bulk migration is not a hundred separate security events. The
		// account holder alert exists to expose an attacker adding a factor, and
		// a mail to every user saying their methods changed would bury the one
		// that mattered on any other day.
		add_filter( 'sigil_send_change_alert', '__return_false', 99 );

		foreach ( $user_ids as $user_id ) {
			$result  = $importer::import_user( (int) $user_id, $dry_run );
			$users[] = $result;

			++$counts['users'];
			if ( 'not_using' === $result['status'] ) {
				++$counts['not_using'];
			}
			foreach ( array( 'email', 'totp', 'backup', 'passkey' ) as $method ) {
				if ( in_array( $method, $result['imported'], true ) ) {
					++$counts[ $method ];
				}
			}
			if ( array() !== $result['already'] ) {
				++$counts['already'];
			}
			if ( $result['needs_attention'] ) {
				++$counts['attention'];
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
	 *   needs_attention: bool,
	 *   flags: list<string>
	 * }
	 */
	public static function blank_result( int $user_id ): array {
		return array(
			'user_id'         => $user_id,
			'login'           => '',
			'status'          => 'ok',
			'imported'        => array(),
			'already'         => array(),
			'preferred'       => '',
			'needs_attention' => false,
			'flags'           => array(),
		);
	}

	/**
	 * Store what the importer decided on, then record what actually landed.
	 *
	 * @param array<string, mixed>                $result
	 * @param array<string, array<string, mixed>> $writes   Sigil method id => stored data.
	 * @param list<array{credential_id: string, public_key: string, sign_count: int, label: string, transports: string}> $passkeys
	 * @return array<string, mixed>
	 */
	public static function apply( array $result, int $user_id, array $writes, array $passkeys, bool $dry_run ): array {
		$imported = array_keys( $writes );
		if ( array() !== $passkeys ) {
			$imported[] = 'passkey';
		}

		if ( ! $dry_run && array() !== $imported ) {
			do_action( 'sigil_before_methods_change', $user_id );

			foreach ( $writes as $provider_id => $data ) {
				Store::set_method( $user_id, $provider_id, $data );
			}

			$added = 0;
			foreach ( $passkeys as $row ) {
				if ( Credentials::add( $user_id, $row['credential_id'], $row['public_key'], $row['sign_count'], $row['label'], $row['transports'] ) > 0 ) {
					++$added;
				}
			}
			if ( $added > 0 && ! isset( Store::methods( $user_id )['passkey'] ) ) {
				Store::set_method( $user_id, 'passkey', array( 'enrolled_at' => time() ) );
			}
			if ( $added < count( $passkeys ) ) {
				$result['flags'][] = 'write_failed:passkey';
				if ( 0 === $added ) {
					$imported = array_values( array_diff( $imported, array( 'passkey' ) ) );
				}
				$result['status']          = 'needs_attention';
				$result['needs_attention'] = true;
			}

			$written = Store::methods( $user_id );
			foreach ( array_keys( $writes ) as $provider_id ) {
				if ( ! isset( $written[ $provider_id ] ) ) {
					$result['status']          = 'needs_attention';
					$result['needs_attention'] = true;
					$result['flags'][]         = 'write_failed:' . $provider_id;
					$imported                  = array_values( array_diff( $imported, array( $provider_id ) ) );
				}
			}

			/** This action is documented in includes/class-enrolment.php */
			do_action( 'sigil_methods_changed', $user_id );
		}

		if ( ! $dry_run && '' !== $result['preferred'] && '' === Providers::preference( $user_id ) ) {
			Providers::set_preference( $user_id, $result['preferred'] );
		}

		$result['imported'] = $imported;

		return $result;
	}

	/**
	 * Methods Sigil can already challenge this account with, other than backup
	 * codes. Asked of the providers rather than read from the stored list, so a
	 * passkey row whose credentials are gone does not count.
	 *
	 * @return list<string>
	 */
	public static function usable_sign_in_methods( int $user_id ): array {
		$ids = array();
		foreach ( Providers::instance()->enrolled_for( $user_id ) as $provider ) {
			if ( 'backup' !== $provider->id() ) {
				$ids[] = $provider->id();
			}
		}

		return $ids;
	}

	/**
	 * A base32 authenticator secret as Sigil stores it, or null when Sigil could
	 * never accept a code from it.
	 *
	 * @return array{secret: string, last_step: int}|null
	 */
	public static function totp_record( string $key, int $last_step ): ?array {
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

		return array(
			'secret'    => base64_encode( $encrypted ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- binary ciphertext stored the same way the TOTP provider does.
			'last_step' => max( 0, $last_step ),
		);
	}

	public static function base32_encode( string $data ): string {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits     = '';
		$len      = strlen( $data );

		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= $alphabet[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}

		return $out;
	}

	public static function is_password_hash( string $hash ): bool {
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
	 * A passkey credential as Sigil stores it, from the raw credential id and
	 * the public key, either as COSE (what the authenticator sent) or as PEM.
	 *
	 * Returns the reason it cannot come across instead when there is one:
	 * passkeys_unavailable, passkey_key_unusable or passkey_id_too_long.
	 *
	 * @return array{credential_id: string, public_key: string, sign_count: int, label: string, transports: string}|string
	 */
	public static function passkey_row( string $credential_id, string $public_key, int $sign_count, string $label, string $transports ) {
		$provider = Providers::instance()->get( 'passkey' );
		if ( null === $provider || ! $provider->is_available() ) {
			return 'passkeys_unavailable';
		}

		if ( '' === $credential_id || strlen( $credential_id ) > self::MAX_CREDENTIAL_ID_BYTES ) {
			return 'passkey_id_too_long';
		}

		$pem = 0 === strpos( $public_key, '-----BEGIN PUBLIC KEY-----' ) ? $public_key : self::cose_to_pem( $public_key );
		if ( '' !== $pem && false === openssl_pkey_get_public( $pem ) ) {
			$pem = '';
		}
		if ( '' === $pem ) {
			return 'passkey_key_unusable';
		}

		return array(
			'credential_id' => $credential_id,
			'public_key'    => $pem,
			'sign_count'    => max( 0, $sign_count ),
			'label'         => '' !== trim( $label ) ? $label : __( 'Passkey', 'sigil-2fa' ),
			'transports'    => $transports,
		);
	}

	/**
	 * The PEM public key Sigil's WebAuthn library verifies against.
	 *
	 * That library only reads keys out of authenticator data, so the stored key
	 * is wrapped in the smallest authenticator data that carries one: a blank RP
	 * hash, the user-present and attested-data flags, a zero AAGUID and a one
	 * byte credential id. Nothing here is verified; it is a parse.
	 */
	private static function cose_to_pem( string $cose_key ): string {
		Providers\Passkey::boot();
		if ( '' === $cose_key || ! class_exists( '\lbuchs\WebAuthn\Attestation\AuthenticatorData' ) ) {
			return '';
		}

		$auth = str_repeat( "\0", 32 ) . "\x41" . pack( 'N', 0 ) . str_repeat( "\0", 16 ) . pack( 'n', 1 ) . "\0" . $cose_key;

		try {
			$pem = ( new \lbuchs\WebAuthn\Attestation\AuthenticatorData( $auth ) )->getPublicKeyPem();
		} catch ( \Throwable $e ) {
			return '';
		}

		return is_string( $pem ) ? $pem : '';
	}

	/**
	 * Whether a credential is already in Sigil: '' when it is not, 'mine' when
	 * this user has it, 'other' when it belongs to someone else.
	 */
	public static function passkey_owner( string $credential_id, int $user_id ): string {
		$row = Credentials::by_credential_id( $credential_id );
		if ( null === $row ) {
			return '';
		}

		return (int) $row->user_id === $user_id ? 'mine' : 'other';
	}

	public static function table_exists( string $table ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
	}

	public static function base64url_decode( string $value ): string {
		$b64 = strtr( $value, '-_', '+/' );
		$pad = strlen( $b64 ) % 4;
		if ( $pad > 0 ) {
			$b64 .= str_repeat( '=', 4 - $pad );
		}
		$decoded = base64_decode( $b64, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode

		return false === $decoded ? '' : $decoded;
	}

	/**
	 * @param array{users: list<array<string, mixed>>, counts: array<string, int>} $report
	 */
	public static function remember_report( string $source, int $user_id, array $report, bool $dry_run ): void {
		$report['dry_run'] = $dry_run;
		set_transient( self::REPORT_TRANSIENT . $source . '_' . $user_id, $report, 15 * MINUTE_IN_SECONDS );
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public static function recall_report( string $source, int $user_id ): ?array {
		$report = get_transient( self::REPORT_TRANSIENT . $source . '_' . $user_id );

		return is_array( $report ) ? $report : null;
	}

	/**
	 * Labels for the flags any importer can raise. Each source labels its own
	 * flags first and falls back to these.
	 */
	public static function flag_label( string $flag ): string {
		$parts = explode( ':', $flag, 2 );

		switch ( $parts[0] ) {
			case 'passkeys_unavailable':
				return __( 'Passkeys need PHP 8 with the OpenSSL and mbstring extensions, so they were not imported', 'sigil-2fa' );
			case 'passkey_key_unusable':
				return __( 'A passkey is stored in a key format Sigil cannot check, so it was not imported', 'sigil-2fa' );
			case 'passkey_id_too_long':
				return __( 'A passkey has a credential ID longer than Sigil can store, so it was not imported', 'sigil-2fa' );
			case 'passkey_u2f':
				return __( 'A security key was registered through the old U2F API, which Sigil cannot verify, so it was not imported', 'sigil-2fa' );
			case 'passkey_other_user':
				return __( 'A passkey is already registered to a different account in Sigil, so it was not imported', 'sigil-2fa' );
			case 'passkey_rp_mismatch':
				/* translators: %s: relying party domain the passkeys were registered for */
				return sprintf( __( 'Passkeys were registered for %s, a different domain from the one Sigil signs in on, so browsers would refuse them. They were not imported', 'sigil-2fa' ), $parts[1] ?? '' );
			case 'unsupported_method':
				/* translators: %s: method name in the source plugin */
				return sprintf( __( 'Method %s has no Sigil equivalent', 'sigil-2fa' ), $parts[1] ?? '' );
			case 'email_address_invalid':
				return __( 'Account has no valid email address, so email codes could not be set up', 'sigil-2fa' );
			case 'totp_secret_unusable':
				return __( 'Authenticator secret could not be read, so it was not imported', 'sigil-2fa' );
			case 'backup_codes_unverifiable':
				return __( 'Backup codes are in a format Sigil cannot check, so they were not imported', 'sigil-2fa' );
			case 'backup_codes_none_left':
				return __( 'Backup codes were switched on but none were left', 'sigil-2fa' );
			case 'write_failed':
				/* translators: %s: Sigil method id */
				return sprintf( __( 'Saving %s failed', 'sigil-2fa' ), $parts[1] ?? '' );
			case 'user_not_found':
				return __( 'User not found', 'sigil-2fa' );
		}

		return $flag;
	}
}
