<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Carry users over from WP 2FA by Melapress.
 *
 * Reads WP 2FA's user meta and options directly and writes none of it, so the
 * import works with WP 2FA active or not and deactivating Sigil puts everyone
 * back on WP 2FA.
 *
 * WP 2FA gives each user one primary method plus optional backup codes. While
 * both plugins are active, Sigil's challenge runs first on wp_login and WP 2FA
 * never sees the sign-in of anyone Sigil can challenge; everyone else stays
 * with WP 2FA.
 */
final class WP_2FA_Import {

	private const META_METHOD    = 'wp_2fa_enabled_methods';
	private const META_TOTP      = 'wp_2fa_totp_key';
	private const META_TOTP_STEP = 'wp_2fa_last_totp_step';
	private const META_BACKUP    = 'wp_2fa_backup_codes';
	private const META_EMAIL     = 'wp_2fa_nominated_email_address';
	private const META_PASSKEY   = 'wp_2fa_passkey_';

	private const OPTION_KEY    = 'wp_2fa_secret_key';
	private const OPTION_POLICY = 'wp_2fa_policy';
	private const CONSTANT_KEY  = 'WP2FA_ENCRYPT_KEY';

	// WP 2FA's backup codes are sixteen digits.
	private const BACKUP_LENGTH = 16;

	private const MAP = array(
		'totp'     => 'totp',
		'email'    => 'email',
		'passkeys' => 'passkey',
	);

	public static function is_active(): bool {
		return defined( 'WP_2FA_VERSION' ) || class_exists( '\WP2FA\WP2FA', false );
	}

	public static function has_data(): bool {
		return array() !== self::candidates( 1 );
	}

	/**
	 * Every user with a WP 2FA method, secret or backup codes.
	 *
	 * @return list<int>
	 */
	public static function candidates( int $limit = -1 ): array {
		$ids = array();

		foreach ( array( self::META_METHOD, self::META_TOTP, self::META_BACKUP ) as $key ) {
			$args = array(
				'meta_key' => $key, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'fields'   => 'ID',
				'number'   => $limit,
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

		$method   = get_user_meta( $user_id, self::META_METHOD, true );
		$method   = is_string( $method ) ? $method : '';
		$keys     = self::passkey_records( $user_id );
		$sigil    = Store::methods( $user_id );
		$writes   = array();
		$passkeys = array();
		$lost     = false;

		if ( '' === $method && array() === $keys ) {
			// A secret or codes left behind by someone who never finished setting
			// up, or who was reset, was not protecting the account.
			$result['status'] = 'not_using';
			if ( '' !== (string) get_user_meta( $user_id, self::META_TOTP, true ) || array() !== self::backup_hashes( $user_id ) ) {
				$result['flags'][] = 'data_without_enabled_method';
			}
			return $result;
		}

		if ( '' !== $method && ! isset( self::MAP[ $method ] ) ) {
			$result['flags'][] = 'unsupported_method:' . sanitize_key( $method );
			$lost              = true;
		}

		if ( 'totp' === $method ) {
			if ( isset( $sigil['totp'] ) ) {
				$result['already'][] = 'totp';
			} else {
				$data = self::totp_record( $user_id, $result['flags'] );
				if ( null === $data ) {
					$lost = true;
				} else {
					$writes['totp'] = $data;
				}
			}
		}

		if ( 'email' === $method ) {
			$nominated = (string) get_user_meta( $user_id, self::META_EMAIL, true );
			if ( isset( $sigil['email'] ) ) {
				$result['already'][] = 'email';
			} elseif ( '' !== $nominated && 0 !== strcasecmp( $nominated, $user->user_email ) ) {
				// Sigil sends codes to the account address. Someone who told WP 2FA
				// to use another inbox may not read this one, so they are left on
				// WP 2FA rather than locked out.
				$result['flags'][] = 'email_address_differs';
				$lost              = true;
			} elseif ( ! is_email( $user->user_email ) ) {
				$result['flags'][] = 'email_address_invalid';
				$lost              = true;
			} else {
				$writes['email'] = array( 'enrolled_at' => time() );
			}
		}

		if ( array() !== $keys ) {
			$carried  = self::passkey_rows( $user_id, $keys, $result['flags'] );
			$passkeys = $carried['rows'];
			$lost     = $carried['lost'] || $lost;
			if ( $carried['already'] ) {
				$result['already'][] = 'passkey';
			}
		} elseif ( 'passkeys' === $method ) {
			$result['flags'][] = 'passkey_never_registered';
			$lost              = true;
		}

		$hashes = self::backup_hashes( $user_id );
		if ( isset( $sigil['backup'] ) ) {
			$result['already'][] = 'backup';
		} elseif ( array() !== $hashes ) {
			$codes = self::backup_record( $hashes );
			if ( null === $codes ) {
				$result['flags'][] = 'backup_codes_unverifiable';
			} else {
				$writes['backup'] = $codes;
			}
		}

		$will_have_signin = array() !== Import::usable_sign_in_methods( $user_id ) || isset( $writes['totp'] ) || isset( $writes['email'] ) || array() !== $passkeys;

		if ( ! $will_have_signin || ( $lost && ! isset( $sigil['email'] ) && ! isset( $writes['email'] ) ) ) {
			// Half a setup would have Sigil challenge this person with whatever came
			// across, and WP 2FA would never get to ask for the method they actually
			// use. Nothing is written; WP 2FA keeps them until they have set up
			// something in Sigil.
			$writes   = array();
			$passkeys = array();

			$result['status']          = 'needs_attention';
			$result['needs_attention'] = true;
		}

		$will_have = array_merge( array_keys( $sigil ), array_keys( $writes ), array() !== $passkeys ? array( 'passkey' ) : array() );
		foreach ( array( self::MAP[ $method ] ?? '', 'passkey', 'totp', 'email' ) as $id ) {
			if ( '' !== $id && in_array( $id, $will_have, true ) ) {
				$result['preferred'] = $id;
				break;
			}
		}

		return Import::apply( $result, $user_id, $writes, $passkeys, $dry_run );
	}

	/**
	 * @param list<string> $flags
	 * @return array{secret: string, last_step: int}|null
	 */
	private static function totp_record( int $user_id, array &$flags ): ?array {
		$stored = get_user_meta( $user_id, self::META_TOTP, true );
		if ( ! is_string( $stored ) || '' === $stored ) {
			$flags[] = 'totp_never_configured';
			return null;
		}

		$secret = self::decrypt( $stored );
		if ( null === $secret ) {
			$flags[] = 'encryption_key_unreadable';
			return null;
		}

		// WP 2FA refuses a code from a step it has already accepted. Carrying the
		// step across stops that same code being replayed into Sigil.
		$data = Import::totp_record( $secret, (int) get_user_meta( $user_id, self::META_TOTP_STEP, true ) );
		if ( null === $data ) {
			$flags[] = 'totp_secret_unusable';
		}

		return $data;
	}

	/**
	 * The base32 secret behind a stored WP 2FA value, or null when it cannot be
	 * opened. A value that opens to garbage comes back as garbage, and the
	 * secret check that follows refuses it.
	 *
	 * WP 2FA has written four formats over the years, told apart by prefix:
	 * "lsc_v2:" is XSalsa20-Poly1305 (sodium secretbox) under a key derived from
	 * its own site key, "lsc_" and "ssl_" are AES-256-CTR under a SHA-256 of
	 * that key, and "wps_" is AES-256-CTR under a SHA-256 of WordPress's auth
	 * salt. Anything without a prefix was stored in the clear.
	 */
	private static function decrypt( string $stored ): ?string {
		$prefix = substr( $stored, 0, 4 );
		$body   = (string) substr( $stored, 4 );

		if ( 'wps_' === $prefix ) {
			return self::open_ctr( $body, hash( 'sha256', (string) base64_decode( wp_salt() ), true ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- WP 2FA's key derivation.
		}

		if ( 'lsc_' !== $prefix && 'ssl_' !== $prefix ) {
			return $stored;
		}

		$site_key = self::site_key();
		if ( '' === $site_key ) {
			return null;
		}
		$key = hash( 'sha256', (string) base64_decode( $site_key ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- WP 2FA's key derivation.

		if ( 'lsc_' === $prefix && 0 === strpos( $body, 'v2:' ) ) {
			$raw = base64_decode( substr( $body, 3 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false === $raw || strlen( $raw ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
				return null;
			}

			try {
				$plain = sodium_crypto_secretbox_open(
					substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ),
					substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ),
					hash_hmac( 'sha256', 'wp-2fa authenticated encryption v2', $key, true )
				);
			} catch ( \Throwable $e ) {
				return null;
			}

			return false === $plain ? null : $plain;
		}

		return self::open_ctr( $body, $key );
	}

	private static function open_ctr( string $body, string $key ): ?string {
		$raw = base64_decode( $body, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $raw || strlen( $raw ) <= 16 ) {
			return null;
		}

		$plain = openssl_decrypt( substr( $raw, 16 ), 'aes-256-ctr', $key, OPENSSL_RAW_DATA, substr( $raw, 0, 16 ) );

		return false === $plain ? null : $plain;
	}

	/**
	 * WP 2FA's own encryption key: a constant in wp-config.php when it could
	 * write one there, otherwise an option.
	 */
	private static function site_key(): string {
		if ( defined( self::CONSTANT_KEY ) && is_string( constant( self::CONSTANT_KEY ) ) ) {
			return (string) constant( self::CONSTANT_KEY );
		}

		$key = is_multisite() ? get_network_option( null, self::OPTION_KEY, '' ) : get_option( self::OPTION_KEY, '' );

		return is_string( $key ) ? $key : '';
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
	 * WP 2FA hashes its sixteen-digit codes with wp_hash_password(), so the
	 * hashes carry over unchanged and Sigil checks them at that length.
	 *
	 * @param list<string> $hashes
	 * @return array{codes: list<array{hash: string, used: bool}>, length: int}|null
	 */
	private static function backup_record( array $hashes ): ?array {
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

		return array(
			'codes'  => $codes,
			'length' => self::BACKUP_LENGTH,
		);
	}

	/**
	 * WP 2FA's passkeys, one user meta row each holding JSON.
	 *
	 * @return list<array<string, mixed>>
	 */
	private static function passkey_records( int $user_id ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WP 2FA keys its passkeys by credential id inside the meta key, so there is no fixed key to ask get_user_meta() for.
		$values = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key LIKE %s ORDER BY umeta_id ASC",
				$user_id,
				$wpdb->esc_like( self::META_PASSKEY ) . '%'
			)
		);

		$records = array();
		foreach ( is_array( $values ) ? $values : array() as $value ) {
			$data = json_decode( (string) $value, true );
			if ( is_array( $data ) && isset( $data['extra']['credential_id'], $data['extra']['public_key'] ) && false !== ( $data['extra']['enabled'] ?? true ) ) {
				$records[] = $data['extra'];
			}
		}

		return $records;
	}

	/**
	 * @param list<array<string, mixed>> $records
	 * @param list<string>               $flags
	 * @return array{rows: list<array{credential_id: string, public_key: string, sign_count: int, label: string, transports: string, user_handle: string, discoverable: bool|null}>, lost: bool, already: bool}
	 */
	private static function passkey_rows( int $user_id, array $records, array &$flags ): array {
		$out = array(
			'rows'    => array(),
			'lost'    => false,
			'already' => false,
		);

		// WP 2FA registers passkeys for the host in the site URL.
		$source_rp = strtolower( (string) wp_parse_url( (string) get_option( 'siteurl' ), PHP_URL_HOST ) );
		if ( Providers\Passkey::rp_id() !== $source_rp ) {
			$flags[]     = 'passkey_rp_mismatch:' . $source_rp;
			$out['lost'] = true;
			return $out;
		}

		foreach ( $records as $record ) {
			$credential_id = base64_decode( (string) $record['credential_id'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			$credential_id = false === $credential_id ? '' : $credential_id;

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

			$transports = json_decode( (string) ( $record['transports'] ?? '' ), true );
			$transports = is_array( $transports ) ? implode( ',', array_filter( $transports, 'is_string' ) ) : '';

			$row = Import::passkey_row( $credential_id, (string) $record['public_key'], (int) ( $record['signature_counter'] ?? 0 ), (string) ( $record['name'] ?? '' ), $transports );
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
	 * WP 2FA's enforcement policy restated as Sigil's, for an administrator to
	 * apply if they want it. Parts with no Sigil equivalent are listed in
	 * 'skipped' rather than guessed at.
	 *
	 * @return array{policy: array{enabled: bool, roles: array<string, bool>, grace_days: int}|null, skipped: list<string>}
	 */
	public static function policy(): array {
		$raw = is_multisite() ? get_network_option( null, self::OPTION_POLICY, array() ) : get_option( self::OPTION_POLICY, array() );
		$raw = is_array( $raw ) ? $raw : array();

		$mode     = isset( $raw['enforcement-policy'] ) && is_string( $raw['enforcement-policy'] ) ? $raw['enforcement-policy'] : 'do-not-enforce';
		$excluded = self::role_list( $raw['excluded_roles'] ?? array() );
		$skipped  = array();

		$roles = array();
		if ( 'all-users' === $mode ) {
			$roles = array_keys( wp_roles()->roles );
		} elseif ( 'certain-roles-only' === $mode ) {
			$roles = self::role_list( $raw['enforced_roles'] ?? array() );
		} elseif ( 'do-not-enforce' !== $mode ) {
			// Per-user and super-admin-only enforcement have no role-based Sigil
			// equivalent, and a policy that silently widened would lock people out.
			$skipped[] = 'enforcement:' . sanitize_key( $mode );
		}

		if ( array() !== self::role_list( $raw['enforced_users'] ?? array() ) ) {
			$skipped[] = 'enforced_users';
		}
		if ( array() !== self::role_list( $raw['excluded_users'] ?? array() ) ) {
			$skipped[] = 'excluded_users';
		}

		$roles = array_values( array_diff( $roles, $excluded ) );
		if ( array() === $roles ) {
			return array(
				'policy'  => null,
				'skipped' => $skipped,
			);
		}

		$grace = isset( $raw['grace-period'] ) ? max( 0, (int) $raw['grace-period'] ) : 3;
		$unit  = isset( $raw['grace-period-denominator'] ) && is_string( $raw['grace-period-denominator'] ) ? $raw['grace-period-denominator'] : 'days';
		if ( 'hours' === $unit ) {
			$grace = (int) ceil( $grace / 24 );
		} elseif ( 'minutes' === $unit ) {
			$grace = (int) ceil( $grace / 1440 );
		}

		return array(
			'policy'  => array(
				'enabled'    => true,
				'roles'      => array_fill_keys( $roles, true ),
				'grace_days' => $grace,
			),
			'skipped' => $skipped,
		);
	}

	/**
	 * @param mixed $raw
	 * @return list<string>
	 */
	private static function role_list( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}

		return array_values( array_map( 'sanitize_key', array_filter( $raw, 'is_string' ) ) );
	}

	/**
	 * Switch Sigil's policy on for the roles WP 2FA enforced. Returns false when
	 * WP 2FA enforced nothing Sigil can express.
	 */
	public static function apply_policy(): bool {
		$mapped = self::policy()['policy'];
		if ( null === $mapped ) {
			return false;
		}

		$roles = array();
		foreach ( array_keys( wp_roles()->roles ) as $role ) {
			$roles[ $role ] = ! empty( $mapped['roles'][ $role ] );
		}

		Policy::update(
			array(
				'enabled'     => true,
				'enforce_all' => false,
				'roles'       => $roles,
				'grace_days'  => $mapped['grace_days'],
			)
		);

		return true;
	}

	public static function flag_label( string $flag ): string {
		switch ( explode( ':', $flag, 2 )[0] ) {
			case 'totp_never_configured':
				return __( 'Authenticator app was chosen but no secret was ever saved in WP 2FA', 'sigil-2fa' );
			case 'encryption_key_unreadable':
				return __( 'WP 2FA\'s encryption key is missing, so the authenticator secret could not be read', 'sigil-2fa' );
			case 'email_address_differs':
				return __( 'WP 2FA sent codes to a different address from the account email, so email codes were not set up', 'sigil-2fa' );
			case 'passkey_never_registered':
				return __( 'Passkeys were chosen but none was ever registered', 'sigil-2fa' );
			case 'data_without_enabled_method':
				return __( 'WP 2FA data exists but no method was switched on, so nothing was imported', 'sigil-2fa' );
		}

		return Import::flag_label( $flag );
	}
}
