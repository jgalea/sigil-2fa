<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Policy {

	public const OPTION_KEY   = 'sigil_policy';
	public const DEADLINE_META = '_sigil_deadline';

	private const EXTRA = array( 'trusted_enabled', 'trusted_days', 'trusted_roles', 'zero_setup' );

	/**
	 * @return array{
	 *   enabled: bool,
	 *   enforce_all: bool,
	 *   roles: array<string, bool>,
	 *   min_capability: string,
	 *   grace_days: int,
	 *   block_app_passwords: array<string, bool>,
	 *   passwordless: bool,
	 *   limit_passwords: bool
	 * }
	 */
	private static function defaults(): array {
		return [
			'enabled'             => false,
			'enforce_all'         => false,
			'roles'               => [],
			'min_capability'      => '',
			'grace_days'          => 7,
			'block_app_passwords' => [],
			'passwordless'        => true,
			'limit_passwords'     => true,
		];
	}

	/**
	 * @return array{
	 *   enabled: bool,
	 *   enforce_all: bool,
	 *   roles: array<string, bool>,
	 *   min_capability: string,
	 *   grace_days: int,
	 *   block_app_passwords: array<string, bool>,
	 *   passwordless: bool,
	 *   limit_passwords: bool
	 * }
	 */
	public static function get(): array {
		$raw = Network::get_option( self::OPTION_KEY, [] );
		if ( ! is_array( $raw ) ) {
			$raw = [];
		}

		return self::sanitize( array_merge( self::defaults(), $raw ) );
	}

	/**
	 * The policy plus the switches next to it that also decide how much a
	 * sign-in is protected, so one comparison covers all of them.
	 *
	 * @return array<string, mixed>
	 */
	public static function protections(): array {
		return self::get() + array(
			'trusted_enabled' => (bool) Network::get_option( Trusted_Devices::OPTION_ENABLED, 1 ),
			'trusted_days'    => Trusted_Devices::trust_days(),
			'trusted_roles'   => array_filter( self::sanitize_role_map( Network::get_option( Trusted_Devices::OPTION_ROLES, array() ) ) ),
			'zero_setup'      => Zero_Setup::is_enabled(),
		);
	}

	/**
	 * @param array<string, mixed> $current
	 * @param array<string, mixed> $patch
	 * @return array<string, mixed>
	 */
	private static function merged( array $current, array $patch ): array {
		$after = self::sanitize( array_merge( $current, $patch ) );
		$extra = array_merge( array_intersect_key( $current, array_flip( self::EXTRA ) ), array_intersect_key( $patch, array_flip( self::EXTRA ) ) );

		$after['trusted_enabled'] = ! empty( $extra['trusted_enabled'] );
		$after['trusted_days']    = max( 1, min( 365, (int) ( $extra['trusted_days'] ?? 1 ) ) );
		$after['trusted_roles']   = array_filter( self::sanitize_role_map( $extra['trusted_roles'] ?? array() ) );
		$after['zero_setup']      = ! empty( $extra['zero_setup'] );

		return $after;
	}

	/**
	 * @param array<string, mixed> $patch Policy fields, and any of trusted_enabled, trusted_days, trusted_roles and zero_setup.
	 */
	public static function update( array $patch ): void {
		$before = self::protections();
		$after  = self::merged( $before, $patch );

		Network::update_option( self::OPTION_KEY, array_diff_key( $after, array_flip( self::EXTRA ) ) );
		if ( array_key_exists( 'trusted_enabled', $patch ) ) {
			Network::update_option( Trusted_Devices::OPTION_ENABLED, $after['trusted_enabled'] ? 1 : 0 );
		}
		if ( array_key_exists( 'trusted_days', $patch ) ) {
			Network::update_option( Trusted_Devices::OPTION_DAYS, $after['trusted_days'] );
		}
		if ( array_key_exists( 'trusted_roles', $patch ) ) {
			Network::update_option( Trusted_Devices::OPTION_ROLES, $after['trusted_roles'] );
		}
		if ( array_key_exists( 'zero_setup', $patch ) ) {
			Zero_Setup::set_enabled( $after['zero_setup'] );
		}

		$weakened = self::weakened( $before, $after );
		if ( array() !== $weakened ) {
			/**
			 * Fires after a policy change that protects less than before.
			 *
			 * @param list<string> $weakened What was switched off, in words.
			 */
			do_action( 'sigil_policy_weakened', $weakened );
		}
	}

	/**
	 * What saving this patch would loosen.
	 *
	 * @param array<string, mixed> $patch
	 * @return list<string>
	 */
	public static function weakened_by( array $patch ): array {
		$current = self::protections();

		return self::weakened( $current, self::merged( $current, $patch ) );
	}

	/**
	 * @param array<string, mixed> $before
	 * @param array<string, mixed> $after
	 * @return list<string>
	 */
	private static function weakened( array $before, array $after ): array {
		$labels = array(
			'enabled'         => __( 'Requiring two-factor authentication', 'sigil-2fa' ),
			'enforce_all'     => __( 'Requiring it for all users', 'sigil-2fa' ),
			'passwordless'    => __( 'Passwordless sign-in', 'sigil-2fa' ),
			'limit_passwords' => __( 'Password attempt limits', 'sigil-2fa' ),
		);

		$out = array();
		foreach ( $labels as $key => $label ) {
			if ( ! empty( $before[ $key ] ) && empty( $after[ $key ] ) ) {
				$out[] = $label;
			}
		}

		foreach ( (array) $before['roles'] as $role => $on ) {
			if ( $on && empty( $after['roles'][ $role ] ) ) {
				/* translators: %s: role slug */
				$out[] = sprintf( __( 'Requiring it for the %s role', 'sigil-2fa' ), $role );
			}
		}

		foreach ( (array) $before['block_app_passwords'] as $role => $on ) {
			if ( $on && empty( $after['block_app_passwords'][ $role ] ) ) {
				/* translators: %s: role slug */
				$out[] = sprintf( __( 'Blocking application passwords for the %s role', 'sigil-2fa' ), $role );
			}
		}

		if ( '' !== $before['min_capability'] && $before['min_capability'] !== $after['min_capability'] ) {
			$was = self::roles_holding( $before['min_capability'] );
			$now = '' === $after['min_capability'] ? array() : self::roles_holding( $after['min_capability'] );
			if ( '' === $after['min_capability'] || array() !== array_diff( $was, $now ) ) {
				$out[] = __( 'The minimum capability rule', 'sigil-2fa' );
			}
		}

		if ( empty( $before['zero_setup'] ) && ! empty( $after['zero_setup'] ) ) {
			$out[] = __( 'Accepting email codes without setup', 'sigil-2fa' );
		}

		if ( empty( $before['trusted_enabled'] ) && ! empty( $after['trusted_enabled'] ) ) {
			$out[] = __( 'Trusted devices', 'sigil-2fa' );
		}

		if ( (int) $after['trusted_days'] > (int) $before['trusted_days'] ) {
			$out[] = __( 'How long a device stays trusted', 'sigil-2fa' );
		}

		$trusting = array_keys( (array) $before['trusted_roles'] );
		if ( array() !== $trusting && ( array() === $after['trusted_roles'] || array() !== array_diff( array_keys( (array) $after['trusted_roles'] ), $trusting ) ) ) {
			$out[] = __( 'Which roles can trust a device', 'sigil-2fa' );
		}

		return $out;
	}

	/**
	 * @return list<string>
	 */
	private static function roles_holding( string $capability ): array {
		$roles = array();
		foreach ( wp_roles()->roles as $slug => $role ) {
			if ( ! empty( $role['capabilities'][ $capability ] ) ) {
				$roles[] = (string) $slug;
			}
		}

		return $roles;
	}

	public static function required_for( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$user = get_userdata( $user_id );

		return $user instanceof \WP_User && self::covers( self::get(), $user );
	}

	/**
	 * Whether switching the policy to this one would put the person making the
	 * change under a requirement they cannot yet meet.
	 *
	 * Only a new requirement counts. Someone already covered by the stored
	 * policy is not being locked out by an unrelated save.
	 *
	 * @param array<string, mixed> $patch
	 */
	public static function would_lock_out( int $user_id, array $patch ): bool {
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user instanceof \WP_User ) {
			return false;
		}

		$current = self::get();
		$next    = self::sanitize( array_merge( $current, $patch ) );

		return self::covers( $next, $user )
			&& ! self::covers( $current, $user )
			&& ! Providers::instance()->has_usable( $user_id );
	}

	/**
	 * Whether a role on this site carries the capability. An empty value is
	 * fine, it means no capability rule.
	 */
	public static function is_known_capability( string $cap ): bool {
		if ( '' === $cap ) {
			return true;
		}

		foreach ( wp_roles()->roles as $role ) {
			if ( is_array( $role ) && ! empty( $role['capabilities'][ $cap ] ) ) {
				return true;
			}
		}

		return false;
	}

	public static function lockout_message(): string {
		return __( 'Nothing was saved. This would require two-factor authentication for your own account, and you have not set up a method yet, so you would be locked out. Set up a passkey or an authenticator app first, then try again.', 'sigil-2fa' );
	}

	/**
	 * @param array{enabled: bool, enforce_all: bool, roles: array<string, bool>, min_capability: string} $policy
	 */
	private static function covers( array $policy, \WP_User $user ): bool {
		if ( ! $policy['enabled'] ) {
			return false;
		}

		if ( $policy['enforce_all'] ) {
			return true;
		}

		foreach ( (array) $user->roles as $role ) {
			if ( ! is_string( $role ) || '' === $role ) {
				continue;
			}
			if ( ! empty( $policy['roles'][ $role ] ) ) {
				return true;
			}
		}

		$cap = $policy['min_capability'];

		return '' !== $cap && user_can( $user, $cap );
	}

	/**
	 * The deadline already on record, for screens that only show it. Unlike
	 * deadline_for() this never starts a clock, so listing users can't assign
	 * deadlines or send warning emails as a side effect.
	 */
	public static function recorded_deadline( int $user_id ): ?int {
		if ( $user_id <= 0 || ! self::required_for( $user_id ) ) {
			return null;
		}

		$existing = get_user_meta( $user_id, self::DEADLINE_META, true );

		return is_numeric( $existing ) && (int) $existing > 0 ? (int) $existing : null;
	}

	public static function deadline_for( int $user_id ): ?int {
		if ( $user_id <= 0 || ! self::required_for( $user_id ) ) {
			return null;
		}

		$existing = get_user_meta( $user_id, self::DEADLINE_META, true );
		if ( is_numeric( $existing ) && (int) $existing > 0 ) {
			return (int) $existing;
		}

		$policy   = self::get();
		$deadline = time() + ( (int) $policy['grace_days'] * DAY_IN_SECONDS );
		update_user_meta( $user_id, self::DEADLINE_META, $deadline );

		/**
		 * Fires the first time a user is given a deadline to enrol by.
		 *
		 * The only moment we know someone has just come under the policy, and
		 * the only chance to tell them before they meet it.
		 *
		 * @param int $user_id
		 * @param int $deadline Unix timestamp.
		 */
		do_action( 'sigil_deadline_assigned', $user_id, $deadline );

		return $deadline;
	}

	public static function must_enrol_now( int $user_id ): bool {
		if ( $user_id <= 0 || ! self::required_for( $user_id ) ) {
			return false;
		}

		if ( Providers::instance()->has_usable( $user_id ) ) {
			return false;
		}

		$deadline = self::deadline_for( $user_id );
		if ( null === $deadline ) {
			return false;
		}

		return time() >= $deadline;
	}

	/**
	 * @param array<string, mixed> $policy
	 * @return array{
	 *   enabled: bool,
	 *   enforce_all: bool,
	 *   roles: array<string, bool>,
	 *   min_capability: string,
	 *   grace_days: int,
	 *   block_app_passwords: array<string, bool>,
	 *   passwordless: bool,
	 *   limit_passwords: bool
	 * }
	 */
	private static function sanitize( array $policy ): array {
		$defaults = self::defaults();

		$grace = isset( $policy['grace_days'] ) ? (int) $policy['grace_days'] : $defaults['grace_days'];
		if ( $grace < 0 ) {
			$grace = 0;
		}

		$cap = '';
		if ( isset( $policy['min_capability'] ) && is_string( $policy['min_capability'] ) ) {
			$cap = sanitize_key( $policy['min_capability'] );
		}

		return [
			'enabled'             => ! empty( $policy['enabled'] ),
			'enforce_all'         => ! empty( $policy['enforce_all'] ),
			'roles'               => self::sanitize_role_map( $policy['roles'] ?? [] ),
			'min_capability'      => $cap,
			'grace_days'          => $grace,
			'block_app_passwords' => self::sanitize_role_map( $policy['block_app_passwords'] ?? [] ),
			'passwordless'        => ! empty( $policy['passwordless'] ),
			'limit_passwords'     => ! empty( $policy['limit_passwords'] ),
		];
	}

	/**
	 * @param mixed $map
	 * @return array<string, bool>
	 */
	private static function sanitize_role_map( $map ): array {
		if ( ! is_array( $map ) ) {
			return [];
		}

		$out = [];
		foreach ( $map as $role => $enabled ) {
			if ( ! is_string( $role ) || '' === $role ) {
				continue;
			}
			$role = sanitize_key( $role );
			if ( '' === $role ) {
				continue;
			}
			$out[ $role ] = (bool) $enabled;
		}

		return $out;
	}
}
