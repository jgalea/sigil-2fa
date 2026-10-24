<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Policy {

	public const OPTION_KEY   = 'sigil_policy';
	public const DEADLINE_META = '_sigil_deadline';

	/**
	 * @return array{
	 *   enabled: bool,
	 *   roles: array<string, bool>,
	 *   min_capability: string,
	 *   grace_days: int,
	 *   block_app_passwords: array<string, bool>,
	 *   passwordless: bool
	 * }
	 */
	private static function defaults(): array {
		return [
			'enabled'             => false,
			'roles'               => [],
			'min_capability'      => '',
			'grace_days'          => 7,
			'block_app_passwords' => [],
			'passwordless'        => true,
		];
	}

	/**
	 * @return array{
	 *   enabled: bool,
	 *   roles: array<string, bool>,
	 *   min_capability: string,
	 *   grace_days: int,
	 *   block_app_passwords: array<string, bool>,
	 *   passwordless: bool
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
	 * @param array<string, mixed> $policy
	 */
	public static function update( array $policy ): void {
		$merged = array_merge( self::get(), $policy );
		Network::update_option( self::OPTION_KEY, self::sanitize( $merged ) );
	}

	public static function required_for( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$policy = self::get();
		if ( ! $policy['enabled'] ) {
			return false;
		}

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User ) {
			return false;
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
		if ( '' !== $cap && user_can( $user, $cap ) ) {
			return true;
		}

		return false;
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
	 *   roles: array<string, bool>,
	 *   min_capability: string,
	 *   grace_days: int,
	 *   block_app_passwords: array<string, bool>,
	 *   passwordless: bool
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
			'roles'               => self::sanitize_role_map( $policy['roles'] ?? [] ),
			'min_capability'      => $cap,
			'grace_days'          => $grace,
			'block_app_passwords' => self::sanitize_role_map( $policy['block_app_passwords'] ?? [] ),
			'passwordless'        => ! empty( $policy['passwordless'] ),
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
