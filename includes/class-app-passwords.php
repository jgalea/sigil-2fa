<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class App_Passwords {

	private static ?App_Passwords $instance = null;

	/** @var array<int, true> */
	private array $app_password_users = array();

	public static function instance(): App_Passwords {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'filter_available' ), 10, 2 );
		add_action( 'application_password_did_authenticate', array( $this, 'note_application_password' ) );
		add_filter( 'authenticate', array( $this, 'refuse_api_password' ), 40 );
	}

	/**
	 * @param mixed $user
	 */
	public function note_application_password( $user ): void {
		if ( $user instanceof \WP_User ) {
			$this->app_password_users[ (int) $user->ID ] = true;
		}
	}

	public function used_application_password( int $user_id ): bool {
		return isset( $this->app_password_users[ $user_id ] );
	}

	/**
	 * Refuse the account password on XML-RPC and REST for anyone with a second
	 * factor.
	 *
	 * Those requests never reach wp_login, where the challenge runs, so a
	 * password accepted there is a sign-in with one factor. Application
	 * passwords are the way in for API clients and are left alone.
	 *
	 * @param mixed $user
	 * @return mixed
	 */
	public function refuse_api_password( $user ) {
		if ( ! $user instanceof \WP_User || ! self::is_api_request() ) {
			return $user;
		}

		if ( $this->used_application_password( (int) $user->ID ) ) {
			return $user;
		}

		if ( ! Providers::instance()->has_usable( (int) $user->ID ) ) {
			return $user;
		}

		return new \WP_Error(
			'sigil_api_password_refused',
			__( 'This account uses two-factor authentication. Use an application password for API access.', 'sigil-2fa' )
		);
	}

	public static function is_api_request(): bool {
		return ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST );
	}

	/**
	 * @param bool             $available Whether application passwords are available.
	 * @param int|\WP_User|null $user     User id or object.
	 */
	public function filter_available( $available, $user ): bool {
		if ( ! $available ) {
			return false;
		}

		if ( ! $user instanceof \WP_User ) {
			$user = get_userdata( (int) $user );
		}

		if ( ! $user instanceof \WP_User ) {
			return (bool) $available;
		}

		$blocked = Policy::get()['block_app_passwords'];
		foreach ( (array) $user->roles as $role ) {
			if ( ! is_string( $role ) || '' === $role ) {
				continue;
			}
			if ( ! empty( $blocked[ $role ] ) ) {
				return false;
			}
		}

		return true;
	}
}
