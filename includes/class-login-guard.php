<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Keeps password-only sign-ins out of admin-ajax and cron.
 *
 * The challenge runs on wp_login and needs a page to render, so it stands
 * aside for AJAX and cron. Any admin-ajax handler that calls wp_signon(), as
 * popup and theme login forms do, would then hand out a session on the
 * password alone. Two layers stop that: the password is refused when an AJAX
 * request asks for it, and no auth cookie leaves an AJAX or cron response for
 * someone with a second factor, whoever tries to set one.
 *
 * A request that only checks the credentials is a different thing. Wordfence
 * calls wp_authenticate() over admin-ajax before letting wp-login.php submit
 * normally, and refusing it there would mean nobody with a second factor could
 * sign in. Those actions keep their answer, and the real POST that follows is
 * challenged as usual.
 */
final class Login_Guard {

	private static ?Login_Guard $instance = null;

	/** @var array<int, true> */
	private array $new_users = array();

	public static function instance(): Login_Guard {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'authenticate', array( $this, 'refuse_password' ), 40 );
		add_filter( 'send_auth_cookies', array( $this, 'hold_cookies' ), 10, 6 );
		add_action( 'user_register', array( $this, 'note_new_user' ) );
	}

	/**
	 * @param mixed $user_id
	 */
	public function note_new_user( $user_id ): void {
		$this->new_users[ (int) $user_id ] = true;
	}

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function refuse_password( $user ) {
		if ( ! $user instanceof \WP_User || ! self::is_guarded_request() || self::is_credential_check() ) {
			return $user;
		}

		if ( App_Passwords::instance()->used_application_password( (int) $user->ID ) ) {
			return $user;
		}

		if ( ! Providers::instance()->has_usable( (int) $user->ID ) ) {
			return $user;
		}

		return new \WP_Error(
			'sigil_ajax_password_refused',
			__( 'This account uses two-factor authentication. Sign in from the login page.', 'sigil-2fa' ),
			array(
				'status'    => 403,
				'login_url' => wp_login_url(),
			)
		);
	}

	/**
	 * Refuse to send a session cookie from AJAX or cron to anyone with a second
	 * factor.
	 *
	 * This catches the handlers that skip wp_signon() and set the cookie
	 * themselves, and anything that slips past refuse_password(). The session
	 * WordPress has just stored for the cookie is destroyed too, so nothing is
	 * left behind that could be used later. Sigil never issues a session from
	 * either context, so nothing legitimate is held here.
	 *
	 * An account created in this same request is let through. WooCommerce signs
	 * a new customer in from its checkout over AJAX, and when every account
	 * counts as covered by an emailed code, holding that cookie would leave
	 * people who have just registered signed out. Registering can only create
	 * an account, never reach an existing one.
	 *
	 * @param bool   $send
	 * @param int    $expire
	 * @param int    $expiration
	 * @param int    $user_id
	 * @param string $scheme
	 * @param string $token
	 */
	public function hold_cookies( $send, $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ): bool {
		unset( $expire, $expiration, $scheme );

		$user_id = (int) $user_id;
		if ( ! $send || $user_id <= 0 || ! self::is_guarded_request() ) {
			return (bool) $send;
		}

		if ( isset( $this->new_users[ $user_id ] ) || ! Providers::instance()->has_usable( $user_id ) ) {
			return true;
		}

		if ( is_string( $token ) && '' !== $token ) {
			\WP_Session_Tokens::get_instance( $user_id )->destroy( $token );
		}

		return false;
	}

	private static function is_guarded_request(): bool {
		return wp_doing_ajax() || wp_doing_cron();
	}

	private static function is_credential_check(): bool {
		if ( ! wp_doing_ajax() ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- routing check only.
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		if ( '' === $action ) {
			return false;
		}

		/**
		 * Filter the admin-ajax actions that only check a password before the
		 * login form submits normally.
		 *
		 * The password is accepted for these, but hold_cookies() still applies,
		 * so listing an action that does sign people in never gets them a
		 * session.
		 *
		 * @param string[] $actions
		 */
		$actions = (array) apply_filters( 'sigil_credential_check_ajax_actions', array( 'wordfence_ls_authenticate' ) );

		return in_array( $action, $actions, true );
	}
}
