<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Makes sure a session is only ever issued after the second factor.
 *
 * WordPress sets the session cookie inside wp_signon(), before wp_login fires
 * and the challenge runs. Clearing it afterwards only appends expiring headers
 * behind the live ones, and leaves the stored session in place, so a client
 * that keeps the first headers is signed in on the password alone. So no
 * session cookie goes to anyone with a second factor until something in this
 * request has granted it: a completed challenge, an excused sign-in, or a
 * session they already held.
 *
 * AJAX and cron have no page to show the challenge on, so the password is also
 * refused there outright, which gives a login form something to tell the user.
 * A request that only checks the credentials is a different thing. Wordfence
 * calls wp_authenticate() over admin-ajax before letting wp-login.php submit
 * normally, and refusing it there would mean nobody with a second factor could
 * sign in. Those actions keep their answer, and the real POST that follows is
 * challenged as usual.
 */
final class Login_Guard {

	private static ?Login_Guard $instance = null;

	/** @var array<int, true> */
	private array $granted = array();

	/** @var array<int, true> */
	private array $new_users = array();

	/**
	 * Who the request arrived signed in as, proven by its auth cookie.
	 */
	private ?int $session_user = null;

	private bool $password_attempted = false;

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
		add_filter( 'determine_current_user', array( $this, 'note_session_user' ), PHP_INT_MAX );
		add_action( 'wp_authenticate', array( $this, 'note_password_attempt' ) );
	}

	/**
	 * Let this request issue a session to the user.
	 *
	 * Call it only once the second factor has been verified server-side, or the
	 * sign-in has been deliberately excused, and before wp_set_auth_cookie().
	 * Never on the strength of anything the request itself says.
	 */
	public static function grant( int $user_id ): void {
		if ( $user_id > 0 ) {
			self::instance()->granted[ $user_id ] = true;
		}
	}

	/**
	 * Read who the request arrived as the first time WordPress asks, which is
	 * before anything in the request can have changed the password the auth
	 * cookie is checked against.
	 *
	 * Only the auth cookie for this scheme counts. The answer passed in can
	 * come from the logged_in cookie, which is sent to every page and is the
	 * weaker of the two, from an application password, or from any plugin's
	 * filter, and none of those is a session someone has already signed in to.
	 *
	 * @param mixed $user_id
	 * @return mixed
	 */
	public function note_session_user( $user_id ) {
		$this->arrived_as();
		return $user_id;
	}

	/**
	 * wp_signon() announces the password check here before any authenticate
	 * filter runs, and refuse_password() notes it again for direct
	 * wp_authenticate() calls.
	 */
	public function note_password_attempt(): void {
		$this->password_attempted = true;
	}

	private function arrived_as(): int {
		if ( null === $this->session_user ) {
			$this->session_user = (int) wp_validate_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		}
		return $this->session_user;
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
		$this->note_password_attempt();

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
	 * Refuse to send a session cookie to anyone with a second factor unless this
	 * request has earned it.
	 *
	 * The session WordPress has just stored for the cookie is destroyed too, so
	 * nothing is left behind that could be used later. A user who arrived
	 * already signed in keeps their session when WordPress re-issues it, as it
	 * does after they change their own password; see is_existing_session().
	 *
	 * An account created in this same request is let through. WooCommerce signs
	 * a new customer in from its checkout, over AJAX or its Store API on REST,
	 * and when every account counts as covered by an emailed code, holding that
	 * cookie would leave people who have just registered signed out.
	 * Registering can only create an account, never reach an existing one.
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
		if ( ! $send || $user_id <= 0 ) {
			return (bool) $send;
		}

		if ( isset( $this->granted[ $user_id ] ) || isset( $this->new_users[ $user_id ] ) ) {
			return true;
		}

		if ( $this->is_existing_session( $user_id ) ) {
			return true;
		}

		if ( ! Providers::instance()->has_usable( $user_id ) ) {
			return true;
		}

		if ( is_string( $token ) && '' !== $token ) {
			\WP_Session_Tokens::get_instance( $user_id )->destroy( $token );
		}

		return false;
	}

	/**
	 * Whether the cookie is a re-issue of a session the user already holds.
	 *
	 * Never while a password is being checked in the same request: holding a
	 * session for an account is no reason to let a password sign-in for it
	 * skip the factor. Never for an application password either, which is
	 * for API clients and must not become a browser session.
	 */
	private function is_existing_session( int $user_id ): bool {
		if ( $this->password_attempted || App_Passwords::instance()->used_application_password( $user_id ) ) {
			return false;
		}

		return $user_id === $this->arrived_as();
	}

	private static function is_guarded_request(): bool {
		return wp_doing_ajax() || wp_doing_cron();
	}

	private static function is_credential_check(): bool {
		if ( ! wp_doing_ajax() ) {
			return false;
		}

		// Compared exactly as admin-ajax dispatches it. sanitize_key() would
		// lowercase it and let a differently cased action match a listed one.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- routing check only, compared strictly against a fixed list.
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? wp_unslash( $_REQUEST['action'] ) : '';
		if ( '' === $action ) {
			return false;
		}

		// Wordfence's check is only trusted where Wordfence has registered it.
		$defaults = array();
		if ( has_action( 'wp_ajax_nopriv_wordfence_ls_authenticate' ) ) {
			$defaults[] = 'wordfence_ls_authenticate';
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
		$actions = (array) apply_filters( 'sigil_credential_check_ajax_actions', $defaults );

		return in_array( $action, $actions, true );
	}
}
