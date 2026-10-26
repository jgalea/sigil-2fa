<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * The password and the email are credentials too.
 *
 * WordPress lets a signed-in session set a new password and a new email
 * without the old password. On an account with a second factor that hands a
 * stolen session the account itself: a password of its choosing, or a reset
 * link sent to its own address. So changing either of your own needs the same
 * fresh proof as changing a method, and a password set by a session, or since
 * it signed in, is not proof that it belongs to the owner.
 *
 * Reset-by-email and administrators editing someone else are unaffected: the
 * first is a different proof of its own, the second is governed by edit_user.
 */
final class Credential_Changes {

	private static ?Credential_Changes $instance = null;

	/**
	 * Set when profile.php is about to send an email change, so the error can
	 * be added where core collects them.
	 *
	 * @var array<int, true>
	 */
	private array $held_email = array();

	public static function instance(): Credential_Changes {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->register();
	}

	/**
	 * Hook registration, separate from construction so the test suite can
	 * apply it again after it restores the hook table.
	 */
	public function register(): void {
		// Before core's send_confirmation_on_profile_email at 10.
		add_action( 'personal_options_update', array( $this, 'hold_email' ), 1 );
		add_action( 'user_profile_update_errors', array( $this, 'profile_errors' ), 10, 3 );
		// Before the callback rather than on rest_pre_insert_user, whose
		// WP_Error update_item() does not check for.
		add_filter( 'rest_request_before_callbacks', array( $this, 'rest_check' ), 10, 3 );
		add_action( 'woocommerce_save_account_details_errors', array( $this, 'woocommerce_errors' ), 10, 2 );
		add_action( 'profile_update', array( $this, 'note_profile_password' ), 10, 2 );
		add_action( 'wp_set_password', array( $this, 'note_set_password' ), 10, 3 );
	}

	/**
	 * Whether the current user may change their own password or email now.
	 */
	public static function allowed( int $user_id ): bool {
		return (int) get_current_user_id() !== $user_id || Step_Up::allows( $user_id );
	}

	public static function error(): \WP_Error {
		return new \WP_Error(
			'sigil_step_up_required',
			sprintf(
				/* translators: %s: URL of the two-factor page */
				__( 'Confirm it is you before changing your password or email: %s', 'sigil-2fa' ),
				admin_url( 'users.php?page=' . Enrolment::PAGE_SLUG )
			),
			array( 'status' => 403 )
		);
	}

	/**
	 * Core sends the confirmation for a new email before it validates anything
	 * else, to the new address, so a stolen session would confirm its own
	 * change. Put the old address back first.
	 *
	 * @param int $user_id
	 */
	public function hold_email( $user_id ): void {
		$user_id = (int) $user_id;
		$user    = get_userdata( $user_id );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- profile.php checked its nonce before this action.
		$posted = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( (string) $_POST['email'] ) ) : '';

		if ( ! $user instanceof \WP_User || '' === $posted || $posted === $user->user_email || self::allowed( $user_id ) ) {
			return;
		}

		$_POST['email']                 = $user->user_email;
		$this->held_email[ $user_id ] = true;
	}

	/**
	 * @param \WP_Error $errors
	 * @param bool      $update
	 * @param \stdClass $user
	 */
	public function profile_errors( $errors, $update, $user ): void {
		if ( ! $update || ! $errors instanceof \WP_Error || ! is_object( $user ) || empty( $user->ID ) ) {
			return;
		}

		$user_id = (int) $user->ID;
		if ( isset( $this->held_email[ $user_id ] ) || ( ! empty( $user->user_pass ) && ! self::allowed( $user_id ) ) ) {
			unset( $this->held_email[ $user_id ] );
			$errors->add( 'sigil_step_up_required', esc_html( self::error()->get_error_message() ) );
		}
	}

	/**
	 * Updates through the core users controller, for wp/v2/users/me or a user id.
	 *
	 * Decided on the handler the server dispatched to rather than the route the
	 * client sent: core matches routes case-insensitively, so /wp/v2/users/ME
	 * reaches the same handler while slipping past a path pattern.
	 *
	 * @param mixed            $response
	 * @param mixed            $handler
	 * @param \WP_REST_Request $request
	 * @return mixed
	 */
	public function rest_check( $response, $handler, $request ) {
		if ( null !== $response || ! $request instanceof \WP_REST_Request || in_array( $request->get_method(), array( 'GET', 'HEAD', 'DELETE', 'OPTIONS' ), true ) ) {
			return $response;
		}

		$callback = is_array( $handler ) && isset( $handler['callback'] ) ? $handler['callback'] : null;
		if ( ! is_array( $callback ) || ! $callback[0] instanceof \WP_REST_Users_Controller || ! in_array( $callback[1], array( 'update_item', 'update_current_item' ), true ) ) {
			return $response;
		}

		$user_id = 'update_current_item' === $callback[1] ? (int) get_current_user_id() : (int) $request->get_param( 'id' );
		$current = get_userdata( $user_id );
		if ( ! $current instanceof \WP_User ) {
			return $response;
		}

		$password = '' !== (string) $request->get_param( 'password' );
		$email    = null !== $request->get_param( 'email' ) && (string) $request->get_param( 'email' ) !== $current->user_email;

		if ( ( $password || $email ) && ! self::allowed( $user_id ) ) {
			return self::error();
		}

		return $response;
	}

	/**
	 * @param \WP_Error $errors
	 * @param \stdClass $user
	 */
	public function woocommerce_errors( $errors, $user ): void {
		if ( ! $errors instanceof \WP_Error || ! is_object( $user ) || empty( $user->ID ) ) {
			return;
		}

		$user_id = (int) $user->ID;
		$current = get_userdata( $user_id );
		if ( ! $current instanceof \WP_User ) {
			return;
		}

		$password = ! empty( $user->user_pass );
		$email    = isset( $user->user_email ) && (string) $user->user_email !== $current->user_email;

		if ( ( $password || $email ) && ! self::allowed( $user_id ) ) {
			$errors->add( 'sigil_step_up_required', self::error()->get_error_message() );
		}
	}

	/**
	 * @param int      $user_id
	 * @param \WP_User $old
	 */
	public function note_profile_password( $user_id, $old ): void {
		$current = get_userdata( (int) $user_id );
		if ( $old instanceof \WP_User && $current instanceof \WP_User && $current->user_pass !== $old->user_pass ) {
			Step_Up::password_changed( (int) $user_id );
		}
	}

	/**
	 * Guarded on the password actually changing: core calls this during login
	 * to rehash the one just typed.
	 *
	 * @param string   $password
	 * @param int      $user_id
	 * @param \WP_User $old
	 */
	public function note_set_password( $password, $user_id, $old = null ): void {
		if ( $old instanceof \WP_User && wp_check_password( (string) $password, (string) $old->user_pass, (int) $user_id ) ) {
			return;
		}

		Step_Up::password_changed( (int) $user_id );
	}
}
