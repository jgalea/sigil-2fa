<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Recovery {

	public const LOG_META = '_sigil_reset_log';

	private static ?Recovery $instance = null;

	public static function instance(): Recovery {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'user_row_actions', [ $this, 'row_actions' ], 10, 2 );
		add_action( 'admin_post_sigil_reset_user', [ $this, 'handle_reset' ] );
		add_action( 'admin_notices', [ $this, 'admin_notices' ] );
	}

	/**
	 * Wipe every 2FA method for a user, on behalf of an actor who must be
	 * allowed to edit that user.
	 *
	 * An actor of 0 is nobody, not an exemption: a logged-out request reaching
	 * here is refused. The unattended path is reset_as_system(), which callers
	 * have to name deliberately.
	 *
	 * @return true|\WP_Error
	 */
	public static function reset_user( int $user_id, int $actor_id ) {
		if ( $actor_id <= 0
			|| ! user_can( $actor_id, 'edit_users' )
			|| ! user_can( $actor_id, 'edit_user', $user_id ) ) {
			return new \WP_Error(
				'sigil_forbidden',
				__( 'You are not allowed to reset two-factor authentication for this user.', 'sigil-2fa' )
			);
		}

		return self::perform_reset( $user_id, $actor_id );
	}

	/**
	 * The lockout escape hatch, for WP-CLI and other unattended contexts where
	 * there is no current user. Reaching this already requires shell access to
	 * the install, which outranks any capability.
	 *
	 * @return true|\WP_Error
	 */
	public static function reset_as_system( int $user_id ) {
		return self::perform_reset( $user_id, 0 );
	}

	/**
	 * @return true|\WP_Error
	 */
	private static function perform_reset( int $user_id, int $actor_id ) {
		if ( $user_id <= 0 ) {
			return new \WP_Error(
				'sigil_invalid_user',
				__( 'Invalid user.', 'sigil-2fa' )
			);
		}

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User ) {
			return new \WP_Error(
				'sigil_invalid_user',
				__( 'User not found.', 'sigil-2fa' )
			);
		}

		require_once SIGIL_DIR . 'includes/class-credentials.php';

		// A reset sends its own notice below, so the generic change alert would
		// only be a second mail about one event.
		add_filter( 'sigil_send_change_alert', '__return_false', 99 );

		// Deliberately the unnarrowed list: a reset has to reach every method the
		// account holds, including one a policy would no longer let it choose.
		foreach ( Providers::instance()->all() as $provider ) {
			if ( $provider->is_enrolled( $user_id ) ) {
				$provider->unenrol( $user_id );
			}
		}

		// Residual method rows (e.g. provider unavailable on this runtime) and credentials.
		delete_user_meta( $user_id, Store::META_KEY );
		Credentials::delete_for_user( $user_id );

		$sessions = \WP_Session_Tokens::get_instance( $user_id );
		$sessions->destroy_all();

		$log = get_user_meta( $user_id, self::LOG_META, true );
		if ( ! is_array( $log ) ) {
			$log = [];
		}
		array_unshift(
			$log,
			[
				'actor' => $actor_id,
				'time'  => time(),
			]
		);
		// Keep the last 50 entries.
		$log = array_slice( $log, 0, 50 );
		update_user_meta( $user_id, self::LOG_META, $log );

		self::notify_user( $user, $actor_id );

		/**
		 * Fires after a user's 2FA methods have been reset.
		 *
		 * @param int $user_id  Target user.
		 * @param int $actor_id Actor user ID, or 0 for system/CLI.
		 */
		do_action( 'sigil_user_reset', $user_id, $actor_id );

		remove_filter( 'sigil_send_change_alert', '__return_false', 99 );

		return true;
	}

	/**
	 * @param array<string, string> $actions
	 * @return array<string, string>
	 */
	public function row_actions( array $actions, \WP_User $user ): array {
		if ( ! current_user_can( 'edit_users' ) || ! current_user_can( 'edit_user', $user->ID ) ) {
			return $actions;
		}

		if ( (int) get_current_user_id() === (int) $user->ID ) {
			return $actions;
		}

		$url = self::reset_url( (int) $user->ID );

		$confirm = esc_js( self::reset_confirmation() );

		$actions['sigil_reset'] = sprintf(
			'<a class="sigil-reset-2fa" href="%1$s" onclick="return confirm( \'%2$s\' );">%3$s</a>',
			esc_url( $url ),
			$confirm,
			esc_html__( 'Reset 2FA', 'sigil-2fa' )
		);

		return $actions;
	}

	/**
	 * The nonce-checked link that resets someone's 2FA. A link rather than a
	 * form, so it can sit inside screens that are forms already.
	 */
	public static function reset_url( int $user_id ): string {
		return wp_nonce_url(
			admin_url( 'admin-post.php?action=sigil_reset_user&user_id=' . $user_id ),
			'sigil_reset_user_' . $user_id
		);
	}

	public static function reset_confirmation(): string {
		return __( 'Reset two-factor authentication for this user? Their enrolled methods will be removed and their sessions will end.', 'sigil-2fa' );
	}

	public function handle_reset(): void {
		$user_id = isset( $_GET['user_id'] ) ? absint( wp_unslash( $_GET['user_id'] ) ) : 0;

		if ( $user_id <= 0 ) {
			wp_die( esc_html__( 'Invalid user.', 'sigil-2fa' ), '', [ 'response' => 400 ] );
		}

		check_admin_referer( 'sigil_reset_user_' . $user_id );

		if ( ! current_user_can( 'edit_users' ) || ! current_user_can( 'edit_user', $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to reset two-factor authentication for this user.', 'sigil-2fa' ), '', [ 'response' => 403 ] );
		}

		$result = self::reset_user( $user_id, (int) get_current_user_id() );

		$redirect = add_query_arg(
			[
				'sigil_reset' => is_wp_error( $result ) ? '0' : '1',
				'user_id'       => $user_id,
			],
			admin_url( 'users.php' )
		);

		wp_safe_redirect( $redirect );
		exit;
	}

	public function admin_notices(): void {
		if ( ! is_admin() || ! current_user_can( 'edit_users' ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag after redirect.
		if ( ! isset( $_GET['sigil_reset'] ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice flag set by our own redirect.
		$ok = '1' === sanitize_key( wp_unslash( $_GET['sigil_reset'] ) );

		if ( $ok ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Two-factor authentication was reset for that user.', 'sigil-2fa' ) . '</p></div>';
			return;
		}

		echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Could not reset two-factor authentication for that user.', 'sigil-2fa' ) . '</p></div>';
	}

	private static function notify_user( \WP_User $user, int $actor_id ): void {
		if ( ! is_email( $user->user_email ) ) {
			return;
		}

		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $site_name ) {
			$site_name = home_url();
		}

		$actor_label = __( 'a site administrator', 'sigil-2fa' );
		if ( $actor_id > 0 ) {
			$actor = get_userdata( $actor_id );
			if ( $actor instanceof \WP_User ) {
				$actor_label = $actor->user_login;
			}
		} elseif ( 0 === $actor_id ) {
			$actor_label = __( 'a site administrator (via command line)', 'sigil-2fa' );
		}

		$subject = sprintf(
			/* translators: %s: site name */
			__( 'Your two-factor authentication was reset on %s', 'sigil-2fa' ),
			$site_name
		);

		$message = sprintf(
			/* translators: 1: site name, 2: actor description */
			__(
				"Your two-factor authentication methods on %1\$s were reset by %2\$s.\n\nYou can sign in with your password alone until you set up two-factor authentication again.\n\nIf you did not expect this change, contact a site administrator immediately.",
				'sigil-2fa'
			),
			$site_name,
			$actor_label
		);

		wp_mail( $user->user_email, $subject, $message );
	}
}
