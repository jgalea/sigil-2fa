<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Ask an administrator for a WordPress.org review, once the plugin has earned it.
 *
 * The ask waits for two things: the plugin has been active for a week, and this
 * person has just signed in through a second factor, which is the moment Sigil
 * did its job. It appears only on Sigil's own screen and the Dashboard, and every
 * answer is remembered per user. Nothing is sent anywhere and nothing is offered
 * in return for a review.
 */
final class Review_Prompt {

	public const OPTION_ACTIVATED = 'sigil_first_activated';
	public const META_FACTOR      = '_sigil_last_factor';
	public const META_HIDDEN      = '_sigil_review_hidden';
	public const ACTION           = 'sigil_review_prompt';
	public const REVIEW_URL       = 'https://wordpress.org/support/plugin/sigil-2fa/reviews/#new-post';
	public const MIN_AGE          = 7 * DAY_IN_SECONDS;
	public const SNOOZE           = 30 * DAY_IN_SECONDS;

	private const CHOICES = array( 'review', 'later', 'never' );

	// Backup codes are left out: someone using one has lost their device, and
	// that is a bad moment to ask for a review.
	private const FACTORS = array( 'passkey', 'totp', 'email' );

	private static ?Review_Prompt $instance = null;

	public static function instance(): Review_Prompt {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_init', array( __CLASS__, 'record_activation' ) );
		add_action( 'sigil_challenge_passed', array( $this, 'remember_factor' ), 10, 2 );
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'network_admin_notices', array( $this, 'render' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle_post' ) );
		add_action( 'wp_ajax_' . self::ACTION, array( $this, 'handle_ajax' ) );
	}

	/**
	 * Stamps the first activation. Existing installs have no stamp when they
	 * upgrade, so the first admin request afterwards starts their clock.
	 */
	public static function record_activation(): void {
		if ( false === Network::get_option( self::OPTION_ACTIVATED, false ) ) {
			Network::update_option( self::OPTION_ACTIVATED, time() );
		}
	}

	public function remember_factor( int $user_id, string $provider_id ): void {
		if ( in_array( $provider_id, self::FACTORS, true ) ) {
			update_user_meta( $user_id, self::META_FACTOR, $provider_id );
		}
	}

	private static function capability(): string {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	public static function eligible( int $user_id ): bool {
		if ( $user_id <= 0 || ! user_can( $user_id, self::capability() ) ) {
			return false;
		}

		if ( ! in_array( get_user_meta( $user_id, self::META_FACTOR, true ), self::FACTORS, true ) ) {
			return false;
		}

		$activated = (int) Network::get_option( self::OPTION_ACTIVATED, 0 );
		if ( $activated <= 0 || time() - $activated < self::MIN_AGE ) {
			return false;
		}

		$hidden = get_user_meta( $user_id, self::META_HIDDEN, true );
		if ( 'never' === $hidden ) {
			return false;
		}

		return ! ( is_numeric( $hidden ) && (int) $hidden > time() );
	}

	public static function apply( int $user_id, string $choice ): bool {
		if ( ! in_array( $choice, self::CHOICES, true ) ) {
			return false;
		}

		update_user_meta( $user_id, self::META_HIDDEN, 'later' === $choice ? (string) ( time() + self::SNOOZE ) : 'never' );
		return true;
	}

	private static function on_allowed_screen(): bool {
		$screen = get_current_screen();
		if ( ! $screen instanceof \WP_Screen ) {
			return false;
		}

		return in_array(
			$screen->id,
			array( 'dashboard', 'dashboard-network', 'settings_page_sigil-2fa', 'settings_page_sigil-2fa-network' ),
			true
		);
	}

	private static function action_url( string $choice ): string {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => self::ACTION,
					'choice' => $choice,
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION,
			'_wpnonce'
		);
	}

	public function render(): void {
		$user_id = get_current_user_id();
		// The setup nudge says nothing is set up yet, which would contradict this.
		if ( ! self::on_allowed_screen() || ! self::eligible( $user_id ) || Wizard::nudge_showing( $user_id ) ) {
			return;
		}

		$first = __( 'You just signed in with a passkey.', 'sigil-2fa' );
		$last  = get_user_meta( $user_id, self::META_FACTOR, true );
		if ( 'totp' === $last ) {
			$first = __( 'You just signed in with your authenticator app.', 'sigil-2fa' );
		} elseif ( 'email' === $last ) {
			$first = __( 'You just signed in with an emailed code.', 'sigil-2fa' );
		}

		wp_enqueue_script( 'sigil-review-prompt', SIGIL_URL . 'assets/js/review-prompt.js', array(), SIGIL_VERSION, true );

		?>
		<div class="notice notice-info is-dismissible sigil-review-prompt" data-ajax-url="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" data-nonce="<?php echo esc_attr( wp_create_nonce( self::ACTION ) ); ?>">
			<p><strong><?php esc_html_e( 'Sigil is protecting your login', 'sigil-2fa' ); ?></strong></p>
			<p>
				<?php
				echo esc_html( $first . ' ' );
				esc_html_e( 'If Sigil has saved you time or stress, a short review on WordPress.org helps other site owners find it.', 'sigil-2fa' );
				?>
			</p>
			<p>
				<a class="button button-primary" data-sigil-choice="review" href="<?php echo esc_url( self::action_url( 'review' ) ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Leave a review', 'sigil-2fa' ); ?></a>
				<a class="button" data-sigil-choice="later" href="<?php echo esc_url( self::action_url( 'later' ) ); ?>"><?php esc_html_e( 'Maybe later', 'sigil-2fa' ); ?></a>
				<a class="button button-link" data-sigil-choice="never" href="<?php echo esc_url( self::action_url( 'never' ) ); ?>"><?php esc_html_e( "Don't ask again", 'sigil-2fa' ); ?></a>
			</p>
		</div>
		<?php
	}

	public function handle_post(): void {
		if ( ! current_user_can( self::capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION );

		$choice = isset( $_GET['choice'] ) ? sanitize_key( wp_unslash( $_GET['choice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- checked by check_admin_referer above.
		if ( ! self::apply( get_current_user_id(), $choice ) ) {
			wp_die( esc_html__( 'Unknown choice.', 'sigil-2fa' ), '', array( 'response' => 400 ) );
		}

		if ( 'review' === $choice ) {
			// Fixed address on WordPress.org, so wp_safe_redirect's host allowlist would only get in the way.
			wp_redirect( self::REVIEW_URL ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}

		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url() );
		exit;
	}

	public function handle_ajax(): void {
		if ( ! current_user_can( self::capability() ) ) {
			wp_send_json_error( null, 403 );
		}

		if ( false === check_ajax_referer( self::ACTION, '_wpnonce', false ) ) {
			wp_send_json_error( null, 403 );
		}

		$choice = isset( $_POST['choice'] ) ? sanitize_key( wp_unslash( $_POST['choice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- checked by check_ajax_referer above.
		if ( ! self::apply( get_current_user_id(), $choice ) ) {
			wp_send_json_error( null, 400 );
		}

		wp_send_json_success();
	}
}
