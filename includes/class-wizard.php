<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * A guided first run for the administrator setting the site up.
 *
 * Three steps, in the order that keeps the administrator from being the first
 * person a policy locks out: a passkey (an authenticator app where PHP is too
 * old for passkeys), the backup codes that get them back in without it, and only
 * then, optionally, a requirement for roles.
 */
final class Wizard {

	public const PAGE = 'sigil-2fa-wizard';

	// Named for the add-on it first shipped in, so a site that already finished
	// or dismissed it is not walked through it again.
	public const OPTION = 'sigil_pro_wizard_done';

	private const FINISH = 'sigil_wizard_finish';
	private const POLICY = 'sigil_wizard_policy';
	private const FIELD  = 'sigil_wizard';

	private static ?Wizard $instance = null;

	public static function instance(): Wizard {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( Network::is_network() ? 'network_admin_menu' : 'admin_menu', array( $this, 'register' ) );
		add_action( Network::is_network() ? 'network_admin_notices' : 'admin_notices', array( $this, 'nudge' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_post_' . self::FINISH, array( $this, 'finish' ) );
		add_action( 'admin_post_' . self::POLICY, array( $this, 'save_policy' ) );
		add_filter( 'sigil_enrol_redirect', array( $this, 'redirect' ), 20, 3 );
	}

	public static function url( int $step = 0 ): string {
		$base = Network::is_network() ? network_admin_url( 'settings.php' ) : admin_url( 'options-general.php' );
		$args = array( 'page' => self::PAGE );
		if ( $step > 0 ) {
			$args['step'] = $step;
		}

		return add_query_arg( $args, $base );
	}

	/**
	 * Finished or dismissed, or a site that already enforces something and has
	 * no first run left to do.
	 */
	public static function is_done(): bool {
		return (bool) Network::get_option( self::OPTION, false ) || self::policy_set();
	}

	private static function policy_set(): bool {
		$policy = Policy::get();
		if ( empty( $policy['enabled'] ) ) {
			return false;
		}

		return in_array( true, $policy['roles'], true ) || '' !== $policy['min_capability'];
	}

	/**
	 * Which of the three steps to show.
	 *
	 * The requested step only matters once the earlier ones are real: a step is
	 * never skipped by asking for a later one, and backup codes still waiting to
	 * be shown keep the page on step 2 so they cannot be navigated past unseen.
	 */
	public static function step_for( int $user_id, int $requested ): int {
		if ( ! self::has_primary_factor( $user_id ) ) {
			return 1;
		}

		$backup = Providers::instance()->get( 'backup' );
		$saved  = $backup instanceof Providers\Backup_Codes
			&& $backup->is_enrolled( $user_id )
			&& ! $backup->has_pending_display( $user_id );
		if ( ! $saved ) {
			return 2;
		}

		return 2 === $requested ? 2 : 3;
	}

	private static function has_primary_factor( int $user_id ): bool {
		foreach ( Providers::instance()->enrolled_for( $user_id ) as $provider ) {
			if ( in_array( $provider->id(), array( 'passkey', 'totp' ), true ) ) {
				return true;
			}
		}

		return false;
	}

	public function register(): void {
		// Only while there is something to walk through, so a one-time task does
		// not leave a permanent menu entry behind.
		//
		// Registered under a real parent rather than the empty slug that hides a
		// page: with no parent, core cannot resolve the admin page title and
		// admin-header.php emits a deprecation notice for passing null to
		// strip_tags() on every view of it.
		if ( self::is_done() ) {
			return;
		}

		add_submenu_page(
			Network::is_network() ? 'settings.php' : 'options-general.php',
			__( 'Set up two-factor authentication', 'sigil-2fa' ),
			__( 'Set up two-factor', 'sigil-2fa' ),
			Network::manage_capability(),
			self::PAGE,
			array( $this, 'render' )
		);
	}

	/**
	 * One prompt, on the plugin's own settings screen only, with a way to make
	 * it go away. Nagging from every page of the dashboard is how plugins get
	 * deleted.
	 */
	public function nudge(): void {
		if ( self::is_done() || ! current_user_can( Network::manage_capability() ) ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || ! in_array( $screen->id, array( 'settings_page_sigil-2fa', 'settings_page_sigil-2fa-network' ), true ) ) {
			return;
		}

		echo '<div class="notice notice-info"><p>';
		echo esc_html__( 'Two-factor authentication is installed but not yet set up.', 'sigil-2fa' );
		echo ' <a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Walk me through it', 'sigil-2fa' ) . '</a> | ';
		echo '<a href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=' . self::FINISH ), self::FINISH ) ) . '">' . esc_html__( 'Dismiss', 'sigil-2fa' ) . '</a>';
		echo '</p></div>';
	}

	/**
	 * @param string $hook_suffix
	 */
	public function enqueue( $hook_suffix ): void {
		if ( ! is_string( $hook_suffix ) || false === strpos( $hook_suffix, self::PAGE ) ) {
			return;
		}

		wp_enqueue_style( 'sigil-admin', SIGIL_URL . 'assets/css/admin.css', array(), SIGIL_VERSION );
		Enrolment::enqueue_enrol_assets();
		wp_enqueue_script( 'sigil-wizard', SIGIL_URL . 'assets/js/wizard.js', array(), SIGIL_VERSION, true );
	}

	/**
	 * Bring the enrolment handlers' redirect back to the wizard when the form
	 * came from it. The handler has already checked its own nonce by the time
	 * this filter runs.
	 *
	 * @param string $url
	 * @param int    $user_id
	 * @param string $status
	 */
	public function redirect( $url, $user_id, $status ): string {
		unset( $user_id );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified by the enrolment handler that applies this filter.
		$step = isset( $_POST[ self::FIELD ] ) ? absint( wp_unslash( $_POST[ self::FIELD ] ) ) : 0;
		if ( $step < 1 ) {
			return (string) $url;
		}

		if ( 'success' === $status ) {
			return self::url( 2 );
		}

		// The handler's own message is what says why it failed, so carry it over.
		wp_parse_str( (string) wp_parse_url( (string) $url, PHP_URL_QUERY ), $args );
		$keep = array_intersect_key( $args, array_flip( array( 'sigil_status', 'sigil_code', 'sigil_msg' ) ) );

		return add_query_arg( array_map( 'rawurlencode', $keep ), self::url( $step ) );
	}

	public function render(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'sigil-2fa' ) );
		}

		$user_id = (int) get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only step selector.
		$step = self::step_for( $user_id, isset( $_GET['step'] ) ? absint( wp_unslash( $_GET['step'] ) ) : 0 );

		echo '<div class="wrap sigil-wizard">';
		echo '<h1>' . esc_html__( 'Set up two-factor authentication', 'sigil-2fa' ) . '</h1>';

		$this->render_notices();

		$labels = array(
			1 => __( 'Add a passkey', 'sigil-2fa' ),
			2 => __( 'Save your backup codes', 'sigil-2fa' ),
			3 => __( 'Require it for roles', 'sigil-2fa' ),
		);
		echo '<ol class="sigil-wizard__steps">';
		foreach ( $labels as $number => $label ) {
			$class = $number < $step ? 'is-done' : ( $number === $step ? 'is-current' : '' );
			echo '<li class="' . esc_attr( $class ) . '"' . ( $number === $step ? ' aria-current="step"' : '' ) . '>' . esc_html( $label ) . '</li>';
		}
		echo '</ol>';

		echo '<div class="card sigil-wizard__panel">';
		if ( 1 === $step ) {
			$this->render_factor( $user_id );
		} elseif ( 2 === $step ) {
			$this->render_codes( $user_id );
		} else {
			$this->render_policy();
		}
		echo '</div>';
		echo '</div>';
	}

	private function render_notices(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- display-only flags set by our own redirects.
		$status  = isset( $_GET['sigil_status'] ) ? sanitize_key( wp_unslash( (string) $_GET['sigil_status'] ) ) : '';
		$message = isset( $_GET['sigil_msg'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['sigil_msg'] ) ) : '';
		$lockout = isset( $_GET['lockout'] ) && '1' === sanitize_key( wp_unslash( (string) $_GET['lockout'] ) );
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( $lockout ) {
			$status  = 'error';
			$message = Policy::lockout_message();
		}

		if ( 'error' !== $status ) {
			return;
		}

		if ( '' === $message ) {
			$message = __( 'That did not work. Please try again.', 'sigil-2fa' );
		}

		echo '<div class="notice notice-error"><p>' . esc_html( $message ) . '</p></div>';
	}

	private function render_factor( int $user_id ): void {
		$available = array();
		foreach ( Providers::instance()->all( $user_id ) as $provider ) {
			$available[ $provider->id() ] = $provider;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only choice between two forms.
		$wants_totp = isset( $_GET['method'] ) && 'totp' === sanitize_key( wp_unslash( (string) $_GET['method'] ) );
		$method     = isset( $available['passkey'] ) && ! $wants_totp ? 'passkey' : 'totp';

		if ( ! isset( $available[ $method ] ) ) {
			echo '<p>' . esc_html__( 'Neither a passkey nor an authenticator app can be used on this account.', 'sigil-2fa' ) . ' ';
			echo '<a href="' . esc_url( admin_url( 'users.php?page=' . Enrolment::PAGE_SLUG ) ) . '">' . esc_html__( 'See the other options', 'sigil-2fa' ) . '</a></p>';
			return;
		}

		$post_url = admin_url( 'admin-post.php' );

		echo '<h2>' . esc_html( 'passkey' === $method ? __( 'Add a passkey', 'sigil-2fa' ) : __( 'Add an authenticator app', 'sigil-2fa' ) ) . '</h2>';
		echo '<p>' . esc_html__( 'Set up a second factor for yourself before requiring it of anyone else. Turning on enforcement first is how an administrator becomes the first person locked out.', 'sigil-2fa' ) . '</p>';

		if ( 'passkey' === $method ) {
			// The passkey registers over AJAX, so there is nothing to submit. This
			// form is what wizard.js posts once it has, to mint the backup codes.
			echo '<form method="post" action="' . esc_url( $post_url ) . '" id="sigil-wizard-next">';
			$this->enrol_fields( $user_id, 'backup', 2 );
			echo '</form>';
			$available['passkey']->render_enrol( $user_id );
			echo '<p><a href="' . esc_url( add_query_arg( 'method', 'totp', self::url( 1 ) ) ) . '">' . esc_html__( 'Use an authenticator app instead', 'sigil-2fa' ) . '</a></p>';
			return;
		}

		if ( ! isset( $available['passkey'] ) ) {
			echo '<p class="description">' . esc_html__( 'Passkeys need PHP 8.0 or newer, so an authenticator app is the way in on this server.', 'sigil-2fa' ) . '</p>';
		}

		echo '<form method="post" action="' . esc_url( $post_url ) . '">';
		$this->enrol_fields( $user_id, 'totp', 1 );
		$available['totp']->render_enrol( $user_id );
		echo '<p class="submit"><button type="submit" class="button button-primary">' . esc_html__( 'Enable authenticator app', 'sigil-2fa' ) . '</button></p>';
		echo '</form>';

		if ( isset( $available['passkey'] ) ) {
			echo '<p><a href="' . esc_url( self::url( 1 ) ) . '">' . esc_html__( 'Use a passkey instead', 'sigil-2fa' ) . '</a></p>';
		}
	}

	private function render_codes( int $user_id ): void {
		$backup = Providers::instance()->get( 'backup' );
		if ( ! $backup instanceof Providers\Backup_Codes ) {
			return;
		}

		echo '<h2>' . esc_html__( 'Save your backup codes', 'sigil-2fa' ) . '</h2>';

		$pending  = $backup->has_pending_display( $user_id );
		$enrolled = $backup->is_enrolled( $user_id );

		// Showing the codes is what spends them, so the state above has to be
		// read first.
		$backup->render_enrol( $user_id );

		$post_url = admin_url( 'admin-post.php' );

		if ( ! $enrolled ) {
			echo '<form method="post" action="' . esc_url( $post_url ) . '">';
			$this->enrol_fields( $user_id, 'backup', 2 );
			echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Generate backup codes', 'sigil-2fa' ) . '</button></p>';
			echo '</form>';
			return;
		}

		if ( ! $pending ) {
			echo '<form method="post" action="' . esc_url( $post_url ) . '">';
			wp_nonce_field( 'sigil_regenerate_backup_' . $user_id );
			echo '<input type="hidden" name="action" value="sigil_regenerate_backup" />';
			echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $user_id ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::FIELD ) . '" value="2" />';
			echo '<p><button type="submit" class="button">' . esc_html__( 'Generate new backup codes', 'sigil-2fa' ) . '</button></p>';
			echo '</form>';
		}

		echo '<p><a class="button button-primary" href="' . esc_url( self::url( 3 ) ) . '">' . esc_html__( 'I have saved them, continue', 'sigil-2fa' ) . '</a></p>';
	}

	private function render_policy(): void {
		$policy = Policy::get();

		echo '<h2>' . esc_html__( 'Require it for roles (optional)', 'sigil-2fa' ) . '</h2>';
		echo '<p>' . esc_html__( 'Pick the roles that must set up two-factor authentication. A grace period gives existing users time to set themselves up instead of meeting a wall at their next sign-in. You can change this later under Settings, Sigil.', 'sigil-2fa' ) . '</p>';

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( self::POLICY );
		echo '<input type="hidden" name="action" value="' . esc_attr( self::POLICY ) . '" />';

		echo '<fieldset>';
		foreach ( wp_roles()->roles as $slug => $role ) {
			$slug = sanitize_key( (string) $slug );
			echo '<label style="display:block;margin-bottom:4px">';
			echo '<input type="checkbox" name="roles[' . esc_attr( $slug ) . ']" value="1"' . checked( 'administrator' === $slug, true, false ) . ' /> ';
			echo esc_html( translate_user_role( (string) ( $role['name'] ?? $slug ) ) ) . '</label>';
		}
		echo '</fieldset>';

		echo '<p><label>' . esc_html__( 'Grace period (days)', 'sigil-2fa' ) . ' ';
		echo '<input type="number" name="grace_days" min="0" step="1" class="small-text" value="' . esc_attr( (string) (int) $policy['grace_days'] ) . '" /></label></p>';

		echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Require two-factor for these roles', 'sigil-2fa' ) . '</button> ';
		echo '<a class="button" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=' . self::FINISH ), self::FINISH ) ) . '">' . esc_html__( 'Skip, I will do this later', 'sigil-2fa' ) . '</a></p>';
		echo '</form>';
	}

	/**
	 * The fields sigil_enrol expects, plus the flag that brings its redirect
	 * back here. The flag's value is the step to return to on a failure.
	 */
	private function enrol_fields( int $user_id, string $provider, int $step ): void {
		wp_nonce_field( 'sigil_enrol_' . $user_id );
		echo '<input type="hidden" name="action" value="sigil_enrol" />';
		echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $user_id ) . '" />';
		echo '<input type="hidden" name="provider" value="' . esc_attr( $provider ) . '" />';
		echo '<input type="hidden" name="' . esc_attr( self::FIELD ) . '" value="' . esc_attr( (string) $step ) . '" />';
	}

	public function save_policy(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to change these settings.', 'sigil-2fa' ) );
		}

		check_admin_referer( self::POLICY );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only read by the sanitized slugs of the known roles below.
		$posted = isset( $_POST['roles'] ) && is_array( $_POST['roles'] ) ? wp_unslash( $_POST['roles'] ) : array();
		$roles  = array();
		foreach ( array_keys( wp_roles()->roles ) as $slug ) {
			$slug           = sanitize_key( (string) $slug );
			$roles[ $slug ] = ! empty( $posted[ $slug ] );
		}

		$patch = array(
			'enabled'    => in_array( true, $roles, true ),
			'roles'      => $roles,
			'grace_days' => isset( $_POST['grace_days'] ) ? absint( wp_unslash( $_POST['grace_days'] ) ) : 7,
		);

		if ( Policy::would_lock_out( get_current_user_id(), $patch ) ) {
			wp_safe_redirect( add_query_arg( 'lockout', '1', self::url( 3 ) ) );
			exit;
		}

		Policy::update( $patch );
		Network::update_option( self::OPTION, true );

		wp_safe_redirect( add_query_arg( 'updated', '1', Network::settings_url() ) );
		exit;
	}

	public function finish(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to change these settings.', 'sigil-2fa' ) );
		}

		check_admin_referer( self::FINISH );
		Network::update_option( self::OPTION, true );

		wp_safe_redirect( Network::settings_url() );
		exit;
	}
}
