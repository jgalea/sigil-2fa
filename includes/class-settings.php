<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Settings {

	private static ?Settings $instance = null;

	public static function instance(): Settings {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// On a network the policy covers every site, so it belongs to the network
		// administrator and lives under Network Admin -> Settings.
		add_action( Network::is_network() ? 'network_admin_menu' : 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_post_sigil_save_settings', array( $this, 'handle_save' ) );
		add_filter( 'sigil_enrol_redirect', array( $this, 'return_from_step_up' ), 10, 3 );
	}

	/**
	 * Bring a confirmation given from this screen back to it.
	 *
	 * @param string $url
	 * @param int    $user_id
	 * @param string $status
	 */
	public function return_from_step_up( $url, $user_id, $status ): string {
		unset( $user_id );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified by the step-up handler that applies this filter.
		if ( empty( $_POST['sigil_settings'] ) ) {
			return (string) $url;
		}

		return add_query_arg( 'success' === $status ? 'confirmed' : 'sigil_status', 'success' === $status ? '1' : 'error', Network::settings_url() );
	}

	public function register_menu(): void {
		if ( Network::is_network() ) {
			add_submenu_page(
				'settings.php',
				__( 'Sigil', 'sigil-2fa' ),
				__( 'Sigil', 'sigil-2fa' ),
				Network::manage_capability(),
				'sigil-2fa',
				array( $this, 'render_page' )
			);
			return;
		}

		add_options_page(
			__( 'Sigil', 'sigil-2fa' ),
			__( 'Sigil', 'sigil-2fa' ),
			Network::manage_capability(),
			'sigil-2fa',
			array( $this, 'render_page' )
		);
	}

	public function render_page(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'sigil-2fa' ) );
		}

		$policy = Policy::get();
		$roles  = wp_roles()->roles;
		if ( ! is_array( $roles ) ) {
			$roles = array();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice flag set by our own redirect.
		$updated = isset( $_GET['updated'] ) && '1' === sanitize_key( wp_unslash( $_GET['updated'] ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice flag set by our own redirect.
		$locked_out = isset( $_GET['lockout'] ) && '1' === sanitize_key( wp_unslash( $_GET['lockout'] ) );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice flag set by our own redirect.
		$bad_cap = isset( $_GET['bad_cap'] ) ? sanitize_key( wp_unslash( (string) $_GET['bad_cap'] ) ) : '';

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice flags set by our own redirects.
		$needs_step_up = isset( $_GET['stepup'] ) && '1' === sanitize_key( wp_unslash( (string) $_GET['stepup'] ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$confirmed = isset( $_GET['confirmed'] ) && '1' === sanitize_key( wp_unslash( (string) $_GET['confirmed'] ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$step_up_error = isset( $_GET['sigil_status'] ) && 'error' === sanitize_key( wp_unslash( (string) $_GET['sigil_status'] ) ) ? Enrolment::take_message() : '';

		wp_enqueue_script( 'sigil-enforce-all', SIGIL_URL . 'assets/js/enforce-all.js', array(), SIGIL_VERSION, true );

		require SIGIL_DIR . 'templates/settings.php';
	}

	public function handle_save(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to save these settings.', 'sigil-2fa' ) );
		}

		check_admin_referer( 'sigil_save_settings' );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized below field by field.
		$raw = isset( $_POST['sigil_policy'] ) && is_array( $_POST['sigil_policy'] ) ? wp_unslash( $_POST['sigil_policy'] ) : array();

		// Unchecked boxes are absent from POST; enumerate every role so clears stick.
		$known_roles = array_keys( wp_roles()->roles );
		$posted_roles = ( isset( $raw['roles'] ) && is_array( $raw['roles'] ) ) ? $raw['roles'] : array();
		$posted_block = ( isset( $raw['block_app_passwords'] ) && is_array( $raw['block_app_passwords'] ) ) ? $raw['block_app_passwords'] : array();

		$roles_in = array();
		$block_in = array();
		foreach ( $known_roles as $role ) {
			if ( ! is_string( $role ) || '' === $role ) {
				continue;
			}
			$role               = sanitize_key( $role );
			$roles_in[ $role ] = ! empty( $posted_roles[ $role ] );
			$block_in[ $role ] = ! empty( $posted_block[ $role ] );
		}

		$grace = isset( $raw['grace_days'] ) ? (int) $raw['grace_days'] : 7;
		if ( $grace < 0 ) {
			$grace = 0;
		}

		$cap = '';
		if ( isset( $raw['min_capability'] ) && is_string( $raw['min_capability'] ) ) {
			$cap = sanitize_key( $raw['min_capability'] );
		}

		if ( ! Policy::is_known_capability( $cap ) ) {
			wp_safe_redirect( add_query_arg( 'bad_cap', rawurlencode( $cap ), Network::settings_url() ) );
			exit;
		}

		$patch = array(
			'enabled'             => ! empty( $raw['enabled'] ),
			'enforce_all'         => ! empty( $raw['enforce_all'] ),
			'roles'               => $roles_in,
			'min_capability'      => $cap,
			'grace_days'          => $grace,
			'block_app_passwords' => $block_in,
			'passwordless'        => ! empty( $raw['passwordless'] ),
			'limit_passwords'     => ! empty( $raw['limit_passwords'] ),
		);

		if ( Policy::would_lock_out( get_current_user_id(), $patch ) ) {
			wp_safe_redirect( add_query_arg( 'lockout', '1', Network::settings_url() ) );
			exit;
		}

		if ( isset( $_POST['sigil_trusted_days'] ) ) {
			$trusted_roles = array();
			$posted        = isset( $_POST['sigil_trusted_roles'] ) && is_array( $_POST['sigil_trusted_roles'] ) ? wp_unslash( $_POST['sigil_trusted_roles'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- keys are checked against the known roles below.
			foreach ( array_keys( wp_roles()->roles ) as $role ) {
				if ( ! empty( $posted[ $role ] ) ) {
					$trusted_roles[ sanitize_key( (string) $role ) ] = true;
				}
			}

			$patch['trusted_days']    = absint( wp_unslash( $_POST['sigil_trusted_days'] ) );
			$patch['trusted_enabled'] = ! empty( $_POST['sigil_trusted_enabled'] );
			$patch['trusted_roles']   = $trusted_roles;
		}
		$patch['zero_setup'] = ! empty( $_POST['sigil_zero_setup'] );

		// Loosening protection is what a hijacked session would do first, so it
		// needs the same fresh proof as changing a method.
		if ( array() !== Policy::weakened_by( $patch ) && ! Step_Up::allows( get_current_user_id() ) ) {
			wp_safe_redirect( add_query_arg( 'stepup', '1', Network::settings_url() ) );
			exit;
		}

		Policy::update( $patch );

		if ( ! empty( $_POST['sigil_revoke_trusted'] ) ) {
			Trusted_Devices::instance()->revoke_everyone();
		}
		wp_safe_redirect( add_query_arg( 'updated', '1', Network::settings_url() ) );
		exit;
	}
}
