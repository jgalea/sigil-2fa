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

		$patch = array(
			'enabled'             => ! empty( $raw['enabled'] ),
			'roles'               => $roles_in,
			'min_capability'      => $cap,
			'grace_days'          => $grace,
			'block_app_passwords' => $block_in,
			'passwordless'        => ! empty( $raw['passwordless'] ),
		);

		if ( Policy::would_lock_out( get_current_user_id(), $patch ) ) {
			wp_safe_redirect( add_query_arg( 'lockout', '1', Network::settings_url() ) );
			exit;
		}

		Policy::update( $patch );

		if ( isset( $_POST['sigil_trusted_days'] ) ) {
			Network::update_option( Trusted_Devices::OPTION_DAYS, max( 1, min( 365, absint( wp_unslash( $_POST['sigil_trusted_days'] ) ) ) ) );
		}
		if ( ! empty( $_POST['sigil_revoke_trusted'] ) ) {
			Trusted_Devices::instance()->revoke_all( get_current_user_id() );
		}
		Zero_Setup::set_enabled( ! empty( $_POST['sigil_zero_setup'] ) );

		wp_safe_redirect( add_query_arg( 'updated', '1', Network::settings_url() ) );
		exit;
	}
}
