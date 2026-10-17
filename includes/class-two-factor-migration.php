<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Two_Factor_Migration {

	private const ACTION = 'sigil_import_two_factor';

	private static ?Two_Factor_Migration $instance = null;

	public static function instance(): Two_Factor_Migration {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'two_factor_is_required_for_user', array( Two_Factor_Import::class, 'filter_two_factor_required' ), 99, 2 );
		add_action( Network::is_network() ? 'network_admin_notices' : 'admin_notices', array( $this, 'notice' ) );
		add_action( 'sigil_settings_after', array( $this, 'render_section' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle_post' ) );
	}

	public function notice(): void {
		if ( ! Two_Factor_Import::is_two_factor_active() || ! current_user_can( Network::manage_capability() ) ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$id     = $screen instanceof \WP_Screen ? preg_replace( '/-network$/', '', $screen->id ) : '';
		if ( ! in_array( $id, array( 'dashboard', 'plugins', 'users', 'settings_page_sigil-2fa' ), true ) ) {
			return;
		}

		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'The Two Factor plugin is active alongside Sigil. Import its users\' two-factor methods into Sigil, then deactivate Two Factor so there is one place sign-ins are checked.', 'sigil-2fa' );
		if ( 'settings_page_sigil-2fa' !== $id ) {
			echo ' <a href="' . esc_url( Network::settings_url() . '#sigil-import-two-factor' ) . '">' . esc_html__( 'Import from Two Factor', 'sigil-2fa' ) . '</a>';
		}
		echo '</p></div>';
	}

	public function render_section(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			return;
		}

		$report = Two_Factor_Import::recall_report( get_current_user_id() );
		if ( ! Two_Factor_Import::is_two_factor_active() && null === $report && ! $this->has_two_factor_data() ) {
			return;
		}

		require SIGIL_DIR . 'templates/import-two-factor.php';
	}

	public function handle_post(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to import two-factor data.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION );

		$dry_run = ! isset( $_POST['sigil_import_run'] );

		$report = Two_Factor_Import::run( null, $dry_run );
		Two_Factor_Import::remember_report( get_current_user_id(), $report, $dry_run );

		wp_safe_redirect( Network::settings_url() . '#sigil-import-two-factor' );
		exit;
	}

	private function has_two_factor_data(): bool {
		$args = array(
			'meta_key' => '_two_factor_enabled_providers', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_query_meta_key
			'fields'   => 'ID',
			'number'   => 1,
		);
		if ( is_multisite() ) {
			$args['blog_id'] = 0;
		}

		return array() !== get_users( $args );
	}

	public static function action(): string {
		return self::ACTION;
	}
}
