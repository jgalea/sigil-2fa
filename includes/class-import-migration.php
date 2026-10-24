<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * The admin side of the importers: a notice while a source plugin is active,
 * an import section per source on the settings screen, and the hooks that
 * keep a source plugin out of the way for users Sigil already covers.
 */
final class Import_Migration {

	private const ACTION = 'sigil_import';

	private static ?Import_Migration $instance = null;

	public static function instance(): Import_Migration {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'two_factor_is_required_for_user', array( Two_Factor_Import::class, 'filter_two_factor_required' ), 99, 2 );
		add_filter( 'authenticate', array( Wordfence_Import::class, 'stand_down' ), 24 );
		add_action( 'wp_ajax_nopriv_wordfence_ls_authenticate', array( Wordfence_Import::class, 'ajax_stand_down' ), 1 );
		add_action( 'wp_ajax_wordfence_ls_authenticate', array( Wordfence_Import::class, 'ajax_stand_down' ), 1 );

		add_action( Network::is_network() ? 'network_admin_notices' : 'admin_notices', array( $this, 'notice' ) );
		add_action( 'sigil_settings_after', array( $this, 'render_sections' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle_post' ) );
	}

	public function notice(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$id     = $screen instanceof \WP_Screen ? preg_replace( '/-network$/', '', $screen->id ) : '';
		if ( ! in_array( $id, array( 'dashboard', 'plugins', 'users', 'settings_page_sigil-2fa' ), true ) ) {
			return;
		}

		foreach ( Import::sources() as $slug => $source ) {
			if ( ! $source['class']::is_active() ) {
				continue;
			}

			echo '<div class="notice notice-warning"><p>';
			/* translators: %s: name of the other two-factor plugin */
			echo esc_html( sprintf( __( 'The %s plugin is active alongside Sigil. Import its users\' two-factor methods into Sigil, then deactivate it so there is one place sign-ins are checked.', 'sigil-2fa' ), $source['label'] ) );
			if ( 'settings_page_sigil-2fa' !== $id ) {
				/* translators: %s: name of the other two-factor plugin */
				echo ' <a href="' . esc_url( Network::settings_url() . '#sigil-import-' . $slug ) . '">' . esc_html( sprintf( __( 'Import from %s', 'sigil-2fa' ), $source['label'] ) ) . '</a>';
			}
			echo '</p></div>';
		}
	}

	public function render_sections(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			return;
		}

		foreach ( Import::sources() as $slug => $source ) {
			$report = Import::recall_report( $slug, get_current_user_id() );
			if ( ! $source['class']::is_active() && null === $report && ! $source['class']::has_data() ) {
				continue;
			}

			$importer = $source['class'];
			$label    = $source['label'];

			require SIGIL_DIR . 'templates/import.php';
		}
	}

	public function handle_post(): void {
		if ( ! current_user_can( Network::manage_capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to import two-factor data.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the nonce is per source, so the source is read first and the nonce checked against it straight after.
		$slug    = isset( $_POST['sigil_import_source'] ) ? sanitize_key( wp_unslash( $_POST['sigil_import_source'] ) ) : '';
		$sources = Import::sources();
		if ( ! isset( $sources[ $slug ] ) ) {
			wp_die( esc_html__( 'Unknown import source.', 'sigil-2fa' ), '', array( 'response' => 400 ) );
		}

		check_admin_referer( self::nonce_action( $slug ) );

		$dry_run = ! isset( $_POST['sigil_import_run'] );

		$report = Import::run( $sources[ $slug ]['class'], null, $dry_run );
		Import::remember_report( $slug, get_current_user_id(), $report, $dry_run );

		wp_safe_redirect( Network::settings_url() . '#sigil-import-' . $slug );
		exit;
	}

	public static function action(): string {
		return self::ACTION;
	}

	public static function nonce_action( string $slug ): string {
		return self::ACTION . '_' . $slug;
	}
}
