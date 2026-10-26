<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Put two-factor setup where a shop's customers already manage their account.
 *
 * WooCommerce customers are exactly the people who never see wp-admin, so
 * without this the only way to reach enrolment is a page someone remembered to
 * build. This adds a Two-factor tab to My Account, using WooCommerce's own
 * endpoint system so it inherits the theme and sits with the other tabs.
 */
final class WooCommerce {

	public const ENDPOINT = 'two-factor';

	private static ?WooCommerce $instance = null;

	public static function instance(): WooCommerce {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function is_active(): bool {
		return class_exists( 'WooCommerce' );
	}

	/**
	 * Decide once every plugin has loaded.
	 *
	 * The add-on boots while plugins are still being included, so asking whether
	 * WooCommerce exists at that moment answers for load order rather than for
	 * the site: on an install where this plugin sorts first, the tab silently
	 * never registers.
	 */
	public static function boot(): void {
		add_action(
			'plugins_loaded',
			static function (): void {
				if ( self::is_active() ) {
					self::instance();
				}
			},
			20
		);
	}

	private function __construct() {
		add_action( 'init', array( $this, 'add_endpoint' ) );
		add_filter( 'woocommerce_get_query_vars', array( $this, 'add_query_var' ) );
		add_filter( 'woocommerce_account_menu_items', array( $this, 'add_menu_item' ) );
		add_action( 'woocommerce_account_' . self::ENDPOINT . '_endpoint', array( $this, 'render' ) );
		add_filter( 'woocommerce_endpoint_' . self::ENDPOINT . '_title', array( $this, 'title' ) );
		add_filter( 'sigil_needs_frontend_assets', array( $this, 'needs_assets' ) );
	}

	public function add_endpoint(): void {
		// EP_PAGES only: EP_ROOT would claim /two-factor/ site-wide and shadow
		// any page a site already has at that slug.
		add_rewrite_endpoint( self::ENDPOINT, EP_PAGES );

		// Rules built before this endpoint existed send the tab's URL somewhere
		// else until they are rebuilt, and nobody thinks to re-save permalinks.
		$rules = get_option( 'rewrite_rules' );
		if ( is_array( $rules ) && array() === preg_grep( '#/' . self::ENDPOINT . '#', array_keys( $rules ) ) ) {
			flush_rewrite_rules( false );
		}
	}

	/**
	 * @param array<string, string> $vars
	 * @return array<string, string>
	 */
	public function add_query_var( $vars ) {
		if ( is_array( $vars ) ) {
			$vars[ self::ENDPOINT ] = self::ENDPOINT;
		}

		return $vars;
	}

	/**
	 * @param array<string, string> $items
	 * @return array<string, string>
	 */
	public function add_menu_item( $items ) {
		if ( ! is_array( $items ) ) {
			return $items;
		}

		// Before logout, which belongs last, and after the account details the
		// tab is a sibling of.
		$logout = isset( $items['customer-logout'] ) ? array( 'customer-logout' => $items['customer-logout'] ) : array();
		unset( $items['customer-logout'] );

		$items[ self::ENDPOINT ] = __( 'Two-factor', 'sigil-2fa' );

		return $items + $logout;
	}

	/**
	 * @param bool $needed
	 */
	public function needs_assets( $needed ): bool {
		if ( $needed ) {
			return true;
		}

		global $wp_query;

		return isset( $wp_query->query_vars[ self::ENDPOINT ] );
	}

	public function title(): string {
		return __( 'Two-factor authentication', 'sigil-2fa' );
	}

	public function render(): void {
		$user_id = (int) get_current_user_id();
		if ( $user_id <= 0 ) {
			echo '<p>' . esc_html__( 'Sign in to manage two-factor authentication.', 'sigil-2fa' ) . '</p>';
			return;
		}

		// The same UI the shortcode renders, so a shop and a plain site show the
		// same thing and only one of them needs maintaining.
		echo '<div class="sigil-enrol--frontend">';
		Enrolment::instance()->render_enrol_ui( $user_id, false );
		echo '</div>';
	}
}
