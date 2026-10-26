<?php

declare( strict_types=1 );

/**
 * Deleting the plugin takes everything it stored with it.
 */
class Test_Uninstall extends WP_UnitTestCase {

	// On a network, settings the add-on prefix covers are network options, which
	// live in sitemeta rather than in any site's options table.
	public function test_network_options_under_the_add_on_prefix_are_removed(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Network options only exist on multisite.' );
		}

		global $wpdb;

		update_site_option( 'sigil_pro_trusted_days', 14 );
		update_site_option( 'sigil_pro_zero_setup', true );
		update_site_option( 'sigilpro_unrelated', 'kept' );

		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'sigil-2fa/sigil-2fa.php' );
		}
		require dirname( __DIR__ ) . '/uninstall.php';

		$left = $wpdb->get_col( "SELECT meta_key FROM {$wpdb->sitemeta} WHERE meta_key LIKE 'sigil%'" );

		$this->assertNotContains( 'sigil_pro_trusted_days', $left );
		$this->assertNotContains( 'sigil_pro_zero_setup', $left );
		$this->assertContains( 'sigilpro_unrelated', $left, 'the underscore is literal, not a wildcard' );
	}
}
