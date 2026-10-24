<?php

declare( strict_types=1 );

/**
 * The My Account tab, without WooCommerce itself: the class only talks to it
 * through filters, so the filters can be called directly.
 */
class Test_WooCommerce extends WP_UnitTestCase {

	private function tab(): \Sigil\WooCommerce {
		return \Sigil\WooCommerce::instance();
	}

	public function test_the_tab_goes_before_log_out(): void {
		$items = $this->tab()->add_menu_item(
			array(
				'dashboard'       => 'Dashboard',
				'edit-account'    => 'Account details',
				'customer-logout' => 'Log out',
			)
		);

		$keys = array_keys( $items );
		$this->assertSame( 'customer-logout', end( $keys ) );
		$this->assertSame( 'two-factor', $keys[ count( $keys ) - 2 ] );
	}

	public function test_the_endpoint_is_added_to_woocommerces_query_vars(): void {
		$vars = $this->tab()->add_query_var( array( 'orders' => 'orders' ) );

		$this->assertSame( 'two-factor', $vars['two-factor'] );
	}

	public function test_stale_rewrite_rules_are_rebuilt_with_the_endpoint(): void {
		$this->set_permalink_structure( '/%postname%/' );
		update_option( 'rewrite_rules', array( '^unrelated/?$' => 'index.php?unrelated=1' ) );

		$this->tab()->add_endpoint();

		$this->assertNotEmpty( preg_grep( '#/two-factor#', array_keys( (array) get_option( 'rewrite_rules' ) ) ) );
	}

	public function test_fresh_rules_are_left_alone(): void {
		$this->set_permalink_structure( '/%postname%/' );
		$this->tab()->add_endpoint();
		$rules = get_option( 'rewrite_rules' );
		$this->assertNotEmpty( preg_grep( '#/two-factor#', array_keys( (array) $rules ) ), 'precondition' );

		$marker           = (array) $rules;
		$marker['^kept$'] = 'index.php?kept=1';
		update_option( 'rewrite_rules', $marker );

		$this->tab()->add_endpoint();

		$this->assertArrayHasKey( '^kept$', (array) get_option( 'rewrite_rules' ), 'a flush would have dropped the marker' );
	}
}
