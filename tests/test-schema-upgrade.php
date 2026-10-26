<?php

declare( strict_types=1 );

// An update can add columns, and a front-end request may be the first one a
// site sees afterwards, so the upgrade can't wait for an admin to visit.
class Test_Schema_Upgrade extends WP_UnitTestCase {
	private function columns(): array {
		global $wpdb;
		return $wpdb->get_col( 'SHOW COLUMNS FROM ' . \Sigil\Schema::table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}

	public function test_a_front_end_request_upgrades_an_old_schema(): void {
		global $wpdb;

		$wpdb->query( 'ALTER TABLE ' . \Sigil\Schema::table() . ' DROP COLUMN second_factor_only' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		\Sigil\Network::update_option( 'sigil_db_version', '0.4.1' );
		$this->assertNotContains( 'second_factor_only', $this->columns() );

		\Sigil\Schema::instance();
		do_action( 'init' );

		$this->assertContains( 'second_factor_only', $this->columns() );
		$this->assertSame( SIGIL_VERSION, \Sigil\Network::get_option( 'sigil_db_version' ) );
	}

	public function test_the_check_is_hooked_on_init(): void {
		$this->assertNotFalse( has_action( 'init', array( \Sigil\Schema::instance(), 'maybe_install' ) ) );
	}
}
