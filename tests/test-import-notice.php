<?php

declare( strict_types=1 );

use Sigil\Import_Migration;

class Test_Import_Notice extends WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();

		if ( ! defined( 'WP_2FA_VERSION' ) ) {
			define( 'WP_2FA_VERSION', '0.0.0-test' );
		}

		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $admin );
		}
		wp_set_current_user( $admin );
		set_current_screen( 'dashboard' );
		\Sigil\Network::delete_option( 'sigil_import_notice_hidden' );
	}

	private function notice_html(): string {
		ob_start();
		Import_Migration::instance()->notice();
		return (string) ob_get_clean();
	}

	public function test_notice_shows_while_the_source_is_active_and_offers_a_dismiss_link(): void {
		$html = $this->notice_html();

		$this->assertStringContainsString( 'WP 2FA plugin is active alongside Sigil', $html );
		$this->assertStringContainsString( 'action=sigil_dismiss_import_notice', $html );
		$this->assertStringContainsString( 'source=wp-2fa', $html );
	}

	public function test_notice_stays_gone_once_hidden(): void {
		Import_Migration::hide_notice( 'wp-2fa' );

		$this->assertStringNotContainsString( 'WP 2FA plugin is active alongside Sigil', $this->notice_html() );
		$this->assertTrue( Import_Migration::notice_hidden( 'wp-2fa' ) );
		$this->assertFalse( Import_Migration::notice_hidden( 'two-factor' ) );
	}
}
