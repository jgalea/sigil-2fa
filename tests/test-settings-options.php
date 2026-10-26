<?php

declare( strict_types=1 );

/**
 * The settings the free screen took over from the add-on.
 */
class Test_Settings_Options extends WP_UnitTestCase {

	public function tear_down(): void {
		\Sigil\Network::delete_option( \Sigil\Trusted_Devices::OPTION_DAYS );
		\Sigil\Network::delete_option( \Sigil\Zero_Setup::OPTION );
		$_POST    = array();
		$_REQUEST = array();
		parent::tear_down();
	}

	private function admin(): int {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		return $id;
	}

	/**
	 * Run the save handler and return where it sent the browser.
	 *
	 * @param array<string, mixed> $post
	 */
	private function submit( array $post ): string {
		$_POST                = $post;
		$_REQUEST             = $post;
		$_REQUEST['_wpnonce'] = wp_create_nonce( 'sigil_save_settings' );

		add_filter(
			'wp_redirect',
			static function ( $location ) {
				throw new \RuntimeException( (string) $location );
			}
		);

		try {
			\Sigil\Settings::instance()->handle_save();
		} catch ( \RuntimeException $e ) {
			return $e->getMessage();
		}

		$this->fail( 'the handler did not redirect' );
	}

	public function test_the_settings_screen_saves_the_ux_options(): void {
		$admin = $this->admin();
		wp_set_current_user( $admin );
		$token = \Sigil\Trusted_Devices::instance()->trust_current_device( $admin );

		$this->submit(
			array(
				'sigil_trusted_days'   => '14',
				'sigil_zero_setup'     => '1',
				'sigil_revoke_trusted' => '1',
			)
		);

		$this->assertSame( 14, \Sigil\Trusted_Devices::trust_days() );
		$this->assertTrue( \Sigil\Zero_Setup::is_enabled() );
		$this->assertFalse( \Sigil\Trusted_Devices::instance()->is_trusted( $admin, $token ) );
	}

	public function test_the_trusted_days_are_clamped(): void {
		wp_set_current_user( $this->admin() );

		$this->submit(
			array( 'sigil_trusted_days' => '9000' )
		);

		$this->assertSame( 365, \Sigil\Trusted_Devices::trust_days() );
	}

	// Pro stored these under its own names before they moved into the free
	// plugin, so a site that already had them set must read them unchanged.
	public function test_values_saved_by_the_addon_are_still_read(): void {
		update_option( 'sigil_pro_trusted_days', 45 );
		update_option( 'sigil_pro_zero_setup', true );

		if ( is_multisite() ) {
			update_site_option( 'sigil_pro_trusted_days', 45 );
			update_site_option( 'sigil_pro_zero_setup', true );
		}

		$this->assertSame( 45, \Sigil\Trusted_Devices::trust_days() );
		$this->assertTrue( \Sigil\Zero_Setup::is_enabled() );

		delete_option( 'sigil_pro_trusted_days' );
		delete_option( 'sigil_pro_zero_setup' );
		delete_site_option( 'sigil_pro_trusted_days' );
		delete_site_option( 'sigil_pro_zero_setup' );
	}
}
