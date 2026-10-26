<?php

declare( strict_types=1 );

use Sigil\Enrolment;
use Sigil\Store;

/**
 * The profile screen wraps everything hooked into it in its own form, and a
 * form inside a form is dropped by the browser: its buttons would submit the
 * profile instead. So Sigil's section there only reports, and links out.
 */
class Test_Profile_Section extends WP_UnitTestCase {

	private function section( int $user_id ): string {
		ob_start();
		Enrolment::instance()->render_profile_section( get_userdata( $user_id ) );

		return (string) ob_get_clean();
	}

	private function user_with_methods(): int {
		$user = (int) self::factory()->user->create();
		Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );
		Store::set_method( $user, 'email', array( 'enrolled_at' => time() ) );
		\Sigil\Providers::set_preference( $user, 'email' );
		\Sigil\Trusted_Devices::instance()->trust_current_device( $user );

		return $user;
	}

	public function test_your_own_profile_summarises_and_links_to_the_setup_page(): void {
		$user = $this->user_with_methods();
		wp_set_current_user( $user );

		$html = $this->section( $user );

		$this->assertStringNotContainsString( '<form', $html );
		$this->assertStringNotContainsString( '<button', $html );
		$this->assertStringNotContainsString( '<input', $html );
		$this->assertStringContainsString( 'Authenticator app', $html );
		$this->assertStringContainsString( 'Email', $html );
		$this->assertStringContainsString( '1 trusted device', $html );
		$this->assertStringContainsString( esc_url( admin_url( 'users.php?page=' . Enrolment::PAGE_SLUG ) ), $html );
	}

	public function test_an_administrator_gets_a_reset_link_not_a_form(): void {
		$user  = $this->user_with_methods();
		$admin = (int) self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $admin );
		}
		wp_set_current_user( $admin );

		$html = $this->section( $user );

		$this->assertStringNotContainsString( '<form', $html );
		$this->assertStringNotContainsString( '<button', $html );
		$this->assertMatchesRegularExpression( '/admin-post\.php\?action=sigil_reset_user&(amp;|#038;)user_id=' . $user . '&(amp;|#038;)_wpnonce=[a-f0-9]{10}/', $html );
		$this->assertStringNotContainsString( Enrolment::PAGE_SLUG, $html, 'the setup page is the viewer\'s own, not this user\'s' );
	}
}
