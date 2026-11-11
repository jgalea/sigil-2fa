<?php

declare( strict_types=1 );

class Test_App_Passwords extends WP_UnitTestCase {
	public function test_blocked_role_cannot_use_application_passwords(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'block_app_passwords' => [ 'administrator' => true ] ] );
		$uid = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$this->assertFalse( wp_is_application_passwords_available_for_user( get_user_by( 'id', $uid ) ) );
	}

	public function test_unblocked_role_is_untouched(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'block_app_passwords' => [] ] );
		$uid = self::factory()->user->create( [ 'role' => 'editor' ] );
		$this->assertTrue( wp_is_application_passwords_available_for_user( get_user_by( 'id', $uid ) ) );
	}

	// A third-party endpoint that calls wp_authenticate() and issues its own token
	// outside REST and XML-RPC got a password-only sign-in.
	public function test_a_filtered_api_request_refuses_the_password_for_a_2fa_account(): void {
		$user = self::factory()->user->create_and_get();
		\Sigil\Store::set_method( $user->ID, 'totp', array( 'secret' => 'x' ) );

		$this->assertInstanceOf( WP_User::class, \Sigil\App_Passwords::instance()->refuse_api_password( $user ), 'a normal request is left to the login challenge' );

		add_filter( 'sigil_is_api_request', '__return_true' );
		$result = \Sigil\App_Passwords::instance()->refuse_api_password( $user );
		remove_filter( 'sigil_is_api_request', '__return_true' );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_api_password_refused', $result->get_error_code() );
	}
}
