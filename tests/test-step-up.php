<?php

declare( strict_types=1 );

use Sigil\Enrolment;
use Sigil\Step_Up;
use Sigil\Store;

/**
 * Holding someone's session for a minute should not be enough to give yourself
 * a factor of your own on their account. Once an account has a method, changing
 * its methods needs a fresh proof: the password, a current factor, or a sign-in
 * in the last few minutes.
 */
class Test_Step_Up extends WP_UnitTestCase {

	use Clears_Attempts;
	use Passkey_Fixtures;
	use Signed_In;

	private const PASS   = 'correct horse battery';
	private const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
	private const STALE  = HOUR_IN_SECONDS;

	private function user(): int {
		return (int) self::factory()->user->create(
			array(
				'role'      => 'subscriber',
				'user_pass' => self::PASS,
			)
		);
	}

	private function with_totp( int $user ): void {
		$totp = \Sigil\Providers::instance()->get( 'totp' );
		$totp->handle_enrol(
			$user,
			array(
				'secret' => self::SECRET,
				'code'   => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ),
			)
		);
		$this->assertTrue( $totp->is_enrolled( $user ) );
	}

	public function test_a_first_method_needs_only_the_session(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'email', array() ) );
	}

	public function test_adding_a_method_to_an_account_that_has_one_needs_a_fresh_proof(): void {
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, self::STALE );

		$result = Enrolment::instance()->complete_method( $user, 'email', array() );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_step_up_required', $result->get_error_code() );
		$this->assertArrayNotHasKey( 'email', Store::methods( $user ) );
	}

	public function test_removing_a_method_needs_a_fresh_proof(): void {
		$user = $this->user();
		$this->with_totp( $user );
		Store::set_method( $user, 'email', array( 'enrolled_at' => time() ) );
		$this->sign_in( $user, self::STALE );

		$result = Enrolment::instance()->remove_method( $user, 'email' );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_step_up_required', $result->get_error_code() );
		$this->assertArrayHasKey( 'email', Store::methods( $user ) );
	}

	public function test_new_backup_codes_need_a_fresh_proof(): void {
		$user = $this->user();
		$this->with_totp( $user );
		Enrolment::instance()->ensure_backup_codes( $user );
		$codes = Store::methods( $user )['backup'];
		$this->sign_in( $user, self::STALE );

		$result = Enrolment::instance()->regenerate_backup_codes( $user );

		$this->assertWPError( $result );
		$this->assertSame( $codes, Store::methods( $user )['backup'] );
	}

	public function test_a_sign_in_in_the_last_few_minutes_is_the_proof(): void {
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, 2 * MINUTE_IN_SECONDS );

		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'email', array() ) );
	}

	public function test_the_password_proves_it_for_this_session_only(): void {
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, self::STALE );

		$this->assertWPError( Step_Up::prove( $user, array( 'password' => 'wrong' ) ) );
		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );
		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'email', array() ) );

		// Another session on the same account, say the one somebody else holds,
		// has proved nothing.
		$this->sign_in( $user, self::STALE );
		$this->assertFalse( Step_Up::satisfied( $user ) );
	}

	public function test_a_current_authenticator_code_proves_it(): void {
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, self::STALE );

		$code = \Sigil\Providers\TOTP::code_at( self::SECRET, time() );
		$this->assertTrue( Step_Up::prove( $user, array( 'code' => $code ) ) );
		$this->assertTrue( Step_Up::satisfied( $user ) );
	}

	public function test_a_passkey_proves_it(): void {
		if ( PHP_VERSION_ID < 80000 ) {
			$this->markTestSkipped( 'Passkeys need PHP 8.0.' );
		}

		$user = $this->user();
		$key  = self::new_key();
		$cred = random_bytes( 32 );
		\Sigil\Credentials::add( $user, $cred, openssl_pkey_get_details( $key )['key'], 0, 'Key', 'internal', (string) $user, true );
		Store::set_method( $user, 'passkey', array( 'enrolled_at' => time() ) );
		$this->sign_in( $user, self::STALE );

		$options   = $this->passkey_provider()->auth_options( $user );
		$assertion = self::signed_assertion( $options->publicKey->challenge->getBinaryString(), $key, $cred, (string) $user );

		$this->assertTrue( Step_Up::prove( $user, array( 'passkey_assertion' => wp_json_encode( $assertion ) ) ) );
		$this->assertTrue( Step_Up::satisfied( $user ) );
	}

	public function test_guessing_the_password_is_limited(): void {
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, self::STALE );

		for ( $i = 0; $i < \Sigil\Rate_Limit::max_attempts(); $i++ ) {
			Step_Up::prove( $user, array( 'password' => 'wrong' ) );
		}

		$result = Step_Up::prove( $user, array( 'password' => self::PASS ) );
		$this->assertWPError( $result );
		$this->assertSame( 'sigil_rate_limited', $result->get_error_code() );
	}

	public function test_an_administrator_changing_someone_else_is_not_asked(): void {
		$user = $this->user();
		$this->with_totp( $user );
		Store::set_method( $user, 'email', array( 'enrolled_at' => time() ) );

		$admin = (int) self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $admin );
		}
		$this->with_totp( $admin );
		$this->sign_in( $admin, self::STALE );

		$this->assertTrue( Enrolment::instance()->remove_method( $user, 'email' ) );
	}

	public function test_the_rest_route_asks_for_the_proof_and_takes_a_password(): void {
		$user = $this->user();
		$this->with_totp( $user );
		Store::set_method( $user, 'email', array( 'enrolled_at' => time() ) );
		$this->sign_in( $user, self::STALE );

		$route   = '/sigil/v1/users/' . $user . '/methods/email';
		$refused = rest_do_request( new WP_REST_Request( 'DELETE', $route ) );
		$this->assertSame( 403, $refused->get_status() );
		$this->assertSame( 'sigil_step_up_required', $refused->get_data()['code'] );
		$this->assertArrayHasKey( 'email', Store::methods( $user ) );

		$request = new WP_REST_Request( 'DELETE', $route );
		$request->set_param( 'password', self::PASS );
		$allowed = rest_do_request( $request );
		$this->assertSame( 200, $allowed->get_status(), wp_json_encode( $allowed->get_data() ) );
		$this->assertArrayNotHasKey( 'email', Store::methods( $user ) );
	}

	public function test_the_confirm_route_records_the_proof(): void {
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, self::STALE );

		$request = new WP_REST_Request( 'POST', '/sigil/v1/me/confirm' );
		$request->set_param( 'password', self::PASS );
		$response = rest_do_request( $request );

		$this->assertSame( 200, $response->get_status(), wp_json_encode( $response->get_data() ) );
		$this->assertTrue( Step_Up::satisfied( $user ) );
	}

	public function test_the_enrolment_screen_asks_to_confirm_instead_of_offering_changes(): void {
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, self::STALE );
		$_GET['method'] = 'totp';

		ob_start();
		Enrolment::instance()->render_enrol_ui( $user, false );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'name="action" value="sigil_step_up"', $html );
		$this->assertStringNotContainsString( 'value="sigil_remove_method"', $html );

		Step_Up::prove( $user, array( 'password' => self::PASS ) );
		ob_start();
		Enrolment::instance()->render_enrol_ui( $user, false );
		$html = (string) ob_get_clean();

		$this->assertStringNotContainsString( 'value="sigil_step_up"', $html );
		$this->assertStringContainsString( 'value="sigil_remove_method"', $html );
		unset( $_GET['method'] );
	}
}
