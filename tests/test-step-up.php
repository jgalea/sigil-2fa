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

	/**
	 * @return array<string, string>
	 */
	private function passkey_input( int $user ): array {
		return $this->attestation( $this->open_registration( $user ), self::new_key(), random_bytes( 32 ) );
	}

	private function skip_without_passkeys(): void {
		if ( PHP_VERSION_ID < 80000 ) {
			$this->markTestSkipped( 'Passkeys need PHP 8.0.' );
		}
	}

	// Under zero-setup every account with an address already has email as its
	// second step, so nothing it adds is a first method.
	public function test_under_zero_setup_a_change_needs_a_fresh_proof(): void {
		\Sigil\Zero_Setup::set_enabled( true );
		\Sigil\Zero_Setup::instance()->register();
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$result = Enrolment::instance()->complete_method( $user, 'backup', array() );
		\Sigil\Zero_Setup::set_enabled( false );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_step_up_required', $result->get_error_code() );
	}

	public function test_under_zero_setup_a_passkey_needs_a_fresh_proof(): void {
		$this->skip_without_passkeys();
		\Sigil\Zero_Setup::set_enabled( true );
		\Sigil\Zero_Setup::instance()->register();
		$user = $this->user();
		$this->sign_in( $user );

		$result = Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) );
		\Sigil\Zero_Setup::set_enabled( false );

		$this->assertWPError( $result );
		$this->assertSame( array(), \Sigil\Credentials::for_user( $user ) );
	}

	// A passkey can be the whole sign-in, so a session alone, however fresh,
	// must not be able to make one: that is a stolen cookie turned into a
	// credential that outlives it.
	public function test_a_first_passkey_needs_the_password(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		$this->sign_in( $user );

		$refused = Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) );
		$this->assertWPError( $refused );
		$this->assertSame( 'sigil_step_up_required', $refused->get_error_code() );

		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );
		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
		$this->assertCount( 1, \Sigil\Credentials::for_user( $user ) );
	}

	public function test_a_first_authenticator_still_needs_only_the_session(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'totp', array( 'secret' => 'x' ) ) );
	}

	public function test_a_recent_sign_in_is_not_enough_to_add_a_passkey(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, MINUTE_IN_SECONDS );

		$this->assertWPError( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );

		$this->assertTrue( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
	}

	// Otherwise a stolen session sets up an authenticator, which needs nothing,
	// and then counts that as the proof for a passkey.
	public function test_setting_up_a_first_method_is_not_proof_for_a_passkey(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'email', array() ) );
		$this->assertWPError( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
	}

	public function test_wrong_confirmation_passwords_count_as_wrong_passwords(): void {
		\Sigil\Policy::update( array( 'limit_passwords' => true ) );
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		for ( $i = 0; $i < 5; $i++ ) {
			Step_Up::prove( $user, array( 'password' => 'wrong' ) );
		}
		$this->forget_step_up_attempts( $user );

		$result = wp_authenticate( get_userdata( $user )->user_login, self::PASS );
		$this->assertWPError( $result );
		$this->assertSame( 'sigil_password_limited', $result->get_error_code() );
	}

	public function test_the_wizard_asks_for_the_password_before_a_first_passkey(): void {
		$this->skip_without_passkeys();
		$admin = $this->admin_user();
		$this->sign_in( $admin );

		$html = $this->wizard_page( 1 );

		$this->assertStringContainsString( 'value="sigil_step_up"', $html );
		$this->assertStringContainsString( 'name="sigil_step_up_password"', $html );
		$this->assertStringNotContainsString( 'sigil-passkey-register', $html );

		Step_Up::prove( $admin, array( 'password' => self::PASS ) );
		$this->assertStringContainsString( 'sigil-passkey-register', $this->wizard_page( 1 ) );
	}

	public function test_the_wizard_offers_the_confirm_form_for_new_backup_codes(): void {
		$admin = $this->admin_user();
		$this->with_totp( $admin );
		Enrolment::instance()->ensure_backup_codes( $admin );
		$this->sign_in( $admin, self::STALE );
		$this->wizard_page( 2 );

		$html = $this->wizard_page( 2 );

		$this->assertStringContainsString( 'value="sigil_step_up"', $html );
		$this->assertStringNotContainsString( 'value="sigil_regenerate_backup"', $html );
	}

	private function admin_user(): int {
		$id = (int) self::factory()->user->create(
			array(
				'role'      => 'administrator',
				'user_pass' => self::PASS,
			)
		);
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}

		return $id;
	}

	private function wizard_page( int $step ): string {
		$_GET['step'] = (string) $step;
		ob_start();
		\Sigil\Wizard::instance()->render();
		$html = (string) ob_get_clean();
		unset( $_GET['step'] );

		return $html;
	}

	private function forget_step_up_attempts( int $user ): void {
		\Sigil\Rate_Limit::clear( 'su:' . $user );
	}

	private function enrol_totp_through_the_screen( int $user ): void {
		$result = Enrolment::instance()->complete_method(
			$user,
			'totp',
			array(
				'secret' => self::SECRET,
				'code'   => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ),
			)
		);
		$this->assertTrue( $result );
	}

	// A stolen session on an account with nothing set up can add an
	// authenticator without proof. A code from that authenticator proves only
	// that the thief holds it.
	public function test_an_authenticator_set_up_in_this_session_does_not_prove_it_for_a_passkey(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		$this->sign_in( $user, self::STALE );
		$this->enrol_totp_through_the_screen( $user );

		$this->assertWPError( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
		$this->assertWPError( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );

		// The password still does.
		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );
		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
	}

	public function test_an_authenticator_added_on_a_recent_sign_in_does_not_prove_it_either(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		Store::set_method( $user, 'email', array( 'enrolled_at' => time() - DAY_IN_SECONDS ) );
		$this->sign_in( $user, 2 * MINUTE_IN_SECONDS );
		$this->enrol_totp_through_the_screen( $user );

		$this->assertWPError( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
		$this->assertWPError( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
	}

	public function test_an_authenticator_from_an_earlier_session_proves_it(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		$this->sign_in( $user );
		$this->enrol_totp_through_the_screen( $user );
		$this->set_up_at( $user, 'totp', time() - MINUTE_IN_SECONDS );

		// Signed in again later, with the password and that authenticator.
		$this->sign_in( $user );

		$this->assertTrue( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
	}

	// A factor's proof covers the one change it was given for. The password
	// is the stronger proof and lasts the window.
	public function test_a_factor_proof_is_spent_by_the_change_it_allowed(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		$this->with_totp( $user );
		$this->sign_in( $user, self::STALE );

		$this->assertTrue( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
		$this->assertFalse( Step_Up::proven( $user ) );

		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );
		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
		$this->assertTrue( Step_Up::proven( $user ) );
	}

	// Times are to the second, so the same second cannot say which came first.
	public function test_an_authenticator_set_up_in_the_second_the_session_signed_in_does_not_prove_it(): void {
		$user = $this->user();
		$this->sign_in( $user );
		$this->enrol_totp_through_the_screen( $user );

		$token = $this->sign_in( $user );
		$login = (int) WP_Session_Tokens::get_instance( $user )->get( $token )['login'];
		$this->set_up_at( $user, 'totp', $login );

		$this->assertWPError( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
	}

	public function test_a_reset_forgets_when_each_factor_was_set_up(): void {
		$user = $this->user();
		$this->sign_in( $user );
		$this->enrol_totp_through_the_screen( $user );
		$this->assertNotEmpty( get_user_meta( $user, Step_Up::ORIGIN_META, true ) );

		$this->assertTrue( \Sigil\Recovery::reset_as_system( $user ) );

		$this->assertSame( '', get_user_meta( $user, Step_Up::ORIGIN_META, true ) );
	}

	private function set_up_at( int $user, string $factor, int $at ): void {
		$origins                  = get_user_meta( $user, Step_Up::ORIGIN_META, true );
		$origins[ $factor ]['at'] = $at;
		update_user_meta( $user, Step_Up::ORIGIN_META, $origins );
	}

	private function with_three_methods( int $user ): void {
		$this->with_totp( $user );
		Store::set_method( $user, 'email', array( 'enrolled_at' => time() ) );
		Enrolment::instance()->ensure_backup_codes( $user );
	}

	public function test_one_authenticator_proof_removes_one_method(): void {
		$user = $this->user();
		$this->with_three_methods( $user );
		$this->sign_in( $user, self::STALE );

		$this->assertTrue( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
		$this->assertTrue( Enrolment::instance()->remove_method( $user, 'email' ) );

		$again = Enrolment::instance()->remove_method( $user, 'backup' );
		$this->assertWPError( $again );
		$this->assertSame( 'sigil_step_up_required', $again->get_error_code() );
		$this->assertArrayHasKey( 'backup', Store::methods( $user ) );
	}

	public function test_a_password_proof_removes_several(): void {
		$user = $this->user();
		$this->with_three_methods( $user );
		$this->sign_in( $user, self::STALE );

		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );
		$this->assertTrue( Enrolment::instance()->remove_method( $user, 'email' ) );
		$this->assertTrue( Enrolment::instance()->remove_method( $user, 'backup' ) );
	}

	public function test_removing_a_method_forgets_when_it_was_set_up(): void {
		$user = $this->user();
		$this->sign_in( $user );
		$this->enrol_totp_through_the_screen( $user );
		Store::set_method( $user, 'email', array( 'enrolled_at' => time() ) );
		$this->assertArrayHasKey( 'totp', get_user_meta( $user, Step_Up::ORIGIN_META, true ) );

		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );
		$this->assertTrue( Enrolment::instance()->remove_method( $user, 'totp' ) );

		$this->assertSame( '', get_user_meta( $user, Step_Up::ORIGIN_META, true ) );
	}

	// What an administrator registered for this account is theirs, not the
	// owner's, so it never vouches for the owner.
	public function test_a_passkey_someone_else_registered_proves_nothing(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		$key  = self::new_key();
		$cred = random_bytes( 32 );
		\Sigil\Credentials::add( $user, $cred, openssl_pkey_get_details( $key )['key'], 0, 'Desk key', 'usb', (string) $user, false, true );
		Store::set_method( $user, 'passkey', array( 'enrolled_at' => time() ) );
		$this->sign_in( $user, self::STALE );

		$options   = $this->passkey_provider()->auth_options( $user );
		$assertion = self::signed_assertion( $options->publicKey->challenge->getBinaryString(), $key, $cred, (string) $user );

		$this->assertWPError( Step_Up::prove( $user, array( 'passkey_assertion' => wp_json_encode( $assertion ) ) ) );
	}

	// Imported factors arrive while sessions are already open, so they only
	// vouch for sessions that sign in after the import.
	public function test_an_imported_authenticator_does_not_prove_it_for_a_session_already_open(): void {
		$donor = $this->user();
		$this->with_totp( $donor );
		$data = Store::methods( $donor )['totp'];

		$user = $this->user();
		$this->sign_in( $user, self::STALE );
		\Sigil\Import::apply( \Sigil\Import::blank_result( $user ), $user, array( 'totp' => $data ), array(), false );

		$this->assertArrayHasKey( 'totp', (array) get_user_meta( $user, Step_Up::ORIGIN_META, true ) );
		$this->assertWPError( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
	}

	public function test_imported_passkeys_are_recorded_when_they_arrive(): void {
		$user   = $this->user();
		$passes = did_action( 'sigil_methods_changed' );
		$row    = array(
			'credential_id' => random_bytes( 32 ),
			'public_key'    => openssl_pkey_get_details( self::new_key() )['key'],
			'sign_count'    => 0,
			'label'         => 'Imported',
			'transports'    => '',
			'user_handle'   => '',
			'discoverable'  => null,
		);

		\Sigil\Import::apply( \Sigil\Import::blank_result( $user ), $user, array(), array( $row ), false );

		$id = (int) \Sigil\Credentials::for_user( $user )[0]->id;
		$this->assertArrayHasKey( 'passkey:' . $id, (array) get_user_meta( $user, Step_Up::ORIGIN_META, true ) );
		$this->assertSame( $passes + 1, did_action( 'sigil_methods_changed' ) );
	}

	// Two registrations sent at once both read the proof before either spends
	// it. Only one may use it.
	public function test_one_factor_proof_covers_one_passkey_even_when_two_race(): void {
		$this->skip_without_passkeys();
		$user = $this->user();
		$this->with_totp( $user );
		$token = $this->sign_in( $user, self::STALE );

		$this->assertTrue( Step_Up::prove( $user, array( 'code' => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ) ) ) );
		$manager = WP_Session_Tokens::get_instance( $user );
		$proved  = $manager->get( $token );

		$this->assertTrue( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );

		// The second request read the session before the first spent it.
		$manager->update( $token, $proved );
		$this->forget_request_proof();

		$this->assertWPError( Enrolment::instance()->complete_method( $user, 'passkey', $this->passkey_input( $user ) ) );
		$this->assertCount( 1, \Sigil\Credentials::for_user( $user ) );
	}

	private function forget_request_proof(): void {
		foreach ( array( 'proven', 'by_password', 'set_up' ) as $name ) {
			if ( property_exists( Step_Up::class, $name ) ) {
				$property = new ReflectionProperty( Step_Up::class, $name );
				$property->setAccessible( true );
				$property->setValue( null, array() );
			}
		}
	}
}
