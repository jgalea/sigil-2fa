<?php

declare( strict_types=1 );

use Sigil\Enrolment;
use Sigil\Step_Up;

/**
 * WordPress lets a signed-in session set a new password, and change the email,
 * without the old password. Left alone, a stolen session sets a password of its
 * choosing and offers it as the proof that adds a passkey.
 */
class Test_Credential_Changes extends WP_UnitTestCase {

	use Clears_Attempts;
	use Passkey_Fixtures;
	use Signed_In;

	private const PASS   = 'correct horse battery';
	private const NEW    = 'chosen by the thief';
	private const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
	private const STALE  = HOUR_IN_SECONDS;

	public function set_up(): void {
		parent::set_up();
		if ( class_exists( '\Sigil\Credential_Changes' ) ) {
			\Sigil\Credential_Changes::instance()->register();
		}
	}

	private function user(): int {
		$user = (int) self::factory()->user->create(
			array(
				'role'       => 'subscriber',
				'user_pass'  => self::PASS,
				'user_email' => 'owner-' . wp_generate_password( 6, false ) . '@example.com',
			)
		);
		\Sigil\Providers::instance()->get( 'totp' )->handle_enrol(
			$user,
			array(
				'secret' => self::SECRET,
				'code'   => \Sigil\Providers\TOTP::code_at( self::SECRET, time() ),
			)
		);

		return $user;
	}

	/**
	 * profile.php's save, as core runs it.
	 *
	 * @param array<string, string> $fields
	 * @return int|WP_Error
	 */
	private function save_profile( int $user_id, array $fields ) {
		$user  = get_userdata( $user_id );
		$_POST = array_merge(
			array(
				'email'    => $user->user_email,
				'nickname' => $user->nickname,
			),
			$fields
		);
		if ( isset( $fields['pass1'] ) ) {
			$_POST['pass2'] = $fields['pass1'];
		}

		require_once ABSPATH . 'wp-admin/includes/user.php';
		do_action( 'personal_options_update', $user_id );
		$result = edit_user( $user_id );
		$_POST  = array();

		return $result;
	}

	private function password_is( int $user_id, string $password ): bool {
		clean_user_cache( $user_id );

		return wp_check_password( $password, get_userdata( $user_id )->user_pass, $user_id );
	}

	public function test_profile_password_change_on_a_stale_session_is_refused(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$result = $this->save_profile( $user, array( 'pass1' => self::NEW ) );

		$this->assertWPError( $result );
		$this->assertContains( 'sigil_step_up_required', $result->get_error_codes() );
		$this->assertTrue( $this->password_is( $user, self::PASS ) );
	}

	public function test_profile_email_change_on_a_stale_session_is_refused(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$result = $this->save_profile( $user, array( 'email' => 'thief@example.com' ) );

		$this->assertWPError( $result );
		$this->assertSame( '', (string) get_user_meta( $user, '_new_email', true ), 'no confirmation mail to the new address' );
		$this->assertNotSame( 'thief@example.com', get_userdata( $user )->user_email );
	}

	public function test_a_fresh_proof_lets_the_profile_change_the_password(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );
		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );

		$this->assertSame( $user, $this->save_profile( $user, array( 'pass1' => self::NEW ) ) );
		$this->assertTrue( $this->password_is( $user, self::NEW ) );
	}

	public function test_an_administrator_changing_someone_elses_password_is_not_asked(): void {
		$user  = $this->user();
		$admin = (int) self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $admin );
		}
		$this->sign_in( $admin, self::STALE );

		$this->assertSame( $user, $this->save_profile( $user, array( 'pass1' => self::NEW ) ) );
	}

	// The chain from the review, through profile.php on a session that signed
	// in a few minutes ago: the new password goes in, but it proves nothing.
	public function test_a_password_this_session_set_is_no_proof_for_a_passkey(): void {
		if ( PHP_VERSION_ID < 80000 ) {
			$this->markTestSkipped( 'Passkeys need PHP 8.0.' );
		}

		$user = $this->user();
		$this->sign_in( $user, 2 * MINUTE_IN_SECONDS );
		$this->assertSame( $user, $this->save_profile( $user, array( 'pass1' => self::NEW ) ) );

		$this->assertWPError( Step_Up::prove( $user, array( 'password' => self::NEW ) ) );
		$input = $this->attestation( $this->open_registration( $user ), self::new_key(), random_bytes( 32 ) );
		$this->assertWPError( Enrolment::instance()->complete_method( $user, 'passkey', $input ) );
	}

	public function test_a_password_set_after_this_session_signed_in_is_no_proof(): void {
		$user = $this->user();
		$this->sign_in( $user, 2 * MINUTE_IN_SECONDS );
		$this->assertSame( $user, $this->save_profile( $user, array( 'pass1' => self::NEW ) ) );

		// Another session that signed in before the change.
		$this->sign_in( $user, 5 * MINUTE_IN_SECONDS );

		$this->assertWPError( Step_Up::prove( $user, array( 'password' => self::NEW ) ) );
	}

	public function test_a_password_set_before_this_session_signed_in_proves_it(): void {
		$user = $this->user();
		$this->sign_in( $user, 2 * MINUTE_IN_SECONDS );
		$this->assertSame( $user, $this->save_profile( $user, array( 'pass1' => self::NEW ) ) );
		$origins                    = get_user_meta( $user, Step_Up::ORIGIN_META, true );
		$origins['password']['at'] -= 2 * MINUTE_IN_SECONDS;
		update_user_meta( $user, Step_Up::ORIGIN_META, $origins );

		// Signed in again with it.
		$this->sign_in( $user, MINUTE_IN_SECONDS );

		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::NEW ) ) );
	}

	// An application password authenticates the REST call with no session at
	// all, so there is nothing fresh to rely on.
	public function test_rest_password_change_with_an_application_password_is_refused(): void {
		$user = $this->user();
		wp_set_current_user( $user );

		$request = new WP_REST_Request( 'POST', '/wp/v2/users/me' );
		$request->set_param( 'password', self::NEW );
		$response = rest_do_request( $request );

		$this->assertSame( 403, $response->get_status() );
		$this->assertSame( 'sigil_step_up_required', $response->get_data()['code'] );
		$this->assertTrue( $this->password_is( $user, self::PASS ) );
	}

	public function test_rest_email_change_on_a_stale_session_is_refused(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$request = new WP_REST_Request( 'POST', '/wp/v2/users/' . $user );
		$request->set_param( 'email', 'thief@example.com' );
		$response = rest_do_request( $request );

		$this->assertSame( 403, $response->get_status() );
	}

	// Core matches routes case-insensitively, so a differently cased route
	// reaches the same handler.
	public function test_rest_password_change_through_a_differently_cased_route_is_refused(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		foreach ( array( '/wp/v2/users/ME', '/WP/V2/USERS/me', '/wp/v2/Users/' . $user ) as $route ) {
			$request = new WP_REST_Request( 'POST', $route );
			$request->set_param( 'password', self::NEW );
			$response = rest_do_request( $request );

			$this->assertSame( 403, $response->get_status(), $route );
		}
		$this->assertTrue( $this->password_is( $user, self::PASS ) );
	}

	public function test_rest_changes_to_anything_else_go_through(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$request = new WP_REST_Request( 'POST', '/wp/v2/users/me' );
		$request->set_param( 'description', 'Hello' );

		$this->assertSame( 200, rest_do_request( $request )->get_status() );
	}

	public function test_woocommerce_account_details_on_a_stale_session_are_refused(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$errors  = new WP_Error();
		$details = (object) array(
			'ID'         => $user,
			'user_email' => get_userdata( $user )->user_email,
			'user_pass'  => self::NEW,
		);
		do_action_ref_array( 'woocommerce_save_account_details_errors', array( &$errors, &$details ) );

		$this->assertContains( 'sigil_step_up_required', $errors->get_error_codes() );
	}

	public function test_woocommerce_account_details_without_a_credential_change_go_through(): void {
		$user = $this->user();
		$this->sign_in( $user, self::STALE );

		$errors  = new WP_Error();
		$details = (object) array(
			'ID'         => $user,
			'user_email' => get_userdata( $user )->user_email,
			'first_name' => 'Owner',
		);
		do_action_ref_array( 'woocommerce_save_account_details_errors', array( &$errors, &$details ) );

		$this->assertFalse( $errors->has_errors() );
	}

	// An administrator wiping their own methods is the account owner removing
	// every factor at once, so it needs the same proof as removing one.
	public function test_an_administrators_own_reset_needs_a_fresh_proof(): void {
		$admin = (int) self::factory()->user->create(
			array(
				'role'      => 'administrator',
				'user_pass' => self::PASS,
			)
		);
		if ( is_multisite() ) {
			grant_super_admin( $admin );
		}
		\Sigil\Store::set_method( $admin, 'email', array( 'enrolled_at' => time() ) );
		$this->sign_in( $admin, self::STALE );

		$refused = rest_do_request( new WP_REST_Request( 'DELETE', '/sigil/v1/users/' . $admin . '/methods' ) );
		$this->assertSame( 403, $refused->get_status() );
		$this->assertTrue( \Sigil\Store::has_any( $admin ) );

		$this->assertTrue( Step_Up::prove( $admin, array( 'password' => self::PASS ) ) );
		$allowed = rest_do_request( new WP_REST_Request( 'DELETE', '/sigil/v1/users/' . $admin . '/methods' ) );
		$this->assertSame( 200, $allowed->get_status() );
		$this->assertFalse( \Sigil\Store::has_any( $admin ) );
	}
}
