<?php

declare( strict_types=1 );

class Test_Login_Guard extends WP_UnitTestCase {

	/** @var list<bool> */
	private array $sent = array();

	public function set_up(): void {
		parent::set_up();

		// The test suite turns session cookies off for everyone. Put WordPress's
		// own default back, record what reaches the end, and stop it there:
		// setcookie() after phpunit has printed only raises warnings.
		$this->sent = array();
		remove_filter( 'send_auth_cookies', '__return_false' );
		add_filter(
			'send_auth_cookies',
			function ( $send, $expire, $expiration, $user_id ) {
				if ( $user_id > 0 ) {
					$this->sent[] = (bool) $send;
				}
				return false;
			},
			PHP_INT_MAX,
			4
		);
	}

	public function tear_down(): void {
		unset( $_REQUEST['action'] );
		$this->reset_guard( 'granted', array() );
		$this->reset_guard( 'session_user', null );
		$this->reset_guard( 'password_attempted', false );
		unset( $_COOKIE[ AUTH_COOKIE ], $_COOKIE[ LOGGED_IN_COOKIE ] );
		parent::tear_down();
	}

	/**
	 * @param mixed $value
	 */
	private function reset_guard( string $property, $value ): void {
		$prop = new ReflectionProperty( \Sigil\Login_Guard::class, $property );
		$prop->setAccessible( true );
		$prop->setValue( \Sigil\Login_Guard::instance(), $value );
	}

	// Every factory user is registered inside the test's own request, which the
	// guard treats as a new account. Forget that unless a test is about it.
	private function enrolled_user( bool $registered_now = false ): WP_User {
		$user = self::factory()->user->create_and_get( array( 'user_pass' => 'password' ) );
		\Sigil\Store::set_method( (int) $user->ID, 'backup', array( 'hashes' => array( 'x' ) ) );

		if ( ! $registered_now ) {
			$this->reset_guard( 'new_users', array() );
		}

		return $user;
	}

	private function as_ajax( string $action ): void {
		add_filter( 'wp_doing_ajax', '__return_true' );
		$_REQUEST['action'] = $action;
	}

	private function sign_on( WP_User $user ) {
		return wp_signon(
			array(
				'user_login'    => $user->user_login,
				'user_password' => 'password',
			)
		);
	}

	public function test_ajax_sign_on_refuses_the_password_of_someone_with_a_second_factor(): void {
		$user = $this->enrolled_user();
		$this->as_ajax( 'popup_login' );

		$result = $this->sign_on( $user );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_ajax_password_refused', $result->get_error_code() );
		$this->assertSame( wp_login_url(), $result->get_error_data()['login_url'] );
		$this->assertNotContains( true, $this->sent, 'no session cookie goes out' );
	}

	public function test_a_handler_that_sets_the_cookie_itself_sends_nothing_and_keeps_no_session(): void {
		$user = $this->enrolled_user();
		$this->as_ajax( 'popup_login' );

		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( false ), $this->sent, 'no cookie is sent' );
		$this->assertSame( array(), WP_Session_Tokens::get_instance( (int) $user->ID )->get_all(), 'the stored session is gone too' );
	}

	private function with_wordfence_check(): void {
		add_action( 'wp_ajax_nopriv_wordfence_ls_authenticate', '__return_null' );
	}

	public function test_a_credential_check_still_gets_its_answer(): void {
		$user = $this->enrolled_user();
		$this->with_wordfence_check();
		$this->as_ajax( 'wordfence_ls_authenticate' );

		$result = wp_authenticate( $user->user_login, 'password' );

		$this->assertInstanceOf( WP_User::class, $result );
		$this->assertSame( (int) $user->ID, (int) $result->ID );
	}

	public function test_a_credential_check_action_still_cannot_issue_a_session(): void {
		$user = $this->enrolled_user();
		$this->with_wordfence_check();
		$this->as_ajax( 'wordfence_ls_authenticate' );

		$this->sign_on( $user );

		$this->assertNotEmpty( $this->sent );
		$this->assertNotContains( true, $this->sent );
	}

	// admin-ajax dispatches on the action exactly as sent, so a differently
	// cased one reaches some other handler and must not borrow the exemption.
	public function test_a_differently_cased_action_is_not_a_credential_check(): void {
		$user = $this->enrolled_user();
		$this->with_wordfence_check();
		$this->as_ajax( 'Wordfence_LS_Authenticate' );

		$this->assertWPError( wp_authenticate( $user->user_login, 'password' ) );
	}

	public function test_the_wordfence_check_is_not_trusted_without_wordfence(): void {
		$user = $this->enrolled_user();
		$this->as_ajax( 'wordfence_ls_authenticate' );

		$this->assertWPError( wp_authenticate( $user->user_login, 'password' ) );
	}

	public function test_a_site_can_list_its_own_credential_check(): void {
		$user = $this->enrolled_user();
		add_filter(
			'sigil_credential_check_ajax_actions',
			static function ( array $actions ): array {
				$actions[] = 'my_login_precheck';
				return $actions;
			}
		);
		$this->as_ajax( 'my_login_precheck' );

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, 'password' ) );
	}

	public function test_someone_without_a_second_factor_still_signs_in_over_ajax(): void {
		$user = self::factory()->user->create_and_get( array( 'user_pass' => 'password' ) );
		$this->as_ajax( 'popup_login' );

		$result = $this->sign_on( $user );

		$this->assertInstanceOf( WP_User::class, $result );
		$this->assertSame( array( true ), $this->sent );
	}

	public function test_an_account_registered_in_the_same_request_is_signed_in(): void {
		$this->as_ajax( 'woocommerce_checkout' );
		$user = $this->enrolled_user( true );

		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( true ), $this->sent );
	}

	public function test_cron_is_not_a_password_only_way_in(): void {
		$user = $this->enrolled_user();
		add_filter( 'wp_doing_cron', '__return_true' );

		$this->assertWPError( $this->sign_on( $user ) );

		wp_set_auth_cookie( (int) $user->ID );
		$this->assertNotContains( true, $this->sent );
	}

	public function test_an_ordinary_login_is_left_to_the_challenge(): void {
		$user = $this->enrolled_user();

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, 'password' ) );
	}

	public function test_clearing_cookies_over_ajax_is_never_held(): void {
		$this->enrolled_user();
		$this->as_ajax( 'popup_login' );

		$this->assertTrue( \Sigil\Login_Guard::instance()->hold_cookies( true, 0, 0, 0, '', '' ) );
	}

	public function test_an_ordinary_sign_on_issues_no_session_before_the_challenge(): void {
		$user = $this->enrolled_user();

		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( false ), $this->sent );
		$this->assertSame( array(), WP_Session_Tokens::get_instance( (int) $user->ID )->get_all() );
	}

	public function test_a_completed_challenge_grants_the_session(): void {
		$user  = $this->enrolled_user();
		$codes = ( new \Sigil\Providers\Backup_Codes() )->generate( (int) $user->ID );
		$token = \Sigil\Challenge::start( $user, false );

		wp_set_auth_cookie( (int) $user->ID );
		$this->assertTrue( \Sigil\Challenge::complete( $token, 'backup', array( 'code' => $codes[0] ) ) );
		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( false, true ), $this->sent, 'held before the factor, sent after it' );
	}

	public function test_a_failed_challenge_grants_nothing(): void {
		$user = $this->enrolled_user();
		( new \Sigil\Providers\Backup_Codes() )->generate( (int) $user->ID );
		$token = \Sigil\Challenge::start( $user, false );

		$this->assertWPError( \Sigil\Challenge::complete( $token, 'backup', array( 'code' => 'wrong' ) ) );
		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( false ), $this->sent );
	}

	public function test_a_grant_is_for_that_user_only(): void {
		$granted = $this->enrolled_user();
		$other   = $this->enrolled_user();

		\Sigil\Login_Guard::grant( (int) $granted->ID );
		wp_set_auth_cookie( (int) $other->ID );
		wp_set_auth_cookie( (int) $granted->ID );

		$this->assertSame( array( false, true ), $this->sent );
	}

	private function arrive_with( string $name, string $value ): void {
		$_COOKIE[ $name ] = $value;
		$this->reset_guard( 'session_user', null );
	}

	public function test_someone_already_signed_in_keeps_their_session_when_it_is_reissued(): void {
		$user = $this->enrolled_user();
		$this->arrive_with( AUTH_COOKIE, wp_generate_auth_cookie( (int) $user->ID, time() + HOUR_IN_SECONDS, 'auth' ) );

		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( true ), $this->sent );
	}

	public function test_a_logged_in_cookie_alone_is_not_an_existing_session(): void {
		$user = $this->enrolled_user();
		$this->arrive_with( LOGGED_IN_COOKIE, wp_generate_auth_cookie( (int) $user->ID, time() + HOUR_IN_SECONDS, 'logged_in' ) );

		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( false ), $this->sent );
	}

	public function test_who_wordpress_says_is_signed_in_is_not_an_existing_session(): void {
		$user = $this->enrolled_user();
		$this->reset_guard( 'session_user', null );

		\Sigil\Login_Guard::instance()->note_session_user( (int) $user->ID );
		wp_set_current_user( (int) $user->ID );
		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( false ), $this->sent );
	}

	public function test_a_password_sign_in_never_rides_on_an_existing_session(): void {
		$user = $this->enrolled_user();
		$this->arrive_with( AUTH_COOKIE, wp_generate_auth_cookie( (int) $user->ID, time() + HOUR_IN_SECONDS, 'auth' ) );

		// wp_signon() would go on to render the challenge and exit, so take its
		// two steps by hand.
		wp_authenticate( $user->user_login, 'password' );
		wp_set_auth_cookie( (int) $user->ID );

		$this->assertSame( array( false ), $this->sent );
	}
}
