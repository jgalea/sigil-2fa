<?php

declare( strict_types=1 );

class Test_REST extends WP_UnitTestCase {

	private \WP_REST_Server $server;

	public function set_up(): void {
		parent::set_up();
		\Sigil\Schema::install();

		global $wp_rest_server;
		$wp_rest_server = new \WP_REST_Server();
		$this->server   = $wp_rest_server;
		do_action( 'rest_api_init' );
	}

	public function tear_down(): void {
		global $wp_rest_server;
		$wp_rest_server = null;
		parent::tear_down();
	}

	/**
	 * @param array<string, mixed> $body
	 */
	private function request( string $method, string $route, array $body = array() ): \WP_REST_Response {
		$request = new \WP_REST_Request( $method, $route );
		foreach ( $body as $key => $value ) {
			$request->set_param( $key, $value );
		}

		return $this->server->dispatch( $request );
	}

	private function user_manager(): int {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		return $id;
	}

	public function test_me_requires_a_logged_in_user(): void {
		$response = $this->request( 'GET', '/sigil/v1/me' );
		$this->assertSame( 401, $response->get_status() );
	}

	public function test_me_reports_enrolled_methods(): void {
		$uid = self::factory()->user->create();
		wp_set_current_user( $uid );
		\Sigil\Store::set_method( $uid, 'totp', array( 'secret' => 'x', 'enrolled_at' => 123 ) );

		$data = $this->request( 'GET', '/sigil/v1/me' )->get_data();

		$this->assertTrue( $data['enrolled'] );
		$this->assertSame( 'totp', $data['methods'][0]['id'] );
		$this->assertSame( 123, $data['methods'][0]['enrolled_at'] );
		$this->assertNotEmpty( $data['available'] );
	}

	public function test_reading_another_user_needs_list_users(): void {
		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$other      = self::factory()->user->create();

		wp_set_current_user( $subscriber );
		$this->assertSame( 403, $this->request( 'GET', "/sigil/v1/users/{$other}" )->get_status() );

		wp_set_current_user( $this->user_manager() );
		$this->assertSame( 200, $this->request( 'GET', "/sigil/v1/users/{$other}" )->get_status() );
	}

	public function test_unknown_user_is_a_404(): void {
		wp_set_current_user( $this->user_manager() );
		$this->assertSame( 404, $this->request( 'GET', '/sigil/v1/users/999999' )->get_status() );
	}

	public function test_reset_clears_every_method(): void {
		$user = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );
		\Sigil\Credentials::add( $user, 'cred-rest', 'pk', 0, 'Key', 'internal' );

		wp_set_current_user( $this->user_manager() );
		$response = $this->request( 'DELETE', "/sigil/v1/users/{$user}/methods" );

		$this->assertSame( 200, $response->get_status() );
		$this->assertFalse( $response->get_data()['enrolled'] );
		$this->assertFalse( \Sigil\Store::has_any( $user ) );
		$this->assertSame( array(), \Sigil\Credentials::for_user( $user ) );
	}

	// The route must not become a way around the capability check that guards
	// the admin screen doing the same thing.
	public function test_reset_is_refused_without_the_capability(): void {
		$actor = self::factory()->user->create( array( 'role' => 'editor' ) );
		$user  = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );

		wp_set_current_user( $actor );
		$this->assertSame( 403, $this->request( 'DELETE', "/sigil/v1/users/{$user}/methods" )->get_status() );
		$this->assertTrue( \Sigil\Store::has_any( $user ) );
	}

	// A logged-out request must not be able to strip anyone's second factor.
	// Recovery treats actor 0 as the unattended CLI context, so the route has to
	// refuse before that convention is ever reached.
	public function test_a_logged_out_request_cannot_reset_anyone(): void {
		$user = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );
		\Sigil\Credentials::add( $user, 'cred-anon', 'pk', 0, 'Key', 'internal' );

		wp_set_current_user( 0 );
		$response = $this->request( 'DELETE', "/sigil/v1/users/{$user}/methods" );

		$this->assertSame( 401, $response->get_status() );
		$this->assertTrue( \Sigil\Store::has_any( $user ) );
		$this->assertNotSame( array(), \Sigil\Credentials::for_user( $user ) );
	}

	public function test_a_logged_out_request_cannot_remove_a_method(): void {
		$user = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );

		wp_set_current_user( 0 );
		$response = $this->request( 'DELETE', "/sigil/v1/users/{$user}/methods/totp" );

		$this->assertSame( 401, $response->get_status() );
		$this->assertTrue( \Sigil\Store::has_any( $user ) );
	}

	public function test_removing_one_method_leaves_the_others(): void {
		$user = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );
		\Sigil\Store::set_method( $user, 'email', array( 'enrolled_at' => 1 ) );

		wp_set_current_user( $user );
		$response = $this->request( 'DELETE', "/sigil/v1/users/{$user}/methods/totp" );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( array( 'email' ), array_column( $response->get_data()['methods'], 'id' ) );
	}

	public function test_policy_needs_the_settings_capability(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );
		$this->assertSame( 403, $this->request( 'GET', '/sigil/v1/policy' )->get_status() );

		wp_set_current_user( $this->user_manager() );
		$this->assertSame( 200, $this->request( 'GET', '/sigil/v1/policy' )->get_status() );
	}

	public function test_policy_can_be_updated(): void {
		$admin = $this->user_manager();
		\Sigil\Store::set_method( $admin, 'totp', array( 'secret' => 'x' ) );
		wp_set_current_user( $admin );

		$response = $this->request(
			'POST',
			'/sigil/v1/policy',
			array(
				'enabled'    => true,
				'grace_days' => 2,
				'roles'      => array( 'administrator' => true ),
			)
		);

		$this->assertSame( 200, $response->get_status() );
		$this->assertTrue( $response->get_data()['enabled'] );
		$this->assertSame( 2, $response->get_data()['grace_days'] );
		$this->assertTrue( \Sigil\Policy::get()['roles']['administrator'] );
	}

	public function test_challenge_rejects_a_bad_token(): void {
		$this->assertSame( 401, $this->request( 'GET', '/sigil/v1/challenge', array( 'token' => 'nope' ) )->get_status() );
	}

	public function test_challenge_describes_the_pending_login(): void {
		$user = self::factory()->user->create_and_get();
		\Sigil\Store::set_method( $user->ID, 'totp', array( 'secret' => 'x' ) );
		$token = \Sigil\Challenge::start( $user, false, '' );

		$data = $this->request( 'GET', '/sigil/v1/challenge', array( 'token' => $token ) )->get_data();

		$this->assertSame( $user->ID, $data['user_id'] );
		$this->assertSame( 'totp', $data['active'] );
		$this->assertNull( $data['passkey_options'] );
	}

	// Each mint occupies a slot in the user's open passkey challenges, so simply
	// describing the login must not evict the challenge a waiting tab holds.
	public function test_describing_a_login_does_not_mint_passkey_options_unasked(): void {
		if ( PHP_VERSION_ID < 80000 ) {
			$this->markTestSkipped( 'passkeys need PHP 8.0, so they cannot be the active method here' );
		}

		$user = self::factory()->user->create_and_get();
		\Sigil\Store::set_method( $user->ID, 'totp', array( 'secret' => 'x' ) );
		\Sigil\Store::set_method( $user->ID, 'passkey', array( 'enrolled_at' => 1 ) );
		\Sigil\Credentials::add( $user->ID, 'cred-describe', 'pk', 0, 'Key', 'internal' );
		$token = \Sigil\Challenge::start( $user, false, '' );

		$plain = $this->request( 'GET', '/sigil/v1/challenge', array( 'token' => $token ) )->get_data();
		$asked = $this->request(
			'GET',
			'/sigil/v1/challenge',
			array( 'token' => $token, 'provider' => 'passkey' )
		)->get_data();

		// Passkey outranks TOTP, so it is the active method and options come with it.
		$this->assertSame( 'passkey', $plain['active'] );
		$this->assertNotNull( $asked['passkey_options'] );
	}

	public function test_options_are_withheld_when_passkey_is_not_in_play(): void {
		$user = self::factory()->user->create_and_get();
		\Sigil\Store::set_method( $user->ID, 'totp', array( 'secret' => 'x' ) );
		$token = \Sigil\Challenge::start( $user, false, '' );

		$data = $this->request( 'GET', '/sigil/v1/challenge', array( 'token' => $token ) )->get_data();

		$this->assertSame( 'totp', $data['active'] );
		$this->assertNull( $data['passkey_options'] );
	}

	public function test_a_wrong_code_does_not_log_anyone_in(): void {
		$user = self::factory()->user->create_and_get();
		\Sigil\Store::set_method( $user->ID, 'email', array( 'enrolled_at' => 1 ) );
		$token = \Sigil\Challenge::start( $user, false, '' );

		$response = $this->request(
			'POST',
			'/sigil/v1/challenge',
			array(
				'token'    => $token,
				'provider' => 'email',
				'code'     => '000000',
			)
		);

		$this->assertSame( 401, $response->get_status() );
	}

	public function test_a_correct_code_completes_the_login(): void {
		$user = self::factory()->user->create_and_get();
		$email = new \Sigil\Providers\Email();
		\Sigil\Store::set_method( $user->ID, 'email', array( 'enrolled_at' => 1 ) );
		$email->send_code( $user->ID );
		$code = get_user_meta( $user->ID, '_sigil_email_debug_code', true );

		$token    = \Sigil\Challenge::start( $user, false, '' );
		$response = $this->request(
			'POST',
			'/sigil/v1/challenge',
			array(
				'token'    => $token,
				'provider' => 'email',
				'code'     => $code,
			)
		);

		$this->assertSame( 200, $response->get_status() );
		$this->assertTrue( $response->get_data()['success'] );
		$this->assertSame( $user->ID, $response->get_data()['user_id'] );

		// The token is single use: replaying it must not mint a second session.
		$replay = $this->request(
			'POST',
			'/sigil/v1/challenge',
			array(
				'token'    => $token,
				'provider' => 'email',
				'code'     => $code,
			)
		);
		$this->assertSame( 401, $replay->get_status() );
	}
}
