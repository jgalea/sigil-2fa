<?php

declare( strict_types=1 );

/**
 * An administrator turning enforcement on for a role they hold, before they have
 * a second factor of their own, is the first person the policy locks out.
 */
class Test_Lockout_Guard extends WP_UnitTestCase {

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
		\Sigil\Network::delete_option( \Sigil\Policy::OPTION_KEY );
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

	private function enrol( int $user_id ): void {
		\Sigil\Store::set_method( $user_id, 'totp', array( 'secret' => 'x' ) );
	}

	/**
	 * @param array<string, mixed> $body
	 */
	private function post_policy( array $body ): \WP_REST_Response {
		$request = new \WP_REST_Request( 'POST', '/sigil/v1/policy' );
		foreach ( $body as $key => $value ) {
			$request->set_param( $key, $value );
		}

		return $this->server->dispatch( $request );
	}

	/**
	 * Run an admin-post handler and return where it sent the browser.
	 *
	 * @param array<string, mixed> $post
	 */
	private function submit( callable $handler, string $nonce_action, array $post ): string {
		$_POST                = $post;
		$_REQUEST             = $post;
		$_REQUEST['_wpnonce'] = wp_create_nonce( $nonce_action );

		add_filter(
			'wp_redirect',
			static function ( $location ) {
				throw new \RuntimeException( (string) $location );
			}
		);

		try {
			$handler();
		} catch ( \RuntimeException $e ) {
			return $e->getMessage();
		}

		$this->fail( 'the handler did not redirect' );
	}

	/**
	 * @return array<string, mixed>
	 */
	private function enforce_admins(): array {
		return array(
			'enabled' => true,
			'roles'   => array( 'administrator' => true ),
		);
	}

	public function test_enforcing_your_own_role_without_a_method_is_a_lockout(): void {
		$admin = $this->admin();

		$this->assertTrue( \Sigil\Policy::would_lock_out( $admin, $this->enforce_admins() ) );
	}

	public function test_it_is_fine_once_you_have_a_method(): void {
		$admin = $this->admin();
		$this->enrol( $admin );

		$this->assertFalse( \Sigil\Policy::would_lock_out( $admin, $this->enforce_admins() ) );
	}

	public function test_enforcing_a_role_you_do_not_hold_is_fine(): void {
		$admin = $this->admin();

		$this->assertFalse(
			\Sigil\Policy::would_lock_out( $admin, array( 'enabled' => true, 'roles' => array( 'subscriber' => true ) ) )
		);
	}

	public function test_a_capability_you_hold_counts_like_a_role(): void {
		$admin = $this->admin();

		$this->assertTrue(
			\Sigil\Policy::would_lock_out( $admin, array( 'enabled' => true, 'min_capability' => 'manage_options' ) )
		);
	}

	public function test_a_policy_that_is_switched_off_locks_nobody_out(): void {
		$admin = $this->admin();

		$this->assertFalse(
			\Sigil\Policy::would_lock_out( $admin, array( 'enabled' => false, 'roles' => array( 'administrator' => true ) ) )
		);
	}

	// An unrelated save on a policy that already covered the administrator is not
	// a new lockout, and refusing it would make every setting unsaveable.
	public function test_a_save_that_changes_nothing_for_you_is_allowed(): void {
		$admin = $this->admin();
		\Sigil\Policy::update( $this->enforce_admins() );

		$this->assertFalse( \Sigil\Policy::would_lock_out( $admin, array( 'grace_days' => 30 ) ) );
	}

	// The command line has no current user and is how an operator recovers a
	// site, so the guard lives on the screens, not on Policy::update().
	public function test_the_command_line_is_not_guarded(): void {
		wp_set_current_user( 0 );

		\Sigil\Policy::update( $this->enforce_admins() );

		$this->assertTrue( \Sigil\Policy::get()['roles']['administrator'] );
		$this->assertFalse( \Sigil\Policy::would_lock_out( 0, $this->enforce_admins() ) );
	}

	public function test_the_rest_route_refuses_and_stores_nothing(): void {
		wp_set_current_user( $this->admin() );

		$response = $this->post_policy( $this->enforce_admins() );

		$this->assertSame( 409, $response->get_status() );
		$this->assertSame( 'sigil_lockout', $response->get_data()['code'] );
		$this->assertFalse( \Sigil\Policy::get()['enabled'] );
	}

	public function test_the_rest_route_accepts_it_after_enrolment(): void {
		$admin = $this->admin();
		$this->enrol( $admin );
		wp_set_current_user( $admin );

		$this->assertSame( 200, $this->post_policy( $this->enforce_admins() )->get_status() );
		$this->assertTrue( \Sigil\Policy::get()['roles']['administrator'] );
	}

	public function test_the_rest_route_lets_you_require_other_roles(): void {
		wp_set_current_user( $this->admin() );

		$response = $this->post_policy( array( 'enabled' => true, 'roles' => array( 'subscriber' => true ) ) );

		$this->assertSame( 200, $response->get_status() );
	}

	public function test_the_settings_screen_refuses_and_stores_nothing(): void {
		wp_set_current_user( $this->admin() );

		$location = $this->submit(
			array( \Sigil\Settings::instance(), 'handle_save' ),
			'sigil_save_settings',
			array(
				'sigil_policy' => array(
					'enabled' => '1',
					'roles'   => array( 'administrator' => '1' ),
				),
			)
		);

		$this->assertStringContainsString( 'lockout=1', $location );
		$this->assertFalse( \Sigil\Policy::get()['enabled'] );
	}

	public function test_the_settings_screen_saves_once_you_have_a_method(): void {
		$admin = $this->admin();
		$this->enrol( $admin );
		wp_set_current_user( $admin );

		$location = $this->submit(
			array( \Sigil\Settings::instance(), 'handle_save' ),
			'sigil_save_settings',
			array(
				'sigil_policy' => array(
					'enabled' => '1',
					'roles'   => array( 'administrator' => '1' ),
				),
			)
		);

		$this->assertStringContainsString( 'updated=1', $location );
		$this->assertTrue( \Sigil\Policy::get()['roles']['administrator'] );
	}
}
