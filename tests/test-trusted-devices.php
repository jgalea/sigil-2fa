<?php

declare( strict_types=1 );

/**
 * Security properties of the trusted-device bearer token.
 */
class Test_Trusted_Devices extends WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();
		// The singleton registers hooks in its constructor (once per request in
		// production). WP_UnitTestCase restores $wp_filter each tearDown, so
		// re-add them for deterministic isolation.
		\Sigil\Trusted_Devices::instance()->register();
	}

	private function td(): \Sigil\Trusted_Devices {
		return \Sigil\Trusted_Devices::instance();
	}

	public function test_valid_token_is_trusted(): void {
		$uid   = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $uid );
		$this->assertTrue( $this->td()->is_trusted( $uid, $token ) );
	}

	public function test_wrong_token_is_not_trusted(): void {
		$uid = self::factory()->user->create();
		$this->td()->trust_current_device( $uid );
		$this->assertFalse( $this->td()->is_trusted( $uid, str_repeat( 'a', 64 ) ) );
	}

	public function test_malformed_token_is_rejected(): void {
		$uid   = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $uid );
		$this->assertFalse( $this->td()->is_trusted( $uid, 'not-hex' ) );
		$this->assertFalse( $this->td()->is_trusted( $uid, substr( $token, 0, 10 ) ) );
		$this->assertFalse( $this->td()->is_trusted( $uid, '' ) );
	}

	public function test_token_is_bound_to_its_user(): void {
		$a     = self::factory()->user->create();
		$b     = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $a );
		$this->assertFalse( $this->td()->is_trusted( $b, $token ) );
	}

	public function test_raw_token_is_never_stored(): void {
		$uid   = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $uid );
		$raw   = wp_json_encode( get_user_meta( $uid, '_sigil_pro_trusted', true ) );
		$this->assertStringNotContainsString( $token, (string) $raw );
	}

	public function test_expired_token_is_rejected(): void {
		$uid   = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $uid );
		$devices = get_user_meta( $uid, '_sigil_pro_trusted', true );
		$devices[0]['expires'] = time() - 1;
		update_user_meta( $uid, '_sigil_pro_trusted', $devices );
		$this->assertFalse( $this->td()->is_trusted( $uid, $token ) );
	}

	public function test_revoke_all_invalidates_token(): void {
		$uid   = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $uid );
		$this->td()->revoke_all( $uid );
		$this->assertFalse( $this->td()->is_trusted( $uid, $token ) );
	}

	public function test_methods_changed_revokes_trust(): void {
		$uid   = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $uid );
		do_action( 'sigil_methods_changed', $uid );
		$this->assertFalse( $this->td()->is_trusted( $uid, $token ) );
	}

	public function test_skip_filter_defaults_to_challenge_without_cookie(): void {
		$uid = self::factory()->user->create();
		unset( $_COOKIE['sigil_pro_trusted'] );
		$this->assertFalse( (bool) apply_filters( 'sigil_skip_challenge', false, get_user_by( 'id', $uid ) ) );
	}

	/**
	 * Whoever reads the inbox can request a reset link. Without a second factor
	 * on that form, 2FA guards the front door and leaves the window open.
	 *
	 * @param array<string, string> $post
	 */
	// A trusted device is a standing permission to skip the second step, and a
	// new password is what somebody does when they think another person has
	// been in the account.
	public function test_changing_the_password_revokes_trusted_devices(): void {
		$user   = self::factory()->user->create( array( 'user_pass' => 'first-password' ) );
		$device = \Sigil\Trusted_Devices::instance();
		$token  = $device->trust_current_device( $user );

		$this->assertTrue( $device->is_trusted( $user, $token ), 'the device is trusted to begin with' );

		wp_update_user(
			array(
				'ID'        => $user,
				'user_pass' => 'second-password',
			)
		);

		$this->assertFalse( $device->is_trusted( $user, $token ) );
	}

	public function test_an_unrelated_profile_edit_leaves_trust_alone(): void {
		$user   = self::factory()->user->create( array( 'user_pass' => 'first-password' ) );
		$device = \Sigil\Trusted_Devices::instance();
		$token  = $device->trust_current_device( $user );

		wp_update_user(
			array(
				'ID'         => $user,
				'first_name' => 'Renamed',
			)
		);

		$this->assertTrue( $device->is_trusted( $user, $token ), 'changing a name is not a credential change' );
	}

	// Membership, single sign-on and password-expiry plugins set a password
	// directly rather than going through the profile or the reset form.
	public function test_setting_a_password_directly_revokes_trusted_devices(): void {
		$user   = self::factory()->user->create( array( 'user_pass' => 'first-password' ) );
		$device = \Sigil\Trusted_Devices::instance();
		$token  = $device->trust_current_device( $user );

		wp_set_password( 'second-password', $user );

		$this->assertFalse( $device->is_trusted( $user, $token ) );
	}

	// Core sets the password again, unchanged, when a stored hash needs
	// rehashing at login. Treating that as a credential change would revoke
	// every device on the site as people signed in after a hashing change.
	public function test_a_rehash_of_the_same_password_keeps_trust(): void {
		$user   = self::factory()->user->create( array( 'user_pass' => 'first-password' ) );
		$device = \Sigil\Trusted_Devices::instance();
		$token  = $device->trust_current_device( $user );

		$before = get_userdata( $user );
		$device->revoke_on_set_password( 'first-password', $user, $before );

		$this->assertTrue( $device->is_trusted( $user, $token ) );
	}

	public function test_a_password_reset_revokes_trusted_devices(): void {
		$user   = self::factory()->user->create_and_get( array( 'user_pass' => 'first-password' ) );
		$device = \Sigil\Trusted_Devices::instance();
		$token  = $device->trust_current_device( (int) $user->ID );

		reset_password( $user, 'third-password' );

		$this->assertFalse( $device->is_trusted( (int) $user->ID, $token ) );
	}

	public function test_the_owner_can_forget_every_trusted_device(): void {
		$uid   = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $uid );
		wp_set_current_user( $uid );

		$_POST = array(
			'user_id'  => (string) $uid,
			'_wpnonce' => wp_create_nonce( 'sigil_forget_devices_' . $uid ),
		);
		$_REQUEST = $_POST;
		$this->assertTrue( $this->post_and_catch_redirect( 'sigil_forget_devices' ) );

		$this->assertFalse( $this->td()->is_trusted( $uid, $token ) );
	}

	public function test_nobody_else_can_forget_them(): void {
		$uid   = self::factory()->user->create();
		$token = $this->td()->trust_current_device( $uid );
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $admin );
		}
		wp_set_current_user( $admin );

		$_POST = array(
			'user_id'  => (string) $uid,
			'_wpnonce' => wp_create_nonce( 'sigil_forget_devices_' . $uid ),
		);
		$_REQUEST = $_POST;
		try {
			$this->post_and_catch_redirect( 'sigil_forget_devices' );
		} catch ( WPDieException $e ) {
			unset( $e );
		}

		$this->assertTrue( $this->td()->is_trusted( $uid, $token ) );
	}

	public function test_the_enrolment_screen_offers_it_only_on_your_own_account(): void {
		$uid = self::factory()->user->create();
		$this->td()->trust_current_device( $uid );

		wp_set_current_user( $uid );
		ob_start();
		\Sigil\Enrolment::instance()->render_enrol_ui( $uid, false );
		$this->assertStringContainsString( 'value="sigil_forget_devices"', (string) ob_get_clean() );

		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $admin );
		}
		wp_set_current_user( $admin );
		ob_start();
		\Sigil\Enrolment::instance()->render_enrol_ui( $uid, false );
		$this->assertStringNotContainsString( 'value="sigil_forget_devices"', (string) ob_get_clean() );
	}

	/**
	 * Run an admin-post handler up to its redirect, which would otherwise exit.
	 */
	private function post_and_catch_redirect( string $action ): bool {
		$stop = static function () {
			throw new RuntimeException( 'redirected' );
		};
		add_filter( 'sigil_enrol_redirect', $stop );

		try {
			do_action( 'admin_post_' . $action );
		} catch ( RuntimeException $e ) {
			return 'redirected' === $e->getMessage();
		} finally {
			remove_filter( 'sigil_enrol_redirect', $stop );
			$_POST    = array();
			$_REQUEST = array();
		}

		return false;
	}
}
