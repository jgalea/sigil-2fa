<?php

declare( strict_types=1 );

/**
 * Regressions for the second security review.
 */
class Test_Council_Round_Two extends WP_UnitTestCase {

	private \WP_REST_Server $server;

	public function set_up(): void {
		parent::set_up();

		if ( ! defined( 'SIGIL_PRO' ) || ! SIGIL_PRO ) {
			$this->markTestSkipped( 'pro add-on not installed' );
		}

		\Sigil\Schema::install();
		foreach ( array( 'class-method-policy', 'class-bypass' ) as $f ) {
			require_once SIGIL_DIR . 'pro/' . $f . '.php';
		}

		global $wp_rest_server;
		$wp_rest_server = new \WP_REST_Server();
		$this->server   = $wp_rest_server;
		do_action( 'rest_api_init' );
	}

	public function tear_down(): void {
		delete_option( \Sigil\Pro\Method_Policy::OPTION );
		global $wp_rest_server;
		$wp_rest_server = null;
		parent::tear_down();
	}

	// The worst outcome a policy can have is switching the thing off. Forbidding
	// the only method an account holds must never leave it with no challenge.
	public function test_forbidding_someones_only_method_does_not_disable_their_2fa(): void {
		$user = self::factory()->user->create_and_get( array( 'role' => 'subscriber' ) );
		\Sigil\Store::set_method( $user->ID, 'email', array( 'enrolled_at' => 1 ) );

		\Sigil\Pro\Method_Policy::update(
			array( 'subscriber' => array( 'email' => false, 'totp' => true, 'backup' => true, 'passkey' => true ) )
		);
		\Sigil\Pro\Method_Policy::instance()->register();
		wp_set_current_user( (int) $user->ID );

		$this->assertNotEmpty(
			\Sigil\Providers::instance()->enrolled_for( (int) $user->ID ),
			'the account still has a factor, so the login must still be challenged'
		);
		$this->assertTrue( \Sigil\Providers::instance()->has_usable( (int) $user->ID ) );
	}

	// The rule belongs where a method is chosen.
	public function test_a_forbidden_method_cannot_be_enrolled(): void {
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		\Sigil\Pro\Method_Policy::update( array( 'subscriber' => array( 'email' => false ) ) );
		\Sigil\Pro\Method_Policy::instance()->register();
		wp_set_current_user( $user );

		$result = \Sigil\Enrolment::instance()->complete_method( $user, 'email', array() );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_method_not_allowed', $result->get_error_code() );
	}

	public function test_an_allowed_method_still_enrols(): void {
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		\Sigil\Pro\Method_Policy::update( array( 'subscriber' => array( 'email' => false, 'backup' => true ) ) );
		\Sigil\Pro\Method_Policy::instance()->register();
		wp_set_current_user( $user );

		$this->assertTrue( \Sigil\Enrolment::instance()->complete_method( $user, 'backup', array() ) );
	}

	// The policy used to identify the challenged user from $_REQUEST, which the
	// REST route never populates, so it silently did not apply there at all.
	public function test_the_rest_route_is_not_a_way_around_the_policy(): void {
		$user = self::factory()->user->create_and_get( array( 'role' => 'subscriber' ) );
		\Sigil\Store::set_method( $user->ID, 'email', array( 'enrolled_at' => 1 ) );
		\Sigil\Pro\Method_Policy::update( array( 'subscriber' => array( 'email' => false, 'totp' => true ) ) );
		\Sigil\Pro\Method_Policy::instance()->register();

		$email = new \Sigil\Providers\Email();
		$email->send_code( (int) $user->ID );
		$code = get_user_meta( $user->ID, '_sigil_email_debug_code', true );

		$token = \Sigil\Challenge::start( $user, false, '' );

		$request = new \WP_REST_Request( 'POST', '/sigil/v1/challenge' );
		$request->set_header( 'Content-Type', 'application/json' );
		$request->set_body( wp_json_encode( array( 'token' => $token, 'provider' => 'email', 'code' => $code ) ) );

		// The account holds email, so it may still use it. What matters is that
		// the outcome no longer depends on which route the request arrived by.
		$rest = $this->server->dispatch( $request )->get_status();

		wp_set_current_user( (int) $user->ID );
		$form_can_use = false;
		foreach ( \Sigil\Providers::instance()->enrolled_for( (int) $user->ID ) as $provider ) {
			if ( 'email' === $provider->id() ) {
				$form_can_use = true;
			}
		}

		$this->assertSame( $form_can_use, 200 === $rest, 'both routes must agree' );
	}

	// One excused sign-in has to mean one, and asking whether somebody would be
	// challenged is not a sign-in. sigil_skip_challenge is a documented
	// extension point, so a grant spent by the question would leave the person
	// it was granted to still locked out.
	public function test_an_excused_sign_in_is_spent_by_the_sign_in_only(): void {
		$actor = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $actor );
		}
		$user   = self::factory()->user->create_and_get();
		$bypass = \Sigil\Pro\Bypass::instance();

		\Sigil\Pro\Bypass::grant_for( (int) $user->ID, $actor );
		$bypass->register();

		$this->assertTrue( $bypass->maybe_skip( false, $user ), 'the excuse is live' );
		$this->assertTrue( $bypass->maybe_skip( false, $user ), 'and asking again does not spend it' );

		$bypass->spend( $user->user_login, $user );

		$this->assertFalse( $bypass->maybe_skip( false, $user ), 'the sign-in spends it' );

		// A second sign-in on the same grant, and a spend with nothing to spend.
		$bypass->spend( $user->user_login, $user );
		$this->assertFalse( $bypass->maybe_skip( false, $user ) );
	}

	// Two sign-ins arriving together must not both be excused.
	public function test_two_simultaneous_sign_ins_spend_one_excuse(): void {
		$actor = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $actor );
		}
		$user   = self::factory()->user->create_and_get();
		$bypass = \Sigil\Pro\Bypass::instance();

		\Sigil\Pro\Bypass::grant_for( (int) $user->ID, $actor );
		$bypass->register();

		$grant = get_user_meta( (int) $user->ID, '_sigil_pro_bypass', true );

		// Both requests hold the same grant they read a moment ago.
		$bypass->spend( $user->user_login, $user );
		$this->assertFalse( delete_user_meta( (int) $user->ID, '_sigil_pro_bypass', $grant ), 'the second delete takes nothing' );
		$this->assertFalse( $bypass->maybe_skip( false, $user ) );
	}
}
