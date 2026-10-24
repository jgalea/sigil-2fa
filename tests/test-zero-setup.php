<?php

declare( strict_types=1 );

/**
 * Zero-setup coverage: an account's own address as the factor of last resort.
 */
class Test_Zero_Setup extends WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();
		\Sigil\Schema::install();
	}

	public function tear_down(): void {
		delete_option( \Sigil\Zero_Setup::OPTION );
		\Sigil\Network::delete_option( \Sigil\Policy::OPTION_KEY );
		parent::tear_down();
	}

	private function require_2fa(): void {
		\Sigil\Policy::update(
			array(
				'enabled'    => true,
				'roles'      => array( 'subscriber' => true, 'administrator' => true ),
				'grace_days' => 0,
			)
		);
	}

	// The wall a policy meets is users who never set anything up. Their own
	// address is a factor they do not have to configure.
	public function test_an_account_that_set_nothing_up_is_still_covered(): void {
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->require_2fa();

		$this->assertFalse( \Sigil\Providers::instance()->has_usable( $user ), 'nothing is set up' );

		\Sigil\Zero_Setup::set_enabled( true );
		\Sigil\Zero_Setup::instance()->register();

		$this->assertTrue( \Sigil\Providers::instance()->has_usable( $user ) );
		$this->assertFalse( \Sigil\Policy::must_enrol_now( $user ), 'and is therefore not pushed at a wall' );
	}

	// It is a floor, not a preference. Anyone who enrols something stronger is
	// challenged with that instead.
	public function test_a_stronger_method_still_wins(): void {
		$user = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );

		\Sigil\Zero_Setup::set_enabled( true );
		\Sigil\Zero_Setup::instance()->register();

		$preferred = \Sigil\Providers::instance()->preferred_for( $user );
		$this->assertInstanceOf( \Sigil\Provider::class, $preferred );
		$this->assertSame( 'totp', $preferred->id() );
	}

	// An address that cannot receive mail is not a factor, and pretending
	// otherwise locks the account into a login it can never finish.
	public function test_an_account_with_no_address_is_not_covered(): void {
		$user = self::factory()->user->create();
		wp_update_user( array( 'ID' => $user, 'user_email' => '' ) );

		\Sigil\Zero_Setup::set_enabled( true );
		\Sigil\Zero_Setup::instance()->register();

		$this->assertFalse( \Sigil\Providers::instance()->has_usable( $user ) );
	}

	public function test_zero_setup_does_nothing_while_it_is_off(): void {
		$user = self::factory()->user->create();
		\Sigil\Zero_Setup::instance()->register();

		$this->assertFalse( \Sigil\Providers::instance()->has_usable( $user ) );
	}

	// Automatic email is a floor for accounts with nothing, not an extra door on
	// accounts that already hold something stronger.
	public function test_zero_setup_does_not_add_email_to_an_account_with_a_stronger_factor(): void {
		\Sigil\Zero_Setup::set_enabled( true );
		\Sigil\Zero_Setup::instance()->register();

		$bare   = self::factory()->user->create();
		$strong = self::factory()->user->create();
		\Sigil\Store::set_method( $strong, 'totp', array( 'secret' => 'x' ) );

		$ids = static function ( int $id ): array {
			return array_map(
				static function ( \Sigil\Provider $p ): string {
					return $p->id();
				},
				\Sigil\Providers::instance()->enrolled_for( $id )
			);
		};

		$this->assertContains( 'email', $ids( $bare ), 'an account with nothing is covered' );
		$this->assertNotContains( 'email', $ids( $strong ), 'an account with an authenticator is not lowered to its inbox' );
	}

	public function test_zero_setup_still_honours_a_deliberate_email_enrolment(): void {
		\Sigil\Zero_Setup::set_enabled( true );
		\Sigil\Zero_Setup::instance()->register();

		$user = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'email', array( 'enrolled_at' => 1 ) );
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );

		$ids = array_map(
			static function ( \Sigil\Provider $p ): string {
				return $p->id();
			},
			\Sigil\Providers::instance()->enrolled_for( $user )
		);

		$this->assertContains( 'email', $ids, 'chosen email is still email' );
	}

	/**
	 * @group ms-required
	 */
	public function test_the_floor_applies_across_the_network(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'network behaviour' );
		}

		\Sigil\Zero_Setup::set_enabled( true );

		switch_to_blog( self::factory()->blog->create() );
		$enabled = \Sigil\Zero_Setup::is_enabled();
		restore_current_blog();

		$this->assertTrue( $enabled );
	}
}
