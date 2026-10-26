<?php

declare( strict_types=1 );

/**
 * Being handed the wrong method first is a small tax paid on every sign-in.
 */
class Test_Preference extends WP_UnitTestCase {

	use Signed_In;

	public function set_up(): void {
		parent::set_up();
		\Sigil\Schema::install();
	}

	private function with_two_methods(): int {
		$user = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );
		\Sigil\Store::set_method( $user, 'email', array( 'enrolled_at' => 1 ) );

		return (int) $user;
	}

	public function test_without_a_choice_the_plugin_ordering_stands(): void {
		$user      = $this->with_two_methods();
		$preferred = \Sigil\Providers::instance()->preferred_for( $user );

		$this->assertInstanceOf( \Sigil\Provider::class, $preferred );
		$this->assertSame( 'totp', $preferred->id(), 'authenticator outranks email' );
	}

	public function test_a_users_own_choice_wins(): void {
		$user = $this->with_two_methods();

		$this->assertTrue( \Sigil\Providers::set_preference( $user, 'email' ) );
		$this->assertSame( 'email', \Sigil\Providers::instance()->preferred_for( $user )->id() );
	}

	public function test_you_cannot_prefer_something_you_have_not_set_up(): void {
		$user = $this->with_two_methods();

		$this->assertWPError( \Sigil\Providers::set_preference( $user, 'passkey' ) );
		$this->assertSame( '', \Sigil\Providers::preference( $user ) );
	}

	// A preference naming a method that is gone must fall back rather than offer
	// something the account cannot use.
	public function test_a_stale_choice_falls_back(): void {
		$user = $this->with_two_methods();
		\Sigil\Providers::set_preference( $user, 'email' );

		\Sigil\Store::remove_method( $user, 'email' );

		$this->assertSame( 'totp', \Sigil\Providers::instance()->preferred_for( $user )->id() );
	}

	public function test_removing_the_preferred_method_clears_the_choice(): void {
		$user = $this->with_two_methods();
		\Sigil\Providers::set_preference( $user, 'email' );

		$this->sign_in( $user );
		\Sigil\Enrolment::instance()->remove_method( $user, 'email' );

		$this->assertSame( '', \Sigil\Providers::preference( $user ) );
	}

	public function test_clearing_the_choice_is_allowed(): void {
		$user = $this->with_two_methods();
		\Sigil\Providers::set_preference( $user, 'email' );

		$this->assertTrue( \Sigil\Providers::set_preference( $user, '' ) );
		$this->assertSame( 'totp', \Sigil\Providers::instance()->preferred_for( $user )->id() );
	}
}
