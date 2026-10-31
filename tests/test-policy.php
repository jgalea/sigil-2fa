<?php

declare( strict_types=1 );

class Test_Policy extends WP_UnitTestCase {
	public function test_disabled_policy_requires_nobody(): void {
		\Sigil\Policy::update( [ 'enabled' => false, 'roles' => [ 'administrator' => true ] ] );
		$uid = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$this->assertFalse( \Sigil\Policy::required_for( $uid ) );
	}

	public function test_role_targeting(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'roles' => [ 'administrator' => true ], 'grace_days' => 7 ] );
		$admin = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$sub   = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$this->assertTrue( \Sigil\Policy::required_for( $admin ) );
		$this->assertFalse( \Sigil\Policy::required_for( $sub ) );
	}

	public function test_deadline_is_stamped_once_and_is_stable(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'roles' => [ 'administrator' => true ], 'grace_days' => 7 ] );
		$uid   = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$first = \Sigil\Policy::deadline_for( $uid );
		$this->assertSame( $first, \Sigil\Policy::deadline_for( $uid ) );
		$this->assertGreaterThan( time(), $first );
	}

	public function test_grace_zero_requires_immediately(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'roles' => [ 'administrator' => true ], 'grace_days' => 0 ] );
		$uid = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$this->assertTrue( \Sigil\Policy::must_enrol_now( $uid ) );
	}

	public function test_enrolled_user_never_forced(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'roles' => [ 'administrator' => true ], 'grace_days' => 0 ] );
		$uid = self::factory()->user->create( [ 'role' => 'administrator' ] );
		\Sigil\Store::set_method( $uid, 'totp', [ 'secret' => 'x' ] );
		$this->assertFalse( \Sigil\Policy::must_enrol_now( $uid ) );
	}

	public function test_multi_role_user_matches_any_targeted_role(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'roles' => [ 'editor' => true ], 'grace_days' => 7 ] );
		$uid  = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$user = get_user_by( 'id', $uid );
		$user->add_role( 'editor' );
		$this->assertTrue( \Sigil\Policy::required_for( $uid ) );
	}

	public function test_enforce_all_defaults_to_off(): void {
		$this->assertFalse( \Sigil\Policy::get()['enforce_all'] );
	}

	public function test_enforce_all_covers_a_role_that_is_not_listed(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'enforce_all' => true, 'roles' => [ 'administrator' => true ] ] );
		$uid = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$this->assertTrue( \Sigil\Policy::required_for( $uid ) );
	}

	public function test_enforce_all_covers_a_role_added_later(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'enforce_all' => true ] );
		add_role( 'sigil_late_role', 'Late role' );
		$uid = self::factory()->user->create( [ 'role' => 'sigil_late_role' ] );
		$this->assertTrue( \Sigil\Policy::required_for( $uid ) );
		remove_role( 'sigil_late_role' );
	}

	public function test_enforce_all_covers_a_user_with_no_role(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'enforce_all' => true ] );
		$uid  = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$user = get_user_by( 'id', $uid );
		$user->set_role( '' );
		$this->assertSame( [], $user->roles );
		$this->assertTrue( \Sigil\Policy::required_for( $uid ) );
	}

	public function test_enforce_all_covers_a_user_with_several_roles(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'enforce_all' => true ] );
		$uid  = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$user = get_user_by( 'id', $uid );
		$user->add_role( 'contributor' );
		$this->assertTrue( \Sigil\Policy::required_for( $uid ) );
	}

	public function test_enforce_all_off_keeps_the_per_role_behaviour(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'enforce_all' => false, 'roles' => [ 'administrator' => true ] ] );
		$admin = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$sub   = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$none  = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		get_user_by( 'id', $none )->set_role( '' );
		$this->assertTrue( \Sigil\Policy::required_for( $admin ) );
		$this->assertFalse( \Sigil\Policy::required_for( $sub ) );
		$this->assertFalse( \Sigil\Policy::required_for( $none ) );
	}

	public function test_enforce_all_does_nothing_while_enforcement_is_off(): void {
		\Sigil\Policy::update( [ 'enabled' => false, 'enforce_all' => true ] );
		$uid = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$this->assertFalse( \Sigil\Policy::required_for( $uid ) );
	}

	public function test_enforce_all_drives_the_grace_deadline(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'enforce_all' => true, 'grace_days' => 0 ] );
		$uid = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$this->assertNotNull( \Sigil\Policy::deadline_for( $uid ) );
		$this->assertTrue( \Sigil\Policy::must_enrol_now( $uid ) );
	}
}
