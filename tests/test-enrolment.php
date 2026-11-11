<?php

declare( strict_types=1 );

class Test_Enrolment extends WP_UnitTestCase {
	public function test_first_method_forces_backup_code_generation(): void {
		$uid = self::factory()->user->create();
		wp_set_current_user( $uid );
		\Sigil\Enrolment::instance()->complete_method( $uid, 'totp', [ 'secret' => 'x' ] );
		$this->assertArrayHasKey( 'backup', \Sigil\Store::methods( $uid ) );
	}

	public function test_cannot_remove_last_method_while_required(): void {
		\Sigil\Policy::update( [ 'enabled' => true, 'roles' => [ 'administrator' => true ] ] );
		$uid = self::factory()->user->create( [ 'role' => 'administrator' ] );
		wp_set_current_user( $uid );
		\Sigil\Store::set_method( $uid, 'totp', [ 'secret' => 'x' ] );
		$this->assertWPError( \Sigil\Enrolment::instance()->remove_method( $uid, 'totp' ) );
	}

	public function test_user_cannot_edit_another_users_methods(): void {
		$a = self::factory()->user->create( [ 'role' => 'editor' ] );
		$b = self::factory()->user->create( [ 'role' => 'editor' ] );
		wp_set_current_user( $a );
		$this->assertWPError( \Sigil\Enrolment::instance()->remove_method( $b, 'totp' ) );
	}

	// sigil_msg used to be read from the URL, so a crafted link could print its
	// own wording inside a genuine 2FA screen.
	public function test_notice_wording_is_not_taken_from_the_url(): void {
		wp_set_current_user( self::factory()->user->create() );
		$_GET = array( 'sigil_status' => 'error', 'sigil_code' => 'x', 'sigil_msg' => 'Call 555-0100 to verify your account.' );

		$method = new ReflectionMethod( \Sigil\Enrolment::instance(), 'consume_notices' );
		$method->setAccessible( true );
		$notices = $method->invoke( \Sigil\Enrolment::instance() );
		$_GET    = array();

		$this->assertSame( '', $notices['message'] );
	}

	public function test_the_failure_reason_arrives_through_the_users_own_transient(): void {
		$uid = self::factory()->user->create();
		wp_set_current_user( $uid );
		set_transient( 'sigil_msg_' . $uid, 'That code was wrong.', 60 );
		$_GET = array( 'sigil_status' => 'error' );

		$method = new ReflectionMethod( \Sigil\Enrolment::instance(), 'consume_notices' );
		$method->setAccessible( true );
		$first  = $method->invoke( \Sigil\Enrolment::instance() );
		$second = $method->invoke( \Sigil\Enrolment::instance() );
		$_GET   = array();

		$this->assertSame( 'That code was wrong.', $first['message'] );
		$this->assertSame( '', $second['message'], 'shown once' );
	}
}
