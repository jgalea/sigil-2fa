<?php

declare( strict_types=1 );

use Sigil\Credentials;
use Sigil\Enrolment;
use Sigil\Step_Up;
use Sigil\Store;

/**
 * Each passkey is listed by name and can go on its own. Without that, the only
 * way to drop a lost laptop's passkey was to drop every passkey.
 */
class Test_Passkey_Removal extends WP_UnitTestCase {

	use Signed_In;

	private const PASS = 'correct horse battery';

	public function set_up(): void {
		parent::set_up();
		\Sigil\Schema::install();
	}

	private function owner_with_passkeys( int $count ): array {
		$user = (int) self::factory()->user->create(
			array(
				'role'      => 'subscriber',
				'user_pass' => self::PASS,
			)
		);
		$this->sign_in( $user );

		$ids = array();
		for ( $i = 1; $i <= $count; $i++ ) {
			$ids[] = Credentials::add( $user, 'cred-' . $user . '-' . $i, 'pk', 0, 'Device ' . $i, 'internal' );
		}
		Store::set_method( $user, 'passkey', array( 'enrolled_at' => time() ) );
		Enrolment::instance()->ensure_backup_codes( $user );

		return array( $user, $ids );
	}

	private function screen( int $user ): string {
		ob_start();
		Enrolment::instance()->render_enrol_ui( $user, true );

		return (string) ob_get_clean();
	}

	public function test_removing_one_passkey_keeps_the_others(): void {
		list( $user, $ids ) = $this->owner_with_passkeys( 2 );
		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );

		$this->assertTrue( Enrolment::instance()->remove_passkey( $user, $ids[0] ) );

		$left = array_map( 'intval', wp_list_pluck( Credentials::for_user( $user ), 'id' ) );
		$this->assertSame( array( $ids[1] ), $left );
		$this->assertArrayHasKey( 'passkey', Store::methods( $user ) );
	}

	public function test_removing_the_last_passkey_turns_the_method_off(): void {
		list( $user, $ids ) = $this->owner_with_passkeys( 1 );
		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );

		$this->assertTrue( Enrolment::instance()->remove_passkey( $user, $ids[0] ) );

		$this->assertSame( array(), Credentials::for_user( $user ) );
		$this->assertArrayNotHasKey( 'passkey', Store::methods( $user ) );
	}

	public function test_removing_a_passkey_needs_confirmation(): void {
		list( $user, $ids ) = $this->owner_with_passkeys( 2 );
		$this->sign_in( $user, HOUR_IN_SECONDS );

		$result = Enrolment::instance()->remove_passkey( $user, $ids[0] );

		$this->assertWPError( $result );
		$this->assertCount( 2, Credentials::for_user( $user ) );
	}

	public function test_another_users_passkey_cannot_be_removed(): void {
		list( $other, $theirs ) = $this->owner_with_passkeys( 2 );
		list( $user ) = $this->owner_with_passkeys( 2 );
		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );

		$result = Enrolment::instance()->remove_passkey( $user, $theirs[0] );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_unknown_passkey', $result->get_error_code() );
		$this->assertCount( 2, Credentials::for_user( $other ) );
	}

	public function test_the_passkey_tab_lists_each_passkey_with_its_own_remove_button(): void {
		list( $user, $ids ) = $this->owner_with_passkeys( 2 );
		$this->assertTrue( Step_Up::prove( $user, array( 'password' => self::PASS ) ) );
		$_GET['method'] = 'passkey';

		$html = $this->screen( $user );
		unset( $_GET['method'] );

		$this->assertStringContainsString( 'Device 1', $html );
		$this->assertStringContainsString( 'Device 2', $html );
		$this->assertSame( 2, substr_count( $html, 'value="sigil_remove_passkey"' ) );
		$this->assertStringContainsString( 'name="credential" value="' . $ids[1] . '"', $html );
		$this->assertStringContainsString( 'never used', $html );
	}

	public function test_a_passkey_method_with_no_passkeys_left_shows_as_off(): void {
		list( $user, $ids ) = $this->owner_with_passkeys( 1 );
		Credentials::delete( $ids[0], $user );

		$html = $this->screen( $user );

		$this->assertMatchesRegularExpression( '/Active methods:<\/strong>\s*Backup codes\s*</', $html );
	}

	public function test_before_confirming_the_passkeys_are_listed_without_remove_buttons(): void {
		list( $user ) = $this->owner_with_passkeys( 2 );
		$this->sign_in( $user, HOUR_IN_SECONDS );
		$_GET['method'] = 'passkey';

		$html = $this->screen( $user );
		unset( $_GET['method'] );

		$this->assertStringContainsString( 'sigil_step_up', $html );
		$this->assertStringContainsString( 'Device 1', $html );
		$this->assertStringContainsString( 'Device 2', $html );
		$this->assertStringNotContainsString( 'sigil_remove_passkey', $html );
	}
}
