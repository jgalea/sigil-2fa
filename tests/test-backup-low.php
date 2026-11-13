<?php

declare( strict_types=1 );

class Test_Backup_Low extends WP_UnitTestCase {

	private function user_with_codes_left( int $left ): int {
		$user   = self::factory()->user->create();
		$backup = new \Sigil\Providers\Backup_Codes();
		$codes  = $backup->generate( $user );
		foreach ( array_slice( $codes, 0, count( $codes ) - $left ) as $code ) {
			$this->assertTrue( $backup->validate( $user, array( 'code' => $code ) ) );
		}
		$this->assertSame( $left, $backup->remaining( $user ), 'the setup has to leave exactly this many' );

		return $user;
	}

	private function notice_for( int $user ): string {
		wp_set_current_user( $user );
		ob_start();
		\Sigil\Enforcement::instance()->low_codes_notice();

		return (string) ob_get_clean();
	}

	public function test_two_codes_or_fewer_raises_the_warning(): void {
		$this->assertStringContainsString( '2 backup codes left', $this->notice_for( $this->user_with_codes_left( 2 ) ) );
		$this->assertStringContainsString( '1 backup code left', $this->notice_for( $this->user_with_codes_left( 1 ) ) );
		$this->assertStringContainsString( '0 backup codes left', $this->notice_for( $this->user_with_codes_left( 0 ) ) );
	}

	public function test_three_codes_is_not_yet_a_warning(): void {
		$this->assertSame( '', $this->notice_for( $this->user_with_codes_left( 3 ) ) );
	}

	public function test_someone_without_backup_codes_is_not_warned(): void {
		$this->assertSame( '', $this->notice_for( self::factory()->user->create() ) );
	}

	public function test_the_enrolment_screen_warns_too(): void {
		$user = $this->user_with_codes_left( 1 );

		$backup = new \Sigil\Providers\Backup_Codes();
		ob_start();
		$backup->render_enrol( $user );
		ob_end_clean();

		ob_start();
		$backup->render_enrol( $user );

		$this->assertStringContainsString( 'running low on backup codes', (string) ob_get_clean() );
	}
}
