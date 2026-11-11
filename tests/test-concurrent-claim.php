<?php

declare( strict_types=1 );

/**
 * Two simultaneous submissions of one code both read the unspent state. The
 * claim is taken in a single statement, so only one request may win it; here
 * the other request is played by taking the claim first.
 */
class Test_Concurrent_Claim extends WP_UnitTestCase {

	use Clears_Attempts;

	private const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	public function test_a_totp_code_already_claimed_by_another_request_is_refused(): void {
		$uid  = self::factory()->user->create();
		$totp = new \Sigil\Providers\Totp();
		$totp->handle_enrol( $uid, array( 'secret' => self::SECRET, 'code' => $totp::code_at( self::SECRET, time() - 30 ) ) );

		$key  = 'totp:' . $uid . ':' . (int) floor( time() / 30 );
		$code = $totp::code_at( self::SECRET, time() );
		$this->assertSame( 1, \Sigil\Rate_Limit::reserve( $key, 120 ), 'the other request took the step' );

		$this->assertFalse( $totp->validate( $uid, array( 'code' => $code ) ) );

		\Sigil\Rate_Limit::clear( $key );
		$this->assertTrue( $totp->validate( $uid, array( 'code' => $code ) ), 'control: the same code passes when nobody else holds the step' );
	}

	public function test_a_backup_code_already_claimed_by_another_request_is_refused(): void {
		$uid    = self::factory()->user->create();
		$backup = new \Sigil\Providers\Backup_Codes();
		$codes  = $backup->generate( $uid );

		$entries = \Sigil\Store::methods( $uid )['backup']['codes'];
		$this->assertSame( 1, \Sigil\Rate_Limit::reserve( 'backup:' . $uid . ':' . md5( $entries[0]['hash'] ), 120 ) );

		$this->assertFalse( $backup->validate( $uid, array( 'code' => $codes[0] ) ) );
		$this->assertTrue( $backup->validate( $uid, array( 'code' => $codes[1] ) ), 'another code is unaffected' );
		$this->assertSame( count( $codes ) - 1, $backup->remaining( $uid ) );
	}
}
