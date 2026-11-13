<?php

declare( strict_types=1 );

class Test_Crypto extends WP_UnitTestCase {
	public function test_roundtrip(): void {
		$secret = 'JBSWY3DPEHPK3PXP';
		$this->assertSame( $secret, \Sigil\Crypto::decrypt( \Sigil\Crypto::encrypt( $secret ) ) );
	}

	public function test_ciphertext_is_not_plaintext(): void {
		$this->assertNotSame( 'hello', \Sigil\Crypto::encrypt( 'hello' ) );
	}

	public function test_tampered_ciphertext_returns_empty(): void {
		$ct = \Sigil\Crypto::encrypt( 'hello' );
		$this->assertSame( '', \Sigil\Crypto::decrypt( $ct . 'x' ) );
	}

	public function test_same_plaintext_gives_different_ciphertext(): void {
		$this->assertNotSame( \Sigil\Crypto::encrypt( 'a' ), \Sigil\Crypto::encrypt( 'a' ) );
	}

	// Rotating the salts makes every stored secret unreadable, and every code
	// then looks wrong. Nothing said why.
	public function test_an_unreadable_authenticator_secret_raises_a_notice_for_admins(): void {
		delete_transient( \Sigil\Providers\Totp::UNREADABLE_KEY );
		$uid = self::factory()->user->create();
		\Sigil\Store::set_method( $uid, 'totp', array( 'secret' => base64_encode( "\x01" . str_repeat( 'x', 60 ) ) ) );

		$this->assertFalse( ( new \Sigil\Providers\Totp() )->validate( $uid, array( 'code' => '123456' ) ) );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		if ( is_multisite() ) {
			grant_super_admin( get_current_user_id() );
		}
		ob_start();
		\Sigil\Enforcement::instance()->unreadable_secret_notice();
		$this->assertStringContainsString( 'SIGIL_KEY', (string) ob_get_clean() );

		delete_transient( \Sigil\Providers\Totp::UNREADABLE_KEY );
		ob_start();
		\Sigil\Enforcement::instance()->unreadable_secret_notice();
		$this->assertSame( '', (string) ob_get_clean() );
	}
}
