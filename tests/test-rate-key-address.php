<?php

declare( strict_types=1 );

use Sigil\Challenge;

/**
 * Every counter keyed by address agrees on what one address is.
 *
 * A dual-stack server reports IPv4 visitors as IPv4-mapped IPv6 addresses.
 * Read as IPv6, they all share the ::ffff:0:0/96 prefix and so one /64, which
 * would put every IPv4 visitor in one bucket.
 */
class Test_Rate_Key_Address extends WP_UnitTestCase {

	use Clears_Attempts;

	public function test_mapped_and_compatible_ipv4_count_as_the_ipv4_address(): void {
		$this->assertSame( Challenge::ip_rate_key_for( '198.51.100.7' ), Challenge::ip_rate_key_for( '::ffff:198.51.100.7' ) );
		$this->assertSame( Challenge::ip_rate_key_for( '198.51.100.7' ), Challenge::ip_rate_key_for( '::198.51.100.7' ) );
		$this->assertNotSame( Challenge::ip_rate_key_for( '::ffff:198.51.100.7' ), Challenge::ip_rate_key_for( '::ffff:198.51.100.8' ) );
	}

	public function test_one_real_ipv6_64_is_one_bucket(): void {
		$this->assertSame( Challenge::ip_rate_key_for( '2001:db8:aa:bb::1' ), Challenge::ip_rate_key_for( '2001:db8:aa:bb:ffff::2' ) );
		$this->assertNotSame( Challenge::ip_rate_key_for( '2001:db8:aa:bb::1' ), Challenge::ip_rate_key_for( '2001:db8:aa:cc::1' ) );
	}

	public function test_loopback_is_its_own_address(): void {
		$this->assertNotSame( Challenge::ip_rate_key_for( '::1' ), Challenge::ip_rate_key_for( '::2' ) );
		$this->assertNotSame( Challenge::ip_rate_key_for( '::1' ), Challenge::ip_rate_key_for( '0.0.0.1' ) );
	}

	public function test_two_mapped_ipv4_clients_mint_from_separate_allowances(): void {
		if ( PHP_VERSION_ID < 80000 ) {
			$this->markTestSkipped( 'Passkeys need PHP 8.0.' );
		}

		\Sigil\Policy::update( array( 'passwordless' => true ) );
		$previous = $_SERVER['REMOTE_ADDR'] ?? null;

		$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.1';
		for ( $i = 0; $i < 200 && null !== \Sigil\Passwordless::instance()->mint(); $i++ ) {
			continue;
		}
		$spent = \Sigil\Passwordless::instance()->mint();

		$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.2';
		$other                  = \Sigil\Passwordless::instance()->mint();
		$_SERVER['REMOTE_ADDR'] = $previous;

		$this->assertNull( $spent, 'the first client did run out' );
		$this->assertIsArray( $other, 'a different IPv4 client is not affected' );
	}

	// The password limiter and the challenge read the same key, so they must
	// see the same address.
	public function test_the_password_limiter_counts_a_mapped_address_as_the_ipv4_one(): void {
		\Sigil\Password_Limit::instance();
		\Sigil\Policy::update( array( 'limit_passwords' => true ) );
		add_filter(
			'sigil_password_limits',
			static function ( $limits ) {
				return array_merge( $limits, array( 'ip_attempts' => 3 ) );
			}
		);
		$previous = $_SERVER['REMOTE_ADDR'] ?? null;
		$user     = self::factory()->user->create_and_get( array( 'user_pass' => 'right-one' ) );

		$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
		for ( $i = 0; $i < 3; $i++ ) {
			wp_authenticate( 'spray-' . $i, 'wrong' );
		}
		$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.9';
		$result                 = wp_authenticate( $user->user_login, 'right-one' );
		$_SERVER['REMOTE_ADDR'] = $previous;
		remove_all_filters( 'sigil_password_limits' );

		$this->assertWPError( $result );
	}
}
