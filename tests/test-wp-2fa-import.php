<?php

declare( strict_types=1 );

use Sigil\Credentials;
use Sigil\Policy;
use Sigil\Providers;
use Sigil\Store;
use Sigil\WP_2FA_Import;

class Test_WP_2FA_Import extends WP_UnitTestCase {

	use Import_Fixtures;

	private const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	private string $site_key = '';

	public function set_up(): void {
		parent::set_up();
		$this->site_key = base64_encode( random_bytes( 16 ) );
		update_option( 'wp_2fa_secret_key', $this->site_key );
		update_site_option( 'wp_2fa_secret_key', $this->site_key );
	}

	public function tear_down(): void {
		delete_option( 'wp_2fa_policy' );
		delete_site_option( 'wp_2fa_policy' );
		Policy::update( array( 'enabled' => false, 'roles' => array() ) );
		parent::tear_down();
	}

	private function key(): string {
		return hash( 'sha256', base64_decode( $this->site_key ), true );
	}

	// What WP 2FA writes today: "lsc_v2:" and a sodium secretbox.
	private function seal_v2( string $plain ): string {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = sodium_crypto_secretbox( $plain, $nonce, hash_hmac( 'sha256', 'wp-2fa authenticated encryption v2', $this->key(), true ) );

		return 'lsc_v2:' . base64_encode( $nonce . $box );
	}

	// What WP 2FA wrote before 4.x: "lsc_" and AES-256-CTR.
	private function seal_ctr( string $plain ): string {
		$iv = random_bytes( 16 );

		return 'lsc_' . base64_encode( $iv . openssl_encrypt( $plain, 'aes-256-ctr', $this->key(), OPENSSL_RAW_DATA, $iv ) );
	}

	private function wp2fa_user( string $method, array $meta = array(), string $email = '' ): int {
		$uid = self::factory()->user->create( '' !== $email ? array( 'user_email' => $email ) : array() );
		update_user_meta( $uid, 'wp_2fa_enabled_methods', $method );
		foreach ( $meta as $key => $value ) {
			update_user_meta( $uid, $key, $value );
		}

		return $uid;
	}

	public function test_encrypted_secret_carries_over_and_signs_in(): void {
		foreach ( array( 'v2' => $this->seal_v2( self::SECRET ), 'ctr' => $this->seal_ctr( self::SECRET ), 'plain' => self::SECRET ) as $format => $stored ) {
			$uid = $this->wp2fa_user( 'totp', array( 'wp_2fa_totp_key' => $stored ) );

			$result = WP_2FA_Import::import_user( $uid, false );
			$this->assertSame( array( 'totp' ), $result['imported'], $format );
			$this->assertSame( 'totp', Providers::preference( $uid ) );
			$this->assertStringNotContainsString( self::SECRET, (string) Store::methods( $uid )['totp']['secret'] );
			$this->assertTrue( $this->totp_signs_in( $uid, self::SECRET ), $format );
		}
	}

	public function test_wrong_site_key_leaves_the_user_on_wp_2fa(): void {
		$stored = $this->seal_v2( self::SECRET );
		update_option( 'wp_2fa_secret_key', base64_encode( random_bytes( 16 ) ) );
		update_site_option( 'wp_2fa_secret_key', get_option( 'wp_2fa_secret_key' ) );

		$uid    = $this->wp2fa_user( 'totp', array( 'wp_2fa_totp_key' => $stored ) );
		$result = WP_2FA_Import::import_user( $uid, false );

		$this->assertContains( 'encryption_key_unreadable', $result['flags'] );
		$this->assertTrue( $result['needs_attention'] );
		$this->assertSame( array(), Store::methods( $uid ) );
	}

	public function test_ctr_garbage_from_a_wrong_key_is_refused(): void {
		$stored = $this->seal_ctr( self::SECRET );
		update_option( 'wp_2fa_secret_key', base64_encode( random_bytes( 16 ) ) );
		update_site_option( 'wp_2fa_secret_key', get_option( 'wp_2fa_secret_key' ) );

		$uid    = $this->wp2fa_user( 'totp', array( 'wp_2fa_totp_key' => $stored ) );
		$result = WP_2FA_Import::import_user( $uid, false );

		$this->assertContains( 'totp_secret_unusable', $result['flags'] );
		$this->assertSame( array(), Store::methods( $uid ) );
	}

	public function test_last_step_is_not_replayable(): void {
		$uid = $this->wp2fa_user(
			'totp',
			array(
				'wp_2fa_totp_key'       => $this->seal_v2( self::SECRET ),
				'wp_2fa_last_totp_step' => (int) floor( time() / 30 ),
			)
		);
		WP_2FA_Import::import_user( $uid, false );

		$this->assertFalse( $this->totp_signs_in( $uid, self::SECRET ) );
	}

	public function test_sixteen_digit_backup_codes_carry_over(): void {
		$uid = $this->wp2fa_user(
			'totp',
			array(
				'wp_2fa_totp_key'     => $this->seal_v2( self::SECRET ),
				'wp_2fa_backup_codes' => array( wp_hash_password( '1234567890123456' ), wp_hash_password( '6543210987654321' ) ),
			)
		);

		$result = WP_2FA_Import::import_user( $uid, false );
		$this->assertEqualsCanonicalizing( array( 'totp', 'backup' ), $result['imported'] );

		$backup = Providers::instance()->get( 'backup' );
		$this->assertFalse( $backup->validate( $uid, array( 'code' => '1234567890123457' ) ) );
		$this->assertFalse( $backup->validate( $uid, array( 'code' => '12345678' ) ), 'a code of Sigil\'s own length must not match' );
		$this->assertTrue( $backup->validate( $uid, array( 'code' => '1234567890123456' ) ) );
		$this->assertFalse( $backup->validate( $uid, array( 'code' => '1234567890123456' ) ) );
		$this->assertSame( 16, Store::methods( $uid )['backup']['length'], 'using a code keeps the imported length' );
	}

	public function test_email_user_gets_email_codes(): void {
		$uid    = $this->wp2fa_user( 'email' );
		$result = WP_2FA_Import::import_user( $uid, false );

		$this->assertSame( array( 'email' ), $result['imported'] );
		$this->assertSame( 'email', Providers::preference( $uid ) );
	}

	public function test_email_sent_elsewhere_is_left_on_wp_2fa(): void {
		$uid    = $this->wp2fa_user( 'email', array( 'wp_2fa_nominated_email_address' => 'phone@example.net' ), 'desk@example.org' );
		$result = WP_2FA_Import::import_user( $uid, false );

		$this->assertContains( 'email_address_differs', $result['flags'] );
		$this->assertTrue( $result['needs_attention'] );
		$this->assertSame( array(), Store::methods( $uid ) );
	}

	public function test_backup_codes_without_a_sign_in_method_are_not_written(): void {
		$uid    = $this->wp2fa_user( 'totp', array( 'wp_2fa_backup_codes' => array( wp_hash_password( '1234567890123456' ) ) ) );
		$result = WP_2FA_Import::import_user( $uid, false );

		$this->assertContains( 'totp_never_configured', $result['flags'] );
		$this->assertTrue( $result['needs_attention'] );
		$this->assertSame( array(), Store::methods( $uid ) );
	}

	public function test_premium_method_is_reported(): void {
		$uid    = $this->wp2fa_user( 'oob' );
		$result = WP_2FA_Import::import_user( $uid, false );

		$this->assertContains( 'unsupported_method:oob', $result['flags'] );
		$this->assertTrue( $result['needs_attention'] );
	}

	public function test_leftover_secret_without_a_method_is_skipped(): void {
		$uid = self::factory()->user->create();
		update_user_meta( $uid, 'wp_2fa_totp_key', $this->seal_v2( self::SECRET ) );

		$result = WP_2FA_Import::import_user( $uid, false );
		$this->assertSame( 'not_using', $result['status'] );
		$this->assertContains( 'data_without_enabled_method', $result['flags'] );
	}

	public function test_passkey_carries_over_and_signs_in(): void {
		$keys          = $this->passkey_keypair();
		$credential_id = random_bytes( 20 );
		$pem           = openssl_pkey_get_details( $keys['private'] )['key'];
		$uid           = $this->wp2fa_user( 'totp', array( 'wp_2fa_totp_key' => $this->seal_v2( self::SECRET ) ) );
		update_user_meta(
			$uid,
			'wp_2fa_passkey_' . self::b64url( base64_encode( $credential_id ) ),
			// Slashed first, as WP 2FA does, so update_user_meta() unslashes it back
			// to the JSON it meant.
			addcslashes(
				wp_json_encode(
					array(
						'extra' => array(
							'name'              => 'Pixel',
							'enabled'           => true,
							'public_key'        => $pem,
							'credential_id'     => base64_encode( $credential_id ),
							'transports'        => '["hybrid"]',
							'signature_counter' => 0,
						),
					),
					JSON_UNESCAPED_SLASHES
				),
				'\\'
			)
		);

		$result = WP_2FA_Import::import_user( $uid, false );
		$this->assertEqualsCanonicalizing( array( 'totp', 'passkey' ), $result['imported'] );
		$this->assertSame( 'totp', Providers::preference( $uid ), 'their WP 2FA primary method stays first' );
		$this->assertSame( 'Pixel', Credentials::for_user( $uid )[0]->label );
		$this->assertTrue( $this->passkey_signs_in( $uid, $credential_id, $keys['private'], 1 ) );
	}

	public function test_role_policy_maps_only_when_applied(): void {
		update_option(
			'wp_2fa_policy',
			array(
				'enforcement-policy'       => 'certain-roles-only',
				'enforced_roles'           => array( 'administrator', 'editor' ),
				'excluded_roles'           => array( 'editor' ),
				'excluded_users'           => array( 'bob' ),
				'grace-period'             => 36,
				'grace-period-denominator' => 'hours',
			)
		);
		update_site_option( 'wp_2fa_policy', get_option( 'wp_2fa_policy' ) );

		$mapped = WP_2FA_Import::policy();
		$this->assertSame( array( 'administrator' => true ), $mapped['policy']['roles'] );
		$this->assertSame( 2, $mapped['policy']['grace_days'] );
		$this->assertSame( array( 'excluded_users' ), $mapped['skipped'] );

		$uid = $this->wp2fa_user( 'email' );
		WP_2FA_Import::run( array( $uid ), false );
		$this->assertFalse( Policy::get()['enabled'], 'importing users never changes the policy' );

		$this->assertTrue( WP_2FA_Import::apply_policy() );
		$policy = Policy::get();
		$this->assertTrue( $policy['enabled'] );
		$this->assertTrue( $policy['roles']['administrator'] );
		$this->assertFalse( $policy['roles']['editor'] );
		$this->assertSame( 2, $policy['grace_days'] );
	}

	public function test_per_user_enforcement_is_not_widened(): void {
		update_option( 'wp_2fa_policy', array( 'enforcement-policy' => 'certain-users-only', 'enforced_users' => array( 'alice' ) ) );
		update_site_option( 'wp_2fa_policy', get_option( 'wp_2fa_policy' ) );

		$mapped = WP_2FA_Import::policy();
		$this->assertNull( $mapped['policy'] );
		$this->assertContains( 'enforcement:certain-users-only', $mapped['skipped'] );
		$this->assertFalse( WP_2FA_Import::apply_policy() );
	}
}
