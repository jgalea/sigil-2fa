<?php

declare( strict_types=1 );

use Sigil\Credentials;
use Sigil\Import;
use Sigil\Providers;
use Sigil\Two_Factor_Import;

class Test_WebAuthn_Import extends WP_UnitTestCase {

	use Import_Fixtures;

	/** @var array<int, string> */
	private array $handles = array();

	public function set_up(): void {
		parent::set_up();

		global $wpdb;
		$this->real_table(
			"CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}2fa_webauthn_users (
				user_id bigint(20) unsigned NOT NULL,
				user_handle varchar(128) NOT NULL,
				PRIMARY KEY  (user_id),
				UNIQUE KEY user_handle (user_handle)
			) ENGINE=InnoDB"
		);
		$this->real_table(
			"CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}2fa_webauthn_credentials (
				id bigint(20) unsigned NOT NULL auto_increment,
				user_handle varchar(128) NOT NULL,
				credential_id varchar(767) CHARSET ascii COLLATE ascii_bin NOT NULL,
				public_key varchar(1024) NOT NULL,
				counter int(11) NOT NULL,
				name varchar(255) NOT NULL,
				added int(11) NOT NULL,
				last_used int(11) NOT NULL,
				u2f tinyint(2) NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY credential_id (credential_id)
			) ENGINE=InnoDB"
		);
	}

	public function tear_down(): void {
		remove_all_filters( 'webauthn_app_id' );
		parent::tear_down();
	}

	/**
	 * A user enrolled with the WebAuthn provider, stored the way it stores keys:
	 * base64url credential id and base64url COSE key under a random handle.
	 *
	 * @return array{0: int, 1: string, 2: \OpenSSLAsymmetricKey}
	 */
	private function webauthn_user( array $providers, int $counter = 0, int $u2f = 0 ): array {
		global $wpdb;

		$uid = self::factory()->user->create();
		update_user_meta( $uid, '_two_factor_enabled_providers', $providers );

		$handle        = self::b64url( random_bytes( 32 ) );
		$credential_id = random_bytes( 32 );
		$keys          = $this->passkey_keypair();

		$wpdb->insert( $wpdb->base_prefix . '2fa_webauthn_users', array( 'user_id' => $uid, 'user_handle' => $handle ) );
		$wpdb->insert(
			$wpdb->base_prefix . '2fa_webauthn_credentials',
			array(
				'user_handle'   => $handle,
				'credential_id' => self::b64url( $credential_id ),
				'public_key'    => self::b64url( $keys['cose'] ),
				'counter'       => $counter,
				'name'          => 'YubiKey 5',
				'added'         => time(),
				'last_used'     => time(),
				'u2f'           => $u2f,
			)
		);

		$this->handles[ $uid ] = $handle;

		return array( $uid, $credential_id, $keys['private'] );
	}

	public function test_passkey_carries_over_and_signs_in(): void {
		list( $uid, $credential_id, $private ) = $this->webauthn_user( array( 'TwoFactor_Provider_WebAuthn' ), 7 );

		$dry = Two_Factor_Import::run( array( $uid ), true );
		$this->assertSame( 1, $dry['counts']['users'] );
		$this->assertSame( 1, $dry['counts']['passkey'] );
		$this->assertSame( array(), Credentials::for_user( $uid ), 'a dry run writes nothing' );

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( array( 'passkey' ), $result['imported'] );
		$this->assertFalse( $result['needs_attention'] );
		$this->assertSame( 'passkey', Providers::preference( $uid ) );

		$rows = Credentials::for_user( $uid );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'YubiKey 5', $rows[0]->label );
		$this->assertSame( 7, (int) $rows[0]->sign_count );
		$this->assertSame( Import::base64url_decode( $this->handles[ $uid ] ), $rows[0]->user_handle, 'the base64url handle is stored as raw bytes' );
		$this->assertNull( $rows[0]->discoverable, 'the provider does not say whether the key is resident' );
		$this->assertTrue( Providers::instance()->get( 'passkey' )->is_enrolled( $uid ) );

		$other = $this->passkey_keypair();
		$this->assertFalse( $this->passkey_signs_in( $uid, $credential_id, $other['private'], 8 ), 'a signature from another key must fail' );
		$this->assertFalse( $this->passkey_signs_in( $uid, $credential_id, $private, 7 ), 'the carried counter must refuse a replayed count' );
		$this->assertTrue( $this->passkey_signs_in( $uid, $credential_id, $private, 8 ) );
	}

	public function test_second_run_reports_passkey_already_there(): void {
		list( $uid ) = $this->webauthn_user( array( 'TwoFactor_Provider_WebAuthn' ) );
		Two_Factor_Import::import_user( $uid, false );

		$again = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( array(), $again['imported'] );
		$this->assertSame( array( 'passkey' ), $again['already'] );
		$this->assertCount( 1, Credentials::for_user( $uid ) );
	}

	public function test_u2f_key_is_reported_and_two_factor_keeps_the_user(): void {
		list( $uid ) = $this->webauthn_user( array( 'TwoFactor_Provider_WebAuthn' ), 3, 1 );

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( array(), $result['imported'] );
		$this->assertContains( 'passkey_u2f', $result['flags'] );
		$this->assertTrue( $result['needs_attention'] );
		$this->assertSame( array(), Credentials::for_user( $uid ) );
	}

	public function test_unadopted_u2f_meta_is_reported(): void {
		$uid = self::factory()->user->create();
		update_user_meta( $uid, '_two_factor_enabled_providers', array( 'Two_Factor_FIDO_U2F', 'Two_Factor_Email' ) );
		add_user_meta( $uid, '_two_factor_fido_u2f_registered_key', array( 'keyHandle' => 'abc' ) );

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertContains( 'passkey_u2f', $result['flags'] );
		$this->assertSame( array( 'email' ), $result['imported'], 'email still covers the user' );
		$this->assertFalse( $result['needs_attention'] );
	}

	public function test_keys_for_another_domain_are_reported(): void {
		add_filter( 'webauthn_app_id', static fn() => 'https://login.example.net' );
		list( $uid ) = $this->webauthn_user( array( 'TwoFactor_Provider_WebAuthn' ) );

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertContains( 'passkey_rp_mismatch:login.example.net', $result['flags'] );
		$this->assertTrue( $result['needs_attention'] );
		$this->assertSame( array(), Credentials::for_user( $uid ) );
	}

	public function test_provider_switched_on_without_a_key_is_not_a_method(): void {
		$uid = self::factory()->user->create();
		update_user_meta( $uid, '_two_factor_enabled_providers', array( 'TwoFactor_Provider_WebAuthn' ) );

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( 'not_using', $result['status'] );
		$this->assertContains( 'passkey_never_registered', $result['flags'] );
	}

	public function test_credential_owned_by_someone_else_is_not_moved(): void {
		list( $uid, $credential_id ) = $this->webauthn_user( array( 'TwoFactor_Provider_WebAuthn' ) );
		$other                       = self::factory()->user->create();
		Credentials::add( $other, $credential_id, 'pem', 0, 'theirs', '' );

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertContains( 'passkey_other_user', $result['flags'] );
		$this->assertSame( array(), Credentials::for_user( $uid ) );
	}
}
