<?php

declare( strict_types=1 );

use Sigil\Credentials;
use Sigil\Providers;
use Sigil\Providers\TOTP;
use Sigil\Store;
use Sigil\Wordfence_Import;

class Test_Wordfence_Import extends WP_UnitTestCase {

	use Import_Fixtures;

	// The raw bytes behind the RFC 6238 test key, as Wordfence stores a secret.
	private const RAW_SECRET = '12345678901234567890';
	private const SECRET     = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	public function set_up(): void {
		parent::set_up();

		global $wpdb;
		$this->real_table(
			"CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}wfls_2fa_secrets (
				`id` int(11) unsigned NOT NULL AUTO_INCREMENT,
				`user_id` bigint(20) unsigned NOT NULL,
				`secret` tinyblob NOT NULL,
				`recovery` blob NOT NULL,
				`ctime` int(10) unsigned NOT NULL,
				`vtime` int(10) unsigned NOT NULL,
				`mode` enum('authenticator') NOT NULL DEFAULT 'authenticator',
				PRIMARY KEY (`id`),
				KEY `user_id` (`user_id`)
			) ENGINE=InnoDB"
		);
		$this->real_table(
			"CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}wfls_passkeys (
				`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				`user_id` bigint(20) unsigned NOT NULL,
				`credential_id` varbinary(1023) NOT NULL,
				`credential_id_hash` binary(32) NOT NULL,
				`public_key` blob NOT NULL,
				`sign_count` bigint(20) unsigned NOT NULL DEFAULT 0,
				`transports` varchar(255) DEFAULT NULL,
				`label` varchar(255) DEFAULT NULL,
				`user_handle` varbinary(255) DEFAULT NULL,
				`ctime` int(10) unsigned NOT NULL,
				`mtime` int(10) unsigned NOT NULL,
				`last_used_at` int(10) unsigned DEFAULT NULL,
				PRIMARY KEY (`id`),
				UNIQUE KEY `credential_id_hash` (`credential_id_hash`)
			) ENGINE=InnoDB"
		);
		$this->real_table(
			"CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}wfls_settings (
				`name` varchar(191) NOT NULL DEFAULT '',
				`value` longblob,
				`autoload` enum('no','yes') NOT NULL DEFAULT 'yes',
				PRIMARY KEY (`name`)
			) ENGINE=InnoDB"
		);
	}

	/**
	 * @param list<string> $recovery Recovery codes as Wordfence shows them.
	 */
	private function wf_totp_user( array $recovery, int $vtime = 0 ): int {
		global $wpdb;

		$uid = self::factory()->user->create();
		$wpdb->insert(
			$wpdb->base_prefix . 'wfls_2fa_secrets',
			array(
				'user_id'  => $uid,
				'secret'   => self::RAW_SECRET,
				'recovery' => implode( '', array_map( static fn( $c ) => hex2bin( str_replace( ' ', '', $c ) ), $recovery ) ),
				'ctime'    => time(),
				'vtime'    => $vtime,
			)
		);

		return $uid;
	}

	/**
	 * @return array{0: string, 1: \OpenSSLAsymmetricKey}
	 */
	private function wf_passkey( int $uid, string $rp ): array {
		global $wpdb;

		$credential_id = random_bytes( 16 );
		$keys          = $this->passkey_keypair();
		$wpdb->insert(
			$wpdb->base_prefix . 'wfls_passkeys',
			array(
				'user_id'            => $uid,
				'credential_id'      => $credential_id,
				'credential_id_hash' => hash( 'sha256', $credential_id, true ),
				'public_key'         => $keys['cose'],
				'sign_count'         => 0,
				'transports'         => 'internal,hybrid',
				'label'              => 'MacBook',
				'ctime'              => time(),
				'mtime'              => time(),
			)
		);
		$wpdb->replace( $wpdb->base_prefix . 'wfls_settings', array( 'name' => 'last-passkey-rp', 'value' => $rp, 'autoload' => 'yes' ) );

		return array( $credential_id, $keys['private'] );
	}

	public function test_secret_and_recovery_codes_carry_over(): void {
		$uid = $this->wf_totp_user( array( '0123 4567 89ab cdef', 'fedc ba98 7654 3210' ) );

		$dry = Wordfence_Import::run( null, true );
		$this->assertSame( 1, $dry['counts']['users'], 'the dry run must find the enrolled user' );
		$this->assertSame( 1, $dry['counts']['totp'] );
		$this->assertSame( array(), Store::methods( $uid ) );

		$result = Wordfence_Import::import_user( $uid, false );
		$this->assertEqualsCanonicalizing( array( 'totp', 'backup' ), $result['imported'] );
		$this->assertFalse( $result['needs_attention'] );
		$this->assertSame( 'totp', Providers::preference( $uid ) );
		$this->assertStringNotContainsString( self::SECRET, (string) Store::methods( $uid )['totp']['secret'] );

		$this->assertFalse( Providers::instance()->get( 'totp' )->validate( $uid, array( 'code' => TOTP::code_at( 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', time() ) ) ) );
		$this->assertTrue( $this->totp_signs_in( $uid, self::SECRET ) );

		$backup = Providers::instance()->get( 'backup' );
		$this->assertFalse( $backup->validate( $uid, array( 'code' => '0123 4567 89ab cdee' ) ) );
		$this->assertTrue( $backup->validate( $uid, array( 'code' => '0123 4567 89ab cdef' ) ), 'a code typed the way Wordfence shows it' );
		$this->assertFalse( $backup->validate( $uid, array( 'code' => '0123456789ABCDEF' ) ), 'a recovery code is spent once used' );
		$this->assertTrue( $backup->validate( $uid, array( 'code' => 'FEDCBA9876543210' ) ) );
	}

	public function test_last_accepted_step_is_not_replayable(): void {
		$uid = $this->wf_totp_user( array(), (int) floor( time() / 30 ) * 30 );
		Wordfence_Import::import_user( $uid, false );

		$this->assertFalse( $this->totp_signs_in( $uid, self::SECRET ) );
	}

	public function test_no_recovery_codes_left_is_flagged(): void {
		$uid    = $this->wf_totp_user( array() );
		$result = Wordfence_Import::import_user( $uid, false );

		$this->assertSame( array( 'totp' ), $result['imported'] );
		$this->assertContains( 'backup_codes_none_left', $result['flags'] );
	}

	public function test_passkey_carries_over_and_signs_in(): void {
		$uid                          = $this->wf_totp_user( array( '0123 4567 89ab cdef' ) );
		list( $credential_id, $private ) = $this->wf_passkey( $uid, Providers\Passkey::rp_id() );

		$result = Wordfence_Import::import_user( $uid, false );
		$this->assertEqualsCanonicalizing( array( 'totp', 'backup', 'passkey' ), $result['imported'] );
		$this->assertSame( 'passkey', Providers::preference( $uid ) );

		$rows = Credentials::for_user( $uid );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'MacBook', $rows[0]->label );
		$this->assertSame( 'internal,hybrid', $rows[0]->transports );

		$other = $this->passkey_keypair();
		$this->assertFalse( $this->passkey_signs_in( $uid, $credential_id, $other['private'], 1 ) );
		$this->assertTrue( $this->passkey_signs_in( $uid, $credential_id, $private, 1 ) );
	}

	public function test_passkeys_for_another_domain_leave_the_user_on_wordfence(): void {
		$uid = $this->wf_totp_user( array( '0123 4567 89ab cdef' ) );
		$this->wf_passkey( $uid, 'example.com' );

		$result = Wordfence_Import::import_user( $uid, false );
		$this->assertContains( 'passkey_rp_mismatch:example.com', $result['flags'] );
		$this->assertTrue( $result['needs_attention'] );
		$this->assertSame( array(), $result['imported'], 'half a setup is not written' );
		$this->assertSame( array(), Store::methods( $uid ) );
	}

	public function test_recovery_codes_alone_are_not_written(): void {
		global $wpdb;

		$uid = $this->wf_totp_user( array( '0123 4567 89ab cdef' ) );
		$wpdb->update( $wpdb->base_prefix . 'wfls_2fa_secrets', array( 'secret' => 'short' ), array( 'user_id' => $uid ) );

		$result = Wordfence_Import::import_user( $uid, false );
		$this->assertContains( 'totp_secret_unusable', $result['flags'] );
		$this->assertTrue( $result['needs_attention'] );
		$this->assertSame( array(), Store::methods( $uid ) );
	}

	public function test_enrolment_wordfence_is_not_asking_for_is_skipped(): void {
		global $wpdb;

		$uid = $this->wf_totp_user( array( '0123 4567 89ab cdef' ) );
		$wpdb->replace( $wpdb->base_prefix . 'wfls_settings', array( 'name' => 'enable-2fa', 'value' => '0', 'autoload' => 'yes' ) );

		$result = Wordfence_Import::import_user( $uid, false );
		$this->assertSame( 'not_using', $result['status'] );
		$this->assertContains( 'wordfence_2fa_off', $result['flags'] );
		$this->assertSame( array(), Store::methods( $uid ) );

		$wpdb->replace( $wpdb->base_prefix . 'wfls_settings', array( 'name' => 'enable-2fa', 'value' => '1', 'autoload' => 'yes' ) );
		$this->assertSame( array( 'totp', 'backup' ), Wordfence_Import::import_user( $uid, true )['imported'] );
	}

	public function test_rows_of_deleted_accounts_are_not_candidates(): void {
		$uid = $this->wf_totp_user( array() );
		$this->assertContains( $uid, Wordfence_Import::candidates() );

		global $wpdb;
		$wpdb->delete( $wpdb->users, array( 'ID' => $uid ) );
		$this->assertNotContains( $uid, Wordfence_Import::candidates() );
	}

	public function test_only_fully_covered_users_count_as_covered(): void {
		$covered = $this->wf_totp_user( array( '0123 4567 89ab cdef' ) );
		Wordfence_Import::import_user( $covered, false );
		$stranger = self::factory()->user->create_and_get();

		$this->assertTrue( Wordfence_Import::covers( get_userdata( $covered ) ) );
		$this->assertFalse( Wordfence_Import::covers( $stranger ) );
	}
}
