<?php

declare( strict_types=1 );

use Sigil\Providers;
use Sigil\Providers\TOTP;
use Sigil\Store;
use Sigil\Two_Factor_Import;

class Test_Two_Factor_Import extends WP_UnitTestCase {

	// base32 of "12345678901234567890", the RFC 6238 test key.
	private const SECRET       = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
	private const OTHER_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

	public function tear_down(): void {
		delete_option( 'two_factor_enabled_providers' );
		remove_all_filters( 'two_factor_backup_code_length' );
		parent::tear_down();
	}

	private function tf_user( array $providers, array $meta = array(), string $email = '' ): int {
		$args = array();
		if ( '' !== $email ) {
			$args['user_email'] = $email;
		}
		$uid = self::factory()->user->create( $args );
		update_user_meta( $uid, '_two_factor_enabled_providers', $providers );
		foreach ( $meta as $key => $value ) {
			update_user_meta( $uid, $key, $value );
		}
		return $uid;
	}

	private function totp_code( string $secret, int $offset = 0 ): string {
		return TOTP::code_at( $secret, time() + $offset );
	}

	public function test_email_user_gets_email_codes(): void {
		$uid    = $this->tf_user( array( 'Two_Factor_Email' ), array( '_two_factor_provider' => 'Two_Factor_Email' ) );
		$result = Two_Factor_Import::import_user( $uid, false );

		$this->assertSame( array( 'email' ), $result['imported'] );
		$this->assertSame( array(), $result['flags'] );
		$this->assertTrue( Providers::instance()->get( 'email' )->is_enrolled( $uid ) );
		$this->assertSame( 'email', Providers::preference( $uid ) );
	}

	public function test_totp_secret_carries_over_and_signs_in(): void {
		$uid = $this->tf_user(
			array( 'Two_Factor_Email', 'Two_Factor_Totp' ),
			array(
				'_two_factor_totp_key' => self::SECRET,
				'_two_factor_provider' => 'Two_Factor_Totp',
			)
		);

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertEqualsCanonicalizing( array( 'totp', 'email' ), $result['imported'] );
		$this->assertSame( 'totp', Providers::preference( $uid ) );

		$stored = Store::methods( $uid )['totp']['secret'];
		$this->assertStringNotContainsString( self::SECRET, (string) $stored, 'secret must be stored encrypted' );

		$totp = Providers::instance()->get( 'totp' );
		$this->assertFalse( $totp->validate( $uid, array( 'code' => $this->totp_code( self::OTHER_SECRET ) ) ), 'a code from a different secret must fail' );
		$this->assertTrue( $totp->validate( $uid, array( 'code' => $this->totp_code( self::SECRET ) ) ) );
	}

	public function test_last_used_totp_code_cannot_be_replayed(): void {
		$uid = $this->tf_user(
			array( 'Two_Factor_Totp' ),
			array(
				'_two_factor_totp_key'                   => self::SECRET,
				'_two_factor_totp_last_successful_login' => (int) floor( time() / 30 ) * 30,
			)
		);

		Two_Factor_Import::import_user( $uid, false );
		$this->assertFalse( Providers::instance()->get( 'totp' )->validate( $uid, array( 'code' => $this->totp_code( self::SECRET ) ) ) );
	}

	public function test_totp_listed_without_secret_keeps_email_and_is_flagged(): void {
		$uid    = $this->tf_user( array( 'Two_Factor_Email', 'Two_Factor_Totp' ) );
		$result = Two_Factor_Import::import_user( $uid, false );

		$this->assertSame( array( 'email' ), $result['imported'] );
		$this->assertContains( 'totp_never_configured', $result['flags'] );
		$this->assertFalse( $result['email_fallback'] );
		$this->assertSame( 'email', Providers::preference( $uid ) );
	}

	public function test_totp_only_without_secret_falls_back_to_email(): void {
		$uid    = $this->tf_user( array( 'Two_Factor_Totp' ) );
		$result = Two_Factor_Import::import_user( $uid, false );

		$this->assertSame( array( 'email' ), $result['imported'] );
		$this->assertTrue( $result['email_fallback'] );
		$this->assertSame( 'ok', $result['status'] );
	}

	public function test_unusable_secret_falls_back_to_email(): void {
		foreach ( array( 'GEZDGNBV', 'not a secret!!' ) as $bad ) {
			$uid    = $this->tf_user( array( 'Two_Factor_Totp' ), array( '_two_factor_totp_key' => $bad ) );
			$result = Two_Factor_Import::import_user( $uid, false );

			$this->assertSame( array( 'email' ), $result['imported'], $bad );
			$this->assertContains( 'totp_secret_unusable', $result['flags'] );
			$this->assertTrue( $result['email_fallback'] );
			$this->assertFalse( Providers::instance()->get( 'totp' )->is_enrolled( $uid ) );
		}
	}

	public function test_totp_only_with_secret_gets_no_email(): void {
		$uid    = $this->tf_user( array( 'Two_Factor_Totp' ), array( '_two_factor_totp_key' => self::SECRET ) );
		$result = Two_Factor_Import::import_user( $uid, false );

		$this->assertSame( array( 'totp' ), $result['imported'] );
		$this->assertFalse( Providers::instance()->get( 'email' )->is_enrolled( $uid ) );
	}

	public function test_backup_codes_carry_over_single_use(): void {
		$hashes = array( wp_hash_password( '12345678' ), wp_hash_password( '87654321' ) );
		$uid    = $this->tf_user(
			array( 'Two_Factor_Email', 'Two_Factor_Backup_Codes' ),
			array( '_two_factor_backup_codes' => $hashes )
		);

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertContains( 'backup', $result['imported'] );
		$this->assertSame( 'email', Providers::preference( $uid ) );

		$backup = Providers::instance()->get( 'backup' );
		$this->assertSame( 2, $backup->remaining( $uid ) );
		$this->assertFalse( $backup->validate( $uid, array( 'code' => '11111111' ) ) );
		$this->assertTrue( $backup->validate( $uid, array( 'code' => '1234 5678' ) ) );
		$this->assertFalse( $backup->validate( $uid, array( 'code' => '12345678' ) ), 'single use' );
		$this->assertSame( 1, $backup->remaining( $uid ) );
	}

	public function test_backup_codes_skipped_when_unverifiable(): void {
		$uid    = $this->tf_user(
			array( 'Two_Factor_Email', 'Two_Factor_Backup_Codes' ),
			array( '_two_factor_backup_codes' => array( md5( '12345678' ) ) )
		);
		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertNotContains( 'backup', $result['imported'] );
		$this->assertContains( 'backup_codes_unverifiable', $result['flags'] );

		add_filter(
			'two_factor_backup_code_length',
			static function () {
				return 12;
			}
		);
		$uid    = $this->tf_user(
			array( 'Two_Factor_Email', 'Two_Factor_Backup_Codes' ),
			array( '_two_factor_backup_codes' => array( wp_hash_password( '123456789012' ) ) )
		);
		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertNotContains( 'backup', $result['imported'] );
		$this->assertContains( 'backup_codes_unverifiable', $result['flags'] );
	}

	public function test_backup_codes_not_enabled_are_not_imported(): void {
		$uid    = $this->tf_user(
			array( 'Two_Factor_Email' ),
			array( '_two_factor_backup_codes' => array( wp_hash_password( '12345678' ) ) )
		);
		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( array( 'email' ), $result['imported'] );
		$this->assertFalse( Providers::instance()->get( 'backup' )->is_enrolled( $uid ) );
	}

	public function test_user_not_using_two_factor_is_skipped(): void {
		$uid    = $this->tf_user( array(), array( '_two_factor_totp_key' => self::SECRET ) );
		$result = Two_Factor_Import::import_user( $uid, false );

		$this->assertSame( 'not_using', $result['status'] );
		$this->assertContains( 'data_without_enabled_method', $result['flags'] );
		$this->assertSame( array(), Store::methods( $uid ) );
	}

	public function test_dry_run_writes_nothing(): void {
		$uid    = $this->tf_user( array( 'Two_Factor_Email', 'Two_Factor_Totp' ), array( '_two_factor_totp_key' => self::SECRET ) );
		$result = Two_Factor_Import::import_user( $uid, true );

		$this->assertEqualsCanonicalizing( array( 'totp', 'email' ), $result['imported'] );
		$this->assertSame( array(), Store::methods( $uid ) );
		$this->assertSame( '', Providers::preference( $uid ) );
	}

	public function test_rerun_is_a_no_op_and_two_factor_data_survives(): void {
		$uid = $this->tf_user(
			array( 'Two_Factor_Email', 'Two_Factor_Totp' ),
			array(
				'_two_factor_totp_key' => self::SECRET,
				'_two_factor_provider' => 'Two_Factor_Totp',
			)
		);

		Two_Factor_Import::import_user( $uid, false );
		$this->assertTrue( Providers::instance()->get( 'totp' )->validate( $uid, array( 'code' => $this->totp_code( self::SECRET ) ) ) );
		$after_login = Store::methods( $uid );

		$again = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( array(), $again['imported'] );
		$this->assertEqualsCanonicalizing( array( 'totp', 'email' ), $again['already'] );
		$this->assertSame( $after_login, Store::methods( $uid ), 'a re-run must not reset the replay counter' );

		$this->assertSame( self::SECRET, get_user_meta( $uid, '_two_factor_totp_key', true ) );
		$this->assertSame( array( 'Two_Factor_Email', 'Two_Factor_Totp' ), get_user_meta( $uid, '_two_factor_enabled_providers', true ) );
		$this->assertSame( 'Two_Factor_Totp', get_user_meta( $uid, '_two_factor_provider', true ) );
	}

	public function test_existing_sigil_methods_and_preference_are_kept(): void {
		$uid  = $this->tf_user( array( 'Two_Factor_Totp' ), array( '_two_factor_totp_key' => self::SECRET ) );
		$totp = Providers::instance()->get( 'totp' );
		$totp->handle_enrol( $uid, array( 'secret' => self::OTHER_SECRET, 'code' => $this->totp_code( self::OTHER_SECRET ) ) );
		Providers::instance()->get( 'email' )->handle_enrol( $uid, array() );
		Providers::set_preference( $uid, 'email' );

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( array(), $result['imported'] );
		$this->assertSame( 'email', Providers::preference( $uid ) );
		$this->assertTrue( $totp->validate( $uid, array( 'code' => $this->totp_code( self::OTHER_SECRET ) ) ) );
	}

	public function test_invalid_email_without_totp_is_reported_as_failed(): void {
		$uid = $this->tf_user( array( 'Two_Factor_Email' ) );
		global $wpdb;
		$wpdb->update( $wpdb->users, array( 'user_email' => 'not-an-email' ), array( 'ID' => $uid ) );
		clean_user_cache( $uid );

		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( 'failed', $result['status'] );
		$this->assertContains( 'email_address_invalid', $result['flags'] );
	}

	public function test_site_wide_provider_setting_is_honoured(): void {
		update_option( 'two_factor_enabled_providers', array( 'Two_Factor_Email' ) );
		$uid    = $this->tf_user( array( 'Two_Factor_Email', 'Two_Factor_Totp' ), array( '_two_factor_totp_key' => self::SECRET ) );
		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( array( 'email' ), $result['imported'] );

		$uid    = $this->tf_user( array( 'Two_Factor_Totp' ), array( '_two_factor_totp_key' => self::SECRET ) );
		$result = Two_Factor_Import::import_user( $uid, false );
		$this->assertSame( array( 'email' ), $result['imported'], 'nothing allowed means Two Factor forces email, and so does the import' );
	}

	public function test_run_counts_and_sends_no_alerts(): void {
		$this->tf_user( array( 'Two_Factor_Email' ) );
		$this->tf_user( array( 'Two_Factor_Email', 'Two_Factor_Totp' ), array( '_two_factor_totp_key' => self::SECRET ) );
		$this->tf_user( array( 'Two_Factor_Totp' ) );
		$this->tf_user( array() );

		reset_phpmailer_instance();
		$report = Two_Factor_Import::run( null, false );
		$mailer = tests_retrieve_phpmailer_instance();

		$this->assertSame( 4, $report['counts']['users'] );
		$this->assertSame( 1, $report['counts']['not_using'] );
		$this->assertSame( 3, $report['counts']['email'] );
		$this->assertSame( 1, $report['counts']['totp'] );
		$this->assertSame( 1, $report['counts']['email_fallback'] );
		$this->assertSame( 0, $report['counts']['failed'] );
		$this->assertSame( array(), $mailer->mock_sent );
		$this->assertTrue( (bool) apply_filters( 'sigil_send_change_alert', true, 1 ), 'alerts switched back on afterwards' );
	}

	public function test_two_factor_stands_down_for_sigil_users_only(): void {
		$with    = self::factory()->user->create_and_get();
		$without = self::factory()->user->create_and_get();
		Providers::instance()->get( 'email' )->handle_enrol( $with->ID, array() );

		$this->assertFalse( apply_filters( 'two_factor_is_required_for_user', true, $with ) );
		$this->assertTrue( apply_filters( 'two_factor_is_required_for_user', true, $without ) );
		$this->assertFalse( apply_filters( 'two_factor_is_required_for_user', false, $without ) );
	}
}
