<?php

declare( strict_types=1 );

/**
 * Adding a passkey is the quietest way to make access to an account permanent,
 * and with passwordless sign-in on it is a whole credential, not half of one.
 * So it has to be as loud as any other change of method.
 */
class Test_Passkey_Enrolment extends WP_Ajax_UnitTestCase {

	use Passkey_Fixtures;
	use Signed_In;

	/** @var list<array<string, mixed>> */
	private array $sent = array();

	public function set_up(): void {
		if ( PHP_VERSION_ID < 80000 ) {
			$this->markTestSkipped( 'Passkeys need PHP 8.0.' );
		}

		parent::set_up();
		\Sigil\Schema::install();
		\Sigil\Trusted_Devices::instance()->register();
		\Sigil\Policy::update( array( 'passwordless' => true ) );
		unset( $_REQUEST['_wpnonce'] );

		$this->sent = array();
		add_filter(
			'wp_mail',
			function ( $args ) {
				$this->sent[] = $args;
				return $args;
			}
		);
	}

	private function owner(): int {
		$id = (int) self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->sign_in( $id );

		return $id;
	}

	private function admin(): int {
		$id = (int) self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}

		return $id;
	}

	private function mail_text(): string {
		return implode( "\n", array_map( static fn ( $m ) => (string) $m['subject'] . "\n" . (string) $m['message'], $this->sent ) );
	}

	public function test_registering_a_passkey_fires_the_change_hooks(): void {
		$user   = $this->owner();
		$before = did_action( 'sigil_before_methods_change' );
		$after  = did_action( 'sigil_methods_changed' );

		$response = $this->register_over_ajax( $user, self::new_key(), random_bytes( 32 ) );

		$this->assertTrue( $response['success'] ?? false, wp_json_encode( $response ) );
		$this->assertCount( 1, \Sigil\Credentials::for_user( $user ) );
		$this->assertSame( $before + 1, did_action( 'sigil_before_methods_change' ) );
		$this->assertSame( $after + 1, did_action( 'sigil_methods_changed' ) );
	}

	public function test_a_second_passkey_emails_the_owner_by_name(): void {
		$user = $this->owner();
		$this->register_over_ajax( $user, self::new_key(), random_bytes( 32 ), 'Phone' );
		$this->sent = array();

		$response = $this->register_over_ajax( $user, self::new_key(), random_bytes( 32 ), 'Office laptop' );

		$this->assertTrue( $response['success'] ?? false, wp_json_encode( $response ) );
		$this->assertCount( 1, $this->sent, 'one mail about the new passkey' );
		$this->assertSame( get_userdata( $user )->user_email, $this->sent[0]['to'] );
		$this->assertStringContainsString( 'A passkey named "Office laptop" was added', $this->mail_text() );
	}

	public function test_replacing_a_passkey_names_the_new_one_and_the_old_one(): void {
		$user = $this->owner();
		$this->register_over_ajax( $user, self::new_key(), random_bytes( 32 ), 'Old phone' );
		$old        = \Sigil\Credentials::for_user( $user )[0];
		$this->sent = array();

		$response = $this->register_over_ajax( $user, self::new_key(), random_bytes( 32 ), 'New phone', (int) $old->id );

		$this->assertTrue( $response['success'] ?? false, wp_json_encode( $response ) );
		$labels = array_map( static fn ( $row ) => (string) $row->label, \Sigil\Credentials::for_user( $user ) );
		$this->assertSame( array( 'New phone' ), $labels );
		$this->assertCount( 1, $this->sent );
		$this->assertStringContainsString( 'A passkey named "New phone" was added', $this->mail_text() );
		$this->assertStringContainsString( 'A passkey named "Old phone" was removed', $this->mail_text() );
	}

	public function test_registering_a_passkey_revokes_trusted_devices(): void {
		$user  = $this->owner();
		$token = \Sigil\Trusted_Devices::instance()->trust_current_device( $user );

		$this->register_over_ajax( $user, self::new_key(), random_bytes( 32 ) );

		$this->assertFalse( \Sigil\Trusted_Devices::instance()->is_trusted( $user, $token ) );
	}

	public function test_removing_passkeys_fires_the_change_hooks_and_says_which(): void {
		$user = $this->owner();
		$this->register_over_ajax( $user, self::new_key(), random_bytes( 32 ), 'Phone' );
		$this->sent = array();
		$after      = did_action( 'sigil_methods_changed' );

		$result = \Sigil\Enrolment::instance()->remove_method( $user, 'passkey' );

		$this->assertTrue( $result );
		$this->assertSame( $after + 1, did_action( 'sigil_methods_changed' ) );
		$this->assertStringContainsString( 'A passkey named "Phone" was removed', $this->mail_text() );
	}

	// The control for the test below: the same sign-in works for a passkey the
	// owner registered, so a refusal there is about who registered it.
	public function test_a_passkey_the_owner_registered_signs_in_on_its_own(): void {
		$user = $this->owner();
		$key  = self::new_key();
		$cred = random_bytes( 32 );
		$this->register_over_ajax( $user, $key, $cred );

		$signed = $this->passwordless_assertion( $key, $cred, $user );
		$result = \Sigil\Passwordless::instance()->sign_on( $signed['ceremony'], $signed['assertion'], false );

		$this->assertInstanceOf( WP_User::class, $result );
		$this->assertSame( $user, (int) $result->ID );
	}

	public function test_a_passkey_an_administrator_registered_is_a_second_factor_only(): void {
		$owner = (int) self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$admin = $this->admin();
		$this->sign_in( $admin );
		$key  = self::new_key();
		$cred = random_bytes( 32 );

		$response = $this->register_over_ajax( $owner, $key, $cred, 'Desk key' );
		$this->assertTrue( $response['success'] ?? false, wp_json_encode( $response ) );

		wp_set_current_user( 0 );
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );

		$signed = $this->passwordless_assertion( $key, $cred, $owner );
		$result = \Sigil\Passwordless::instance()->sign_on( $signed['ceremony'], $signed['assertion'], false );
		$this->assertWPError( $result, 'never a whole sign-in' );

		// Still good after the password.
		$options = $this->passkey_provider()->auth_options( $owner );
		$this->assertNotNull( $options );
		$assertion = self::signed_assertion( $options->publicKey->challenge->getBinaryString(), $key, $cred, (string) $owner, 2 );
		$this->assertTrue( $this->passkey_provider()->validate( $owner, array( 'passkey_assertion' => wp_json_encode( $assertion ) ) ) );

		$this->assertSame( get_userdata( $owner )->user_email, $this->sent[0]['to'] ?? '' );
		$this->assertStringContainsString( get_userdata( $admin )->display_name, $this->mail_text() );
	}
}
