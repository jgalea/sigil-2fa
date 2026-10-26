<?php

declare( strict_types=1 );

/**
 * Signing in with a passkey alone, end to end through wp_signon().
 *
 * The assertions are signed here with a real P-256 key, the way an
 * authenticator signs them, so the WebAuthn library verifies them for real.
 */
class Test_Passwordless extends WP_UnitTestCase {

	use Clears_Attempts;

	private const UP_UV = 0x05;
	private const UP    = 0x01;

	/** @var \OpenSSLAsymmetricKey|resource */
	private $key;

	private string $credential_id;

	private int $user_id;

	public function tear_down(): void {
		unset( $_COOKIE['sigil_passwordless'], $_SERVER['HTTP_ORIGIN'] );
		parent::tear_down();
	}

	public function set_up(): void {
		if ( PHP_VERSION_ID < 80000 ) {
			$this->markTestSkipped( 'Passkeys need PHP 8.0.' );
		}

		parent::set_up();

		Sigil\Policy::update( array( 'passwordless' => true ) );

		$this->user_id       = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->key           = openssl_pkey_new(
			array(
				'private_key_type' => OPENSSL_KEYTYPE_EC,
				'curve_name'       => 'prime256v1',
			)
		);
		$this->credential_id = random_bytes( 32 );

		$pem = openssl_pkey_get_details( $this->key )['key'];
		Sigil\Credentials::add( $this->user_id, $this->credential_id, $pem, 0, 'Test key', 'internal', (string) $this->user_id, true );
		Sigil\Store::set_method( $this->user_id, 'passkey', array( 'enrolled_at' => time() ) );
	}

	private function passkey(): Sigil\Providers\Passkey {
		$provider = Sigil\Providers::instance()->get( 'passkey' );
		$this->assertInstanceOf( Sigil\Providers\Passkey::class, $provider );

		return $provider;
	}

	private static function b64url( string $raw ): string {
		return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
	}

	/**
	 * @return array{ceremony: string, assertion: array<string, string>}
	 */
	private function signed( int $flags = self::UP_UV, int $counter = 0, ?string $handle = null ): array {
		// Minted the way the login page asks for it, which binds the ceremony
		// to this browser.
		$minted = Sigil\Passwordless::instance()->mint();
		$this->assertNotNull( $minted );

		$challenge = $minted['options']->publicKey->challenge->getBinaryString();
		$rp_id     = Sigil\Providers\Passkey::rp_id();

		$client_data = (string) wp_json_encode(
			array(
				'type'      => 'webauthn.get',
				'challenge' => self::b64url( $challenge ),
				'origin'    => 'https://' . $rp_id,
			)
		);
		$auth_data   = hash( 'sha256', $rp_id, true ) . chr( $flags ) . pack( 'N', $counter );

		openssl_sign( $auth_data . hash( 'sha256', $client_data, true ), $signature, $this->key, OPENSSL_ALGO_SHA256 );

		return array(
			'ceremony'  => $minted['ceremony'],
			'assertion' => array(
				'id'                => self::b64url( $this->credential_id ),
				'clientDataJSON'    => self::b64url( $client_data ),
				'authenticatorData' => self::b64url( $auth_data ),
				'signature'         => self::b64url( $signature ),
				'userHandle'        => self::b64url( $handle ?? (string) $this->user_id ),
			),
		);
	}

	/**
	 * @param array{ceremony: string, assertion: array<string, string>} $signed
	 * @return WP_User|WP_Error
	 */
	private function sign_on( array $signed ) {
		return Sigil\Passwordless::instance()->sign_on( $signed['ceremony'], $signed['assertion'], false );
	}

	public function test_a_verified_passkey_signs_in_without_a_password_or_a_challenge(): void {
		$logins = did_action( 'wp_login' );
		$passed = did_action( 'sigil_challenge_passed' );

		// Challenge::on_login exits to draw the challenge screen, so reaching
		// the assertions at all means the sign-in was not sent there.
		$user = $this->sign_on( $this->signed() );

		$this->assertInstanceOf( WP_User::class, $user );
		$this->assertSame( $this->user_id, (int) $user->ID );
		$this->assertSame( $logins + 1, did_action( 'wp_login' ), 'wp_login fires as for any sign-in' );
		$this->assertSame( $passed + 1, did_action( 'sigil_challenge_passed' ), 'and it counts as passing the second factor' );
		$this->assertTrue( (bool) apply_filters( 'sigil_skip_challenge', false, $user ) );
	}

	public function test_the_skip_covers_only_the_account_the_passkey_signed_in(): void {
		$this->sign_on( $this->signed() );

		$other = self::factory()->user->create_and_get();
		$this->assertFalse( (bool) apply_filters( 'sigil_skip_challenge', false, $other ) );
	}

	public function test_an_assertion_without_user_verification_is_refused(): void {
		$failed = did_action( 'wp_login_failed' );

		$result = $this->sign_on( $this->signed( self::UP ) );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_passkey_failed', $result->get_error_code() );
		$this->assertSame( $failed + 1, did_action( 'wp_login_failed' ), 'a refusal reaches wp_login_failed' );
	}

	public function test_a_ceremony_cannot_be_spent_twice(): void {
		$signed = $this->signed();

		$this->assertInstanceOf( WP_User::class, $this->sign_on( $signed ) );
		$this->assertWPError( $this->sign_on( $signed ) );
	}

	public function test_a_user_handle_naming_someone_else_is_refused(): void {
		$other = (string) self::factory()->user->create();

		$this->assertWPError( $this->sign_on( $this->signed( self::UP_UV, 0, $other ) ) );
	}

	public function test_a_counter_that_goes_backwards_is_refused(): void {
		$this->assertInstanceOf( WP_User::class, $this->sign_on( $this->signed( self::UP_UV, 10 ) ) );
		$this->assertWPError( $this->sign_on( $this->signed( self::UP_UV, 5 ) ) );
	}

	public function test_a_passkey_whose_method_was_removed_does_not_sign_in(): void {
		Sigil\Store::remove_method( $this->user_id, 'passkey' );

		$this->assertWPError( $this->sign_on( $this->signed() ) );
	}

	public function test_an_account_locked_by_failed_attempts_stays_locked(): void {
		for ( $i = 0; $i < Sigil\Rate_Limit::max_attempts(); $i++ ) {
			Sigil\Rate_Limit::reserve( 'u:' . $this->user_id );
		}

		$result = $this->sign_on( $this->signed() );

		$this->assertWPError( $result );
		$this->assertSame( 'sigil_rate_limited', $result->get_error_code() );
	}

	public function test_failures_count_against_the_address(): void {
		$previous               = $_SERVER['REMOTE_ADDR'] ?? null;
		$_SERVER['REMOTE_ADDR'] = '203.0.113.30';

		$this->sign_on( $this->signed( self::UP ) );
		$count = Sigil\Rate_Limit::count( Sigil\Challenge::ip_rate_key() );

		$_SERVER['REMOTE_ADDR'] = $previous;

		$this->assertSame( 1, $count );
	}

	public function test_switched_off_the_assertion_is_ignored(): void {
		// Minted while it was on: switched off, nothing mints one at all.
		$signed = $this->signed();
		Sigil\Policy::update( array( 'passwordless' => false ) );

		$result = $this->sign_on( $signed );

		$this->assertWPError( $result );
		$this->assertContains( 'empty_username', $result->get_error_codes() );
		$this->assertFalse( Sigil\Passwordless::enabled() );
	}

	public function test_off_where_passkeys_are_unavailable(): void {
		$drop = static function ( $providers ) {
			unset( $providers['passkey'] );
			return $providers;
		};
		add_filter( 'sigil_providers', $drop );

		$this->assertFalse( Sigil\Passwordless::enabled() );

		remove_filter( 'sigil_providers', $drop );
	}

	public function test_a_typed_password_is_left_to_the_password_flow(): void {
		$_POST['sigil_passwordless_ceremony']  = 'x';
		$_POST['sigil_passwordless_assertion'] = '{}';

		$error = new WP_Error( 'incorrect_password', 'no' );
		$this->assertSame( $error, Sigil\Passwordless::instance()->authenticate( $error, 'admin', 'typed' ) );

		unset( $_POST['sigil_passwordless_ceremony'], $_POST['sigil_passwordless_assertion'] );
	}

	public function test_another_filters_refusal_stands(): void {
		$veto = static function () {
			return new WP_Error( 'locked_out', 'Locked out.' );
		};
		add_filter( 'authenticate', $veto, 30 );

		$result = $this->sign_on( $this->signed() );

		remove_filter( 'authenticate', $veto, 30 );

		$this->assertWPError( $result );
		$this->assertSame( 'locked_out', $result->get_error_code() );
	}

	public function test_signing_in_alone_marks_an_old_passkey_discoverable(): void {
		global $wpdb;
		$wpdb->update( Sigil\Schema::table(), array( 'discoverable' => 0 ), array( 'user_id' => $this->user_id ) );

		$this->sign_on( $this->signed() );

		$row = Sigil\Credentials::for_user( $this->user_id )[0];
		$this->assertSame( 1, (int) $row->discoverable );
	}

	public function test_the_options_ask_for_any_passkey_with_user_verification(): void {
		$minted  = $this->passkey()->discoverable_options();
		$options = $minted['options']->publicKey;

		$this->assertSame( 'required', $options->userVerification );
		$this->assertFalse( property_exists( $options, 'allowCredentials' ) );
		$this->assertSame( Sigil\Providers\Passkey::rp_id(), $options->rpId );
	}

	public function test_the_setting_defaults_to_on(): void {
		Sigil\Network::delete_option( Sigil\Policy::OPTION_KEY );

		$this->assertTrue( Sigil\Policy::get()['passwordless'] );
	}

	public function test_a_passkey_with_no_recorded_handle_still_signs_in(): void {
		global $wpdb;
		$wpdb->update( Sigil\Schema::table(), array( 'user_handle' => '' ), array( 'user_id' => $this->user_id ) );

		// An imported passkey hands back the source plugin's handle.
		$this->assertInstanceOf( WP_User::class, $this->sign_on( $this->signed( self::UP_UV, 0, random_bytes( 16 ) ) ) );
	}

	private function rest( string $method, array $body = array() ): WP_REST_Response {
		global $wp_rest_server;
		$wp_rest_server = new WP_REST_Server();
		do_action( 'rest_api_init' );

		$request = new WP_REST_Request( $method, '/sigil/v1/passwordless' );
		foreach ( $body as $key => $value ) {
			$request->set_param( $key, $value );
		}

		$response = $wp_rest_server->dispatch( $request );
		$wp_rest_server = null;

		return $response;
	}

	public function test_rest_hands_out_a_ceremony(): void {
		$data = $this->rest( 'GET' )->get_data();

		$this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/', $data['ceremony'] );
		$this->assertSame( 'required', $data['options']['publicKey']['userVerification'] );
		$this->assertIsString( $data['options']['publicKey']['challenge'] );
	}

	public function test_rest_signs_in_with_a_passkey(): void {
		$signed   = $this->signed();
		$response = $this->rest( 'POST', $signed );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( $this->user_id, $response->get_data()['user_id'] );
		$this->assertSame( $this->user_id, get_current_user_id() );
	}

	public function test_rest_refuses_a_bad_assertion(): void {
		$response = $this->rest( 'POST', $this->signed( self::UP ) );

		$this->assertSame( 401, $response->get_status() );
		$this->assertSame( 0, get_current_user_id() );
	}

	public function test_rest_is_closed_when_switched_off(): void {
		Sigil\Policy::update( array( 'passwordless' => false ) );

		$this->assertSame( 404, $this->rest( 'GET' )->get_status() );
	}

	// On REST and AJAX nothing comes back after wp_signon() to issue a held
	// cookie again, so the one it sets has to be the one that goes out.
	public function test_the_session_goes_out_with_the_sign_in_itself(): void {
		$sent = &$this->record_cookies_ref();

		$this->assertInstanceOf( WP_User::class, $this->sign_on( $this->signed() ) );

		$this->assertSame( array( true ), $sent );
		$this->assertCount( 1, WP_Session_Tokens::get_instance( $this->user_id )->get_all() );
	}

	public function test_a_failed_passkey_issues_no_session(): void {
		$sent = &$this->record_cookies_ref();

		$this->assertWPError( $this->sign_on( $this->signed( self::UP ) ) );
		wp_set_auth_cookie( $this->user_id );

		$this->assertSame( array( false ), $sent );
	}

	public function test_a_passkey_still_signs_in_an_account_locked_by_wrong_passwords(): void {
		\Sigil\Password_Limit::instance();
		\Sigil\Policy::update( array( 'limit_passwords' => true ) );
		$login = get_userdata( $this->user_id )->user_login;
		for ( $i = 0; $i < 6; $i++ ) {
			wp_authenticate( $login, 'wrong-password' );
		}
		$this->assertSame( 'sigil_password_limited', wp_authenticate( $login, 'wrong-password' )->get_error_code() );

		$this->assertInstanceOf( WP_User::class, $this->sign_on( $this->signed() ) );
	}

	/** @var list<bool> */
	private array $sent_cookies = array();

	/**
	 * @return list<bool>
	 */
	private function &record_cookies_ref(): array {
		// The account was created in this same request, which the guard lets
		// through as a new registration.
		foreach ( array( 'new_users', 'granted', 'issued' ) as $property ) {
			$prop = new ReflectionProperty( \Sigil\Login_Guard::class, $property );
			$prop->setAccessible( true );
			$prop->setValue( \Sigil\Login_Guard::instance(), array() );
		}

		$this->sent_cookies = array();
		remove_filter( 'send_auth_cookies', '__return_false' );
		add_filter(
			'send_auth_cookies',
			function ( $send, $expire, $expiration, $user_id ) {
				if ( $user_id > 0 ) {
					$this->sent_cookies[] = (bool) $send;
				}
				return false;
			},
			PHP_INT_MAX,
			4
		);
		return $this->sent_cookies;
	}

	// The REST route runs wp_signon() on a REST request, where core's
	// application-password check answers an empty username with
	// invalid_username once anyone on the site has an application password.
	public function test_the_rest_route_signs_in_on_a_site_using_application_passwords(): void {
		update_network_option( null, 'using_application_passwords', 1 );
		add_filter( 'application_password_is_api_request', '__return_true' );

		$user = $this->sign_on( $this->signed() );

		remove_filter( 'application_password_is_api_request', '__return_true' );
		delete_network_option( null, 'using_application_passwords' );

		$this->assertInstanceOf( WP_User::class, $user );
		$this->assertSame( $this->user_id, (int) $user->ID );
	}

	// A page on another site can post a ceremony and assertion the attacker
	// made with their own passkey, and sign the visitor into the attacker's
	// account. The ceremony only counts from the browser that asked for it.
	public function test_a_ceremony_spent_without_the_browser_that_asked_for_it_signs_nobody_in(): void {
		$signed = $this->signed();
		unset( $_COOKIE['sigil_passwordless'] );

		$this->assertWPError( $this->sign_on( $signed ) );
	}

	public function test_a_ceremony_spent_from_another_browser_signs_nobody_in(): void {
		$signed                         = $this->signed();
		$_COOKIE['sigil_passwordless'] = bin2hex( random_bytes( 32 ) );

		$this->assertWPError( $this->sign_on( $signed ) );
	}

	public function test_switched_off_no_ceremony_is_minted(): void {
		Sigil\Policy::update( array( 'passwordless' => false ) );

		$this->assertNull( Sigil\Passwordless::instance()->mint() );
	}

	public function test_a_browser_keeps_one_binding_across_ceremonies(): void {
		$first  = $this->signed();
		$cookie = $_COOKIE['sigil_passwordless'];
		$this->signed();

		$this->assertSame( $cookie, $_COOKIE['sigil_passwordless'] );
		$this->assertInstanceOf( WP_User::class, $this->sign_on( $first ), 'an earlier tab still works' );
	}

	public function test_a_post_from_another_origin_is_refused(): void {
		$signed                 = $this->signed();
		$_SERVER['HTTP_ORIGIN'] = 'https://attacker.example';

		$this->assertWPError( $this->sign_on( $signed ) );
	}

	public function test_a_post_from_the_sites_own_origin_is_accepted(): void {
		$signed                 = $this->signed();
		$parts                  = wp_parse_url( home_url() );
		$_SERVER['HTTP_ORIGIN'] = $parts['scheme'] . '://' . $parts['host'] . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' );

		$this->assertInstanceOf( WP_User::class, $this->sign_on( $signed ) );
	}

	// Someone with a passkey account of their own could otherwise wipe the
	// address count between guesses at other accounts.
	public function test_signing_in_with_a_passkey_leaves_the_addresses_failures_counted(): void {
		$previous               = $_SERVER['REMOTE_ADDR'] ?? null;
		$_SERVER['REMOTE_ADDR'] = '203.0.113.44';
		$ip                     = Sigil\Challenge::ip_rate_key();

		$victim = self::factory()->user->create_and_get();
		( new Sigil\Providers\Backup_Codes() )->generate( (int) $victim->ID );
		for ( $i = 0; $i < 3; $i++ ) {
			Sigil\Challenge::complete( Sigil\Challenge::start( $victim, false ), 'backup', array( 'code' => 'wrong' ) );
		}

		$this->assertInstanceOf( WP_User::class, $this->sign_on( $this->signed() ) );
		$after = Sigil\Rate_Limit::count( $ip );
		$next  = Sigil\Rate_Limit::reserve( $ip );

		$_SERVER['REMOTE_ADDR'] = $previous;

		$this->assertSame( 3, $after );
		$this->assertSame( 4, $next );
	}

	public function test_passing_the_challenge_leaves_the_addresses_failures_counted(): void {
		$previous               = $_SERVER['REMOTE_ADDR'] ?? null;
		$_SERVER['REMOTE_ADDR'] = '203.0.113.45';
		$ip                     = Sigil\Challenge::ip_rate_key();

		$victim = self::factory()->user->create_and_get();
		( new Sigil\Providers\Backup_Codes() )->generate( (int) $victim->ID );
		for ( $i = 0; $i < 3; $i++ ) {
			Sigil\Challenge::complete( Sigil\Challenge::start( $victim, false ), 'backup', array( 'code' => 'wrong' ) );
		}

		$own   = self::factory()->user->create_and_get();
		$codes = ( new Sigil\Providers\Backup_Codes() )->generate( (int) $own->ID );
		$done  = Sigil\Challenge::complete( Sigil\Challenge::start( $own, false ), 'backup', array( 'code' => $codes[0] ) );
		$after = Sigil\Rate_Limit::count( $ip );

		$_SERVER['REMOTE_ADDR'] = $previous;

		$this->assertTrue( $done );
		$this->assertSame( 3, $after );
	}
}
