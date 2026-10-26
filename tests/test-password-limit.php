<?php

declare( strict_types=1 );

class Test_Password_Limit extends WP_UnitTestCase {

	use Clears_Attempts;

	private const PASS = 'right-password';

	/** @var string|null */
	private $remote;

	public function set_up(): void {
		parent::set_up();
		\Sigil\Password_Limit::instance();
		\Sigil\Policy::update( array( 'limit_passwords' => true ) );
		$this->remote           = $_SERVER['REMOTE_ADDR'] ?? null;
		$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
	}

	public function tear_down(): void {
		$_SERVER['REMOTE_ADDR'] = $this->remote;
		remove_all_filters( 'sigil_password_limits' );
		parent::tear_down();
	}

	private function user(): WP_User {
		return self::factory()->user->create_and_get( array( 'user_pass' => self::PASS ) );
	}

	private function fail_times( string $login, int $times ): void {
		for ( $i = 0; $i < $times; $i++ ) {
			wp_authenticate( $login, 'wrong-password' );
		}
	}

	private function limits( array $limits ): void {
		add_filter(
			'sigil_password_limits',
			static function ( $defaults ) use ( $limits ) {
				return array_merge( $defaults, $limits );
			}
		);
	}

	private function assertLimited( $result ): void {
		$this->assertWPError( $result );
		$this->assertSame( 'sigil_password_limited', $result->get_error_code() );
	}

	private static function account_expiry( string $login ): int {
		global $wpdb;

		$table = \Sigil\Rate_Limit::table();

		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT expires FROM {$table} WHERE bucket = %s", hash( 'sha256', \Sigil\Password_Limit::account_key( $login ) ) ) );
	}

	private static function age_out( string $login ): void {
		global $wpdb;

		$wpdb->update(
			\Sigil\Rate_Limit::table(),
			array( 'expires' => time() - 1 ),
			array( 'bucket' => hash( 'sha256', \Sigil\Password_Limit::account_key( $login ) ) )
		);
	}

	public function test_five_wrong_passwords_and_then_even_the_right_one_is_refused(): void {
		$user = $this->user();
		$this->fail_times( $user->user_login, 5 );

		$this->assertLimited( wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_four_wrong_passwords_still_let_the_right_one_in(): void {
		$user = $this->user();
		$this->fail_times( $user->user_login, 4 );

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_the_right_password_starts_the_count_again(): void {
		$user = $this->user();
		$this->fail_times( $user->user_login, 4 );
		wp_authenticate( $user->user_login, self::PASS );
		$this->fail_times( $user->user_login, 4 );

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_an_account_that_does_not_exist_is_refused_the_same_way(): void {
		$user = $this->user();
		$this->fail_times( $user->user_login, 5 );
		$this->fail_times( 'nobody-by-this-name', 5 );

		$real    = wp_authenticate( $user->user_login, 'wrong-password' );
		$missing = wp_authenticate( 'nobody-by-this-name', 'wrong-password' );

		$this->assertLimited( $real );
		$this->assertLimited( $missing );
		$this->assertSame( $real->get_error_message(), $missing->get_error_message() );
	}

	public function test_the_count_ignores_letter_case(): void {
		$user = $this->user();
		$this->fail_times( strtoupper( $user->user_login ), 5 );

		$this->assertLimited( wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_a_lockout_ends_with_time(): void {
		$user = $this->user();
		$this->fail_times( $user->user_login, 6 );

		self::age_out( $user->user_login );

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_each_lockout_in_a_day_lasts_longer_up_to_the_ceiling(): void {
		$user   = $this->user();
		$window = 15 * MINUTE_IN_SECONDS;

		$lengths = array();
		for ( $round = 0; $round < 4; $round++ ) {
			$this->fail_times( $user->user_login, 6 );
			$lengths[] = self::account_expiry( $user->user_login ) - time();
			self::age_out( $user->user_login );
		}

		$this->assertEqualsWithDelta( $window, $lengths[0], 5 );
		$this->assertEqualsWithDelta( 2 * $window, $lengths[1], 5 );
		$this->assertEqualsWithDelta( HOUR_IN_SECONDS, $lengths[2], 5 );
		$this->assertEqualsWithDelta( HOUR_IN_SECONDS, $lengths[3], 5, 'never longer than the ceiling' );
	}

	public function test_hammering_a_locked_account_does_not_extend_it(): void {
		$user = $this->user();
		$this->fail_times( $user->user_login, 6 );
		$first = self::account_expiry( $user->user_login );

		$this->fail_times( $user->user_login, 20 );

		$this->assertSame( $first, self::account_expiry( $user->user_login ) );
	}

	public function test_one_address_failing_across_many_accounts_is_stopped(): void {
		$this->limits( array( 'ip_attempts' => 3 ) );
		$user = $this->user();

		$this->fail_times( 'spray-one', 1 );
		$this->fail_times( 'spray-two', 1 );
		$this->fail_times( 'spray-three', 1 );

		$this->assertLimited( wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_successful_sign_ins_never_close_the_address(): void {
		$this->limits( array( 'ip_attempts' => 3 ) );

		for ( $i = 0; $i < 6; $i++ ) {
			$user = $this->user();
			$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
		}
	}

	public function test_another_address_is_not_affected(): void {
		$this->limits( array( 'ip_attempts' => 3 ) );
		$this->fail_times( 'spray-one', 3 );
		$user = $this->user();

		$_SERVER['REMOTE_ADDR'] = '198.51.100.8';

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_the_limits_can_be_tuned(): void {
		$this->limits( array( 'attempts' => 2 ) );
		$user = $this->user();
		$this->fail_times( $user->user_login, 2 );

		$this->assertLimited( wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_switched_off_nothing_is_limited(): void {
		\Sigil\Policy::update( array( 'limit_passwords' => false ) );
		$user = $this->user();
		$this->fail_times( $user->user_login, 10 );

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_on_by_default(): void {
		delete_option( \Sigil\Policy::OPTION_KEY );

		$this->assertTrue( \Sigil\Policy::get()['limit_passwords'] );
	}

	public function test_a_refusal_for_another_reason_is_not_a_guess(): void {
		$user = $this->user();
		$deny = static function ( $result ) {
			return $result instanceof WP_User ? new WP_Error( 'captcha_failed', 'No.' ) : $result;
		};
		add_filter( 'authenticate', $deny, 99 );
		for ( $i = 0; $i < 6; $i++ ) {
			wp_authenticate( $user->user_login, self::PASS );
		}
		remove_filter( 'authenticate', $deny, 99 );

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_an_empty_password_is_not_counted(): void {
		$user = $this->user();
		for ( $i = 0; $i < 6; $i++ ) {
			wp_authenticate( $user->user_login, '' );
		}

		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_without_a_counter_table_password_sign_in_still_works(): void {
		global $wpdb;

		$user = $this->user();
		self::set_repair_spent( true );
		$table = \Sigil\Rate_Limit::table();
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );

		$result = wp_authenticate( $user->user_login, self::PASS );

		self::set_repair_spent( false );
		\Sigil\Schema::install();

		$this->assertInstanceOf( WP_User::class, $result );
	}

	public function test_unlock_reopens_an_account_locked_by_its_username_and_its_email(): void {
		$user = $this->user();
		$this->fail_times( $user->user_login, 6 );
		$this->fail_times( $user->user_email, 6 );

		$cleared = \Sigil\Password_Limit::unlock( $user );

		$this->assertSame( 6, $cleared[ 'password: ' . strtolower( $user->user_login ) ] );
		$this->assertSame( 6, $cleared[ 'password: ' . strtolower( $user->user_email ) ] );
		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_email, self::PASS ) );
	}

	public function test_unlock_forgets_earlier_lockouts_too(): void {
		$user = $this->user();
		$this->fail_times( $user->user_login, 6 );
		self::age_out( $user->user_login );
		$this->fail_times( $user->user_login, 6 );

		\Sigil\Password_Limit::unlock( $user );
		$this->fail_times( $user->user_login, 6 );

		$this->assertEqualsWithDelta( 15 * MINUTE_IN_SECONDS, self::account_expiry( $user->user_login ) - time(), 5, 'the next lockout starts again from the shortest' );
	}

	public function test_unlock_leaves_the_address_alone_unless_given_one(): void {
		$this->limits( array( 'ip_attempts' => 3 ) );
		$user = $this->user();
		$this->fail_times( 'spray-one', 3 );

		$cleared = \Sigil\Password_Limit::unlock( $user );
		$this->assertLimited( wp_authenticate( $user->user_login, self::PASS ) );
		$this->assertCount( 2, $cleared );

		// Three failures, and the refusal above, which counts against a closed address.
		$cleared = \Sigil\Password_Limit::unlock( $user, '198.51.100.7' );
		$this->assertSame( 4, $cleared['password: address 198.51.100.7'] );
		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_unlock_leaves_the_challenge_counters_alone_unless_asked(): void {
		$user = $this->user();
		$ip   = \Sigil\Challenge::ip_rate_key();
		\Sigil\Rate_Limit::reserve( 'u:' . $user->ID );
		\Sigil\Rate_Limit::reserve( $ip );

		$cleared = \Sigil\Password_Limit::unlock( $user, '198.51.100.7' );

		$this->assertArrayNotHasKey( 'challenge: account', $cleared );
		$this->assertSame( 1, \Sigil\Rate_Limit::count( 'u:' . $user->ID ) );
		$this->assertSame( 1, \Sigil\Rate_Limit::count( $ip ) );

		$cleared = \Sigil\Password_Limit::unlock( $user, '198.51.100.7', true );

		$this->assertSame( 1, $cleared['challenge: account'] );
		$this->assertSame( 1, $cleared['challenge: address 198.51.100.7'] );
		$this->assertSame( 0, \Sigil\Rate_Limit::count( 'u:' . $user->ID ) );
		$this->assertSame( 0, \Sigil\Rate_Limit::count( $ip ) );
	}

	public function test_unlock_touches_no_other_account(): void {
		$user  = $this->user();
		$other = $this->user();
		$this->fail_times( $other->user_login, 6 );

		\Sigil\Password_Limit::unlock( $user );

		$this->assertLimited( wp_authenticate( $other->user_login, self::PASS ) );
	}

	/**
	 * MySQL's collation matches these to the stored login, and so does core's
	 * password check, so each one is another way to guess at the same account.
	 *
	 * @return list<string>
	 */
	private static function spellings( string $login ): array {
		return array(
			strtoupper( $login ),
			substr( $login, 0, 3 ) . "\u{200d}" . substr( $login, 3 ),
			"\u{ff56}\u{ff41}\u{ff52}" . substr( $login, 3 ),
			strtoupper( $login ) . "\u{00a0}",
			'v' . "\u{00e1}" . substr( $login, 2 ),
		);
	}

	public function test_every_spelling_of_a_login_counts_against_the_one_account(): void {
		$user = self::factory()->user->create_and_get( array( 'user_login' => 'varuser', 'user_pass' => self::PASS ) );

		foreach ( self::spellings( 'varuser' ) as $spelling ) {
			$this->assertSame( (int) $user->ID, (int) get_user_by( 'login', sanitize_user( $spelling ) )->ID, 'the database resolves ' . wp_json_encode( $spelling ) );
			wp_authenticate( $spelling, 'wrong-password' );
		}

		$this->assertLimited( wp_authenticate( $user->user_login, self::PASS ) );
	}

	public function test_a_locked_login_stays_locked_under_another_spelling(): void {
		self::factory()->user->create( array( 'user_login' => 'varuser', 'user_pass' => self::PASS ) );
		$this->fail_times( 'varuser', 5 );

		foreach ( self::spellings( 'varuser' ) as $spelling ) {
			$this->assertLimited( wp_authenticate( $spelling, self::PASS ) );
		}
	}

	public function test_spellings_of_an_email_share_the_emails_bucket(): void {
		$user = self::factory()->user->create_and_get( array( 'user_email' => 'mixed@example.com', 'user_pass' => self::PASS ) );
		$this->fail_times( 'MIXED@example.com', 3 );
		$this->fail_times( 'Mixed@Example.COM', 2 );

		$this->assertLimited( wp_authenticate( 'mixed@example.com', self::PASS ) );
		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, self::PASS ), 'the login keeps its own allowance' );
	}

	public function test_a_name_nobody_has_is_counted_under_its_normalised_form(): void {
		$this->fail_times( 'ghost', 3 );
		$this->fail_times( "GHO\u{200b}ST", 2 );

		$this->assertLimited( wp_authenticate( 'ghost', 'wrong-password' ) );
	}

	public function test_a_login_ending_in_strikes_never_touches_another_accounts_lockouts(): void {
		$user = self::factory()->user->create_and_get( array( 'user_login' => 'x', 'user_pass' => self::PASS ) );
		$this->fail_times( 'x:strikes', 5 );

		$this->fail_times( 'x', 6 );

		$this->assertEqualsWithDelta( 15 * MINUTE_IN_SECONDS, self::account_expiry( 'x' ) - time(), 5, 'the first lockout is the shortest' );
	}

	public function test_unlock_clears_what_any_spelling_counted(): void {
		$user = self::factory()->user->create_and_get( array( 'user_login' => 'varuser', 'user_pass' => self::PASS ) );
		foreach ( self::spellings( 'varuser' ) as $spelling ) {
			wp_authenticate( $spelling, 'wrong-password' );
		}
		wp_authenticate( 'varuser', 'wrong-password' );

		\Sigil\Password_Limit::unlock( $user );

		$this->assertInstanceOf( WP_User::class, wp_authenticate( 'varuser', self::PASS ) );
	}

	/**
	 * Spellings MySQL's collation counts as the same name: case, accents,
	 * zero-width joiners, full-width letters and trailing non-breaking spaces.
	 *
	 * @return list<string>
	 */
	private static function variants( string $base ): array {
		$fullwidth = '';
		foreach ( str_split( substr( $base, 0, 3 ) ) as $char ) {
			$fullwidth .= mb_chr( ord( $char ) + 0xFEE0, 'UTF-8' );
		}

		return array(
			strtoupper( $base ),
			substr( $base, 0, 3 ) . "\u{200d}" . substr( $base, 3 ),
			$fullwidth . substr( $base, 3 ),
			$base . "\u{00a0}",
			preg_replace( '/a/', "\u{00e1}", $base, 1 ),
		);
	}

	private static function rename_login( int $user_id, string $login ): void {
		global $wpdb;

		$wpdb->update( $wpdb->users, array( 'user_login' => $login ), array( 'ID' => $user_id ) );
		clean_user_cache( $user_id );
	}

	/**
	 * Locking a name and trying a variant must say nothing about whether the
	 * account exists, so both kinds of name merge spellings the same way.
	 */
	public function test_variants_of_an_existing_and_a_missing_login_merge_alike(): void {
		$user = self::factory()->user->create_and_get( array( 'user_pass' => self::PASS ) );
		self::rename_login( (int) $user->ID, "\u{03c3}varuser" );

		foreach ( array( 'varuser', 'garuser' ) as $base ) {
			$name     = "\u{03c3}" . $base;
			$key      = \Sigil\Password_Limit::account_key( $name );
			$variants = array_map(
				static function ( $variant ) {
					return "\u{03c3}" . $variant;
				},
				self::variants( $base )
			);
			// Greek final sigma, which NFKC and lowercasing leave alone.
			$variants[] = "\u{03c2}" . $base;
			$variants[] = "\u{03a3}" . strtoupper( $base );

			foreach ( $variants as $variant ) {
				$this->assertSame( $key, \Sigil\Password_Limit::account_key( $variant ), wp_json_encode( $variant ) . ' merges with ' . wp_json_encode( $name ) );
			}
		}
	}

	public function test_a_missing_name_merges_final_sigma_as_the_database_does(): void {
		$this->assertSame(
			\Sigil\Password_Limit::account_key( "\u{03c3}garuser" ),
			\Sigil\Password_Limit::account_key( "\u{03c2}garuser" )
		);
	}

	public function test_an_existing_login_keys_the_same_as_any_name_that_reaches_it(): void {
		$user = self::factory()->user->create_and_get( array( 'user_login' => 'varuser', 'user_pass' => self::PASS ) );

		foreach ( self::variants( 'varuser' ) as $variant ) {
			$found = get_user_by( 'login', sanitize_user( $variant ) );
			if ( $found instanceof WP_User ) {
				$this->assertSame( (int) $user->ID, (int) $found->ID );
				$this->assertSame( \Sigil\Password_Limit::account_key( $found->user_login ), \Sigil\Password_Limit::account_key( $variant ), wp_json_encode( $variant ) );
			}
		}
	}

	public function test_variants_of_an_existing_and_a_missing_email_merge_alike(): void {
		self::factory()->user->create( array( 'user_email' => 'mixed@example.com' ) );

		foreach ( array( 'mixed@example.com', 'nomail@example.com' ) as $email ) {
			$key = \Sigil\Password_Limit::account_key( $email );
			$this->assertSame( $key, \Sigil\Password_Limit::account_key( strtoupper( $email ) ) );
			$this->assertSame( $key, \Sigil\Password_Limit::account_key( ucfirst( $email ) ) );
		}
	}

	public function test_without_collation_weights_the_normaliser_still_merges_the_common_spellings(): void {
		$cache = new ReflectionProperty( \Sigil\Password_Limit::class, 'collations' );
		$cache->setAccessible( true );
		$cache->setValue( null, array( 'user_login' => '', 'user_email' => '' ) );

		$key = \Sigil\Password_Limit::account_key( 'garuser' );
		$merged = array();
		foreach ( array( 'GARUSER', "gar\u{200d}user", "garuser\u{00a0}", "\u{ff47}\u{ff41}\u{ff52}user" ) as $variant ) {
			$merged[] = \Sigil\Password_Limit::account_key( $variant ) === $key;
		}

		$cache->setValue( null, null );

		$this->assertSame( array( true, true, true, true ), $merged );
	}
}
