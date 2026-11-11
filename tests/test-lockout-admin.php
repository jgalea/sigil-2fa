<?php

declare( strict_types=1 );

class Test_Lockout_Admin extends WP_UnitTestCase {

	use Clears_Attempts;

	public function set_up(): void {
		parent::set_up();
		\Sigil\Password_Limit::instance();
		\Sigil\Policy::update( array( 'limit_passwords' => true ) );
		$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
	}

	public function tear_down(): void {
		unset( $_GET['sigil_2fa'], $_REQUEST['_wpnonce'], $_GET['user_id'] );
		parent::tear_down();
	}

	private function locked_user(): WP_User {
		$user = self::factory()->user->create_and_get( array( 'user_pass' => 'right-password' ) );
		for ( $i = 0; $i < 6; $i++ ) {
			wp_authenticate( $user->user_login, 'wrong-password' );
		}

		return $user;
	}

	public function test_a_locked_account_is_reported_with_the_time_left(): void {
		$user = $this->locked_user();

		$this->assertGreaterThan( 0, \Sigil\Password_Limit::locked_for( $user ) );
		$this->assertStringContainsString( 'Locked', \Sigil\Users_Column::instance()->render_column( '', 'sigil', $user->ID ) );

		$open = self::factory()->user->create_and_get();
		$this->assertSame( 0, \Sigil\Password_Limit::locked_for( $open ) );
		$this->assertStringNotContainsString( 'Locked', \Sigil\Users_Column::instance()->render_column( '', 'sigil', $open->ID ) );
	}

	public function test_the_refusal_says_for_how_long(): void {
		$user   = $this->locked_user();
		$result = wp_authenticate( $user->user_login, 'right-password' );

		$this->assertWPError( $result );
		$this->assertMatchesRegularExpression( '/about \d+ minutes?/', $result->get_error_message() );
	}

	public function test_only_a_locked_account_gets_an_unlock_action_and_only_for_an_editor(): void {
		$user = $this->locked_user();
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$actions = \Sigil\Users_Column::instance()->row_actions( array(), $user );
		$this->assertArrayHasKey( 'sigil_unlock', $actions );

		$this->assertSame( array(), \Sigil\Users_Column::instance()->row_actions( array(), self::factory()->user->create_and_get() ) );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$this->assertSame( array(), \Sigil\Users_Column::instance()->row_actions( array(), $user ) );
	}

	public function test_unlocking_reopens_password_and_code_sign_in(): void {
		$user = $this->locked_user();
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$_GET['user_id']     = (string) $user->ID;
		$_REQUEST['_wpnonce'] = wp_create_nonce( 'sigil_unlock_' . $user->ID );

		$stop = static function ( $location ) {
			throw new RuntimeException( (string) $location );
		};
		add_filter( 'wp_redirect', $stop );
		try {
			\Sigil\Users_Column::instance()->handle_unlock();
			$this->fail( 'expected a redirect' );
		} catch ( RuntimeException $e ) {
			$this->assertStringContainsString( 'sigil_unlocked=' . $user->ID, $e->getMessage() );
		} finally {
			remove_filter( 'wp_redirect', $stop );
		}

		$this->assertSame( 0, \Sigil\Password_Limit::locked_for( $user ) );
		$this->assertInstanceOf( WP_User::class, wp_authenticate( $user->user_login, 'right-password' ) );
	}

	public function test_a_user_without_the_capability_cannot_unlock(): void {
		$user = $this->locked_user();
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$_GET['user_id']      = (string) $user->ID;
		$_REQUEST['_wpnonce'] = wp_create_nonce( 'sigil_unlock_' . $user->ID );

		add_filter( 'wp_die_handler', static fn() => static function () {
			throw new RuntimeException( 'died' );
		} );
		$this->expectException( RuntimeException::class );

		try {
			\Sigil\Users_Column::instance()->handle_unlock();
		} finally {
			$this->assertGreaterThan( 0, \Sigil\Password_Limit::locked_for( $user ) );
		}
	}

	public function test_the_status_views_count_and_filter_the_users_list(): void {
		$set_up  = self::factory()->user->create();
		$none    = self::factory()->user->create();
		$overdue = self::factory()->user->create();
		\Sigil\Store::set_method( $set_up, 'totp', array( 'secret' => 'x' ) );
		update_user_meta( $overdue, \Sigil\Policy::DEADLINE_META, time() - DAY_IN_SECONDS );
		update_user_meta( $none, \Sigil\Policy::DEADLINE_META, time() + DAY_IN_SECONDS );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		set_current_screen( 'users' );

		$ids = static function ( string $filter ): array {
			$_GET['sigil_2fa'] = $filter;
			$query             = new WP_User_Query( array( 'fields' => 'ID' ) );
			unset( $_GET['sigil_2fa'] );

			return array_map( 'intval', $query->get_results() );
		};

		$this->assertContains( $set_up, $ids( 'set_up' ) );
		$this->assertNotContains( $none, $ids( 'set_up' ) );
		$this->assertContains( $none, $ids( 'not_set_up' ) );
		$this->assertNotContains( $set_up, $ids( 'not_set_up' ) );
		$this->assertSame( array( $overdue ), $ids( 'overdue' ) );

		$views = \Sigil\Users_Column::instance()->add_views( array() );
		$this->assertArrayHasKey( 'sigil_overdue', $views );
		$this->assertStringContainsString( '(1)', $views['sigil_overdue'] );
	}
}
