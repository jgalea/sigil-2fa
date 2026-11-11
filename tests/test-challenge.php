<?php

declare( strict_types=1 );

class Test_Challenge extends WP_UnitTestCase {

	use Clears_Attempts;

	public function test_token_resolves_to_user(): void {
		$user = self::factory()->user->create_and_get();
		$tok  = \Sigil\Challenge::start( $user, false );
		$this->assertSame( $user->ID, \Sigil\Challenge::user_for( $tok )->ID );
	}

	public function test_unknown_token_resolves_to_null(): void {
		$this->assertNull( \Sigil\Challenge::user_for( 'not-a-token' ) );
	}

	public function test_wrong_code_returns_error_and_counts_against_limit(): void {
		$user = self::factory()->user->create_and_get();
		\Sigil\Store::set_method( $user->ID, 'backup', [ 'hashes' => [] ] );
		$tok = \Sigil\Challenge::start( $user, false );
		$this->assertWPError( \Sigil\Challenge::complete( $tok, 'backup', [ 'code' => 'wrong' ] ) );
	}

	public function test_token_is_single_use(): void {
		$user  = self::factory()->user->create_and_get();
		$p     = new \Sigil\Providers\Backup_Codes();
		$codes = $p->generate( $user->ID );
		$tok   = \Sigil\Challenge::start( $user, false );
		$this->assertTrue( \Sigil\Challenge::complete( $tok, 'backup', [ 'code' => $codes[0] ] ) );
		$this->assertNull( \Sigil\Challenge::user_for( $tok ) );
	}

	public function test_blocked_user_cannot_complete_even_with_right_code(): void {
		$user  = self::factory()->user->create_and_get();
		$p     = new \Sigil\Providers\Backup_Codes();
		$codes = $p->generate( $user->ID );
		$tok   = \Sigil\Challenge::start( $user, false );
		for ( $i = 0; $i < 5; $i++ ) {
			\Sigil\Challenge::complete( $tok, 'backup', [ 'code' => 'wrong' ] );
		}
		$this->assertWPError( \Sigil\Challenge::complete( $tok, 'backup', [ 'code' => $codes[0] ] ) );
	}

	public function test_a_token_is_only_good_in_the_browser_that_started_it(): void {
		$user  = self::factory()->user->create_and_get();
		$p     = new \Sigil\Providers\Backup_Codes();
		$codes = $p->generate( $user->ID );
		$tok   = \Sigil\Challenge::start( $user, false );
		$mine  = $_COOKIE['sigil_challenge'];

		unset( $_COOKIE['sigil_challenge'] );
		$this->assertWPError( \Sigil\Challenge::complete( $tok, 'backup', array( 'code' => $codes[0] ) ), 'no cookie' );

		$_COOKIE['sigil_challenge'] = bin2hex( random_bytes( 32 ) );
		$this->assertWPError( \Sigil\Challenge::complete( $tok, 'backup', array( 'code' => $codes[0] ) ), 'someone else\'s cookie' );

		$_COOKIE['sigil_challenge'] = $mine;
		$this->assertTrue( \Sigil\Challenge::complete( $tok, 'backup', array( 'code' => $codes[0] ) ), 'the starting browser still works' );
	}

	public function test_a_retry_token_stays_bound_to_the_same_browser(): void {
		$user = self::factory()->user->create_and_get();
		\Sigil\Store::set_method( $user->ID, 'backup', array( 'hashes' => array() ) );
		$tok   = \Sigil\Challenge::start( $user, false );
		$error = \Sigil\Challenge::complete( $tok, 'backup', array( 'code' => 'wrong' ) );
		$next  = \Sigil\Challenge::next_token( $error, $tok );
		$this->assertNotSame( $tok, $next );

		$_COOKIE['sigil_challenge'] = bin2hex( random_bytes( 32 ) );
		$again = \Sigil\Challenge::complete( $next, 'backup', array( 'code' => 'wrong' ) );
		$this->assertSame( 'sigil_invalid_token', $again->get_error_code() );
	}

	public function test_spent_token_sends_a_signed_in_browser_on_not_back_to_login(): void {
		$user = self::factory()->user->create_and_get();
		wp_set_current_user( $user->ID );
		$this->assertSame( admin_url(), $this->redirect_for_spent_token() );
	}

	public function test_spent_token_sends_a_signed_out_browser_to_login(): void {
		wp_set_current_user( 0 );
		$this->assertSame( wp_login_url(), $this->redirect_for_spent_token() );
	}

	private function redirect_for_spent_token(): string {
		$stop = static function ( $location ) {
			throw new RuntimeException( (string) $location );
		};
		add_filter( 'wp_redirect', $stop );
		$_POST    = array( 'sigil_token' => str_repeat( 'a', 64 ) );
		$_REQUEST = $_POST;

		try {
			\Sigil\Challenge::instance()->handle_challenge_request();
		} catch ( RuntimeException $e ) {
			return $e->getMessage();
		} finally {
			remove_filter( 'wp_redirect', $stop );
			$_POST    = array();
			$_REQUEST = array();
		}

		return '';
	}
}
