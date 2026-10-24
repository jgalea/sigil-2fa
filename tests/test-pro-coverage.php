<?php

declare( strict_types=1 );

/**
 * The excused sign-in, and the branding that reaches the challenge screen.
 */
class Test_Pro_Coverage extends WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();

		if ( ! defined( 'SIGIL_PRO' ) || ! SIGIL_PRO ) {
			$this->markTestSkipped( 'pro add-on not installed' );
		}

		foreach ( array( 'class-bypass', 'class-branding', 'class-audit' ) as $file ) {
			require_once SIGIL_DIR . 'pro/' . $file . '.php';
		}

		\Sigil\Schema::install();
	}

	public function tear_down(): void {
		delete_option( \Sigil\Pro\Branding::OPTION );
		\Sigil\Network::delete_option( \Sigil\Policy::OPTION_KEY );
		// Deliberately not remove_all_filters(): these are added by singletons that
		// will never re-add them, so stripping one here breaks whatever test runs
		// next. Every one of them no-ops once its option is gone, which is the
		// cleanup that actually matters.
		parent::tear_down();
	}

	private function manager(): int {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		return $id;
	}

	public function test_an_excused_sign_in_is_spent_once(): void {
		$actor = $this->manager();
		$user  = self::factory()->user->create_and_get();

		$this->assertTrue( \Sigil\Pro\Bypass::grant_for( (int) $user->ID, $actor ) );
		\Sigil\Pro\Bypass::instance()->register();

		$this->assertTrue( (bool) apply_filters( 'sigil_skip_challenge', false, $user ), 'the excused sign-in goes through' );

		// Spent by the sign-in rather than by the question, so that anything
		// else consulting the filter cannot burn somebody's one excuse.
		do_action( 'wp_login', $user->user_login, $user );

		$this->assertFalse( (bool) apply_filters( 'sigil_skip_challenge', false, $user ), 'and the next one does not' );
	}

	// An administrator who can excuse their own sign-in has no second factor,
	// only a slower one.
	public function test_nobody_can_excuse_their_own_sign_in(): void {
		$actor = $this->manager();

		$this->assertFalse( \Sigil\Pro\Bypass::can_grant( $actor, $actor ) );
		$this->assertFalse( \Sigil\Pro\Bypass::grant_for( $actor, $actor ) );
	}

	public function test_someone_without_the_capability_cannot_excuse_anyone(): void {
		$editor = self::factory()->user->create( array( 'role' => 'editor' ) );
		$user   = self::factory()->user->create();

		$this->assertFalse( \Sigil\Pro\Bypass::grant_for( $user, $editor ) );
		$this->assertFalse( \Sigil\Pro\Bypass::has_grant( $user ) );
	}

	public function test_an_excused_sign_in_expires_on_its_own(): void {
		$actor = $this->manager();
		$user  = self::factory()->user->create_and_get();

		\Sigil\Pro\Bypass::grant_for( (int) $user->ID, $actor );
		update_user_meta( (int) $user->ID, '_sigil_pro_bypass', array( 'expires' => time() - 1, 'actor' => $actor ) );

		$this->assertFalse( \Sigil\Pro\Bypass::has_grant( (int) $user->ID ) );
	}

	public function test_excusing_a_sign_in_is_written_to_the_audit_log(): void {
		$actor = $this->manager();
		$user  = self::factory()->user->create();

		\Sigil\Pro\Bypass::grant_for( $user, $actor );

		$log = get_user_meta( $user, '_sigil_reset_log', true );
		$this->assertIsArray( $log );
		$this->assertSame( 'bypass', $log[0]['action'] );
		$this->assertSame( $actor, (int) $log[0]['actor'] );
	}

	// The record was already being kept and nothing read it back. The question it
	// answers is asked after something has gone wrong.
	public function test_the_history_shows_both_kinds_of_entry(): void {
		$actor = $this->manager();
		$user  = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'totp', array( 'secret' => 'x' ) );

		\Sigil\Recovery::reset_user( $user, $actor );
		\Sigil\Pro\Bypass::grant_for( $user, $actor );

		$entries = \Sigil\Pro\Audit::entries( $user );

		$this->assertCount( 2, $entries, 'one reset and one excused sign-in' );
		$this->assertSame( 'bypass', $entries[0]['action'] );
		$this->assertSame( 'reset', $entries[1]['action'] );
		$this->assertSame( $actor, $entries[0]['actor'] );
	}

	// Entries written before the log recorded a kind are all resets.
	public function test_an_entry_from_before_this_existed_reads_as_a_reset(): void {
		$user = self::factory()->user->create();
		update_user_meta( $user, '_sigil_reset_log', array( array( 'actor' => 3, 'time' => time() ) ) );

		$entries = \Sigil\Pro\Audit::entries( $user );

		$this->assertCount( 1, $entries );
		$this->assertSame( 'reset', $entries[0]['action'] );
	}

	public function test_an_account_with_no_history_has_nothing_to_show(): void {
		$this->assertSame( array(), \Sigil\Pro\Audit::entries( self::factory()->user->create() ) );
	}

	public function test_the_challenge_screen_takes_the_site_wording(): void {
		\Sigil\Pro\Branding::update( array( 'title' => 'Confirm it is you', 'intro' => 'Signing in as %s, nearly there.' ) );
		\Sigil\Pro\Branding::instance()->register();

		$text = apply_filters(
			'sigil_challenge_text',
			array( 'title' => 'Two-factor authentication', 'intro' => 'Signing in as %s.', 'verify' => 'Verify' )
		);

		$this->assertSame( 'Confirm it is you', $text['title'] );
		$this->assertSame( 'Signing in as %s, nearly there.', $text['intro'] );
		$this->assertSame( 'Verify', $text['verify'], 'anything left unset keeps the default' );
	}

	public function test_a_closing_style_tag_cannot_escape_the_stylesheet(): void {
		\Sigil\Pro\Branding::update( array( 'css' => 'body{color:red}</style><script>alert(1)</script>' ) );

		$stored = \Sigil\Pro\Branding::get()['css'];
		$this->assertStringNotContainsString( '</style>', $stored );
		$this->assertStringNotContainsString( '<script', $stored );
	}
}
