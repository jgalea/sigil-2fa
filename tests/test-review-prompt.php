<?php

declare( strict_types=1 );

use Sigil\Review_Prompt;

/**
 * The review ask must stay rare, per user, and out of the way: only an
 * administrator who has just used a second factor, a week after install, and
 * never again once they say so.
 */
class Test_Review_Prompt extends WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();
		\Sigil\Network::update_option( Review_Prompt::OPTION_ACTIVATED, time() - 8 * DAY_IN_SECONDS );
		unset( $_GET['choice'], $_POST['choice'], $_REQUEST['_wpnonce'], $_POST['_wpnonce'] );
	}

	private function admin( string $factor = 'totp' ): int {
		$id = (int) self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		if ( '' !== $factor ) {
			update_user_meta( $id, Review_Prompt::META_FACTOR, $factor );
		}
		return $id;
	}

	private function render_for( int $user_id, string $screen = 'dashboard' ): string {
		wp_set_current_user( $user_id );
		set_current_screen( $screen );
		ob_start();
		Review_Prompt::instance()->render();
		return (string) ob_get_clean();
	}

	public function test_an_administrator_who_used_a_factor_a_week_ago_is_eligible(): void {
		$this->assertTrue( Review_Prompt::eligible( $this->admin() ) );
	}

	public function test_someone_without_the_capability_is_never_eligible(): void {
		$id = (int) self::factory()->user->create( array( 'role' => 'editor' ) );
		update_user_meta( $id, Review_Prompt::META_FACTOR, 'totp' );

		$this->assertFalse( Review_Prompt::eligible( $id ) );
	}

	public function test_a_user_who_has_not_signed_in_with_a_factor_is_not_eligible(): void {
		$this->assertFalse( Review_Prompt::eligible( $this->admin( '' ) ) );
	}

	public function test_a_backup_code_sign_in_does_not_count(): void {
		$this->assertFalse( Review_Prompt::eligible( $this->admin( 'backup' ) ) );
	}

	public function test_it_waits_seven_days_from_first_activation(): void {
		$id = $this->admin();

		\Sigil\Network::update_option( Review_Prompt::OPTION_ACTIVATED, time() - 7 * DAY_IN_SECONDS + 60 );
		$this->assertFalse( Review_Prompt::eligible( $id ) );

		\Sigil\Network::update_option( Review_Prompt::OPTION_ACTIVATED, time() - 7 * DAY_IN_SECONDS - 60 );
		$this->assertTrue( Review_Prompt::eligible( $id ) );
	}

	public function test_without_an_activation_time_nobody_is_eligible(): void {
		\Sigil\Network::delete_option( Review_Prompt::OPTION_ACTIVATED );

		$this->assertFalse( Review_Prompt::eligible( $this->admin() ) );
	}

	public function test_activation_time_is_set_once(): void {
		\Sigil\Network::delete_option( Review_Prompt::OPTION_ACTIVATED );

		Review_Prompt::record_activation();
		$first = (int) \Sigil\Network::get_option( Review_Prompt::OPTION_ACTIVATED, 0 );
		$this->assertGreaterThan( 0, $first );

		\Sigil\Network::update_option( Review_Prompt::OPTION_ACTIVATED, $first - DAY_IN_SECONDS );
		Review_Prompt::record_activation();

		$this->assertSame( $first - DAY_IN_SECONDS, (int) \Sigil\Network::get_option( Review_Prompt::OPTION_ACTIVATED, 0 ) );
	}

	public function test_passing_a_challenge_records_the_factor(): void {
		$id = (int) self::factory()->user->create();

		foreach ( array( 'passkey', 'totp', 'email' ) as $factor ) {
			do_action( 'sigil_challenge_passed', $id, $factor );
			$this->assertSame( $factor, get_user_meta( $id, Review_Prompt::META_FACTOR, true ) );
		}

		do_action( 'sigil_challenge_passed', $id, 'backup' );
		$this->assertSame( 'email', get_user_meta( $id, Review_Prompt::META_FACTOR, true ) );
	}

	public function test_maybe_later_hides_it_for_thirty_days(): void {
		$id = $this->admin();

		$this->assertTrue( Review_Prompt::apply( $id, 'later' ) );
		$this->assertFalse( Review_Prompt::eligible( $id ) );

		$until = (int) get_user_meta( $id, Review_Prompt::META_HIDDEN, true );
		$this->assertEqualsWithDelta( time() + 30 * DAY_IN_SECONDS, $until, 5 );

		update_user_meta( $id, Review_Prompt::META_HIDDEN, (string) ( time() - 1 ) );
		$this->assertTrue( Review_Prompt::eligible( $id ) );
	}

	public function test_dont_ask_again_and_leaving_a_review_hide_it_for_good(): void {
		foreach ( array( 'never', 'review' ) as $choice ) {
			$id = $this->admin();

			$this->assertTrue( Review_Prompt::apply( $id, $choice ) );
			$this->assertFalse( Review_Prompt::eligible( $id ), $choice );
			$this->assertSame( 'never', get_user_meta( $id, Review_Prompt::META_HIDDEN, true ) );
		}
	}

	public function test_dismissal_is_per_user(): void {
		$one = $this->admin();
		$two = $this->admin();

		Review_Prompt::apply( $one, 'never' );

		$this->assertTrue( Review_Prompt::eligible( $two ) );
	}

	public function tear_down(): void {
		\Sigil\Network::delete_option( \Sigil\Wizard::OPTION );
		parent::tear_down();
	}

	public function test_an_unknown_choice_changes_nothing(): void {
		$id = $this->admin();

		$this->assertFalse( Review_Prompt::apply( $id, 'bogus' ) );
		$this->assertSame( '', get_user_meta( $id, Review_Prompt::META_HIDDEN, true ) );
	}

	public function test_it_shows_on_the_dashboard_and_sigil_screen_only(): void {
		$id = $this->admin();

		$this->assertStringContainsString( 'Sigil is protecting your login', $this->render_for( $id, 'dashboard' ) );
		\Sigil\Store::set_method( $id, 'totp', array( 'secret' => 'x' ) );
		$this->assertStringContainsString( 'Sigil is protecting your login', $this->render_for( $id, 'settings_page_sigil-2fa' ) );
		$this->assertSame( '', $this->render_for( $id, 'plugins' ) );
		$this->assertSame( '', $this->render_for( $id, 'options-general' ) );
	}

	public function test_it_waits_while_the_setup_nudge_is_on_the_screen(): void {
		$id = $this->admin();

		$this->assertSame( '', $this->render_for( $id, 'settings_page_sigil-2fa' ) );
		$this->assertStringContainsString( 'Sigil is protecting your login', $this->render_for( $id, 'dashboard' ) );

		\Sigil\Network::update_option( \Sigil\Wizard::OPTION, true );
		$this->assertStringContainsString( 'Sigil is protecting your login', $this->render_for( $id, 'settings_page_sigil-2fa' ) );
	}

	public function test_the_first_sentence_names_the_factor_used(): void {
		$this->assertStringContainsString( 'You just signed in with a passkey.', $this->render_for( $this->admin( 'passkey' ) ) );
		$this->assertStringContainsString( 'You just signed in with your authenticator app.', $this->render_for( $this->admin( 'totp' ) ) );
		$this->assertStringContainsString( 'You just signed in with an emailed code.', $this->render_for( $this->admin( 'email' ) ) );
	}

	public function test_the_notice_carries_the_three_actions_with_nonces(): void {
		$html = $this->render_for( $this->admin() );

		$this->assertStringContainsString( 'Leave a review', $html );
		$this->assertStringContainsString( 'Maybe later', $html );
		$this->assertStringContainsString( 'Don&#039;t ask again', $html );
		$this->assertSame( 3, substr_count( $html, '_wpnonce=' ) );
		$this->assertStringContainsString( 'target="_blank"', $html );
	}

	public function test_nothing_renders_for_an_ineligible_user(): void {
		$id = (int) self::factory()->user->create( array( 'role' => 'editor' ) );
		update_user_meta( $id, Review_Prompt::META_FACTOR, 'totp' );

		$this->assertSame( '', $this->render_for( $id ) );
	}

	public function test_the_link_without_javascript_rejects_a_bad_nonce(): void {
		$id = $this->admin();
		wp_set_current_user( $id );
		$_GET['choice']       = 'never';
		$_REQUEST['_wpnonce'] = 'bad';

		try {
			Review_Prompt::instance()->handle_post();
			$this->fail( 'A bad nonce was accepted.' );
		} catch ( WPDieException $e ) {
			$this->assertTrue( Review_Prompt::eligible( $id ) );
		}
	}

	public function test_the_link_without_javascript_rejects_a_user_without_the_capability(): void {
		$editor = (int) self::factory()->user->create( array( 'role' => 'editor' ) );
		wp_set_current_user( $editor );
		$_GET['choice']       = 'never';
		$_REQUEST['_wpnonce'] = wp_create_nonce( Review_Prompt::ACTION );

		$this->expectException( WPDieException::class );
		try {
			Review_Prompt::instance()->handle_post();
		} finally {
			$this->assertSame( '', get_user_meta( $editor, Review_Prompt::META_HIDDEN, true ) );
		}
	}

	public function test_the_link_without_javascript_rejects_an_unknown_choice(): void {
		$id = $this->admin();
		wp_set_current_user( $id );
		$_GET['choice']       = 'bogus';
		$_REQUEST['_wpnonce'] = wp_create_nonce( Review_Prompt::ACTION );

		$this->expectException( WPDieException::class );
		Review_Prompt::instance()->handle_post();
	}
}
