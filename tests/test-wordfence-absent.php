<?php

declare( strict_types=1 );

use Sigil\Wordfence_Import;

/**
 * Wordfence's login step is only answered while Wordfence is there to ask it.
 * With it gone, the action is any anonymous visitor's way to have a password
 * checked outside every login form and lockout that watches them.
 */
class Test_Wordfence_Absent extends WP_UnitTestCase {

	public function test_the_stand_in_answers_nothing_while_wordfence_is_inactive(): void {
		if ( Wordfence_Import::is_active() ) {
			$this->markTestSkipped( 'A Wordfence stub was loaded by an earlier test in this process.' );
		}

		$user = self::factory()->user->create_and_get( array( 'user_pass' => 'pass-word-1' ) );
		\Sigil\Store::set_method( (int) $user->ID, 'totp', array( 'secret' => 'x' ) );

		$checked = 0;
		$count   = static function ( $result ) use ( &$checked ) {
			++$checked;
			return $result;
		};
		add_filter( 'authenticate', $count, 1 );
		add_filter( 'wp_doing_ajax', '__return_true' );
		add_filter( 'wp_die_ajax_handler', array( $this, 'get_wp_die_handler' ) );
		$_POST = array(
			'log' => $user->user_login,
			'pwd' => 'pass-word-1',
		);

		ob_start();
		try {
			Wordfence_Import::ajax_stand_down();
		} catch ( WPDieException $e ) {
			unset( $e );
		}
		$out = (string) ob_get_clean();

		$_POST = array();
		remove_filter( 'wp_doing_ajax', '__return_true' );

		$this->assertSame( 0, $checked, 'no password was checked' );
		$this->assertSame( '', $out );
	}
}
