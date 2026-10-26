<?php

declare( strict_types=1 );

use Sigil\Review_Prompt;

/**
 * The same answers, sent from the notice's buttons without a page reload.
 */
class Test_Review_Prompt_Ajax extends WP_Ajax_UnitTestCase {

	public function set_up(): void {
		parent::set_up();
		\Sigil\Network::update_option( Review_Prompt::OPTION_ACTIVATED, time() - 8 * DAY_IN_SECONDS );
		unset( $_REQUEST['_wpnonce'] );
	}

	private function admin(): int {
		$id = (int) self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		update_user_meta( $id, Review_Prompt::META_FACTOR, 'totp' );
		return $id;
	}

	private function ajax( int $user_id, string $choice, string $nonce ): array {
		wp_set_current_user( $user_id );
		$_POST['choice']   = $choice;
		$_POST['_wpnonce'] = $nonce;
		$_REQUEST          = array_merge( $_REQUEST, $_POST );
		$this->_last_response = '';

		try {
			$this->_handleAjax( Review_Prompt::ACTION );
		} catch ( WPAjaxDieContinueException $e ) {
			unset( $e );
		}

		return (array) json_decode( $this->_last_response, true );
	}

	public function test_ajax_records_the_answer(): void {
		$id = $this->admin();
		wp_set_current_user( $id );

		$response = $this->ajax( $id, 'later', wp_create_nonce( Review_Prompt::ACTION ) );

		$this->assertTrue( $response['success'] );
		$this->assertFalse( Review_Prompt::eligible( $id ) );
	}

	public function test_ajax_rejects_a_bad_nonce(): void {
		$id = $this->admin();
		wp_set_current_user( $id );

		$response = $this->ajax( $id, 'never', 'bad' );

		$this->assertFalse( $response['success'] );
		$this->assertTrue( Review_Prompt::eligible( $id ) );
	}

	public function test_ajax_rejects_a_user_without_the_capability(): void {
		$editor = (int) self::factory()->user->create( array( 'role' => 'editor' ) );
		wp_set_current_user( $editor );
		$nonce = wp_create_nonce( Review_Prompt::ACTION );

		$response = $this->ajax( $editor, 'never', $nonce );

		$this->assertFalse( $response['success'] );
		$this->assertSame( '', get_user_meta( $editor, Review_Prompt::META_HIDDEN, true ) );
	}

	public function test_ajax_rejects_an_unknown_choice(): void {
		$id = $this->admin();
		wp_set_current_user( $id );

		$response = $this->ajax( $id, 'bogus', wp_create_nonce( Review_Prompt::ACTION ) );

		$this->assertFalse( $response['success'] );
		$this->assertTrue( Review_Prompt::eligible( $id ) );
	}
}
