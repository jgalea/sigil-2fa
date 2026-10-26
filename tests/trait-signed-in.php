<?php

declare( strict_types=1 );

/**
 * A real WordPress session for the current user, so code that reads the
 * session token sees one, of whatever age the test needs.
 */
trait Signed_In {

	public function tear_down(): void {
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		parent::tear_down();
	}

	/**
	 * @param int $login_age Seconds since the session signed in.
	 */
	protected function sign_in( int $user_id, int $login_age = 0 ): string {
		wp_set_current_user( $user_id );

		$manager = WP_Session_Tokens::get_instance( $user_id );
		$token   = $manager->create( time() + DAY_IN_SECONDS );

		if ( $login_age > 0 ) {
			$session          = $manager->get( $token );
			$session['login'] = time() - $login_age;
			$manager->update( $token, $session );
		}

		$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $user_id, time() + DAY_IN_SECONDS, 'logged_in', $token );

		return $token;
	}
}
