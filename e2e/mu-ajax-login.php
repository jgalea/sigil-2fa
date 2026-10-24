<?php
/**
 * Test environment only: the two shapes of admin-ajax login found in popup and
 * theme login forms, so the browser suite can check what reaches the client.
 *
 * One calls wp_signon(). The other checks the password and sets the cookie
 * itself, which is what the cookie backstop exists for.
 */

declare( strict_types=1 );

$sigil_e2e_ajax_login = static function ( bool $signon ): void {
	// phpcs:disable WordPress.Security.NonceVerification.Missing
	$login    = isset( $_POST['log'] ) ? sanitize_user( wp_unslash( (string) $_POST['log'] ) ) : '';
	$password = isset( $_POST['pwd'] ) ? (string) wp_unslash( $_POST['pwd'] ) : '';
	// phpcs:enable WordPress.Security.NonceVerification.Missing

	if ( $signon ) {
		$user = wp_signon( array( 'user_login' => $login, 'user_password' => $password ) );
	} else {
		$user = wp_authenticate( $login, $password );
		if ( $user instanceof WP_User ) {
			wp_set_auth_cookie( (int) $user->ID );
		}
	}

	if ( is_wp_error( $user ) ) {
		wp_send_json_error(
			array(
				'code'    => $user->get_error_code(),
				'message' => $user->get_error_message(),
				'data'    => $user->get_error_data(),
			)
		);
	}

	wp_send_json_success( array( 'user_id' => (int) $user->ID ) );
};

add_action(
	'wp_ajax_nopriv_sigil_e2e_signon',
	static function () use ( $sigil_e2e_ajax_login ) {
		$sigil_e2e_ajax_login( true );
	}
);

add_action(
	'wp_ajax_nopriv_sigil_e2e_set_cookie',
	static function () use ( $sigil_e2e_ajax_login ) {
		$sigil_e2e_ajax_login( false );
	}
);
