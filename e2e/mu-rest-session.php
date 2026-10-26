<?php
/**
 * Test environment only: a REST route that signs the current user in with a
 * browser session, the way some headless and app login plugins do, so the
 * browser suite can check an application password can't be turned into one.
 */

declare( strict_types=1 );

add_action(
	'rest_api_init',
	static function () {
		register_rest_route(
			'sigil-e2e/v1',
			'/session',
			array(
				'methods'             => 'POST',
				'permission_callback' => 'is_user_logged_in',
				'callback'            => static function () {
					wp_set_auth_cookie( get_current_user_id() );
					return array( 'user_id' => get_current_user_id() );
				},
			)
		);
	}
);
