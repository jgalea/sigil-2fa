<?php
/**
 * Test environment only: a stand-in for a trusted-device add-on, so the browser
 * suite can check that a sign-in excused through sigil_skip_challenge still
 * gets its session. Applies to users carrying the sigil_e2e_skip meta.
 */

declare( strict_types=1 );

add_filter(
	'sigil_skip_challenge',
	static function ( $skip, $user ) {
		return $skip || ( $user instanceof WP_User && '1' === get_user_meta( (int) $user->ID, 'sigil_e2e_skip', true ) );
	},
	10,
	2
);
