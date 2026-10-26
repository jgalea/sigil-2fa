<?php

declare( strict_types=1 );

namespace WordfenceLS;

/**
 * Stands in for Wordfence's login controller: its authenticate check asks for
 * a code from everyone, which is all the coexistence code needs to see.
 */
class Controller_WordfenceLS {

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function _authenticate( $user ) { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore
		if ( $user instanceof \WP_User ) {
			return new \WP_Error( 'wfls_twofactor_required', 'CODE REQUIRED' );
		}

		return $user;
	}
}
