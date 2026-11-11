<?php
/**
 * Test environment only: serves a request as a site whose home path isn't a
 * prefix of the login page's path (home /en/, WordPress at /), when asked to.
 */

declare( strict_types=1 );

if ( isset( $_SERVER['HTTP_X_E2E_COOKIEPATH'] ) && ! defined( 'COOKIEPATH' ) ) {
	define( 'COOKIEPATH', '/en/' );
}
