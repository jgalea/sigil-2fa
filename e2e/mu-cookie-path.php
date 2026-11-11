<?php
/**
 * Test environment only: serves a request as a site whose home and WordPress
 * paths differ, when asked to. X-E2E-Cookiepath gives home /en/ with WordPress
 * at /; X-E2E-Sitepath gives WordPress at /wp/ with home at /.
 */

declare( strict_types=1 );

if ( isset( $_SERVER['HTTP_X_E2E_COOKIEPATH'] ) && ! defined( 'COOKIEPATH' ) ) {
	define( 'COOKIEPATH', '/en/' );
}

if ( isset( $_SERVER['HTTP_X_E2E_SITEPATH'] ) && ! defined( 'SITECOOKIEPATH' ) ) {
	define( 'COOKIEPATH', '/' );
	define( 'SITECOOKIEPATH', '/wp/' );
}
