<?php
/**
 * Test environment only: point the WebAuthn provider's relying party at the
 * site's real origin.
 *
 * The provider builds its AppID as https:// and compares origins exactly, while
 * the test site is http://localhost. The filter only matters while that plugin
 * is active, which is the WebAuthn import spec.
 *
 * It lives here rather than being written into mu-plugins by the spec, because
 * the CLI container cannot write to that folder on a Linux runner.
 */

declare( strict_types=1 );

add_filter(
	'webauthn_app_id',
	static function () {
		$p = wp_parse_url( home_url() );
		return $p['scheme'] . '://' . $p['host'] . ( isset( $p['port'] ) ? ':' . $p['port'] : '' );
	}
);
