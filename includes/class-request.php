<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Where the request came from, as far as the server can actually tell.
 */
final class Request {

	/**
	 * The client address, or empty when there is nothing trustworthy to use.
	 *
	 * REMOTE_ADDR is the only value the server sets itself, so it is the only
	 * one read by default. Behind a reverse proxy it is the proxy, which is why
	 * the filter exists: a site that knows its own infrastructure can supply the
	 * real address and get per-visitor counting back instead of one bucket for
	 * everybody arriving through the same hop.
	 *
	 * Forwarding headers are not read here and should not be trusted lightly.
	 * Anyone can send X-Forwarded-For, so a filter that returns it without
	 * checking the request came from your proxy hands attackers a fresh identity
	 * per request and switches address-based limiting off. Only add one if the
	 * proxy is yours and overwrites the header on the way in.
	 */
	public static function client_ip(): string {
		$raw = isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';

		$remote = filter_var( $raw, FILTER_VALIDATE_IP );
		$remote = false === $remote ? '' : (string) $remote;

		/**
		 * Filter the address this request is treated as coming from.
		 *
		 * @param string $remote The address the server reports.
		 */
		$filtered = apply_filters( 'sigil_client_ip', $remote );

		// A filter that returns nonsense falls back to what the server said,
		// rather than to nothing: an empty address means no address-based
		// limiting at all, which is not something a typo should switch off.
		$valid = is_string( $filtered ) ? filter_var( $filtered, FILTER_VALIDATE_IP ) : false;

		return false === $valid ? $remote : (string) $valid;
	}

	/**
	 * The address as a rate limit should count it, for every counter that is
	 * keyed by address, so they all agree on what one visitor is.
	 *
	 * An IPv4 visitor reaching a dual-stack server is reported as an
	 * IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d) address.
	 * Counted as IPv6, every one of them would share one /64, so they are turned
	 * back into the IPv4 address. A real IPv6 address is counted by its /64,
	 * which is what one subscriber is usually handed. Loopback stays itself.
	 */
	public static function bucket_address( string $ip ): string {
		$packed = '' === $ip ? false : inet_pton( $ip );
		if ( ! is_string( $packed ) || 16 !== strlen( $packed ) ) {
			return $ip;
		}

		$head = substr( $packed, 0, 12 );
		$tail = substr( $packed, 12 );

		if ( str_repeat( "\0", 10 ) . "\xff\xff" === $head ) {
			return (string) inet_ntop( $tail );
		}

		if ( str_repeat( "\0", 12 ) === $head ) {
			// :: and ::1 are not IPv4 addresses in disguise.
			if ( "\0\0\0\0" === $tail || "\0\0\0\x01" === $tail ) {
				return $ip;
			}

			return (string) inet_ntop( $tail );
		}

		return bin2hex( substr( $packed, 0, 8 ) ) . '::/64';
	}
}
