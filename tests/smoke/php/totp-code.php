<?php
// Prints the current RFC 6238 code for the secret in SMOKE_TOTP_SECRET. Its own
// base32 and HMAC, so a bug in the plugin's TOTP can't hide behind itself.
$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
$bits     = '';
foreach ( str_split( rtrim( (string) getenv( 'SMOKE_TOTP_SECRET' ), '=' ) ) as $char ) {
	$bits .= str_pad( decbin( (int) strpos( $alphabet, $char ) ), 5, '0', STR_PAD_LEFT );
}
$key = '';
foreach ( str_split( $bits, 8 ) as $byte ) {
	if ( 8 === strlen( $byte ) ) {
		$key .= chr( bindec( $byte ) );
	}
}
$offset_steps = (int) getenv( 'SMOKE_TOTP_STEPS' );
$hash         = hash_hmac( 'sha1', pack( 'J', intdiv( time(), 30 ) + $offset_steps ), $key, true );
$offset       = ord( $hash[19] ) & 0xf;
$value        = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 ) | ( ord( $hash[ $offset + 1 ] ) << 16 ) | ( ord( $hash[ $offset + 2 ] ) << 8 ) | ord( $hash[ $offset + 3 ] );
echo str_pad( (string) ( $value % 1000000 ), 6, '0', STR_PAD_LEFT );
