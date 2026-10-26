<?php
// Runs against whichever Sigil is installed, so it only uses what 0.4.x and later share.
$secret = (string) getenv( 'SMOKE_TOTP_SECRET' );

$user_id = username_exists( 'smoke_2fa' );
if ( ! $user_id ) {
	$user_id = wp_create_user( 'smoke_2fa', 'smoke-user-pass', 'smoke_2fa@example.com' );
}
$user = new WP_User( $user_id );
$user->set_role( 'editor' );

\Sigil\Store::set_method(
	$user_id,
	'totp',
	array(
		'secret'    => base64_encode( \Sigil\Crypto::encrypt( $secret ) ),
		'last_step' => 0,
	)
);

$codes = \Sigil\Providers::instance()->get( 'backup' )->generate( $user_id );

\Sigil\Policy::update(
	array(
		'enabled'    => true,
		'roles'      => array( 'editor' => true ),
		'grace_days' => 11,
	)
);

update_option( 'sigil_pro_trusted_days', 21 );

echo 'backup_code=' . $codes[0] . "\n";
