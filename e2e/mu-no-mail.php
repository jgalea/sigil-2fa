<?php
/**
 * Test environment only: never attempt to send mail.
 *
 * There is no mail transport in the container, so every wp_mail() blocks until
 * an SMTP connection times out. The plugin now mails on enrolment and on
 * deadline assignment, which turned that into multi-second page loads and made
 * the browser suite time out on unrelated assertions.
 *
 * The content of those emails is asserted in the unit suite, which does not go
 * near a transport. This only removes the wait.
 */

declare( strict_types=1 );

// The last message is kept so a spec can read an emailed login code.
add_filter(
	'pre_wp_mail',
	static function ( $short_circuit, $atts ) {
		update_option(
			'sigil_e2e_last_mail',
			array(
				'to'      => is_array( $atts['to'] ) ? implode( ',', $atts['to'] ) : (string) $atts['to'],
				'message' => (string) $atts['message'],
			),
			false
		);
		return true;
	},
	1,
	2
);
