<?php

declare( strict_types=1 );

use Sigil\Providers;
use Sigil\Providers\TOTP;

/**
 * What the importer tests need to stand up a source plugin's data and then
 * prove Sigil accepts what came across: real tables, real keys, real codes.
 */
trait Import_Fixtures {

	/**
	 * Create a source plugin's table for real. The suite turns CREATE TABLE into
	 * CREATE TEMPORARY TABLE, which SHOW TABLES cannot see, and the importers
	 * look a source table up before reading it.
	 */
	private function real_table( string $sql ): void {
		global $wpdb;

		remove_filter( 'query', array( $this, '_create_temporary_tables' ) );
		remove_filter( 'query', array( $this, '_drop_temporary_tables' ) );
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		add_filter( 'query', array( $this, '_create_temporary_tables' ) );
		add_filter( 'query', array( $this, '_drop_temporary_tables' ) );
	}

	/**
	 * A P-256 key pair, with the public half as the COSE key an authenticator
	 * hands over at registration.
	 *
	 * @return array{private: \OpenSSLAsymmetricKey, cose: string}
	 */
	private function passkey_keypair(): array {
		$key     = openssl_pkey_new( array( 'curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC ) );
		$details = openssl_pkey_get_details( $key );
		$x       = str_pad( $details['ec']['x'], 32, "\0", STR_PAD_LEFT );
		$y       = str_pad( $details['ec']['y'], 32, "\0", STR_PAD_LEFT );

		// CBOR map {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
		$cose = "\xA5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . $x . "\x22\x58\x20" . $y;

		return array(
			'private' => $key,
			'cose'    => $cose,
		);
	}

	private static function b64url( string $raw ): string {
		return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
	}

	/**
	 * Sign in with a passkey through Sigil's own provider: mint the challenge
	 * the login screen would, sign it the way an authenticator does, and hand
	 * the assertion to validate().
	 *
	 * @param \OpenSSLAsymmetricKey $private
	 */
	private function passkey_signs_in( int $user_id, string $credential_id, $private, int $counter ): bool {
		$provider = Providers::instance()->get( 'passkey' );
		$options  = $provider->auth_options( $user_id );
		if ( null === $options ) {
			return false;
		}

		$challenge = json_decode( (string) wp_json_encode( $options ), true )['publicKey']['challenge'];
		// A browser only offers a passkey on a secure origin for its RP ID.
		$origin = 'https://' . Providers\Passkey::rp_id();

		$client_data = (string) wp_json_encode(
			array(
				'type'      => 'webauthn.get',
				'challenge' => $challenge,
				'origin'    => $origin,
			)
		);
		$auth_data   = hash( 'sha256', Providers\Passkey::rp_id(), true ) . "\x05" . pack( 'N', $counter );

		openssl_sign( $auth_data . hash( 'sha256', $client_data, true ), $signature, $private, OPENSSL_ALGO_SHA256 );

		return $provider->validate(
			$user_id,
			array(
				'passkey_assertion' => wp_json_encode(
					array(
						'id'                => self::b64url( $credential_id ),
						'clientDataJSON'    => base64_encode( $client_data ),
						'authenticatorData' => base64_encode( $auth_data ),
						'signature'         => base64_encode( $signature ),
					)
				),
			)
		);
	}

	private function totp_signs_in( int $user_id, string $secret ): bool {
		return Providers::instance()->get( 'totp' )->validate( $user_id, array( 'code' => TOTP::code_at( $secret, time() ) ) );
	}
}
