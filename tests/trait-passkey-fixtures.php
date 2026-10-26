<?php

declare( strict_types=1 );

/**
 * A software authenticator: registers and signs the way a real one does, so the
 * WebAuthn library verifies everything for real.
 */
trait Passkey_Fixtures {

	/**
	 * @return \OpenSSLAsymmetricKey|resource
	 */
	protected static function new_key() {
		return openssl_pkey_new(
			array(
				'private_key_type' => OPENSSL_KEYTYPE_EC,
				'curve_name'       => 'prime256v1',
			)
		);
	}

	protected static function b64url( string $raw ): string {
		return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
	}

	protected function passkey_provider(): \Sigil\Providers\Passkey {
		$provider = \Sigil\Providers::instance()->get( 'passkey' );
		$this->assertInstanceOf( \Sigil\Providers\Passkey::class, $provider );

		return $provider;
	}

	/**
	 * Open a registration ceremony for the account, as the options request does.
	 */
	protected function open_registration( int $user_id ): string {
		$challenge = random_bytes( 32 );
		$store     = new ReflectionMethod( \Sigil\Providers\Passkey::class, 'store_challenge' );
		$store->setAccessible( true );
		$store->invoke( $this->passkey_provider(), $user_id, 'register', $challenge );

		return $challenge;
	}

	/**
	 * The fields the enrolment screen posts after navigator.credentials.create().
	 *
	 * @param \OpenSSLAsymmetricKey|resource $key
	 * @return array<string, string>
	 */
	protected function attestation( string $challenge, $key, string $credential_id, string $label = 'Test key' ): array {
		$rp_id = \Sigil\Providers\Passkey::rp_id();

		$client_data = (string) wp_json_encode(
			array(
				'type'      => 'webauthn.create',
				'challenge' => self::b64url( $challenge ),
				'origin'    => 'https://' . $rp_id,
			)
		);

		$ec   = openssl_pkey_get_details( $key )['ec'];
		$cose = "\xa5"
			. "\x01\x02"                     // kty: EC2
			. "\x03\x26"                     // alg: ES256
			. "\x20\x01"                     // crv: P-256
			. "\x21" . self::cbor_bytes( str_pad( $ec['x'], 32, "\0", STR_PAD_LEFT ) )
			. "\x22" . self::cbor_bytes( str_pad( $ec['y'], 32, "\0", STR_PAD_LEFT ) );

		$auth_data = hash( 'sha256', $rp_id, true )
			. chr( 0x45 )                    // UP, UV, attested credential data
			. pack( 'N', 0 )
			. str_repeat( "\0", 16 )
			. pack( 'n', strlen( $credential_id ) ) . $credential_id
			. $cose;

		$attestation = "\xa3"
			. self::cbor_text( 'fmt' ) . self::cbor_text( 'none' )
			. self::cbor_text( 'attStmt' ) . "\xa0"
			. self::cbor_text( 'authData' ) . self::cbor_bytes( $auth_data );

		return array(
			'clientDataJSON'    => self::b64url( $client_data ),
			'attestationObject' => self::b64url( $attestation ),
			'label'             => $label,
			'transports'        => '["internal"]',
			'discoverable'      => '1',
		);
	}

	/**
	 * Register a passkey through the enrolment screen's AJAX call, as the
	 * signed-in user. Returns the decoded JSON response.
	 *
	 * @param \OpenSSLAsymmetricKey|resource $key
	 * @return array<string, mixed>
	 */
	protected function register_over_ajax( int $user_id, $key, string $credential_id, string $label = 'Test key', int $replace = 0 ): array {
		$challenge = $this->open_registration( $user_id );

		$_POST = $this->attestation( $challenge, $key, $credential_id, $label );
		$_POST['nonce']   = wp_create_nonce( 'sigil_passkey' );
		$_POST['user_id'] = (string) $user_id;
		if ( $replace > 0 ) {
			$_POST['replace'] = (string) $replace;
		}
		$_REQUEST = $_POST;

		$this->_last_response = '';
		try {
			$this->_handleAjax( 'sigil_passkey_register' );
		} catch ( WPAjaxDieContinueException $e ) {
			unset( $e );
		} catch ( WPAjaxDieStopException $e ) {
			unset( $e );
		}

		$_POST    = array();
		$_REQUEST = array();

		return (array) json_decode( (string) $this->_last_response, true );
	}

	/**
	 * A passwordless assertion signed by the key, minted the way the login page
	 * asks for it.
	 *
	 * @param \OpenSSLAsymmetricKey|resource $key
	 * @return array{ceremony: string, assertion: array<string, string>}
	 */
	protected function passwordless_assertion( $key, string $credential_id, int $user_id, int $counter = 1 ): array {
		$minted = \Sigil\Passwordless::instance()->mint();
		$this->assertNotNull( $minted );

		$challenge = $minted['options']->publicKey->challenge->getBinaryString();

		return array(
			'ceremony'  => $minted['ceremony'],
			'assertion' => self::signed_assertion( $challenge, $key, $credential_id, (string) $user_id, $counter ),
		);
	}

	/**
	 * @param \OpenSSLAsymmetricKey|resource $key
	 * @return array<string, string>
	 */
	protected static function signed_assertion( string $challenge, $key, string $credential_id, string $handle, int $counter = 1 ): array {
		$rp_id = \Sigil\Providers\Passkey::rp_id();

		$client_data = (string) wp_json_encode(
			array(
				'type'      => 'webauthn.get',
				'challenge' => self::b64url( $challenge ),
				'origin'    => 'https://' . $rp_id,
			)
		);
		$auth_data   = hash( 'sha256', $rp_id, true ) . chr( 0x05 ) . pack( 'N', $counter );

		openssl_sign( $auth_data . hash( 'sha256', $client_data, true ), $signature, $key, OPENSSL_ALGO_SHA256 );

		return array(
			'id'                => self::b64url( $credential_id ),
			'clientDataJSON'    => self::b64url( $client_data ),
			'authenticatorData' => self::b64url( $auth_data ),
			'signature'         => self::b64url( $signature ),
			'userHandle'        => self::b64url( $handle ),
		);
	}

	private static function cbor_text( string $text ): string {
		return chr( 0x60 + strlen( $text ) ) . $text;
	}

	private static function cbor_bytes( string $bytes ): string {
		$len = strlen( $bytes );
		if ( $len < 24 ) {
			return chr( 0x40 + $len ) . $bytes;
		}
		if ( $len < 256 ) {
			return "\x58" . chr( $len ) . $bytes;
		}

		return "\x59" . pack( 'n', $len ) . $bytes;
	}
}
