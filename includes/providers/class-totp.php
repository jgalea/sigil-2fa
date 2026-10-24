<?php

declare( strict_types=1 );

namespace Sigil\Providers;

use Sigil\Crypto;
use Sigil\Provider;
use Sigil\Store;

defined( 'ABSPATH' ) || exit;

final class TOTP implements Provider {

	private const STEP_SECONDS = 30;
	private const DIGITS       = 6;
	private const WINDOW       = 1;
	private const SECRET_BYTES = 20;
	// RFC 4226 floor. Anything shorter is rejected at enrolment and at validation,
	// so a degenerate secret can never decode to a key that matches a fixed code.
	private const MIN_SECRET_BYTES = 16;

	// How far either side of the accepted window to look when a code is rejected,
	// purely to tell "wrong code" apart from "wrong clock". 40 steps is 20 minutes.
	private const DRIFT_SEARCH = 40;
	private const DRIFT_KEY    = 'sigil_totp_drift';

	public function id(): string {
		return 'totp';
	}

	public function label(): string {
		return __( 'Authenticator app', 'sigil-2fa' );
	}

	public function priority(): int {
		return 20;
	}

	public function is_available(): bool {
		return true;
	}

	public function is_enrolled( int $user_id ): bool {
		$methods = Store::methods( $user_id );
		return isset( $methods[ $this->id() ] );
	}

	public function render_enrol( int $user_id ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$secret = self::generate_secret();
		$site   = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $site ) {
			$site = 'WordPress';
		}

		$label  = rawurlencode( $site . ':' . $user->user_login );
		$issuer = rawurlencode( $site );
		$uri    = 'otpauth://totp/' . $label . '?secret=' . rawurlencode( $secret ) . '&issuer=' . $issuer;

		echo '<div class="sigil-totp-enrol">';
		echo '<p><label for="sigil-totp-secret">' . esc_html__( 'Secret key', 'sigil-2fa' ) . '</label> ';
		echo '<code id="sigil-totp-secret">' . esc_html( $secret ) . '</code></p>';
		echo '<p><label for="sigil-totp-uri">' . esc_html__( 'Provisioning URI', 'sigil-2fa' ) . '</label> ';
		echo '<code id="sigil-totp-uri">' . esc_html( $uri ) . '</code></p>';
		echo '<div class="sigil-totp-qr" data-otpauth="' . esc_attr( $uri ) . '"></div>';
		echo '<input type="hidden" name="sigil_totp_secret" value="' . esc_attr( $secret ) . '" />';
		echo '<p><label for="sigil-totp-code">' . esc_html__( 'Verification code', 'sigil-2fa' ) . '</label> ';
		echo '<input type="text" name="sigil_totp_code" id="sigil-totp-code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" /></p>';
		echo '</div>';
	}

	/**
	 * @param array<string, mixed> $input
	 * @return true|\WP_Error
	 */
	public function handle_enrol( int $user_id, array $input ) {
		$secret = isset( $input['secret'] ) ? (string) $input['secret'] : '';
		$code   = isset( $input['code'] ) ? (string) $input['code'] : '';

		$secret = strtoupper( preg_replace( '/\s+/', '', sanitize_text_field( $secret ) ) ?? '' );
		$code   = preg_replace( '/\s+/', '', sanitize_text_field( $code ) ) ?? '';

		if ( ! preg_match( '/^[A-Z2-7]+$/', $secret ) || strlen( self::base32_decode( $secret ) ) < self::MIN_SECRET_BYTES ) {
			return new \WP_Error(
				'sigil_invalid_secret',
				__( 'Invalid authenticator secret.', 'sigil-2fa' )
			);
		}

		if ( ! preg_match( '/^\d{6}$/', $code ) ) {
			return new \WP_Error(
				'sigil_invalid_code',
				__( 'Enter the 6-digit code from your authenticator app.', 'sigil-2fa' )
			);
		}

		if ( ! $this->code_valid_for_secret( $secret, $code, time() ) ) {
			return new \WP_Error(
				'sigil_invalid_code',
				__( 'That code did not match. Check the time on your device and try again.', 'sigil-2fa' )
			);
		}

		$encrypted = Crypto::encrypt( $secret );
		if ( '' === $encrypted ) {
			return new \WP_Error(
				'sigil_encrypt_failed',
				__( 'Could not store the authenticator secret.', 'sigil-2fa' )
			);
		}

		Store::set_method(
			$user_id,
			$this->id(),
			array(
				'secret'    => base64_encode( $encrypted ),
				'last_step' => 0,
			)
		);

		return true;
	}

	public function render_challenge( int $user_id ): void {
		// Field name is "code" to match what validate() reads and what the backup
		// and email providers already use. The challenge handler passes raw POST
		// straight through, so a mismatch here silently fails every login.
		echo '<p><label for="sigil-totp-challenge">' . esc_html__( 'Authenticator code', 'sigil-2fa' ) . '</label> ';
		echo '<input type="text" name="code" id="sigil-totp-challenge" inputmode="numeric" pattern="[0-9\s\-]{6,12}" autocomplete="one-time-code" maxlength="12" spellcheck="false" aria-describedby="sigil-totp-hint" required autofocus />';
		echo '<span id="sigil-totp-hint" class="sigil-challenge__hint">' . esc_html__( 'Enter the 6-digit code from your authenticator app.', 'sigil-2fa' ) . '</span></p>';
	}

	/**
	 * @param array<string, mixed> $input
	 */
	public function validate( int $user_id, array $input ): bool {
		$methods = Store::methods( $user_id );
		if ( ! isset( $methods[ $this->id() ] ) || ! is_array( $methods[ $this->id() ] ) ) {
			return false;
		}

		$data = $methods[ $this->id() ];
		if ( empty( $data['secret'] ) || ! is_string( $data['secret'] ) ) {
			return false;
		}

		$ciphertext = base64_decode( $data['secret'], true );
		if ( false === $ciphertext || '' === $ciphertext ) {
			return false;
		}

		$secret = Crypto::decrypt( $ciphertext );
		if ( '' === $secret ) {
			return false;
		}

		$code = isset( $input['code'] ) ? (string) $input['code'] : '';
		$code = preg_replace( '/\s+/', '', sanitize_text_field( $code ) ) ?? '';
		if ( ! preg_match( '/^\d{6}$/', $code ) ) {
			return false;
		}

		$last_step = isset( $data['last_step'] ) ? (int) $data['last_step'] : 0;
		$now       = time();
		$step_now  = (int) floor( $now / self::STEP_SECONDS );

		$matched_step = null;
		for ( $delta = -self::WINDOW; $delta <= self::WINDOW; $delta++ ) {
			$step = $step_now + $delta;
			if ( $step <= $last_step ) {
				continue;
			}
			$expected = self::hotp( $secret, $step );
			if ( hash_equals( $expected, $code ) ) {
				if ( null === $matched_step || $step > $matched_step ) {
					$matched_step = $step;
				}
			}
		}

		if ( null === $matched_step ) {
			self::note_clock_drift( $secret, $code, $step_now );
			return false;
		}

		delete_transient( self::DRIFT_KEY );

		$data['last_step'] = $matched_step;
		Store::set_method( $user_id, $this->id(), $data );

		return true;
	}

	public function unenrol( int $user_id ): void {
		Store::remove_method( $user_id, $this->id() );
	}

	/**
	 * Work out whether a rejected code was actually right, just at the wrong time.
	 *
	 * A server clock that has drifted more than a step or two rejects every code
	 * every user enters, and looks exactly like everyone suddenly typing it wrong.
	 * Searching a wider window on failure turns that into an answer: if the code
	 * matches a step well outside the accepted range, the clock is the problem.
	 *
	 * Only ever read to warn an administrator. Nothing authenticates on it.
	 */
	private static function note_clock_drift( string $secret, string $code, int $step_now ): void {
		for ( $delta = -self::DRIFT_SEARCH; $delta <= self::DRIFT_SEARCH; $delta++ ) {
			if ( abs( $delta ) <= self::WINDOW ) {
				continue;
			}

			if ( hash_equals( self::hotp( $secret, $step_now + $delta ), $code ) ) {
				set_transient( self::DRIFT_KEY, $delta * self::STEP_SECONDS, DAY_IN_SECONDS );
				return;
			}
		}
	}

	/**
	 * Seconds the server clock appears to be out by, or null if nothing suggests
	 * it is. Positive means the server is behind the authenticator.
	 */
	public static function clock_drift(): ?int {
		$drift = get_transient( self::DRIFT_KEY );

		return is_numeric( $drift ) ? (int) $drift : null;
	}

	public static function generate_secret(): string {
		return self::base32_encode( random_bytes( self::SECRET_BYTES ) );
	}

	public static function code_at( string $secret, int $timestamp ): string {
		$step = (int) floor( $timestamp / self::STEP_SECONDS );
		return self::hotp( $secret, $step );
	}

	private function code_valid_for_secret( string $secret, string $code, int $timestamp ): bool {
		if ( strlen( self::base32_decode( $secret ) ) < self::MIN_SECRET_BYTES ) {
			return false;
		}

		$step_now = (int) floor( $timestamp / self::STEP_SECONDS );
		for ( $delta = -self::WINDOW; $delta <= self::WINDOW; $delta++ ) {
			$expected = self::hotp( $secret, $step_now + $delta );
			if ( hash_equals( $expected, $code ) ) {
				return true;
			}
		}
		return false;
	}

	private static function hotp( string $base32_secret, int $counter ): string {
		$key = self::base32_decode( $base32_secret );
		if ( strlen( $key ) < self::MIN_SECRET_BYTES ) {
			// A degenerate secret must never produce a code any input can match.
			return '';
		}

		$bin_counter = pack( 'N*', 0, $counter & 0xFFFFFFFF );
		$hash        = hash_hmac( 'sha1', $bin_counter, $key, true );
		$offset      = ord( $hash[19] ) & 0x0f;
		$truncated  = (
			( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xff )
		);

		$modulo = 10 ** self::DIGITS;
		$code   = $truncated % $modulo;

		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	private static function base32_encode( string $data ): string {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits     = '';
		$len      = strlen( $data );

		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		$output = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			if ( strlen( $chunk ) < 5 ) {
				$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			}
			$output .= $alphabet[ bindec( $chunk ) ];
		}

		return $output;
	}

	private static function base32_decode( string $b32 ): string {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$b32      = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', $b32 ) ?? '' );
		$bits     = '';
		$len      = strlen( $b32 );

		for ( $i = 0; $i < $len; $i++ ) {
			$val = strpos( $alphabet, $b32[ $i ] );
			if ( false === $val ) {
				continue;
			}
			$bits .= str_pad( decbin( $val ), 5, '0', STR_PAD_LEFT );
		}

		$output = '';
		foreach ( str_split( $bits, 8 ) as $chunk ) {
			if ( 8 === strlen( $chunk ) ) {
				$output .= chr( bindec( $chunk ) );
			}
		}

		return $output;
	}
}
