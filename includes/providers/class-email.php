<?php

declare( strict_types=1 );

namespace Sigil\Providers;

use Sigil\Provider;
use Sigil\Store;

defined( 'ABSPATH' ) || exit;

final class Email implements Provider {

	private const CODE_TTL       = 600;
	private const RESEND_COOLDOWN = 60;
	private const TRANSIENT_KEY  = 'sigil_email_';
	private const COOLDOWN_KEY   = 'sigil_email_cd_';
	// Test-only plaintext mirror key. See send_code() for write conditions.
	private const DEBUG_META     = '_sigil_email_debug_code';

	public function id(): string {
		return 'email';
	}

	public function label(): string {
		return __( 'Email code', 'sigil-2fa' );
	}

	public function priority(): int {
		return 30;
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
		$email = $user instanceof \WP_User ? $user->user_email : '';
		echo '<p>' . esc_html__( 'We will send a six-digit code to your account email when you sign in.', 'sigil-2fa' ) . '</p>';
		if ( '' !== $email ) {
			echo '<p>' . esc_html(
				sprintf(
					/* translators: %s: user email address */
					__( 'Codes go to: %s', 'sigil-2fa' ),
					$email
				)
			) . '</p>';
		}
	}

	/**
	 * @param array<string, mixed> $input
	 * @return true|\WP_Error
	 */
	public function handle_enrol( int $user_id, array $input ) {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User || ! is_email( $user->user_email ) ) {
			return new \WP_Error(
				'sigil_email_missing',
				__( 'Your account needs a valid email address to use email codes.', 'sigil-2fa' )
			);
		}

		Store::set_method(
			$user_id,
			$this->id(),
			[
				'enrolled_at' => time(),
			]
		);

		return true;
	}

	public function render_challenge( int $user_id ): void {
		// Rendering the screen is what triggers the send, but only when there is no
		// live code: a re-render after a wrong code must not invalidate the code the
		// user is reading out of their inbox.
		if ( false === get_transient( self::TRANSIENT_KEY . $user_id ) ) {
			$this->send_code( $user_id );
		}

		echo '<p><label for="sigil-email-code">' . esc_html__( 'Email code', 'sigil-2fa' ) . '</label> ';
		echo '<input type="text" name="code" id="sigil-email-code" inputmode="numeric" pattern="[0-9\s\-]{6,12}" autocomplete="one-time-code" maxlength="12" spellcheck="false" aria-describedby="sigil-email-hint" required autofocus />';
		echo '<span id="sigil-email-hint" class="sigil-challenge__hint">' . esc_html__( 'Enter the six-digit code we sent to your email.', 'sigil-2fa' ) . '</span></p>';
	}

	/**
	 * @param array<string, mixed> $input
	 */
	public function validate( int $user_id, array $input ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$raw = isset( $input['code'] ) ? $input['code'] : '';
		if ( ! is_string( $raw ) && ! is_numeric( $raw ) ) {
			return false;
		}

		$code = preg_replace( '/\D/', '', (string) $raw );
		if ( ! is_string( $code ) || 6 !== strlen( $code ) ) {
			return false;
		}

		$stored = get_transient( self::TRANSIENT_KEY . $user_id );
		if ( ! is_string( $stored ) || '' === $stored ) {
			return false;
		}

		$expected = $this->hash_code( $code );
		if ( ! hash_equals( $stored, $expected ) ) {
			return false;
		}

		delete_transient( self::TRANSIENT_KEY . $user_id );
		// The cooldown goes with the code it throttled. Leaving it would block the
		// next sign-in from sending, and that screen would ask for a code that no
		// longer exists.
		delete_transient( self::COOLDOWN_KEY . $user_id );
		delete_user_meta( $user_id, self::DEBUG_META );

		return true;
	}

	public function unenrol( int $user_id ): void {
		Store::remove_method( $user_id, $this->id() );
		delete_transient( self::TRANSIENT_KEY . $user_id );
		delete_transient( self::COOLDOWN_KEY . $user_id );
		delete_user_meta( $user_id, self::DEBUG_META );
	}

	public function send_code( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		if ( false !== get_transient( self::COOLDOWN_KEY . $user_id ) ) {
			return false;
		}

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User || ! is_email( $user->user_email ) ) {
			return false;
		}

		$code = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );

		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $site_name ) {
			$site_name = home_url();
		}

		$subject = sprintf(
			/* translators: %s: site name */
			__( 'Your login code for %s', 'sigil-2fa' ),
			$site_name
		);

		/**
		 * Filter the subject of the login code email.
		 *
		 * @param string   $subject   Default subject.
		 * @param \WP_User $user      Recipient.
		 * @param string   $site_name Site name as it appears to the reader.
		 */
		$subject = (string) apply_filters( 'sigil_email_subject', $subject, $user, $site_name );

		$message = sprintf(
			/* translators: 1: site name, 2: six-digit code, 3: where the request came from */
			__(
				"Someone is trying to sign in to %1\$s.\n\nYour one-time code is: %2\$s\n\n%3\$s\n\nThis code expires in ten minutes and can only be used once.\n\nNobody from %1\$s will ever ask you for this code. If you did not try to sign in, you can ignore this email, and consider changing your password: whoever asked for this code already has it.",
				'sigil-2fa'
			),
			$site_name,
			$code,
			\Sigil\Alerts::origin_line()
		);

		/**
		 * Filter the body of the login code email.
		 *
		 * The code is passed so a replacement body can place it. Whatever is
		 * returned is sent as-is, so a template that drops the code leaves the
		 * reader unable to sign in.
		 *
		 * @param string   $message   Default body.
		 * @param \WP_User $user      Recipient.
		 * @param string   $code      The one-time code.
		 * @param string   $site_name Site name as it appears to the reader.
		 */
		$message = (string) apply_filters( 'sigil_email_message', $message, $user, $code, $site_name );

		$from = get_option( 'admin_email' );
		if ( ! is_string( $from ) || ! is_email( $from ) ) {
			$host = wp_parse_url( home_url(), PHP_URL_HOST );
			$from = is_string( $host ) && '' !== $host ? 'wordpress@' . $host : 'wordpress@example.com';
		}

		/**
		 * Filter the address the login code is sent from.
		 *
		 * @param string   $from Admin email, or wordpress@ the site host.
		 * @param \WP_User $user Recipient.
		 */
		$from = (string) apply_filters( 'sigil_email_from', $from, $user );
		if ( ! is_email( $from ) ) {
			$from = (string) get_option( 'admin_email' );
		}

		/**
		 * Filter the sender name the login code is sent under.
		 *
		 * @param string   $from_name Site name.
		 * @param \WP_User $user      Recipient.
		 */
		$from_name = (string) apply_filters( 'sigil_email_from_name', $site_name, $user );

		$from_filter = static function () use ( $from ): string {
			return $from;
		};
		$from_name_filter = static function () use ( $from_name ): string {
			return $from_name;
		};

		add_filter( 'wp_mail_from', $from_filter, 999 );
		add_filter( 'wp_mail_from_name', $from_name_filter, 999 );
		$sent = (bool) wp_mail( $user->user_email, $subject, $message );
		remove_filter( 'wp_mail_from', $from_filter, 999 );
		remove_filter( 'wp_mail_from_name', $from_name_filter, 999 );

		// Arm the code only once the mail is away. A failed send that left a code and
		// a cooldown behind would ask the user for something they never got, and block
		// the retry that would have fixed it.
		if ( ! $sent ) {
			return false;
		}

		set_transient( self::TRANSIENT_KEY . $user_id, $this->hash_code( $code ), self::CODE_TTL );
		set_transient( self::COOLDOWN_KEY . $user_id, 1, self::RESEND_COOLDOWN );

		// Test-suite-only plaintext mirror. WP_TESTS_DOMAIN is defined by the WordPress
		// test bootstrap and by nothing else. WP_DEBUG deliberately does NOT gate this:
		// plenty of production sites run with it on, and this would persist a live OTP.
		if ( defined( 'WP_TESTS_DOMAIN' ) ) {
			update_user_meta( $user_id, self::DEBUG_META, $code );
		}

		return true;
	}

	private function hash_code( string $code ): string {
		return hash_hmac( 'sha256', $code, wp_salt( 'auth' ) );
	}
}
