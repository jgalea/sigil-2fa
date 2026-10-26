<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Sign in with a passkey alone.
 *
 * A passkey that verifies its user is two factors on its own: the device, and
 * the PIN or biometric that unlocks it. A password in front of it adds a
 * phishable secret and no protection, so a user-verified assertion is taken as
 * the whole sign-in and the challenge that follows a password is skipped.
 *
 * The ceremony runs inside WordPress's authenticate filter, so the sign-in
 * still goes through wp_signon(): lockout plugins, the spam check, wp_login and
 * wp_login_failed all see it the way they see a password.
 */
final class Passwordless {

	private const CEREMONY_FIELD  = 'sigil_passwordless_ceremony';
	private const ASSERTION_FIELD = 'sigil_passwordless_assertion';

	/**
	 * What core and the cookie check say when no password was typed. Anything
	 * else came from a filter that refused the sign-in, and stands.
	 */
	private const EMPTY_CODES = array( 'empty_username', 'empty_password', 'expired_session' );

	private static ?Passwordless $instance = null;

	/**
	 * Handed over by the REST route, which has no login form to read.
	 *
	 * @var array{ceremony: string, assertion: array<string, mixed>}|null
	 */
	private ?array $pending = null;

	/**
	 * The account a passkey signed in during this request.
	 */
	private int $verified = 0;

	public static function instance(): Passwordless {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// After core has answered the empty password (20), and after Sigil
		// refuses account passwords on API requests (40), which this is not.
		add_filter( 'authenticate', array( $this, 'authenticate' ), 50, 3 );
		add_filter( 'sigil_skip_challenge', array( $this, 'skip_challenge' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'record_pass' ), 5, 2 );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login' ) );
		add_action( 'login_form', array( $this, 'render_button' ) );
		add_filter( 'login_form_bottom', array( $this, 'append_button' ) );
	}

	/**
	 * On unless an administrator has turned it off, and only where passkeys
	 * themselves work: the provider is unavailable below PHP 8.0.
	 */
	public static function enabled(): bool {
		return Providers::instance()->get( 'passkey' ) instanceof Providers\Passkey
			&& Policy::get()['passwordless'];
	}

	/**
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public function authenticate( $user, $username = '', $password = '' ) {
		unset( $username );

		if ( '' !== (string) $password ) {
			return $user;
		}

		$attempt = $this->attempt();
		if ( null === $attempt || ! self::enabled() ) {
			return $user;
		}

		if ( is_wp_error( $user ) && array() !== array_diff( $user->get_error_codes(), self::EMPTY_CODES ) ) {
			return $user;
		}

		// With no password typed, a user here can only have come from an auth
		// cookie already in the browser. The passkey decides who signs in.
		$result = $this->verify( $attempt['ceremony'], $attempt['assertion'] );
		if ( $result instanceof \WP_User ) {
			$this->verified = (int) $result->ID;
		}

		return $result;
	}

	/**
	 * The REST route's way in: the same wp_signon() the login form takes.
	 *
	 * @param array<string, mixed> $assertion
	 * @return \WP_User|\WP_Error
	 */
	public function sign_on( string $ceremony, array $assertion, bool $remember ) {
		$this->pending = array(
			'ceremony'  => $ceremony,
			'assertion' => $assertion,
		);

		$user = wp_signon(
			array(
				'user_login'    => '',
				'user_password' => '',
				'remember'      => $remember,
			)
		);

		$this->pending = null;

		return $user;
	}

	/**
	 * @param mixed $skip
	 * @param mixed $user
	 */
	public function skip_challenge( $skip, $user ): bool {
		return true === $skip
			|| ( $user instanceof \WP_User && $this->verified > 0 && (int) $user->ID === $this->verified );
	}

	public function record_pass( string $user_login, \WP_User $user ): void {
		unset( $user_login );

		if ( (int) $user->ID === $this->verified ) {
			/** This action is documented in includes/class-challenge.php */
			do_action( 'sigil_challenge_passed', (int) $user->ID, 'passkey' );
		}
	}

	public function enqueue_login(): void {
		if ( ! self::enabled() ) {
			return;
		}

		wp_enqueue_style( 'sigil-login', SIGIL_URL . 'assets/css/login.css', array( 'login' ), SIGIL_VERSION );
		$this->enqueue_script();
	}

	public function render_button(): void {
		if ( ! self::enabled() ) {
			return;
		}

		echo self::markup(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped where it is built.
	}

	/**
	 * The same button on forms built with wp_login_form(), which post to
	 * wp-login.php and so reach the same authenticate filter.
	 *
	 * @param mixed $html
	 */
	public function append_button( $html ): string {
		if ( ! self::enabled() ) {
			return (string) $html;
		}

		$this->enqueue_script();

		return (string) $html . self::markup();
	}

	/**
	 * @param array<string, mixed> $assertion
	 * @return \WP_User|\WP_Error
	 */
	private function verify( string $ceremony, array $assertion ) {
		// Counted before anything is checked, as the challenge does, so a burst
		// of parallel posts cannot all pass a check made before the count.
		$ip_key = Challenge::ip_rate_key();
		if ( Rate_Limit::reserve( $ip_key ) > Rate_Limit::max_ip_attempts() ) {
			return self::rate_limited();
		}

		$passkey = Providers::instance()->get( 'passkey' );
		$user_id = $passkey instanceof Providers\Passkey ? $passkey->discoverable_owner( $ceremony, $assertion ) : 0;
		$user    = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user instanceof \WP_User ) {
			return new \WP_Error( 'sigil_passkey_failed', __( 'That passkey could not be verified. Please try again.', 'sigil-2fa' ) );
		}

		// An account the challenge has locked stays locked here, or signing in
		// with a passkey would be a way round the counter.
		$user_key = 'u:' . $user_id;
		if ( Rate_Limit::reserve( $user_key ) > Rate_Limit::max_attempts() ) {
			return self::rate_limited();
		}

		Rate_Limit::clear( $user_key );
		Rate_Limit::clear( $ip_key );

		return $user;
	}

	/**
	 * @return array{ceremony: string, assertion: array<string, mixed>}|null
	 */
	private function attempt(): ?array {
		if ( null !== $this->pending ) {
			return $this->pending;
		}

		// Read inside the authenticate filter that wp-login.php runs for its own
		// form post, which carries no nonce. The assertion is a signature over a
		// single-use server challenge, so a nonce would add nothing; it is JSON
		// the passkey provider decodes and verifies field by field.
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! isset( $_POST[ self::CEREMONY_FIELD ], $_POST[ self::ASSERTION_FIELD ] ) ) {
			return null;
		}

		$ceremony  = sanitize_key( wp_unslash( (string) $_POST[ self::CEREMONY_FIELD ] ) );
		$assertion = json_decode( wp_unslash( (string) $_POST[ self::ASSERTION_FIELD ] ), true );
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		if ( '' === $ceremony || ! is_array( $assertion ) ) {
			return null;
		}

		return array(
			'ceremony'  => $ceremony,
			'assertion' => $assertion,
		);
	}

	private static function rate_limited(): \WP_Error {
		return new \WP_Error( 'sigil_rate_limited', __( 'Too many failed attempts. Please wait before trying again.', 'sigil-2fa' ) );
	}

	/**
	 * Hidden until the script has checked the browser can do WebAuthn, so
	 * nobody is shown a button that cannot work.
	 */
	private static function markup(): string {
		return '<div class="sigil-passwordless" hidden>'
			. '<p class="sigil-passwordless__or">' . esc_html__( 'or', 'sigil-2fa' ) . '</p>'
			. '<button type="button" class="button button-large sigil-passwordless__button">' . esc_html__( 'Sign in with a passkey', 'sigil-2fa' ) . '</button>'
			. '<p class="sigil-passwordless__status" role="status" aria-live="polite"></p>'
			. '<input type="hidden" name="' . esc_attr( self::CEREMONY_FIELD ) . '" value="" />'
			. '<input type="hidden" name="' . esc_attr( self::ASSERTION_FIELD ) . '" value="" />'
			. '</div>';
	}

	private function enqueue_script(): void {
		wp_enqueue_script( 'sigil-passkey', SIGIL_URL . 'assets/js/passkey.js', array(), SIGIL_VERSION, true );
		wp_enqueue_script( 'sigil-passwordless', SIGIL_URL . 'assets/js/passwordless.js', array( 'sigil-passkey' ), SIGIL_VERSION, true );

		wp_localize_script(
			'sigil-passwordless',
			'sigilPasswordless',
			array(
				'restUrl' => rest_url( REST::NAMESPACE_V1 . '/passwordless' ),
				'i18n'    => array(
					'authenticating' => __( 'Follow the browser prompt to use your passkey…', 'sigil-2fa' ),
					'verifying'      => __( 'Verifying…', 'sigil-2fa' ),
					'failed'         => __( 'Something went wrong. Please try again.', 'sigil-2fa' ),
				),
			)
		);
	}
}
