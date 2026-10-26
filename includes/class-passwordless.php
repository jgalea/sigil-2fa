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
	 * Ties a ceremony to the browser that asked for it. See mint().
	 */
	private const BINDING_COOKIE = 'sigil_passwordless';
	private const BINDING_TTL    = 5 * MINUTE_IN_SECONDS;

	/**
	 * Ceremonies one address may mint per window. Each is a stored row asked
	 * for before anyone is known, so without a ceiling any visitor can write
	 * to the database as fast as they can send requests. A login page asks
	 * once or twice per visit, which leaves room for an office behind one
	 * address.
	 */
	private const MINT_LIMIT  = 60;
	private const MINT_WINDOW = 15 * MINUTE_IN_SECONDS;

	/**
	 * What core and the cookie check say when no password was typed. Anything
	 * else came from a filter that refused the sign-in, and stands.
	 */
	private const EMPTY_CODES = array( 'empty_username', 'empty_password', 'expired_session' );

	/**
	 * What core's application-password check says about an empty username on
	 * a REST or XML-RPC request, once any account on the site has an
	 * application password. Nothing was typed, so these mean the same as the
	 * codes above.
	 */
	private const EMPTY_API_CODES = array( 'invalid_username', 'invalid_email' );

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
		if ( '' !== (string) $password ) {
			return $user;
		}

		$attempt = $this->attempt();
		if ( null === $attempt || ! self::enabled() ) {
			return $user;
		}

		$empty = '' === (string) $username ? array_merge( self::EMPTY_CODES, self::EMPTY_API_CODES ) : self::EMPTY_CODES;
		if ( is_wp_error( $user ) && array() !== array_diff( $user->get_error_codes(), $empty ) ) {
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
	 * Options for a passwordless sign-in, bound to the browser asking.
	 *
	 * A ceremony on its own is a bearer value. An attacker can mint one, sign
	 * it with a passkey for their own account, and have a page on another site
	 * post both through a visitor's browser, which signs the visitor in as the
	 * attacker without their knowing. So the browser gets a random cookie that
	 * other sites cannot send (SameSite=Strict) and cannot read, the ceremony
	 * remembers its hash, and spending the ceremony needs that cookie back. One
	 * value per browser, so several tabs or the autofill request and the button
	 * can each hold a ceremony at once.
	 *
	 * Null when passwordless sign-in is off, or when this address has asked for
	 * too many; mint_refused() tells the two apart.
	 *
	 * @return array{ceremony: string, options: \stdClass}|null
	 */
	public function mint(): ?array {
		$passkey = Providers::instance()->get( 'passkey' );
		if ( ! self::enabled() || ! $passkey instanceof Providers\Passkey ) {
			return null;
		}

		if ( Rate_Limit::reserve( self::mint_key(), self::MINT_WINDOW ) > self::MINT_LIMIT ) {
			return null;
		}

		$binding = self::binding_from_cookie();
		if ( '' === $binding ) {
			$binding = bin2hex( random_bytes( 32 ) );
		}

		$minted = $passkey->discoverable_options( hash( 'sha256', $binding ) );
		if ( null === $minted ) {
			return null;
		}

		self::send_binding( $binding );

		return $minted;
	}

	/**
	 * Whether this address has used up its ceremonies for now.
	 */
	public static function mint_refused(): bool {
		return Rate_Limit::count( self::mint_key() ) > self::MINT_LIMIT;
	}

	/**
	 * By address, with an IPv6 address counted by its /64, which is what one
	 * subscriber is usually given. With no address at all every such request
	 * shares one allowance rather than having none.
	 */
	private static function mint_key(): string {
		$ip = Request::client_ip();
		if ( '' === $ip ) {
			return 'plm:none';
		}

		$packed = inet_pton( $ip );
		if ( is_string( $packed ) && 16 === strlen( $packed ) ) {
			$ip = bin2hex( substr( $packed, 0, 8 ) ) . '::/64';
		}

		return 'plm:' . Challenge::ip_rate_key_for( $ip );
	}

	private static function binding_from_cookie(): string {
		$raw = isset( $_COOKIE[ self::BINDING_COOKIE ] ) && is_string( $_COOKIE[ self::BINDING_COOKIE ] ) ? $_COOKIE[ self::BINDING_COOKIE ] : '';

		return preg_match( '/^[a-f0-9]{64}$/', $raw ) ? $raw : '';
	}

	private static function send_binding( string $binding ): void {
		// Visible to the rest of this request too, so a second ceremony minted
		// before the response goes out shares it.
		$_COOKIE[ self::BINDING_COOKIE ] = $binding;

		if ( headers_sent() ) {
			return;
		}

		setcookie(
			self::BINDING_COOKIE,
			$binding,
			array(
				'expires'  => time() + self::BINDING_TTL,
				'path'     => defined( 'COOKIEPATH' ) && '' !== COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl() || 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME ),
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);
	}

	/**
	 * A browser names the page a POST came from. No header means the request
	 * did not come from a page at all, which is not the attack this stops.
	 */
	private static function origin_allowed(): bool {
		$origin = isset( $_SERVER['HTTP_ORIGIN'] ) && is_string( $_SERVER['HTTP_ORIGIN'] ) ? trim( wp_unslash( $_SERVER['HTTP_ORIGIN'] ) ) : '';
		if ( '' === $origin ) {
			return true;
		}

		$allowed = array();
		foreach ( array( home_url(), site_url() ) as $url ) {
			$parts = wp_parse_url( $url );
			if ( is_array( $parts ) && isset( $parts['scheme'], $parts['host'] ) ) {
				$allowed[] = strtolower( $parts['scheme'] . '://' . $parts['host'] . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' ) );
			}
		}

		return in_array( strtolower( rtrim( $origin, '/' ) ), $allowed, true );
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

		$failed  = new \WP_Error( 'sigil_passkey_failed', __( 'That passkey could not be verified. Please try again.', 'sigil-2fa' ) );
		$binding = self::binding_from_cookie();
		if ( '' === $binding || ! self::origin_allowed() ) {
			return $failed;
		}

		// The ceremony only verifies for the browser it was minted for.
		$passkey = Providers::instance()->get( 'passkey' );
		$user_id = $passkey instanceof Providers\Passkey ? $passkey->discoverable_owner( $ceremony, $assertion, hash( 'sha256', $binding ) ) : 0;
		$user    = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user instanceof \WP_User ) {
			return $failed;
		}

		// An account the challenge has locked stays locked here, or signing in
		// with a passkey would be a way round the counter.
		$user_key = 'u:' . $user_id;
		if ( Rate_Limit::reserve( $user_key ) > Rate_Limit::max_attempts() ) {
			return self::rate_limited();
		}

		// The address only gets back the attempt this request took. Clearing it
		// would let anyone with a passkey account of their own wipe the count
		// between guesses at other accounts from the same address.
		Rate_Limit::clear( $user_key );
		Rate_Limit::release( $ip_key );

		// wp_signon() sets the cookie straight after this filter, before
		// wp_login, and on REST and AJAX nothing comes back later to issue it
		// again. The passkey is verified, so let it through now.
		Login_Guard::grant( $user_id );

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
