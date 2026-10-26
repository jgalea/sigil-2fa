<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Trusted devices. After passing a challenge a user may mark the current
 * device trusted; subsequent logins from it skip the second factor until the
 * trust expires or is revoked.
 *
 * Security model. The cookie holds a 256-bit random token and nothing else.
 * The server stores only its SHA-256 hash, bound to the user id, with an
 * expiry. A device is trusted only when the presented token hashes to a stored
 * entry for that same user that has not expired. Trust is revoked wholesale
 * when the user resets or changes their 2FA methods, because a device trusted
 * under old factors must not survive a credential change.
 */
final class Trusted_Devices {

	// These keep the names they had when the feature shipped with the paid add-on,
	// so devices already trusted, and the saved number of days, carry over.
	private const META_KEY     = '_sigil_pro_trusted';
	private const COOKIE       = 'sigil_pro_trusted';
	// Public: the exporter and importer move this between sites.
	public const OPTION_DAYS   = 'sigil_pro_trusted_days';
	private const DEFAULT_DAYS = 30;
	private const FIELD        = 'sigil_trust_device';
	private const NONCE_FIELD  = 'sigil_trust_nonce';
	private const NONCE        = 'sigil_trust_device';

	private static ?Trusted_Devices $instance = null;

	public static function instance(): Trusted_Devices {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->register();
	}

	/**
	 * Hook registration, separate from construction so it can be applied
	 * again. The test suite restores WordPress's hook table between tests,
	 * which leaves a singleton constructed in an earlier one holding its
	 * instance but none of its filters. add_filter is idempotent, so calling
	 * this twice in production changes nothing.
	 */
	public function register(): void {
		add_filter( 'sigil_skip_challenge', array( $this, 'maybe_skip' ), 10, 2 );
		// Last, so it only ever sees a sign-in every other filter has accepted.
		add_filter( 'authenticate', array( $this, 'grant_session' ), PHP_INT_MAX, 3 );
		add_action( 'sigil_challenge_form', array( $this, 'render_checkbox' ) );
		add_action( 'sigil_challenge_passed', array( $this, 'on_passed' ), 10, 2 );

		// A credential change must invalidate every device trusted before it.
		add_action( 'sigil_user_reset', array( $this, 'revoke_all' ) );
		add_action( 'sigil_methods_changed', array( $this, 'revoke_all' ) );

		// A new password is the usual answer to "somebody else has been in my
		// account", and a trusted device is a standing permission to skip the
		// second step. Leaving the trust in place means the new password locks
		// out everyone except whoever already ticked the box.
		add_action( 'after_password_reset', array( $this, 'revoke_after_reset' ) );
		add_action( 'profile_update', array( $this, 'revoke_on_new_password' ), 10, 2 );
		add_action( 'wp_set_password', array( $this, 'revoke_on_set_password' ), 10, 3 );
	}

	/**
	 * @param \WP_User $user
	 */
	public function revoke_after_reset( $user ): void {
		if ( $user instanceof \WP_User ) {
			$this->revoke_all( (int) $user->ID );
		}
	}

	/**
	 * The route the other two hooks miss: anything calling wp_set_password
	 * directly, which membership, single sign-on and password-expiry plugins do.
	 *
	 * Guarded on the password actually being different, because core calls this
	 * during login with the password just entered whenever a stored hash needs
	 * rehashing. Without the guard, the move to bcrypt would revoke every
	 * trusted device on the site the next time each person signed in.
	 *
	 * @param string   $password
	 * @param int      $user_id
	 * @param \WP_User $old_user_data
	 */
	public function revoke_on_set_password( $password, $user_id, $old_user_data = null ): void {
		if ( $old_user_data instanceof \WP_User
			&& wp_check_password( (string) $password, (string) $old_user_data->user_pass, (int) $user_id ) ) {
			return;
		}

		$this->revoke_all( (int) $user_id );
	}

	/**
	 * Decided by comparing the stored hash before and after, because the update
	 * carries a plaintext password when one was set and the hash when it was
	 * not, and telling those apart by shape is guesswork.
	 *
	 * @param int      $user_id
	 * @param \WP_User $old_user_data
	 */
	public function revoke_on_new_password( $user_id, $old_user_data ): void {
		if ( ! $old_user_data instanceof \WP_User ) {
			return;
		}

		$current = get_userdata( (int) $user_id );
		if ( ! $current instanceof \WP_User ) {
			return;
		}

		if ( $current->user_pass !== $old_user_data->user_pass ) {
			$this->revoke_all( (int) $user_id );
		}
	}

	public static function trust_days(): int {
		$days = (int) Network::get_option( self::OPTION_DAYS, self::DEFAULT_DAYS );
		if ( $days < 1 ) {
			$days = self::DEFAULT_DAYS;
		}
		return min( $days, 365 );
	}

	/**
	 * Skip the challenge when the request carries a valid, unexpired trusted
	 * token for this user.
	 *
	 * @param bool      $skip
	 * @param \WP_User  $user
	 */
	public function maybe_skip( bool $skip, $user ): bool {
		if ( $skip || ! $user instanceof \WP_User ) {
			return $skip;
		}
		$raw = isset( $_COOKIE[ self::COOKIE ] ) ? (string) $_COOKIE[ self::COOKIE ] : '';
		if ( ! $this->token_is_valid( $user->ID, $raw ) ) {
			return $skip;
		}
		$this->touch( $user->ID, $raw );
		return true;
	}

	/**
	 * Let the session through when the password was right and the device is
	 * trusted for that account.
	 *
	 * wp_signon() sets the cookie as soon as authentication returns, before
	 * wp_login runs the challenge and its skip, so without this Login_Guard
	 * holds it and the challenge has to issue a second one.
	 *
	 * Only for a typed account password. An application password is for API
	 * clients and never becomes a browser session, and with no password the
	 * user came from a cookie or a passkey, which grant for themselves.
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public function grant_session( $user, $username = '', $password = '' ) {
		unset( $username );

		if ( ! $user instanceof \WP_User || '' === (string) $password ) {
			return $user;
		}

		if ( App_Passwords::instance()->used_application_password( (int) $user->ID ) ) {
			return $user;
		}

		$raw = isset( $_COOKIE[ self::COOKIE ] ) ? (string) $_COOKIE[ self::COOKIE ] : '';
		if ( $this->token_is_valid( (int) $user->ID, $raw ) ) {
			Login_Guard::grant( (int) $user->ID );
		}

		return $user;
	}

	public function render_checkbox( $user ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		echo '<p class="sigil-trust-device"><label>';
		wp_nonce_field( self::NONCE, self::NONCE_FIELD, false );
		echo '<input type="checkbox" name="' . esc_attr( self::FIELD ) . '" value="1" /> ';
		printf(
			/* translators: %d: number of days a device stays trusted */
			esc_html( _n( 'Trust this device for %d day', 'Trust this device for %d days', self::trust_days(), 'sigil-2fa' ) ),
			(int) self::trust_days()
		);
		echo '</label></p>';
	}

	/**
	 * @param int    $user_id
	 * @param string $provider_id
	 */
	public function on_passed( int $user_id, string $provider_id ): void {
		unset( $provider_id );
		if ( empty( $_POST[ self::FIELD ] ) ) {
			return;
		}
		if ( ! isset( $_POST[ self::NONCE_FIELD ] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( (string) $_POST[ self::NONCE_FIELD ] ) ), self::NONCE ) ) {
			return;
		}
		$this->trust_current_device( $user_id );
	}

	/**
	 * Trust the current device and return the raw token written to the cookie.
	 */
	public function trust_current_device( int $user_id ): string {
		$token   = bin2hex( random_bytes( 32 ) );
		$devices = $this->prune( $user_id );
		$devices[] = array(
			'hash'    => hash( 'sha256', $token ),
			'ua'      => $this->ua_hash(),
			'created' => time(),
			'expires' => time() + self::trust_days() * DAY_IN_SECONDS,
			'used'    => time(),
		);
		update_user_meta( $user_id, self::META_KEY, $devices );

		if ( ! headers_sent() ) {
			// This is a 2FA-bypass bearer token, so mark it Secure whenever the
			// site is HTTPS-capable, not only when is_ssl() detects it. Behind a
			// TLS-terminating proxy is_ssl() is often false even though the user
			// is on HTTPS; keying off the configured scheme too keeps the token
			// off cleartext. Only a genuinely plain-HTTP site leaves it unset.
			$secure = is_ssl() || 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
			setcookie(
				self::COOKIE,
				$token,
				array(
					'expires'  => time() + self::trust_days() * DAY_IN_SECONDS,
					'path'     => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
					'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
					'secure'   => $secure,
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}

		return $token;
	}

	/** Testable core: is this raw token a live trust for this user? */
	public function is_trusted( int $user_id, string $raw ): bool {
		return $this->token_is_valid( $user_id, $raw );
	}

	public function revoke_all( int $user_id ): void {
		delete_user_meta( $user_id, self::META_KEY );
	}

	/**
	 * The owner's own "forget every device", which also drops the token from
	 * the browser they asked from.
	 */
	public function forget( int $user_id ): void {
		$this->revoke_all( $user_id );

		unset( $_COOKIE[ self::COOKIE ] );
		if ( ! headers_sent() ) {
			setcookie(
				self::COOKIE,
				'',
				array(
					'expires'  => time() - YEAR_IN_SECONDS,
					'path'     => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
					'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
	}

	/**
	 * Whether this request carries a live trusted-device token for the account.
	 */
	public function trusts_request( int $user_id ): bool {
		$raw = isset( $_COOKIE[ self::COOKIE ] ) ? (string) $_COOKIE[ self::COOKIE ] : '';

		return $this->token_is_valid( $user_id, $raw );
	}

	public function count_for( int $user_id ): int {
		return count( $this->prune( $user_id ) );
	}

	private function token_is_valid( int $user_id, string $raw ): bool {
		if ( '' === $raw || ! ctype_xdigit( $raw ) || 64 !== strlen( $raw ) ) {
			return false;
		}
		$hash    = hash( 'sha256', $raw );
		$now     = time();
		foreach ( $this->prune( $user_id ) as $device ) {
			if ( hash_equals( (string) $device['hash'], $hash ) && (int) $device['expires'] > $now ) {
				return true;
			}
		}
		return false;
	}

	private function touch( int $user_id, string $raw ): void {
		$hash    = hash( 'sha256', $raw );
		$devices = $this->prune( $user_id );
		foreach ( $devices as &$device ) {
			if ( hash_equals( (string) $device['hash'], $hash ) ) {
				$device['used'] = time();
			}
		}
		unset( $device );
		update_user_meta( $user_id, self::META_KEY, $devices );
	}

	/** Drop expired devices and return the live list. */
	private function prune( int $user_id ): array {
		$devices = get_user_meta( $user_id, self::META_KEY, true );
		if ( ! is_array( $devices ) ) {
			return array();
		}
		$now  = time();
		$live = array();
		foreach ( $devices as $device ) {
			if ( is_array( $device ) && isset( $device['hash'], $device['expires'] ) && (int) $device['expires'] > $now ) {
				$live[] = $device;
			}
		}
		return $live;
	}

	private function ua_hash(): string {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		return hash( 'sha256', $ua );
	}
}
