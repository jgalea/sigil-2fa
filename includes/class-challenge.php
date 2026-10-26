<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Challenge {

	private const TTL = 5 * MINUTE_IN_SECONDS;

	/**
	 * How many unspent tokens one account may hold at once.
	 *
	 * A token is claimed on use, so one token buys one guess. Nothing bounded
	 * how many could be minted, though, and each fresh one is another guess:
	 * hold the password, ask for fifty, spend one on each. The attempt counter
	 * is what actually stops that now, and this keeps the pile of unspent
	 * tokens from growing without limit alongside it. Retries are covered by
	 * the eviction order: the live token is always the newest.
	 */
	private const MAX_OPEN_TOKENS = 5;

	private static ?Challenge $instance = null;

	public static function instance(): Challenge {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
		add_action( 'login_form_sigil', array( $this, 'handle_challenge_request' ) );
	}

	/**
	 * @return string Opaque challenge token.
	 */
	public static function start( \WP_User $user, bool $remember, string $redirect_to = '' ): string {
		$token = bin2hex( random_bytes( 32 ) );

		$payload = array(
			'user_id'     => (int) $user->ID,
			'remember'    => $remember,
			'created'     => time(),
			'redirect_to' => $redirect_to,
		);

		set_transient( self::transient_key( $token ), $payload, self::TTL );
		self::remember_open( (int) $user->ID, $token );

		return $token;
	}

	/**
	 * Keep the newest few and drop the rest, oldest first.
	 *
	 * Spent tokens leave a dead entry behind rather than being tracked out of
	 * the list, which costs nothing: deleting a transient that has already gone
	 * is a no-op, and because eviction runs oldest first a dead entry is always
	 * discarded before a live one.
	 */
	private static function remember_open( int $user_id, string $token ): void {
		$key = 'sigil_ch_open_' . $user_id;

		$open   = Network::get_transient( $key );
		$open   = is_array( $open ) ? $open : array();
		$open[] = self::transient_key( $token );

		$excess = count( $open ) - self::MAX_OPEN_TOKENS;
		if ( $excess > 0 ) {
			foreach ( array_slice( $open, 0, $excess ) as $stale ) {
				delete_transient( (string) $stale );
			}
			$open = array_slice( $open, $excess );
		}

		Network::set_transient( $key, $open, self::TTL );
	}

	public static function user_for( string $token ): ?\WP_User {
		$payload = self::payload( $token );
		if ( null === $payload ) {
			return null;
		}

		$user = get_userdata( $payload['user_id'] );
		return $user instanceof \WP_User ? $user : null;
	}

	/**
	 * What the user chose at the password step. Read this before complete(),
	 * which consumes the token.
	 *
	 * @return array{remember: bool, redirect_to: string}|null
	 */
	public static function context_for( string $token ): ?array {
		$payload = self::payload( $token );
		if ( null === $payload ) {
			return null;
		}

		return array(
			'remember'    => $payload['remember'],
			'redirect_to' => $payload['redirect_to'],
		);
	}

	/**
	 * @param array<string, mixed> $input
	 * @return true|\WP_Error
	 */
	public static function complete( string $token, string $provider_id, array $input ) {
		$payload = self::payload( $token );
		if ( null === $payload ) {
			return new \WP_Error( 'sigil_invalid_token', __( 'This verification session has expired. Please log in again.', 'sigil-2fa' ) );
		}

		$user_id = $payload['user_id'];
		$user_key = 'u:' . $user_id;
		$ip_key   = self::ip_rate_key();

		// Take the attempt before checking anything, and decide on the number it
		// comes back with. Asking whether we are blocked and then counting is two
		// steps, and a burst of parallel guesses passes the first step together.
		if ( Rate_Limit::reserve( $user_key ) > Rate_Limit::max_attempts()
			|| Rate_Limit::reserve( $ip_key ) > Rate_Limit::max_ip_attempts() ) {
			// Nothing was guessed, so the token survives for a later retry.
			return self::retryable(
				'sigil_rate_limited',
				__( 'Too many failed attempts. Please wait before trying again.', 'sigil-2fa' ),
				$token
			);
		}

		// Claim the token before checking anything, and only continue if this
		// request is the one that took it.
		//
		// The attempt counters alone cannot hold a line here: reading, adding one
		// and writing back is not atomic, so a burst of parallel guesses all
		// observe the same count and overwrite each other's increment, and the
		// ceiling becomes the attacker's concurrency rather than MAX_ATTEMPTS.
		// One guess per token makes that structural instead of arithmetic, and it
		// is also what stops two simultaneous completions of the same token both
		// issuing a session.
		if ( ! delete_transient( self::transient_key( $token ) ) ) {
			return new \WP_Error( 'sigil_invalid_token', __( 'This verification session has expired. Please log in again.', 'sigil-2fa' ) );
		}

		$provider_id = sanitize_key( $provider_id );
		$provider    = Providers::instance()->get( $provider_id );
		if ( null === $provider || ! $provider->is_enrolled( $user_id ) ) {
			return self::retryable( 'sigil_invalid_method', __( 'Verification failed.', 'sigil-2fa' ), self::reissue( $payload ) );
		}

		if ( ! $provider->validate( $user_id, $input ) ) {
			return self::retryable( 'sigil_invalid_code', __( 'Verification failed.', 'sigil-2fa' ), self::reissue( $payload ) );
		}

		Rate_Limit::clear( $user_key );
		Rate_Limit::clear( $ip_key );

		// The factor is verified and the token spent, so this request may now
		// issue the session the password step was refused.
		Login_Guard::grant( $user_id );

		return true;
	}

	/**
	 * A failure the user can act on, carrying the token to try again with.
	 *
	 * Empty when the session could not be reissued, which the caller shows as an
	 * expired session rather than a retry.
	 *
	 * @param string $next Token for the next attempt.
	 */
	private static function retryable( string $code, string $message, string $next ): \WP_Error {
		return new \WP_Error( $code, $message, array( 'token' => $next ) );
	}

	/**
	 * Mint a replacement for a token a guess just consumed, carrying the choices
	 * made at the password step.
	 *
	 * @param array{user_id: int, remember: bool, created: int, redirect_to: string} $payload
	 */
	private static function reissue( array $payload ): string {
		$user = get_userdata( $payload['user_id'] );
		if ( ! $user instanceof \WP_User ) {
			return '';
		}

		return self::start( $user, $payload['remember'], $payload['redirect_to'] );
	}

	/**
	 * The token a caller should retry with after a failed attempt, or the one it
	 * already had when the error carries none.
	 *
	 * @param \WP_Error $error
	 */
	public static function next_token( $error, string $current ): string {
		if ( ! $error instanceof \WP_Error ) {
			return $current;
		}

		$data = $error->get_error_data();

		return is_array( $data ) && isset( $data['token'] ) && is_string( $data['token'] ) ? $data['token'] : $current;
	}

	/**
	 * Intercept successful password auth when the user has enrolled methods.
	 */
	public function on_login( string $user_login, \WP_User $user ): void {
		unset( $user_login );

		if ( [] === Providers::instance()->enrolled_for( $user->ID ) ) {
			return;
		}

		// Application passwords and non-interactive flows must not be trapped here.
		// There is no page to render the challenge on, so App_Passwords and
		// Login_Guard keep a password alone from signing anyone in through them.
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return;
		}
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		// Extension point for a trusted-device add-on. Defaults to false, so the
		// second factor is only ever skipped by code that deliberately opts in
		// (the Pro trusted-devices feature, which requires a valid signed token).
		if ( true === apply_filters( 'sigil_skip_challenge', false, $user ) ) {
			// wp_signon() already tried to set the cookie and Login_Guard held
			// it, so issue it again now the sign-in is excused.
			Login_Guard::grant( (int) $user->ID );
			wp_set_auth_cookie( $user->ID, ! empty( $_POST['rememberme'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- wp_login runs after WordPress validated the login POST.
			return;
		}

		// This runs inside wp_login, where WordPress has already validated the login POST;
		// there is no nonce of ours to check yet. sanitize_redirect() runs the value through
		// esc_url_raw() and wp_validate_redirect().
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$remember    = ! empty( $_POST['rememberme'] );
		$redirect_to = self::sanitize_redirect(
			isset( $_REQUEST['redirect_to'] ) ? wp_unslash( (string) $_REQUEST['redirect_to'] ) : ''
		);
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		wp_clear_auth_cookie();

		$token = self::start( $user, $remember, $redirect_to );
		$this->render_screen( $token, $user, null, '' );
		exit;
	}

	/**
	 * Handle POST/GET on wp-login.php?action=sigil.
	 */
	public function handle_challenge_request(): void {
		// Never trap logout, ajax, admin-post, or REST: those are different entry points.
		$token = '';
		if ( isset( $_POST['sigil_token'] ) ) {
			$token = sanitize_text_field( wp_unslash( (string) $_POST['sigil_token'] ) );
		} elseif ( isset( $_GET['sigil_token'] ) ) {
			$token = sanitize_text_field( wp_unslash( (string) $_GET['sigil_token'] ) );
		}

		$user = '' !== $token ? self::user_for( $token ) : null;
		if ( null === $user ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$provider_id = '';
		if ( isset( $_REQUEST['sigil_provider'] ) ) {
			$provider_id = sanitize_key( wp_unslash( (string) $_REQUEST['sigil_provider'] ) );
		}

		$error = null;

		if ( isset( $_POST['sigil_authenticate'] ) ) {
			if ( ! isset( $_POST['sigil_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( (string) $_POST['sigil_nonce'] ) ), 'sigil_challenge' ) ) {
				$error = new \WP_Error( 'sigil_bad_nonce', __( 'Verification failed. Please try again.', 'sigil-2fa' ) );
				$this->render_screen( $token, $user, $error, $provider_id );
				exit;
			}

			$payload_before = self::payload( $token );
			$input          = self::sanitize_input( wp_unslash( $_POST ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$result         = self::complete( $token, $provider_id, $input );

			if ( is_wp_error( $result ) ) {
				// The attempt consumed the token, so re-render against its
				// replacement or the form would post a dead one.
				$this->render_screen( self::next_token( $result, $token ), $user, $result, $provider_id );
				exit;
			}

			$remember = $payload_before ? $payload_before['remember'] : ! empty( $_POST['sigil_remember'] );
			$redirect_to = '';
			if ( $payload_before && '' !== $payload_before['redirect_to'] ) {
				$redirect_to = $payload_before['redirect_to'];
			} elseif ( isset( $_POST['sigil_redirect_to'] ) ) {
				// The challenge nonce was verified at the top of this handler, and
				// sanitize_redirect() applies esc_url_raw() and wp_validate_redirect().
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				$redirect_to = self::sanitize_redirect( wp_unslash( (string) $_POST['sigil_redirect_to'] ) );
			}

			wp_set_auth_cookie( $user->ID, $remember );
			do_action( 'sigil_challenge_passed', $user->ID, $provider_id );

			if ( '' === $redirect_to ) {
				$redirect_to = admin_url();
			}

			wp_safe_redirect( $redirect_to );
			exit;
		}

		$this->render_screen( $token, $user, $error, $provider_id );
		exit;
	}

	/**
	 * @return array{user_id: int, remember: bool, created: int, redirect_to: string}|null
	 */
	private static function payload( string $token ): ?array {
		if ( '' === $token || ! preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return null;
		}

		$raw = get_transient( self::transient_key( $token ) );
		if ( ! is_array( $raw ) || ! isset( $raw['user_id'] ) ) {
			return null;
		}

		return array(
			'user_id'     => (int) $raw['user_id'],
			'remember'    => ! empty( $raw['remember'] ),
			'created'     => isset( $raw['created'] ) ? (int) $raw['created'] : 0,
			'redirect_to' => isset( $raw['redirect_to'] ) && is_string( $raw['redirect_to'] ) ? $raw['redirect_to'] : '',
		);
	}

	private static function transient_key( string $token ): string {
		return 'sigil_ch_' . hash( 'sha256', $token );
	}

	/**
	 * Empty when there is no address to count against.
	 *
	 * Hashing an absent address gives every such request the same bucket, so on
	 * a server that does not report one, failures anywhere would throttle
	 * everybody at once. No address means no second bucket; the per-account
	 * count still applies.
	 */
	public static function ip_rate_key(): string {
		$ip = Request::client_ip();

		return '' === $ip ? '' : 'ip:' . hash( 'sha256', $ip );
	}

	private static function sanitize_redirect( string $redirect_to ): string {
		$redirect_to = esc_url_raw( $redirect_to );
		if ( '' === $redirect_to ) {
			return '';
		}

		$validated = wp_validate_redirect( $redirect_to, '' );
		return is_string( $validated ) ? $validated : '';
	}

	/**
	 * @param mixed $raw
	 * @return array<string, mixed>
	 */
	private static function sanitize_input( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $key => $value ) {
			if ( ! is_string( $key ) ) {
				continue;
			}
			// Skip our own control fields; providers read their own keys (code, etc.).
			if ( 0 === strpos( $key, 'sigil_' ) || 'action' === $key || '_wp_http_referer' === $key ) {
				continue;
			}
			if ( is_string( $value ) ) {
				$out[ $key ] = sanitize_text_field( $value );
			} elseif ( is_array( $value ) ) {
				$out[ $key ] = map_deep( $value, 'sanitize_text_field' );
			}
		}

		return $out;
	}

	/**
	 * @param \WP_Error|null $error
	 */
	private function render_screen( string $token, \WP_User $user, $error, string $provider_id ): void {
		$enrolled = Providers::instance()->enrolled_for( $user->ID );
		if ( [] === $enrolled ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$active = null;
		if ( '' !== $provider_id ) {
			foreach ( $enrolled as $provider ) {
				if ( $provider->id() === $provider_id ) {
					$active = $provider;
					break;
				}
			}
		}
		if ( null === $active ) {
			$active = Providers::instance()->preferred_for( $user->ID );
		}
		if ( null === $active ) {
			$active = $enrolled[0];
		}

		$payload     = self::payload( $token );
		$remember    = $payload ? $payload['remember'] : false;
		$redirect_to = $payload ? $payload['redirect_to'] : '';

		$challenge_token    = $token;
		$challenge_user     = $user;
		$challenge_providers = $enrolled;
		$challenge_active   = $active;
		$challenge_error    = $error instanceof \WP_Error ? $error : null;
		$challenge_remember = $remember;
		$challenge_redirect = $redirect_to;

		nocache_headers();

		wp_enqueue_style( 'sigil-login', SIGIL_URL . 'assets/css/login.css', array( 'login' ), SIGIL_VERSION );

		$login_title = __( 'Two-factor authentication', 'sigil-2fa' );

		// login_header/footer exist when the request entered via wp-login.php.
		// on_login often runs before those helpers have printed, but they are defined.
		// Never require wp-login.php here: it would re-enter the login controller.
		if ( function_exists( 'login_header' ) ) {
			// Core prints the error without a live-region role, so a screen reader
			// never hears that the code was refused.
			$announce = static fn( $html ) => '' === (string) $html ? $html : '<span role="alert">' . $html . '</span>';
			add_filter( 'login_errors', $announce );
			login_header(
				$login_title,
				'',
				$challenge_error instanceof \WP_Error ? $challenge_error : new \WP_Error()
			);
			remove_filter( 'login_errors', $announce );
			require SIGIL_DIR . 'templates/challenge.php';
			login_footer();
			return;
		}

		if ( ! headers_sent() ) {
			status_header( 200 );
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta http-equiv="Content-Type" content="<?php bloginfo( 'html_type' ); ?>; charset=<?php bloginfo( 'charset' ); ?>" />
	<meta name="viewport" content="width=device-width" />
	<title><?php echo esc_html( $login_title ); ?></title>
	<?php
	wp_enqueue_style( 'login' );
	// login_enqueue_scripts, login_head and login_footer are core WordPress hooks, not
	// ours. The challenge screen is a login interstitial, so it fires them to pick up
	// whatever themes and plugins already add to wp-login.php.
	// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
	do_action( 'login_enqueue_scripts' );
	wp_print_styles();
	wp_print_head_scripts();
	do_action( 'login_head' );
	?>
</head>
<body class="login no-js login-action-sigil wp-core-ui">
	<div id="login">
		<?php
		if ( $challenge_error instanceof \WP_Error && $challenge_error->has_errors() ) {
			echo '<div id="login_error" role="alert">' . wp_kses_post( $challenge_error->get_error_message() ) . '</div>';
		}
		require SIGIL_DIR . 'templates/challenge.php';
		?>
	</div>
	<?php
	do_action( 'login_footer' );
	// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
	wp_print_footer_scripts();
	?>
</body>
</html>
		<?php
	}
}
