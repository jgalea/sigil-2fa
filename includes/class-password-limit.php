<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Limits password guesses the way Rate_Limit already limits second-factor
 * guesses.
 *
 * Every password check runs through the authenticate filter, whichever way it
 * arrives: wp-login.php, XML-RPC, an AJAX or REST login form, WooCommerce. This
 * runs after all of them have answered, takes an attempt from the account's
 * bucket and the address's bucket, and refuses outright once either is spent.
 * A refusal looks the same whether the password was right or wrong, and
 * whether the account exists or not, so nothing is learned from it.
 *
 * The account bucket is keyed on what was typed, not on the account it names.
 * Keying on the account would let anyone check whether a username and an email
 * belong together by spending one and watching the other close. The cost is
 * that an account reachable by both gets the allowance twice.
 *
 * Only time ever reopens a bucket, so nobody can lock an account for good, and
 * a passkey sign-in sends no password and is never counted.
 */
final class Password_Limit {

	/**
	 * What WordPress says when the account or its password is wrong. Anything
	 * else came from a filter that turned the sign-in away for its own reason,
	 * such as a correct password Sigil refuses over AJAX, and is not a guess.
	 */
	private const CREDENTIAL_ERRORS = array( 'invalid_username', 'invalid_email', 'incorrect_password' );

	private static ?Password_Limit $instance = null;

	public static function instance(): Password_Limit {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// Last but one: after every other filter has answered, and before
		// trusted devices decide whether to let the session through.
		add_filter( 'authenticate', array( $this, 'limit' ), PHP_INT_MAX - 1, 3 );
	}

	public static function enabled(): bool {
		return Policy::get()['limit_passwords'];
	}

	/**
	 * @return array{attempts: int, ip_attempts: int, window: int, max_lockout: int}
	 */
	public static function limits(): array {
		$defaults = array(
			'attempts'    => 5,
			// An office, a school or a phone network shares one address, and
			// only failures count against it, so this can sit well above what
			// one person mistyping ever reaches.
			'ip_attempts' => 50,
			'window'      => 15 * MINUTE_IN_SECONDS,
			// Each lockout within a day doubles the next, up to this.
			'max_lockout' => HOUR_IN_SECONDS,
		);

		/**
		 * Filter how many failed passwords are allowed before signing in with a
		 * password is refused for a while.
		 *
		 * @param array{attempts: int, ip_attempts: int, window: int, max_lockout: int} $defaults
		 */
		$filtered = apply_filters( 'sigil_password_limits', $defaults );
		$filtered = is_array( $filtered ) ? $filtered : array();

		$limits = array();
		foreach ( $defaults as $key => $default ) {
			$value          = isset( $filtered[ $key ] ) ? (int) $filtered[ $key ] : $default;
			$limits[ $key ] = max( 1, $value );
		}
		$limits['max_lockout'] = max( $limits['max_lockout'], $limits['window'] );

		return $limits;
	}

	/**
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public function limit( $user, $username = '', $password = '' ) {
		$username = strtolower( trim( (string) $username ) );
		if ( '' === (string) $password || '' === $username || ! self::enabled() ) {
			return $user;
		}

		// Application passwords are long and random, so nobody guesses one, and
		// the API clients holding them keep working while the login form is
		// under attack.
		if ( $user instanceof \WP_User && App_Passwords::instance()->used_application_password( (int) $user->ID ) ) {
			return $user;
		}

		$limits      = self::limits();
		$account_key = self::account_key( $username );
		$ip_key      = self::ip_key();

		// Taken before deciding, as the challenge does, so a burst of parallel
		// posts cannot all pass a check made before the count.
		$account = Rate_Limit::reserve( $account_key, $limits['window'] );
		$ip      = Rate_Limit::reserve( $ip_key, $limits['window'] );

		// No table to count in. The challenge fails closed on that, but here it
		// would stop everyone on the site signing in with a password, the
		// administrator who could fix it included.
		if ( PHP_INT_MAX === $account || PHP_INT_MAX === $ip ) {
			return $user;
		}

		if ( $account > $limits['attempts'] ) {
			if ( $account === $limits['attempts'] + 1 ) {
				self::back_off( $account_key, $limits );
			}
			// Turned away without a guess, so the address is not charged.
			Rate_Limit::release( $ip_key );
			return self::refused();
		}

		if ( $ip > $limits['ip_attempts'] ) {
			Rate_Limit::release( $account_key );
			return self::refused();
		}

		if ( $user instanceof \WP_User ) {
			Rate_Limit::clear( $account_key );
			Rate_Limit::clear( self::strike_key( $account_key ) );
			Rate_Limit::release( $ip_key );
			return $user;
		}

		if ( ! is_wp_error( $user ) || array() === array_intersect( $user->get_error_codes(), self::CREDENTIAL_ERRORS ) ) {
			Rate_Limit::release( $account_key );
			Rate_Limit::release( $ip_key );
		}

		return $user;
	}

	/**
	 * Reopen an account someone has locked by guessing at it.
	 *
	 * Clears what was counted against the account's username and its email,
	 * since either may have been typed, and against an address when one is
	 * given. The challenge's counters are a separate allowance for codes and
	 * are left alone unless asked for.
	 *
	 * @return array<string, int> What each cleared bucket held.
	 */
	public static function unlock( \WP_User $user, string $ip = '', bool $challenge = false ): array {
		$buckets = array();
		foreach ( array_unique( array( (string) $user->user_login, (string) $user->user_email ) ) as $login ) {
			$login = strtolower( trim( $login ) );
			if ( '' !== $login ) {
				$buckets[ 'password: ' . $login ] = self::account_key( $login );
			}
		}

		if ( '' !== $ip ) {
			$buckets[ 'password: address ' . $ip ] = 'pw:' . Challenge::ip_rate_key_for( $ip );
		}

		if ( $challenge ) {
			$buckets['challenge: account'] = 'u:' . (int) $user->ID;
			if ( '' !== $ip ) {
				$buckets[ 'challenge: address ' . $ip ] = Challenge::ip_rate_key_for( $ip );
			}
		}

		$cleared = array();
		foreach ( $buckets as $label => $key ) {
			$cleared[ $label ] = Rate_Limit::count( $key );
			Rate_Limit::clear( $key );
			if ( 0 === strpos( $key, 'pw:a:' ) ) {
				Rate_Limit::clear( self::strike_key( $key ) );
			}
		}

		return $cleared;
	}

	private static function account_key( string $login ): string {
		return 'pw:a:' . $login;
	}

	/**
	 * Hold the account closed for longer each time it fills up within a day.
	 *
	 * @param array{attempts: int, ip_attempts: int, window: int, max_lockout: int} $limits
	 */
	private static function back_off( string $account_key, array $limits ): void {
		$strikes = Rate_Limit::reserve( self::strike_key( $account_key ), DAY_IN_SECONDS );
		$strikes = min( max( 1, $strikes ), 16 );
		$lockout = min( $limits['window'] * ( 2 ** ( $strikes - 1 ) ), $limits['max_lockout'] );

		Rate_Limit::extend( $account_key, time() + $lockout );
	}

	private static function strike_key( string $account_key ): string {
		return $account_key . ':strikes';
	}

	/**
	 * Kept apart from the challenge's address bucket, so mistyped passwords
	 * never use up the allowance for codes.
	 */
	private static function ip_key(): string {
		$key = Challenge::ip_rate_key();

		return '' === $key ? '' : 'pw:' . $key;
	}

	private static function refused(): \WP_Error {
		return new \WP_Error(
			'sigil_password_limited',
			__( 'Too many failed sign-in attempts. Please wait a few minutes and try again.', 'sigil-2fa' ),
			array( 'status' => 429 )
		);
	}
}
