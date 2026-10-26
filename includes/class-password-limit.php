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
 * The account bucket is keyed on the account the typed name reaches, found
 * the way core's own password check finds it. MySQL matches a login however
 * it is cased, accented, padded or written in full-width letters, so keying
 * on the text would give every spelling its own allowance. A login and an
 * email are still counted apart: one bucket for both would let anyone check
 * whether a username and an address belong together by spending one and
 * watching the other close. The cost is that an account gets the allowance
 * once under each.
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
		$username = (string) $username;
		if ( '' === (string) $password || '' === trim( $username ) || ! self::enabled() ) {
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
		$buckets = array(
			'password: ' . strtolower( (string) $user->user_login ) => self::key_for( 'l:' . strtolower( (string) $user->user_login ) ),
		);
		if ( '' !== (string) $user->user_email ) {
			$buckets[ 'password: ' . strtolower( (string) $user->user_email ) ] = self::key_for( 'e:' . strtolower( (string) $user->user_email ) );
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

	/**
	 * The bucket a typed name counts against.
	 *
	 * A name that reaches an account by login counts against that account's
	 * stored login, and one that reaches it by email against its stored email.
	 * A name that reaches nobody is normalised, so spellings of a name that
	 * does not exist behave like spellings of one that does.
	 */
	public static function account_key( string $typed ): string {
		$login = sanitize_user( $typed );
		$user  = '' === $login ? false : get_user_by( 'login', $login );
		if ( $user instanceof \WP_User ) {
			return self::key_for( 'l:' . strtolower( (string) $user->user_login ) );
		}

		if ( is_email( $typed ) ) {
			$user = get_user_by( 'email', $typed );
			if ( $user instanceof \WP_User ) {
				return self::key_for( 'e:' . strtolower( (string) $user->user_email ) );
			}
		}

		return self::key_for( 'n:' . self::normalise( $typed ) );
	}

	private static function normalise( string $typed ): string {
		$name = sanitize_user( $typed );
		if ( class_exists( 'Normalizer' ) ) {
			$normalised = \Normalizer::normalize( $name, \Normalizer::FORM_KC );
			$name       = is_string( $normalised ) ? $normalised : $name;
		}
		$name = function_exists( 'mb_strtolower' ) ? mb_strtolower( $name, 'UTF-8' ) : strtolower( $name );
		// Default-ignorable code points: zero-width spaces and joiners, soft
		// hyphens, variation selectors and the like.
		$stripped = preg_replace( '/\p{Cf}|[\x{034F}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180B}-\x{180F}\x{3164}\x{FE00}-\x{FE0F}\x{FFA0}]/u', '', $name );
		$name     = is_string( $stripped ) ? $stripped : $name;
		$trimmed  = preg_replace( '/^[\s\x{00A0}]+|[\s\x{00A0}]+$/u', '', $name );

		return is_string( $trimmed ) ? $trimmed : trim( $name );
	}

	/**
	 * Hashed, so nothing typed can reach into another bucket's name.
	 */
	private static function key_for( string $identity ): string {
		return 'pw:a:' . hash( 'sha256', $identity );
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
		return 'pw:s:' . substr( $account_key, strlen( 'pw:a:' ) );
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
