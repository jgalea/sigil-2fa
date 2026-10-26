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
 * The account bucket is keyed on the name as the database compares it. MySQL
 * matches a login however it is cased, accented, padded or written in
 * full-width letters, and so does core's password check, so keying on the
 * typed text would give every spelling its own allowance. Keying on the
 * collation's own sort weight merges exactly the spellings the database
 * merges, whether or not an account by that name exists, so locking a name
 * and trying a variant says nothing about which names are real. A login and
 * an email are still counted apart: one bucket for both would let anyone
 * check whether a username and an address belong together by spending one
 * and watching the other close. The cost is that an account gets the
 * allowance once under each.
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

	/**
	 * The collation of each users column, read once. Empty when it cannot be
	 * read or weighed, which sends account_key() to the normaliser.
	 *
	 * @var array<string, string>|null
	 */
	private static ?array $collations = null;

	/** @var array<string, string> */
	private static array $weights = array();

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

		// Anyone anywhere can spend an account's allowance, so on its own it
		// would let a stranger keep an administrator out for as long as they
		// kept guessing. The right password from a device that account trusted
		// after passing its second factor is the owner, and skips it. The
		// address bucket still applies.
		$trusted = $user instanceof \WP_User && Trusted_Devices::instance()->trusts_request( (int) $user->ID );

		// Taken before deciding, as the challenge does, so a burst of parallel
		// posts cannot all pass a check made before the count.
		$account = $trusted ? 0 : Rate_Limit::reserve( $account_key, $limits['window'] );
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
			if ( ! $trusted ) {
				Rate_Limit::release( $account_key );
			}
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
			'password: ' . strtolower( (string) $user->user_login ) => self::account_key( (string) $user->user_login ),
		);
		if ( '' !== (string) $user->user_email ) {
			$buckets[ 'password: ' . strtolower( (string) $user->user_email ) ] = self::account_key( (string) $user->user_email );
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
	 * An email counts against user_email's collation and anything else
	 * against user_login's, the columns core looks the name up in. Nothing
	 * here asks whether an account exists.
	 */
	public static function account_key( string $typed ): string {
		$name   = sanitize_user( $typed );
		$column = is_email( $name ) ? 'user_email' : 'user_login';
		$weight = self::weight( $name, $column );

		$identity = '' === $weight ? self::normalise( $typed ) : $weight;

		return self::key_for( ( 'user_email' === $column ? 'e:' : 'l:' ) . $identity );
	}

	/**
	 * The collation's sort weight for the name, hex-encoded: equal exactly
	 * when the database would call the two names equal.
	 *
	 * A PAD SPACE collation also ignores trailing characters that sort as a
	 * space when it compares, which WEIGHT_STRING() keeps for anything but an
	 * ASCII space, so those are dropped first.
	 *
	 * Empty when the database has no WEIGHT_STRING() (SQLite, or a server
	 * that refuses the query), and the caller falls back to the normaliser,
	 * which merges the common spellings but not every one the collation does.
	 */
	private static function weight( string $name, string $column ): string {
		$collation = self::collation( $column );
		if ( '' === $collation || '' === $name ) {
			return '';
		}

		if ( false === strpos( $collation, '_0900_' ) && false === strpos( $collation, 'nopad' ) ) {
			$trimmed = preg_replace( '/\p{Zs}+$/u', '', $name );
			$name    = is_string( $trimmed ) ? $trimmed : $name;
		}

		$memo = $collation . "\0" . $name;
		if ( isset( self::$weights[ $memo ] ) ) {
			return self::$weights[ $memo ];
		}

		global $wpdb;

		$charset = strtok( $collation, '_' );
		$prior   = $wpdb->suppress_errors( true );
		// The charset and collation come from the server's own column
		// definition and are checked to be plain identifiers in collation().
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$weight = $wpdb->get_var( $wpdb->prepare( "SELECT HEX(WEIGHT_STRING(CONVERT(%s USING {$charset}) COLLATE {$collation}))", $name ) );
		$wpdb->suppress_errors( $prior );

		$weight = is_string( $weight ) ? $weight : '';
		if ( count( self::$weights ) < 256 ) {
			self::$weights[ $memo ] = $weight;
		}

		return $weight;
	}

	private static function collation( string $column ): string {
		if ( null === self::$collations ) {
			global $wpdb;

			self::$collations = array(
				'user_login' => '',
				'user_email' => '',
			);

			$prior = $wpdb->suppress_errors( true );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
			$columns = $wpdb->get_results( "SHOW FULL COLUMNS FROM {$wpdb->users}" );
			$wpdb->suppress_errors( $prior );

			foreach ( is_array( $columns ) ? $columns : array() as $row ) {
				$field     = isset( $row->Field ) ? (string) $row->Field : ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				$collation = isset( $row->Collation ) ? (string) $row->Collation : ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				if ( isset( self::$collations[ $field ] ) && preg_match( '/^[A-Za-z0-9]+_[A-Za-z0-9_]+$/', $collation ) ) {
					self::$collations[ $field ] = $collation;
				}
			}
		}

		return self::$collations[ $column ] ?? '';
	}

	/**
	 * Only used where the database cannot weigh a name.
	 */
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
