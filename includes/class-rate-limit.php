<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

// Every read and write here is a direct query against the plugin's own table.
// A counter that answers from cache is not a counter, and the table name cannot
// be bound as a parameter.
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter

/**
 * Attempt counting that a burst of parallel requests cannot outrun.
 *
 * The obvious implementation, read the count and write back one more, is not
 * atomic: fire fifty guesses at once and every one of them reads the same number
 * and writes the same number back, so the counter advances by one and the real
 * ceiling becomes however many requests an attacker can make at the same
 * moment. Claiming the challenge token bounds one token to one guess, but
 * nothing bounds how many tokens somebody with the password can mint, so that
 * alone does not close it.
 *
 * The count therefore lives in a table with a primary key, and every attempt is
 * reserved by a single statement that increments and returns the new value.
 * Whoever asks for the sixth attempt is told it is the sixth, whatever else is
 * happening at the same time.
 */
final class Rate_Limit {

	public const PURGE_HOOK = 'sigil_purge_attempts';

	private const MAX_ATTEMPTS = 5;

	/**
	 * The address bucket counts further before it closes, because an address is
	 * not a person. An office, a school or a phone network arrives from one
	 * address, and holding all of them to one person's allowance means a few
	 * colleagues mistyping can stop everybody else signing in. Guessing any
	 * single account is still bounded by MAX_ATTEMPTS; this only bounds how
	 * widely one address may spray across different accounts.
	 */
	private const MAX_IP_ATTEMPTS = 20;
	private const WINDOW       = 15 * MINUTE_IN_SECONDS;

	/**
	 * One repair attempt per request. Without it a genuinely broken database
	 * would run dbDelta on every single call.
	 */
	private static bool $repaired = false;

	public static function table(): string {
		return Network::table_prefix() . 'sigil_attempts';
	}

	/**
	 * Nothing else deletes a bucket once its window has run out. A busy login
	 * page writes one row per user and per address, so without this the table
	 * only ever grows, and the rows it keeps are a record of who tried to sign
	 * in and from where.
	 */
	public static function schedule_purge(): void {
		add_action( self::PURGE_HOOK, array( __CLASS__, 'purge_expired' ) );

		if ( ! wp_next_scheduled( self::PURGE_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::PURGE_HOOK );
		}
	}

	public static function purge_expired(): void {
		global $wpdb;

		$table = self::table();

		self::run( $wpdb->prepare( "DELETE FROM {$table} WHERE expires < %d", time() ) );
	}

	/**
	 * Take one attempt and say which number it was.
	 *
	 * Callers decide with this rather than with a separate read, because a read
	 * followed by a write is the thing being avoided.
	 */
	public static function reserve( string $key, int $window = self::WINDOW ): int {
		if ( '' === $key ) {
			return 0;
		}

		global $wpdb;

		$table  = self::table();
		$bucket = self::bucket( $key );
		$now    = time();
		$expiry = $now + max( 1, $window );

		// One statement: insert the first attempt, or add one to an existing
		// window, or start a fresh window if the old one has run out.
		// LAST_INSERT_ID() carries the resulting count back on this connection,
		// so the answer belongs to this request and not to whoever wrote last.
		$sql = $wpdb->prepare(
			"INSERT INTO {$table} (bucket, attempts, expires) VALUES (%s, 1, %d)
			 ON DUPLICATE KEY UPDATE
				attempts = LAST_INSERT_ID( IF( expires < %d, 1, attempts + 1 ) ),
				expires  = IF( expires < %d, %d, expires )",
			$bucket,
			$expiry,
			$now,
			$now,
			$expiry
		);

		$ok = self::run( $sql );

		if ( false === $ok && ! self::$repaired ) {
			// Refusing every attempt is the safe answer for a limiter, and also
			// a site-wide lockout: nobody holding a second factor could finish
			// signing in. So try once to put the table back before accepting
			// that outcome. A dropped table, a half-finished upgrade, and a
			// version stamp that ran ahead of the schema all land here.
			self::$repaired = true;
			Schema::install();

			$ok = self::run( $sql );
		}

		if ( false === $ok ) {
			// Still no table, so there is no counter to trust. Refusing reads as
			// "rate limited", which fails closed rather than leaving guesses
			// uncounted.
			return PHP_INT_MAX;
		}

		// A fresh row is the first attempt by definition. Only the update branch
		// ran LAST_INSERT_ID, and on the insert branch insert_id still holds
		// whatever the last query on this connection left there, which is not
		// ours to read.
		if ( 1 === $wpdb->rows_affected ) {
			return 1;
		}

		$count = (int) $wpdb->insert_id;

		return $count > 0 ? $count : self::count( $key );
	}

	/**
	 * Give back one attempt taken by reserve(), for a request that turned out
	 * not to be a guess. One statement, for the same reason reserve() is.
	 */
	public static function release( string $key ): void {
		if ( '' === $key ) {
			return;
		}

		global $wpdb;

		$table = self::table();

		self::run( $wpdb->prepare( "UPDATE {$table} SET attempts = attempts - 1 WHERE bucket = %s AND attempts > 0", self::bucket( $key ) ) );
	}

	/**
	 * Keep a bucket closed until at least this time. Never shortens it.
	 */
	public static function extend( string $key, int $until ): void {
		if ( '' === $key ) {
			return;
		}

		global $wpdb;

		$table = self::table();

		self::run( $wpdb->prepare( "UPDATE {$table} SET expires = GREATEST( expires, %d ) WHERE bucket = %s", $until, self::bucket( $key ) ) );
	}

	public static function max_attempts(): int {
		return self::MAX_ATTEMPTS;
	}

	public static function max_ip_attempts(): int {
		return self::MAX_IP_ATTEMPTS;
	}

	public static function blocked( string $key ): bool {
		return self::count( $key ) >= self::MAX_ATTEMPTS;
	}

	public static function count( string $key ): int {
		if ( '' === $key ) {
			return 0;
		}

		global $wpdb;

		$table = self::table();

		$prior = $wpdb->suppress_errors( true );
		$row   = $wpdb->get_row(
			$wpdb->prepare( "SELECT attempts, expires FROM {$table} WHERE bucket = %s", self::bucket( $key ) )
		);
		$wpdb->suppress_errors( $prior );

		if ( ! $row || (int) $row->expires < time() ) {
			return 0;
		}

		return (int) $row->attempts;
	}

	public static function clear( string $key ): void {
		if ( '' === $key ) {
			return;
		}

		global $wpdb;

		$wpdb->delete( self::table(), array( 'bucket' => self::bucket( $key ) ), array( '%s' ) );
	}

	/**
	 * Errors are suppressed because a missing table is answered here rather
	 * than printed into the page or the log on every attempt.
	 *
	 * @return int|bool Rows affected, or false when the query could not run.
	 */
	private static function run( string $sql ) {
		global $wpdb;

		$prior = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- every caller passes the result of $wpdb->prepare().
		$result = $wpdb->query( $sql );
		$wpdb->suppress_errors( $prior );

		return $result;
	}

	private static function bucket( string $key ): string {
		return hash( 'sha256', $key );
	}
}
