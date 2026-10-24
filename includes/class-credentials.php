<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Credentials {

	/**
	 * @param string    $user_handle  The handle the authenticator was given, empty when it is not known
	 *                                (passkeys registered before it was stored, or brought in by an importer).
	 * @param bool|null $discoverable Whether the browser reported a resident key, null when it did not say.
	 * @return int Inserted row ID, or 0 on failure.
	 */
	public static function add(
		int $user_id,
		string $credential_id,
		string $public_key,
		int $sign_count,
		string $label,
		string $transports,
		string $user_handle = '',
		?bool $discoverable = null
	): int {
		global $wpdb;

		if ( $user_id <= 0 || '' === $credential_id || '' === $public_key ) {
			return 0;
		}

		$row = [
			'user_id'       => $user_id,
			'credential_id' => $credential_id,
			'public_key'    => $public_key,
			'sign_count'    => max( 0, $sign_count ),
			'transports'    => sanitize_text_field( $transports ),
			'label'         => sanitize_text_field( $label ),
			'user_handle'   => $user_handle,
			'created_at'    => current_time( 'mysql', true ),
		];
		$formats = [ '%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s' ];

		// wpdb has no NULL format, so an unknown answer is left to the column default.
		if ( null !== $discoverable ) {
			$row['discoverable'] = $discoverable ? 1 : 0;
			$formats[]           = '%d';
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$ok = $wpdb->insert( Schema::table(), $row, $formats );

		if ( false === $ok ) {
			return 0;
		}

		return (int) $wpdb->insert_id;
	}

	/**
	 * @return list<object{
	 *   id: int|string,
	 *   user_id: int|string,
	 *   credential_id: string,
	 *   public_key: string,
	 *   sign_count: int|string,
	 *   transports: string,
	 *   label: string,
	 *   user_handle: string,
	 *   discoverable: int|string|null,
	 *   created_at: string,
	 *   last_used_at: string|null
	 * }>
	 */
	public static function for_user( int $user_id ): array {
		global $wpdb;

		if ( $user_id <= 0 ) {
			return [];
		}

		$table = Schema::table();

		// Passkey credentials live in a plugin-owned table, so there is no core API to
		// read them through. The only interpolated value is the table name from
		// Schema::table(), which is $wpdb->prefix plus a literal; $wpdb->prepare cannot
		// take a table name as a placeholder. Every user-supplied value is prepared.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE user_id = %d ORDER BY id ASC",
				$user_id
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return is_array( $rows ) ? $rows : [];
	}

	public static function by_credential_id( string $credential_id ): ?object {
		global $wpdb;

		if ( '' === $credential_id ) {
			return null;
		}

		$table = Schema::table();

		// See the note in for_user(): plugin-owned table, table name from Schema::table(),
		// user-supplied credential id passed through $wpdb->prepare.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE credential_id = %s LIMIT 1",
				$credential_id
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return $row instanceof \stdClass ? $row : null;
	}

	public static function touch( int $id, int $sign_count ): void {
		global $wpdb;

		if ( $id <= 0 ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			Schema::table(),
			[
				'sign_count'   => max( 0, $sign_count ),
				'last_used_at' => current_time( 'mysql', true ),
			],
			[ 'id' => $id ],
			[ '%d', '%s' ],
			[ '%d' ]
		);
	}

	/**
	 * Record that a credential has signed in on its own, which only a resident
	 * key can do. Passkeys registered before the browser was asked are learned
	 * this way rather than nagged about.
	 */
	public static function mark_discoverable( int $id ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update( Schema::table(), [ 'discoverable' => 1 ], [ 'id' => $id ], [ '%d' ], [ '%d' ] );
	}

	public static function delete( int $id, int $user_id ): bool {
		global $wpdb;

		if ( $id <= 0 || $user_id <= 0 ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$deleted = $wpdb->delete(
			Schema::table(),
			[
				'id'      => $id,
				'user_id' => $user_id,
			],
			[ '%d', '%d' ]
		);

		return is_int( $deleted ) && $deleted > 0;
	}

	/**
	 * Delete every credential row for a user.
	 */
	public static function delete_for_user( int $user_id ): void {
		global $wpdb;

		if ( $user_id <= 0 ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->delete(
			Schema::table(),
			[ 'user_id' => $user_id ],
			[ '%d' ]
		);
	}
}
