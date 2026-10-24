<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Schema {

	private static ?Schema $instance = null;

	public static function instance(): Schema {
		if ( null === self::$instance ) {
			self::$instance = new self();
			add_action( 'admin_init', array( self::$instance, 'maybe_install' ) );
		}
		return self::$instance;
	}

	// The activation hook is not enough on its own: a half-failed activation, a
	// dropped table, or a site that never fired the hook (some CLI installs)
	// would leave the credentials table missing forever, and every passkey read
	// would throw. A passkey credential can only be created during admin
	// enrolment, so checking here guarantees the table exists before one can.
	public function maybe_install(): void {
		if ( Network::get_option( 'sigil_db_version' ) !== SIGIL_VERSION ) {
			self::install();
		}
	}

	public static function table(): string {
		return Network::table_prefix() . 'sigil_credentials';
	}

	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table           = self::table();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT UNSIGNED NOT NULL,
			credential_id VARBINARY(255) NOT NULL,
			public_key TEXT NOT NULL,
			sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
			transports VARCHAR(120) NOT NULL DEFAULT '',
			label VARCHAR(190) NOT NULL DEFAULT '',
			user_handle VARBINARY(64) NOT NULL DEFAULT '',
			discoverable TINYINT(1) DEFAULT NULL,
			created_at DATETIME NOT NULL,
			last_used_at DATETIME DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY credential_id (credential_id),
			KEY user_id (user_id)
		) {$charset_collate};";

		$attempts = Rate_Limit::table();
		$sql     .= " CREATE TABLE {$attempts} (
			bucket CHAR(64) NOT NULL,
			attempts INT UNSIGNED NOT NULL DEFAULT 0,
			expires BIGINT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY  (bucket),
			KEY expires (expires)
		) {$charset_collate};";

		dbDelta( $sql );
		self::migrate_to_network();
		Network::update_option( 'sigil_db_version', SIGIL_VERSION );
	}

	/**
	 * Carry a pre-network install's data up to network scope.
	 *
	 * Before multisite support, both the policy and the credentials lived per
	 * site. Leaving them there on upgrade would read as "no policy" and "no
	 * passkeys": a passkey-only account would stop being challenged at login
	 * while its method row still said it was covered, so nothing would prompt a
	 * re-enrol either. That is a silent drop to password-only, which is worse
	 * than any migration risk.
	 *
	 * phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
	 * phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
	 */
	private static function migrate_to_network(): void {
		if ( ! is_multisite() ) {
			return;
		}

		global $wpdb;

		$network_table = self::table();

		if ( false === get_site_option( Policy::OPTION_KEY, false ) ) {
			switch_to_blog( get_main_site_id() );
			$legacy_policy = get_option( Policy::OPTION_KEY, false );
			restore_current_blog();

			if ( is_array( $legacy_policy ) ) {
				update_site_option( Policy::OPTION_KEY, $legacy_policy );
			}
		}

		$site_ids = get_sites(
			array(
				'fields'                 => 'ids',
				'number'                 => 0,
				'update_site_meta_cache' => false,
			)
		);

		foreach ( $site_ids as $site_id ) {
			$legacy_table = $wpdb->get_blog_prefix( (int) $site_id ) . 'sigil_credentials';
			if ( $legacy_table === $network_table ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from get_blog_prefix(), which cannot be a placeholder.
			$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $legacy_table ) );
			if ( $exists !== $legacy_table ) {
				continue;
			}

			// INSERT IGNORE so a credential already carried over, or one that
			// somehow exists on two sites, does not abort the whole migration.
			// The old table is left in place: this is not a step to undo blindly.
			//
			// Both names are table identifiers built from $wpdb prefixes, and an
			// identifier cannot be a bound placeholder. Disabled as a pair rather
			// than ignored on one line, because the interpolation sits inside the
			// string on the lines below.
			// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->query(
				"INSERT IGNORE INTO {$network_table}
					(user_id, credential_id, public_key, sign_count, transports, label, created_at, last_used_at)
				 SELECT user_id, credential_id, public_key, sign_count, transports, label, created_at, last_used_at
				 FROM {$legacy_table}"
			);
			// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		}

		self::reconcile_sign_counts( $site_ids );
	}

	/**
	 * Where the same authenticator was registered on two sites, INSERT IGNORE
	 * keeps whichever row was reached first, which may hold the lower signature
	 * counter. Raising each to the highest value seen keeps the clone check as
	 * informed after the merge as it was before.
	 *
	 * @param list<int|string> $site_ids
	 *
	 * phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
	 * phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
	 * phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	 * phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter
	 */
	private static function reconcile_sign_counts( array $site_ids ): void {
		global $wpdb;

		$network_table = self::table();

		foreach ( $site_ids as $site_id ) {
			$legacy_table = $wpdb->get_blog_prefix( (int) $site_id ) . 'sigil_credentials';
			if ( $legacy_table === $network_table ) {
				continue;
			}

			$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $legacy_table ) );
			if ( $exists !== $legacy_table ) {
				continue;
			}

			$wpdb->query(
				"UPDATE {$network_table} AS n
				 JOIN {$legacy_table} AS o ON o.credential_id = n.credential_id
				 SET n.sign_count = o.sign_count
				 WHERE o.sign_count > n.sign_count"
			);
		}
	}
}
