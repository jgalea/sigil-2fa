<?php

declare( strict_types=1 );

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Uninstall runs once, at the moment the user deletes the plugin. Dropping a
 * plugin-owned table and sweeping its options has no core API, and caching a
 * result set here would be meaningless since nothing reads it afterwards.
 *
 * The table name is a $wpdb prefix plus a literal. An identifier cannot be a
 * bound placeholder, so it is interpolated and the sniff is disabled for it.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
 * phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
 * phpcs:disable WordPress.DB.DirectDatabaseQuery.SchemaChange
 * phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
 */
function sigil_uninstall_site(): void {
	global $wpdb;

	foreach ( array( 'sigil_db_version', 'sigil_policy', 'sigil_frontend_page' ) as $option ) {
		delete_option( $option );
	}

	// Anything stored under the add-on's prefix: its own settings, and the ones
	// that moved into this plugin and kept their names. Swept by prefix rather
	// than by a list, so the free build does not have to know what the paid one keeps.
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'sigil\_pro\_%'" );

	// Rate-limit, challenge, email and backup-display transients all carry the
	// sigil_ prefix.
	$wpdb->query(
		"DELETE FROM {$wpdb->options}
		 WHERE option_name LIKE '\\_transient\\_sigil\\_%'
		    OR option_name LIKE '\\_transient\\_timeout\\_sigil\\_%'"
	);
}

function sigil_uninstall(): void {
	global $wpdb;

	// Users are network-wide, and so is the credentials table on multisite.
	// Both are cleared once rather than once per site.
	$prefix = is_multisite() ? $wpdb->base_prefix : $wpdb->prefix;
	$wpdb->query( "DROP TABLE IF EXISTS {$prefix}sigil_credentials" );
	$wpdb->query( "DROP TABLE IF EXISTS {$prefix}sigil_attempts" );

	wp_clear_scheduled_hook( 'sigil_purge_attempts' );

	foreach ( array( '_sigil_methods', '_sigil_deadline', '_sigil_reset_log', '_sigil_email_debug_code', '_sigil_preferred_method', '_sigil_pro_trusted', '_sigil_pro_bypass' ) as $meta_key ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s", $meta_key ) );
	}

	if ( ! is_multisite() ) {
		sigil_uninstall_site();
		return;
	}

	foreach ( array( 'sigil_db_version', 'sigil_policy' ) as $option ) {
		delete_site_option( $option );
	}

	$wpdb->query(
		"DELETE FROM {$wpdb->sitemeta}
		 WHERE meta_key LIKE '\\_site\\_transient\\_sigil\\_%'
		    OR meta_key LIKE '\\_site\\_transient\\_timeout\\_sigil\\_%'"
	);

	// A site that ran the plugin before the network was created still holds its
	// own option rows, and every site keeps its own transient leftovers.
	$site_ids = get_sites(
		array(
			'fields'                 => 'ids',
			'number'                 => 0,
			'update_site_meta_cache' => false,
		)
	);

	foreach ( $site_ids as $site_id ) {
		switch_to_blog( (int) $site_id );
		sigil_uninstall_site();
		restore_current_blog();
	}
}

sigil_uninstall();
