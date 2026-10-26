<?php
global $wpdb;

$tables = $wpdb->get_col(
	$wpdb->prepare(
		'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE %s',
		$wpdb->esc_like( $wpdb->prefix . 'sigil_' ) . '%'
	)
);
sort( $tables );

$credentials = $wpdb->prefix . 'sigil_credentials';
$columns     = in_array( $credentials, $tables, true )
	? $wpdb->get_col( $wpdb->prepare( 'SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION', $credentials ) )
	: array();

$policy = (array) get_option( 'sigil_policy', array() );

$user    = get_user_by( 'login', 'smoke_2fa' );
$methods = $user ? (array) get_user_meta( $user->ID, '_sigil_methods', true ) : array();
$backup  = $methods['backup']['codes'] ?? array();

echo 'tables=' . implode( ',', $tables ) . "\n";
echo 'columns=' . implode( ',', $columns ) . "\n";
echo 'db_version=' . get_option( 'sigil_db_version', '' ) . "\n";
echo 'policy_enabled=' . ( ! empty( $policy['enabled'] ) ? 1 : 0 ) . "\n";
echo 'policy_grace=' . (int) ( $policy['grace_days'] ?? 0 ) . "\n";
echo 'policy_editor=' . ( ! empty( $policy['roles']['editor'] ) ? 1 : 0 ) . "\n";
echo 'methods=' . implode( ',', array_keys( $methods ) ) . "\n";
echo 'backup_unused=' . count( array_filter( (array) $backup, static fn( $c ) => empty( $c['used'] ) ) ) . "\n";
echo 'trusted_days=' . get_option( 'sigil_pro_trusted_days', '' ) . "\n";
echo 'options=' . (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( 'sigil_' ) . '%', $wpdb->esc_like( '_transient_sigil_' ) . '%' ) ) . "\n";
echo 'option_names=' . implode( ',', $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( 'sigil_' ) . '%', $wpdb->esc_like( '_transient_sigil_' ) . '%' ) ) ) . "\n";
echo 'usermeta=' . (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( '_sigil_' ) . '%' ) ) . "\n";
echo 'usermeta_keys=' . implode( ',', $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT meta_key FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( '_sigil_' ) . '%' ) ) ) . "\n";
