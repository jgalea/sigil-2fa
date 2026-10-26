<?php

declare( strict_types=1 );

$_tests_dir = getenv( 'WP_TESTS_DIR' );

if ( ! $_tests_dir ) {
	$_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
}

if ( ! file_exists( $_tests_dir . '/includes/functions.php' ) ) {
	echo "Could not find {$_tests_dir}/includes/functions.php" . PHP_EOL;
	exit( 1 );
}

require_once $_tests_dir . '/includes/functions.php';

/**
 * @return void
 */
function _sigil_manually_load_plugin() {
	require dirname( __DIR__ ) . '/sigil-2fa.php';
}

tests_add_filter( 'muplugins_loaded', '_sigil_manually_load_plugin' );

require $_tests_dir . '/includes/bootstrap.php';
require_once __DIR__ . '/trait-clears-attempts.php';
require_once __DIR__ . '/trait-import-fixtures.php';
