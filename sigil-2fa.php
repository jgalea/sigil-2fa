<?php
/**
 * Plugin Name: Sigil – Passkeys and Two-Factor Authentication
 * Description: Two-factor authentication for WordPress logins: passkeys, authenticator apps, backup codes and email codes, with per-role enforcement, multisite support and account recovery.
 * Version: 0.5.4
 * Requires at least: 6.9
 * Requires PHP: 7.4
 * Author: Jean Galea
 * Author URI: https://jeangalea.com
 * License: GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: sigil-2fa
 * Domain Path: /languages
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

define( 'SIGIL_VERSION', '0.5.4' );
define( 'SIGIL_FILE', __FILE__ );
define( 'SIGIL_DIR', plugin_dir_path( __FILE__ ) );
define( 'SIGIL_URL', plugin_dir_url( __FILE__ ) );

require_once SIGIL_DIR . 'includes/class-plugin.php';

register_activation_hook(
	__FILE__,
	static function (): void {
		require_once SIGIL_DIR . 'includes/class-network.php';
		require_once SIGIL_DIR . 'includes/class-policy.php';
		require_once SIGIL_DIR . 'includes/class-schema.php';
		Sigil\Schema::install();
		require_once SIGIL_DIR . 'includes/class-review-prompt.php';
		Sigil\Review_Prompt::record_activation();
	}
);

register_deactivation_hook(
	__FILE__,
	static function (): void {
		// Otherwise the daily event outlives the code that answers it.
		wp_clear_scheduled_hook( 'sigil_purge_attempts' );
	}
);

Sigil\Plugin::instance()->boot();
