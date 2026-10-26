<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Plugin {

	private static ?Plugin $instance = null;

	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
	}

	public function boot(): void {
		require_once SIGIL_DIR . 'includes/class-crypto.php';
		require_once SIGIL_DIR . 'includes/class-request.php';
		require_once SIGIL_DIR . 'includes/class-network.php';
		require_once SIGIL_DIR . 'includes/class-store.php';
		require_once SIGIL_DIR . 'includes/class-schema.php';
		Schema::instance();
		require_once SIGIL_DIR . 'includes/interface-provider.php';
		require_once SIGIL_DIR . 'includes/class-providers.php';
		require_once SIGIL_DIR . 'includes/class-policy.php';

		Providers::instance();

		require_once SIGIL_DIR . 'includes/class-rate-limit.php';
		Rate_Limit::schedule_purge();
		require_once SIGIL_DIR . 'includes/class-challenge.php';
		Challenge::instance();
		require_once SIGIL_DIR . 'includes/class-passwordless.php';
		Passwordless::instance();

		require_once SIGIL_DIR . 'includes/class-recovery.php';
		require_once SIGIL_DIR . 'includes/class-cli.php';
		Recovery::instance();
		CLI::instance();

		require_once SIGIL_DIR . 'includes/class-settings.php';
		require_once SIGIL_DIR . 'includes/class-users-column.php';
		require_once SIGIL_DIR . 'includes/class-app-passwords.php';
		require_once SIGIL_DIR . 'includes/class-login-guard.php';

		Settings::instance();
		Users_Column::instance();
		App_Passwords::instance();
		Login_Guard::instance();

		require_once SIGIL_DIR . 'includes/class-enrolment.php';
		Enrolment::instance();

		require_once SIGIL_DIR . 'includes/class-alerts.php';
		Alerts::instance();

		require_once SIGIL_DIR . 'includes/class-enforcement.php';
		Enforcement::instance();

		require_once SIGIL_DIR . 'includes/class-rest.php';
		REST::instance();

		require_once SIGIL_DIR . 'includes/class-frontend.php';
		Frontend::instance();

		require_once SIGIL_DIR . 'includes/class-import.php';
		require_once SIGIL_DIR . 'includes/class-two-factor-import.php';
		require_once SIGIL_DIR . 'includes/class-wp-2fa-import.php';
		require_once SIGIL_DIR . 'includes/class-wordfence-import.php';
		require_once SIGIL_DIR . 'includes/class-import-migration.php';
		Import_Migration::instance();

		require_once SIGIL_DIR . 'includes/class-trusted-devices.php';
		require_once SIGIL_DIR . 'includes/class-zero-setup.php';
		require_once SIGIL_DIR . 'includes/class-wizard.php';
		require_once SIGIL_DIR . 'includes/class-woocommerce.php';
		Trusted_Devices::instance();
		Zero_Setup::instance();
		Wizard::instance();

		// The account tab can only be added where there is an account page to put
		// it on, which cannot be known until every plugin has loaded.
		WooCommerce::boot();

		// Pro add-on, when present. The free build strips pro/ entirely, so this
		// include only fires in the Pro distribution.
		if ( SIGIL_PRO ) {
			require_once SIGIL_DIR . 'pro/loader.php';
		}
	}
}
