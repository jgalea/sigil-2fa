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
		require_once SIGIL_DIR . 'includes/class-password-limit.php';

		Settings::instance();
		Users_Column::instance();
		App_Passwords::instance();
		Login_Guard::instance();
		Password_Limit::instance();

		require_once SIGIL_DIR . 'includes/class-step-up.php';
		require_once SIGIL_DIR . 'includes/class-enrolment.php';
		Enrolment::instance();

		require_once SIGIL_DIR . 'includes/class-alerts.php';
		Alerts::instance();

		require_once SIGIL_DIR . 'includes/class-review-prompt.php';
		Review_Prompt::instance();

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

		// Add-ons wait for this rather than guessing when the free plugin is ready.
		// Its absence is also how an add-on tells that the free plugin is missing
		// or too old to extend.
		do_action( 'sigil_loaded' );
	}
}
