<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Cover everyone, including the people who never set anything up.
 *
 * A policy that requires 2FA meets a wall: users who ignore the prompts either
 * get locked out of their own site or the administrator quietly turns the policy
 * off, and the second one is what usually happens. Treating the account's own
 * email as a factor nobody has to configure means the wall is never reached.
 *
 * It is the weakest of the methods, and deliberately so. Anyone who enrols a
 * passkey or an authenticator is challenged with that instead, because the
 * plugin picks by priority and email sorts last. This is a floor, not a choice.
 */
final class Zero_Setup {

	// Named for the add-on it first shipped in, so a saved choice carries over.
	public const OPTION = 'sigil_pro_zero_setup';

	private static ?Zero_Setup $instance = null;

	public static function instance(): Zero_Setup {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->register();
	}

	/**
	 * Hook registration, separate from construction so it can be applied
	 * again. The test suite restores WordPress's hook table between tests,
	 * which leaves a singleton constructed in an earlier one holding its
	 * instance but none of its filters. add_filter is idempotent, so calling
	 * this twice in production changes nothing.
	 */
	public function register(): void {
		add_filter( 'sigil_providers', array( $this, 'swap_email_provider' ), 20 );
	}

	public static function is_enabled(): bool {
		return (bool) Network::get_option( self::OPTION, false );
	}

	public static function set_enabled( bool $on ): void {
		Network::update_option( self::OPTION, $on );
	}

	/**
	 * Replace the email provider with one that counts an account's own address
	 * as enrolment.
	 *
	 * Swapping the registry entry rather than filtering enrolment in a dozen
	 * places means every caller agrees: the login challenge, the enforcement
	 * check, the REST status, and the "last method" guard all ask the provider.
	 *
	 * @param array<string, Provider> $providers
	 * @return array<string, Provider>
	 */
	public function swap_email_provider( $providers ) {
		if ( ! is_array( $providers ) || ! self::is_enabled() || ! isset( $providers['email'] ) ) {
			return $providers;
		}

		require_once __DIR__ . '/class-always-email.php';
		$providers['email'] = new Always_Email( $providers['email'] );

		return $providers;
	}
}
