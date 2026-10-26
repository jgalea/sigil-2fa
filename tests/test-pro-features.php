<?php

declare( strict_types=1 );

/**
 * Pro features, exercised through the seams the free plugin exposes.
 *
 * Lives in the free repo's suite because that is where the WordPress test
 * harness is; it skips entirely when the add-on is not present.
 */
class Test_Pro_Features extends WP_UnitTestCase {

	// This class has its own set_up, which wins over the trait's, so the clear
	// is called there by hand.
	use Clears_Attempts;

	// RFC 6238 canonical example, the same one test-crypto.php and test-totp.php use.
	private const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	public function set_up(): void {
		parent::set_up();
		self::forget_attempts();

		if ( ! defined( 'SIGIL_PRO' ) || ! SIGIL_PRO ) {
			$this->markTestSkipped( 'pro add-on not installed' );
		}

		foreach ( array( 'class-method-policy', 'class-branding', 'class-portability', 'class-password-reset', 'class-destinations' ) as $file ) {
			require_once SIGIL_DIR . 'pro/' . $file . '.php';
		}

		// The suite restores WordPress's hook table between tests, which strips
		// the filters a singleton added when it was first constructed.
		\Sigil\Pro\Method_Policy::instance()->register();
	}

	public function tear_down(): void {
		delete_option( \Sigil\Pro\Destinations::OPTION );
		delete_option( \Sigil\Pro\Method_Policy::OPTION );
		delete_option( \Sigil\Pro\Branding::OPTION );
		// Deliberately not remove_all_filters(): these are added by singletons that
		// will never re-add them, so stripping one here breaks whatever test runs
		// next. Every one of them no-ops once its option is gone, which is the
		// cleanup that actually matters.
		parent::tear_down();
	}

	public function test_a_disallowed_method_is_refused_for_that_role(): void {
		\Sigil\Pro\Method_Policy::update(
			array( 'subscriber' => array( 'email' => false, 'totp' => true ) )
		);

		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$editor     = self::factory()->user->create( array( 'role' => 'editor' ) );

		$this->assertFalse( \Sigil\Pro\Method_Policy::allowed_for( $subscriber, 'email' ) );
		$this->assertTrue( \Sigil\Pro\Method_Policy::allowed_for( $subscriber, 'totp' ) );
		$this->assertTrue( \Sigil\Pro\Method_Policy::allowed_for( $editor, 'email' ), 'a role with no rule keeps everything' );
	}

	/**
	 * On a network the free plugin keeps its policy network-wide, and pro used
	 * to keep its own beside it per site. A network administrator restricting
	 * methods got that restriction on whichever site they happened to be on,
	 * and nowhere else, with nothing to say so.
	 *
	 * @group ms-required
	 */
	public function test_pro_settings_are_network_wide(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'network behaviour' );
		}

		\Sigil\Pro\Method_Policy::update(
			array( 'subscriber' => array( 'email' => false, 'totp' => true ) )
		);

		$other = self::factory()->blog->create();
		switch_to_blog( $other );

		$policy = \Sigil\Pro\Method_Policy::get();

		restore_current_blog();

		$this->assertSame( array( 'email' => false, 'totp' => true ), $policy['subscriber'] ?? array() );
	}

	// The settings screen promises that a role with nothing ticked keeps every
	// method, so a misconfiguration cannot lock anyone out. It writes every cell
	// explicitly, so an all-unticked row was stored as all-denied, and that role
	// could then enrol nothing while enforcement still insisted that it enrol
	// something.
	public function test_a_role_with_nothing_ticked_is_dropped(): void {
		$policy = \Sigil\Pro\Method_Policy::without_empty_roles(
			array(
				'subscriber' => array(
					'email'   => false,
					'totp'    => false,
					'backup'  => false,
					'passkey' => false,
				),
				'editor'     => array(
					'email'   => false,
					'totp'    => true,
					'backup'  => false,
					'passkey' => false,
				),
			)
		);

		$this->assertArrayNotHasKey( 'subscriber', $policy );
		$this->assertArrayHasKey( 'editor', $policy, 'one box left ticked is a rule' );

		\Sigil\Pro\Method_Policy::update( $policy );

		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->assertTrue( \Sigil\Pro\Method_Policy::allowed_for( $subscriber, 'totp' ) );
		$this->assertTrue( \Sigil\Pro\Method_Policy::allowed_for( $subscriber, 'email' ) );
	}

	// "Enabled" decides nothing on its own: a policy naming no role and no
	// capability is switched on and applies to nobody, so an import that leaves
	// the flag standing while emptying coverage was a silent disabling by
	// another route.
	public function test_an_import_that_covers_nobody_is_reported(): void {
		\Sigil\Policy::update(
			array(
				'enabled'        => true,
				'roles'          => array( 'administrator' => true ),
				'min_capability' => '',
			)
		);

		$export                    = \Sigil\Pro\Portability::export();
		$export['policy']['roles'] = array();

		$imported = \Sigil\Pro\Portability::import( (string) wp_json_encode( $export ) );
		$this->assertNotWPError( $imported );

		$policy = \Sigil\Policy::get();
		$this->assertTrue( $policy['enabled'], 'the flag is still on' );

		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->assertFalse( \Sigil\Policy::required_for( $admin ), 'and it now applies to nobody' );
	}

	// An import can rule on a subset, where all-denied is a deny-list rather
	// than an empty row, so it is not normalised on the way in.
	public function test_an_imported_deny_list_survives(): void {
		// Built from a real export so the envelope is whatever the code writes,
		// rather than a guess that import would refuse before storing anything.
		$export = \Sigil\Pro\Portability::export();
		$export['methods'] = array( 'subscriber' => array( 'email' => false, 'totp' => false ) );

		$imported = \Sigil\Pro\Portability::import( (string) wp_json_encode( $export ) );
		$this->assertNotWPError( $imported, 'the import has to be accepted for this to mean anything' );

		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$this->assertFalse( \Sigil\Pro\Method_Policy::allowed_for( $subscriber, 'email' ) );
		$this->assertFalse( \Sigil\Pro\Method_Policy::allowed_for( $subscriber, 'totp' ) );
		$this->assertTrue( \Sigil\Pro\Method_Policy::allowed_for( $subscriber, 'backup' ), 'what it does not name stays allowed' );
	}

	// A row that names one method and denies it is a rule, not an empty row.
	public function test_a_single_denial_is_left_alone(): void {
		$policy = \Sigil\Pro\Method_Policy::without_empty_roles(
			array( 'subscriber' => array( 'email' => false ) )
		);

		$this->assertSame( array( 'subscriber' => array( 'email' => false ) ), $policy );
	}

	// Holding two roles must widen what someone may use, never narrow it, or
	// adding a role would quietly take a method away.
	public function test_the_more_permissive_role_wins(): void {
		\Sigil\Pro\Method_Policy::update(
			array(
				'subscriber' => array( 'email' => false ),
				'editor'     => array( 'email' => true ),
			)
		);

		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		get_user_by( 'id', $user )->add_role( 'editor' );

		$this->assertTrue( \Sigil\Pro\Method_Policy::allowed_for( $user, 'email' ) );
	}

	/**
	 * The registry filter is presentational and admin-side only: it keeps a
	 * method the account may not choose off the enrolment screen. It deliberately
	 * does not run during authentication, because a rule applied there cannot
	 * tell "not allowed" from "not set up" and skips the challenge entirely.
	 */
	public function test_the_enrolment_screen_hides_a_disallowed_method(): void {
		\Sigil\Pro\Method_Policy::update(
			array( 'subscriber' => array( 'email' => false, 'totp' => true, 'backup' => true, 'passkey' => true ) )
		);
		\Sigil\Pro\Method_Policy::instance()->register();

		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$ids = static function ( int $user_id ): array {
			return array_map(
				static function ( \Sigil\Provider $provider ): string {
					return $provider->id();
				},
				\Sigil\Providers::instance()->all( $user_id )
			);
		};

		$this->assertNotContains( 'email', $ids( $subscriber ), 'hidden while choosing a method' );
		$this->assertContains( 'totp', $ids( $subscriber ) );

		$this->assertContains( 'email', $ids( 0 ), 'untouched where the question is not about anybody' );
	}

	/**
	 * The users list builds this for every row while an administrator is the
	 * current user. Keying the rule on the viewer answered the wrong question:
	 * a subscriber holding a method the viewer's own role may not use read as
	 * having nothing set up, on the screen an administrator uses to decide
	 * whether to reset somebody's account.
	 */
	public function test_the_policy_follows_the_account_being_looked_at(): void {
		\Sigil\Pro\Method_Policy::update(
			array( 'administrator' => array( 'email' => false, 'totp' => true, 'backup' => true, 'passkey' => true ) )
		);
		\Sigil\Pro\Method_Policy::instance()->register();

		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		\Sigil\Store::set_method( $subscriber, 'email', array( 'enrolled_at' => time() ) );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		set_current_screen( 'users' );

		$enrolled = array_map(
			static function ( \Sigil\Provider $provider ): string {
				return $provider->id();
			},
			\Sigil\Providers::instance()->enrolled_for( $subscriber )
		);

		$this->assertSame( array( 'email' ), $enrolled );
	}


	// A policy that allows nothing would leave an account unable to authenticate
	// at all, so it is treated as a misconfiguration rather than obeyed.
	public function test_a_policy_that_allows_nothing_is_ignored(): void {
		\Sigil\Pro\Method_Policy::update(
			array( 'subscriber' => array( 'email' => false, 'totp' => false, 'backup' => false, 'passkey' => false ) )
		);

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		\Sigil\Pro\Method_Policy::instance()->register();

		$this->assertNotEmpty( \Sigil\Providers::instance()->all() );
	}

	public function test_a_custom_email_replaces_the_default(): void {
		\Sigil\Pro\Branding::update(
			array(
				'subject'   => 'Your {{site}} code',
				'body'      => 'Hello {{user}}, your code is {{code}}.',
				'from'      => 'security@example.com',
				'from_name' => 'Example Security',
			)
		);
		\Sigil\Pro\Branding::instance()->register();

		$user = self::factory()->user->create_and_get( array( 'display_name' => 'Ada' ) );

		$this->assertSame( 'Your Example code', apply_filters( 'sigil_email_subject', 'default', $user, 'Example' ) );
		$this->assertSame(
			'Hello Ada, your code is 123456.',
			apply_filters( 'sigil_email_message', 'default', $user, '123456', 'Example' )
		);
		$this->assertSame( 'security@example.com', apply_filters( 'sigil_email_from', 'wordpress@example.com', $user ) );
		$this->assertSame( 'Example Security', apply_filters( 'sigil_email_from_name', 'Example', $user ) );
	}

	// A template that lost its placeholder would mail a code-less code email.
	public function test_a_template_without_the_code_falls_back(): void {
		\Sigil\Pro\Branding::update( array( 'body' => 'Hello, please sign in.' ) );
		\Sigil\Pro\Branding::instance()->register();

		$user = self::factory()->user->create_and_get();

		$this->assertSame(
			'the default body',
			apply_filters( 'sigil_email_message', 'the default body', $user, '123456', 'Example' )
		);
	}

	public function test_export_carries_settings_and_no_secrets(): void {
		\Sigil\Policy::update( array( 'enabled' => true, 'grace_days' => 4 ) );
		\Sigil\Pro\Method_Policy::update( array( 'editor' => array( 'email' => false ) ) );

		$payload = \Sigil\Pro\Portability::export();
		$json    = wp_json_encode( $payload );

		$this->assertSame( 'sigil-2fa', $payload['plugin'] );
		$this->assertSame( 4, $payload['policy']['grace_days'] );
		$this->assertFalse( $payload['methods']['editor']['email'] );

		// block_app_passwords is a setting name, not a secret, so the check is
		// for the things that would actually be a leak.
		foreach ( array( 'secret', 'credential', 'public_key', 'sign_count' ) as $forbidden ) {
			$this->assertStringNotContainsStringIgnoringCase( $forbidden, (string) $json );
		}
	}

	public function test_import_restores_settings(): void {
		$json = wp_json_encode(
			array(
				'format'   => 1,
				'plugin'   => 'sigil-2fa',
				'policy'   => array( 'grace_days' => 9 ),
				'methods'  => array( 'author' => array( 'email' => false ) ),
				'branding' => array( 'subject' => 'Imported subject' ),
			)
		);

		$this->assertTrue( \Sigil\Pro\Portability::import( (string) $json ) );
		$this->assertSame( 9, \Sigil\Policy::get()['grace_days'] );
		$this->assertFalse( \Sigil\Pro\Method_Policy::get()['author']['email'] );
		$this->assertSame( 'Imported subject', \Sigil\Pro\Branding::get()['subject'] );
	}

	public function test_import_refuses_a_foreign_or_unreadable_file(): void {
		$this->assertWPError( \Sigil\Pro\Portability::import( 'not json' ) );
		$this->assertWPError( \Sigil\Pro\Portability::import( '{"plugin":"something-else","format":1}' ) );
		$this->assertWPError( \Sigil\Pro\Portability::import( '{"plugin":"sigil-2fa","format":99}' ) );
	}

	// A passkey cannot be typed into the reset form. The account was still asked
	// for a code, and sent an email one that could never be accepted, because
	// the code is checked against enrolled methods and email was not one. That
	// is a form refusing every possible entry, reached by someone who has
	// already lost their way in.
	public function test_a_passkey_only_account_is_not_asked_for_a_code(): void {
		$user = $this->passkey_only_user();

		$errors = $this->reset_errors( $user, array( 'pass1' => 'a-new-password' ) );

		$this->assertSame( array(), $errors->get_error_codes(), 'the reset has to go through' );

		ob_start();
		\Sigil\Pro\Password_Reset::instance()->render_field( get_user_by( 'id', $user ) );
		$this->assertSame( '', trim( (string) ob_get_clean() ), 'and no field is offered' );
	}

	// Holding a passkey alongside something typeable is still guarded.
	public function test_a_passkey_account_with_backup_codes_is_still_asked(): void {
		$user = $this->passkey_only_user();
		\Sigil\Providers::instance()->get( 'backup' )->generate( $user );

		$errors = $this->reset_errors( $user, array( 'pass1' => 'a-new-password' ) );

		$this->assertContains( 'sigil_pro_reset_code_missing', $errors->get_error_codes() );
	}

	/**
	 * A passkey counts as enrolled only when a credential row exists, so the
	 * method meta on its own would leave the account holding nothing and the
	 * test would pass against any behaviour at all.
	 */
	private function passkey_only_user(): int {
		\Sigil\Schema::install();

		$user = self::factory()->user->create();
		\Sigil\Store::set_method( $user, 'passkey', array( 'enrolled_at' => 1 ) );
		\Sigil\Credentials::add( $user, 'cred-' . $user, 'public-key', 0, 'Phone', 'internal' );

		$this->assertTrue(
			\Sigil\Providers::instance()->get( 'passkey' )->is_enrolled( $user ),
			'the passkey has to be enrolled for this to mean anything'
		);

		return $user;
	}

	private function reset_errors( int $user_id, array $post ): \WP_Error {
		$_POST  = $post;
		$errors = new \WP_Error();
		\Sigil\Pro\Password_Reset::instance()->validate( $errors, get_user_by( 'id', $user_id ) );
		$_POST  = array();

		return $errors;
	}

	public function test_a_reset_without_a_code_is_refused(): void {
		$user = self::factory()->user->create();
		$totp = new \Sigil\Providers\Totp();
		$totp->handle_enrol(
			$user,
			array( 'secret' => self::SECRET, 'code' => \Sigil\Providers\Totp::code_at( self::SECRET, time() - 30 ) )
		);

		$errors = $this->reset_errors( $user, array( 'pass1' => 'a-new-password' ) );
		$this->assertContains( 'sigil_pro_reset_code_missing', $errors->get_error_codes() );
	}

	public function test_a_wrong_code_is_refused(): void {
		$user = self::factory()->user->create();
		$totp = new \Sigil\Providers\Totp();
		$totp->handle_enrol(
			$user,
			array( 'secret' => self::SECRET, 'code' => \Sigil\Providers\Totp::code_at( self::SECRET, time() - 30 ) )
		);

		$errors = $this->reset_errors( $user, array( 'pass1' => 'a-new-password', 'sigil_pro_reset_code' => '000000' ) );
		$this->assertContains( 'sigil_pro_reset_code_invalid', $errors->get_error_codes() );

		\Sigil\Rate_Limit::clear( 'reset:u:' . $user );
	}

	public function test_a_correct_code_lets_the_reset_through(): void {
		$user = self::factory()->user->create();
		$totp = new \Sigil\Providers\Totp();
		$totp->handle_enrol( $user, array( 'secret' => self::SECRET, 'code' => \Sigil\Providers\Totp::code_at( self::SECRET, time() - 30 ) ) );

		$errors = $this->reset_errors(
			$user,
			array( 'pass1' => 'a-new-password', 'sigil_pro_reset_code' => \Sigil\Providers\Totp::code_at( self::SECRET, time() ) )
		);

		$this->assertSame( array(), $errors->get_error_codes() );
	}

	// A backup code has to work here, or a passkey-only account could never
	// reset its password: there is nothing to present on that form.
	public function test_a_backup_code_works_for_a_passkey_only_account(): void {
		$user   = self::factory()->user->create();
		$backup = \Sigil\Providers::instance()->get( 'backup' );
		$codes  = $backup->generate( $user );

		$errors = $this->reset_errors(
			$user,
			array( 'pass1' => 'a-new-password', 'sigil_pro_reset_code' => $codes[0] )
		);

		$this->assertSame( array(), $errors->get_error_codes() );
	}

	// An account with no second factor must not be asked for one, or it could
	// never recover its password at all.
	public function test_an_account_without_2fa_is_not_challenged(): void {
		$user   = self::factory()->user->create();
		$errors = $this->reset_errors( $user, array( 'pass1' => 'a-new-password' ) );

		$this->assertSame( array(), $errors->get_error_codes() );
	}

	// Merely displaying the form is not an attempt to complete the reset.
	public function test_showing_the_form_is_not_an_attempt(): void {
		$user = self::factory()->user->create();
		$totp = new \Sigil\Providers\Totp();
		$totp->handle_enrol(
			$user,
			array( 'secret' => self::SECRET, 'code' => \Sigil\Providers\Totp::code_at( self::SECRET, time() - 30 ) )
		);

		$this->assertSame( array(), $this->reset_errors( $user, array() )->get_error_codes() );
	}

	private function enrolled_user(): int {
		$user = self::factory()->user->create();
		$totp = new \Sigil\Providers\Totp();
		$totp->handle_enrol(
			$user,
			array( 'secret' => self::SECRET, 'code' => \Sigil\Providers\Totp::code_at( self::SECRET, time() - 30 ) )
		);

		return (int) $user;
	}

	public function test_setup_sends_the_user_on_once_they_hold_a_factor(): void {
		\Sigil\Pro\Destinations::update( home_url( '/members/' ) );
		\Sigil\Pro\Destinations::instance()->register();

		$this->assertSame(
			home_url( '/members/' ),
			apply_filters( 'sigil_enrol_redirect', 'https://example.org/back', $this->enrolled_user(), 'success', 'enrolled', 'totp' )
		);
	}

	// Part-way through, the setup screen is still where they need to be.
	public function test_setup_does_not_redirect_before_anything_is_enrolled(): void {
		\Sigil\Pro\Destinations::update( home_url( '/members/' ) );
		\Sigil\Pro\Destinations::instance()->register();

		$bare = self::factory()->user->create();

		$this->assertSame(
			'https://example.org/back',
			apply_filters( 'sigil_enrol_redirect', 'https://example.org/back', $bare, 'success', 'enrolled', 'totp' )
		);
	}

	// Backup codes are shown once and never again, so that screen is the one
	// place nobody should be sent away from.
	public function test_setup_never_redirects_off_the_backup_code_display(): void {
		\Sigil\Pro\Destinations::update( home_url( '/members/' ) );
		\Sigil\Pro\Destinations::instance()->register();

		$this->assertSame(
			'https://example.org/back',
			apply_filters( 'sigil_enrol_redirect', 'https://example.org/back', $this->enrolled_user(), 'success', 'enrolled_backup', 'totp' )
		);
	}

	public function test_setup_leaves_removals_and_failures_alone(): void {
		\Sigil\Pro\Destinations::update( home_url( '/members/' ) );
		\Sigil\Pro\Destinations::instance()->register();
		$user = $this->enrolled_user();

		$this->assertSame( 'https://example.org/back', apply_filters( 'sigil_enrol_redirect', 'https://example.org/back', $user, 'success', 'removed', 'totp' ) );
		$this->assertSame( 'https://example.org/back', apply_filters( 'sigil_enrol_redirect', 'https://example.org/back', $user, 'error', 'enrolled', 'totp' ) );
	}

	// Turning 2FA off is not what an administrator expects from "import".
	public function test_import_never_disables_an_enabled_policy(): void {
		\Sigil\Policy::update( array( 'enabled' => true ) );

		$json = wp_json_encode(
			array( 'format' => 1, 'plugin' => 'sigil-2fa', 'policy' => array( 'enabled' => false, 'grace_days' => 2 ) )
		);
		\Sigil\Pro\Portability::import( (string) $json );

		$this->assertTrue( \Sigil\Policy::get()['enabled'] );
		$this->assertSame( 2, \Sigil\Policy::get()['grace_days'] );
	}
}
