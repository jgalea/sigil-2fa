<?php

declare( strict_types=1 );

/**
 * The wizard walks a fresh install through a factor, the backup codes and then,
 * optionally, a requirement for roles, in that order.
 */
class Test_Wizard extends WP_UnitTestCase {

	private const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	public function set_up(): void {
		parent::set_up();
		\Sigil\Schema::install();
	}

	public function tear_down(): void {
		\Sigil\Network::delete_option( \Sigil\Wizard::OPTION );
		\Sigil\Network::delete_option( \Sigil\Policy::OPTION_KEY );
		$_POST    = array();
		$_REQUEST = array();
		parent::tear_down();
	}

	private function admin(): int {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		wp_set_current_user( $id );
		return $id;
	}

	// Through the same path the enrolment form takes, which is what mints the
	// backup codes the second step shows.
	private function enrol_authenticator( int $user_id ): void {
		$result = \Sigil\Enrolment::instance()->complete_method(
			$user_id,
			'totp',
			array( 'secret' => self::SECRET, 'code' => \Sigil\Providers\Totp::code_at( self::SECRET, time() - 30 ) )
		);
		$this->assertTrue( $result );
	}

	private function spend_backup_codes_display( int $user_id ): void {
		delete_transient( 'sigil_backup_show_' . $user_id );
	}

	public function test_it_starts_by_asking_for_a_factor(): void {
		$admin = $this->admin();

		$this->assertSame( 1, \Sigil\Wizard::step_for( $admin, 0 ) );
	}

	public function test_a_later_step_cannot_be_asked_for_early(): void {
		$admin = $this->admin();

		$this->assertSame( 1, \Sigil\Wizard::step_for( $admin, 3 ) );
	}

	public function test_a_factor_alone_is_not_enough_to_move_on(): void {
		$admin = $this->admin();
		\Sigil\Store::set_method( $admin, 'totp', array( 'secret' => self::SECRET ) );

		$this->assertSame( 2, \Sigil\Wizard::step_for( $admin, 3 ), 'no backup codes yet' );
	}

	public function test_codes_waiting_to_be_shown_cannot_be_navigated_past(): void {
		$admin = $this->admin();
		$this->enrol_authenticator( $admin );

		$this->assertTrue( \Sigil\Providers::instance()->get( 'backup' )->has_pending_display( $admin ) );
		$this->assertSame( 2, \Sigil\Wizard::step_for( $admin, 3 ) );
	}

	public function test_it_reaches_the_policy_once_the_codes_have_been_shown(): void {
		$admin = $this->admin();
		$this->enrol_authenticator( $admin );
		$this->spend_backup_codes_display( $admin );

		$this->assertSame( 3, \Sigil\Wizard::step_for( $admin, 0 ) );
		$this->assertSame( 3, \Sigil\Wizard::step_for( $admin, 3 ) );
		$this->assertSame( 2, \Sigil\Wizard::step_for( $admin, 2 ), 'the codes step can be revisited' );
	}

	public function test_the_codes_are_shown_on_the_second_step_and_only_once(): void {
		$admin = $this->admin();
		$this->enrol_authenticator( $admin );

		ob_start();
		( new ReflectionMethod( \Sigil\Wizard::class, 'render_codes' ) )->invoke( \Sigil\Wizard::instance(), $admin );
		$first = (string) ob_get_clean();

		ob_start();
		( new ReflectionMethod( \Sigil\Wizard::class, 'render_codes' ) )->invoke( \Sigil\Wizard::instance(), $admin );
		$second = (string) ob_get_clean();

		$this->assertSame( 10, substr_count( $first, '<li><code>' ) );
		$this->assertSame( 0, substr_count( $second, '<li><code>' ) );
		$this->assertStringContainsString( 'step=3', $second, 'and the way on is offered' );
	}

	public function test_the_prompt_stops_once_it_is_dismissed(): void {
		$this->assertFalse( \Sigil\Wizard::is_done() );
		\Sigil\Network::update_option( \Sigil\Wizard::OPTION, true );
		$this->assertTrue( \Sigil\Wizard::is_done() );
	}

	// A site that already enforces something has no first run left to do.
	public function test_a_site_that_already_enforces_is_done(): void {
		\Sigil\Policy::update( array( 'enabled' => true, 'roles' => array( 'editor' => true ) ) );

		$this->assertTrue( \Sigil\Wizard::is_done() );
	}

	// Enabled with no roles chosen protects nobody, so it does not count as done.
	public function test_an_empty_role_list_is_not_a_policy(): void {
		\Sigil\Policy::update( array( 'enabled' => true, 'roles' => array( 'administrator' => false ) ) );

		$this->assertFalse( \Sigil\Wizard::is_done() );
	}

	public function test_enrolment_forms_from_the_wizard_come_back_to_it(): void {
		$_POST['sigil_wizard'] = '1';

		$url = (string) apply_filters( 'sigil_enrol_redirect', 'https://example.com/elsewhere', 1, 'success', 'enrolled_backup', 'totp' );

		$this->assertSame( \Sigil\Wizard::url( 2 ), $url );
	}

	public function test_a_failure_returns_to_the_step_with_the_reason(): void {
		$_POST['sigil_wizard'] = '1';
		$from                  = add_query_arg(
			array(
				'sigil_status' => 'error',
				'sigil_code'   => 'sigil_totp_invalid',
				'sigil_msg'    => 'That code was wrong.',
			),
			admin_url( 'users.php?page=sigil-2fa-setup' )
		);

		$url = (string) apply_filters( 'sigil_enrol_redirect', $from, 1, 'error', 'sigil_totp_invalid', 'totp' );

		$this->assertStringStartsWith( \Sigil\Wizard::url( 1 ), $url );
		$this->assertStringContainsString( 'sigil_msg=That%20code%20was%20wrong.', $url );
	}

	public function test_other_enrolment_forms_are_left_alone(): void {
		unset( $_POST['sigil_wizard'] );

		$this->assertSame(
			'https://example.com/elsewhere',
			apply_filters( 'sigil_enrol_redirect', 'https://example.com/elsewhere', 1, 'success', 'enrolled', 'totp' )
		);
	}

	/**
	 * @param array<string, mixed> $post
	 */
	private function submit_policy( array $post ): string {
		$_POST                = $post;
		$_REQUEST             = $post;
		$_REQUEST['_wpnonce'] = wp_create_nonce( 'sigil_wizard_policy' );

		add_filter(
			'wp_redirect',
			static function ( $location ) {
				throw new \RuntimeException( (string) $location );
			}
		);

		try {
			\Sigil\Wizard::instance()->save_policy();
		} catch ( \RuntimeException $e ) {
			return $e->getMessage();
		}

		$this->fail( 'the handler did not redirect' );
	}

	public function test_choosing_roles_enables_the_policy_and_finishes(): void {
		$admin = $this->admin();
		$this->enrol_authenticator( $admin );

		$this->submit_policy( array( 'roles' => array( 'administrator' => '1', 'editor' => '1' ), 'grace_days' => '3' ) );

		$policy = \Sigil\Policy::get();
		$this->assertTrue( $policy['enabled'] );
		$this->assertTrue( $policy['roles']['editor'] );
		$this->assertFalse( $policy['roles']['subscriber'] );
		$this->assertSame( 3, $policy['grace_days'] );
		$this->assertTrue( (bool) \Sigil\Network::get_option( \Sigil\Wizard::OPTION, false ) );
	}

	public function test_choosing_no_roles_enforces_nothing(): void {
		$admin = $this->admin();
		$this->enrol_authenticator( $admin );

		$this->submit_policy( array( 'grace_days' => '7' ) );

		$this->assertFalse( \Sigil\Policy::get()['enabled'] );
	}

	public function test_the_wizard_cannot_be_used_to_skip_the_lockout_guard(): void {
		$this->admin();

		$location = $this->submit_policy( array( 'roles' => array( 'administrator' => '1' ) ) );

		$this->assertStringContainsString( 'lockout=1', $location );
		$this->assertFalse( \Sigil\Policy::get()['enabled'] );
		$this->assertFalse( (bool) \Sigil\Network::get_option( \Sigil\Wizard::OPTION, false ) );
	}
}
