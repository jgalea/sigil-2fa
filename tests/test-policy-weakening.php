<?php

declare( strict_types=1 );

/**
 * A hijacked administrator session could switch password limiting, passwordless
 * sign-in or enforcement off without anyone knowing. Loosening now needs fresh
 * proof from an administrator who has a method, and tells the site contact.
 */
class Test_Policy_Weakening extends WP_UnitTestCase {

	use Clears_Attempts;
	use Signed_In;

	private const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	/** @var list<array<string, mixed>> */
	private array $sent = array();

	public function set_up(): void {
		parent::set_up();
		\Sigil\Alerts::instance();
		$this->sent = array();
		add_filter(
			'wp_mail',
			function ( $args ) {
				$this->sent[] = $args;
				return $args;
			}
		);
		\Sigil\Policy::update( array( 'enabled' => true, 'limit_passwords' => true, 'passwordless' => true ) );
		$this->sent = array();
	}

	public function tear_down(): void {
		$_POST    = array();
		$_REQUEST = array();
		parent::tear_down();
	}

	private function admin_with_totp(): int {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		( new \Sigil\Providers\Totp() )->handle_enrol( $id, array( 'secret' => self::SECRET, 'code' => \Sigil\Providers\Totp::code_at( self::SECRET, time() ) ) );

		return $id;
	}

	/**
	 * @param array<string, string> $policy
	 */
	private function save_settings( array $policy ): string {
		$_POST                = array( 'sigil_policy' => $policy );
		$_REQUEST             = $_POST;
		$_REQUEST['_wpnonce'] = wp_create_nonce( 'sigil_save_settings' );

		add_filter(
			'wp_redirect',
			static function ( $location ) {
				throw new \RuntimeException( (string) $location );
			}
		);

		try {
			\Sigil\Settings::instance()->handle_save();
		} catch ( \RuntimeException $e ) {
			return $e->getMessage();
		}

		return '';
	}

	public function test_switching_a_protection_off_tells_the_site_contact(): void {
		\Sigil\Policy::update( array( 'limit_passwords' => false ) );

		$this->assertNotEmpty( $this->sent );
		$this->assertSame( get_bloginfo( 'admin_email' ), $this->sent[0]['to'] );
		$this->assertStringContainsString( 'Password attempt limits', $this->sent[0]['message'] );
	}

	public function test_switching_things_on_sends_nothing(): void {
		\Sigil\Policy::update( array( 'enforce_all' => true, 'grace_days' => 3 ) );

		$this->assertSame( array(), $this->sent );
	}

	public function test_loosening_from_a_stale_session_is_held_for_confirmation(): void {
		$admin = $this->admin_with_totp();
		$this->sign_in( $admin, HOUR_IN_SECONDS );

		$where = $this->save_settings( array( 'enabled' => '1', 'passwordless' => '1' ) );

		$this->assertStringContainsString( 'stepup=1', $where );
		$this->assertTrue( \Sigil\Policy::get()['limit_passwords'], 'nothing was saved' );
	}

	public function test_loosening_with_a_fresh_proof_goes_through(): void {
		$admin = $this->admin_with_totp();
		$this->sign_in( $admin, HOUR_IN_SECONDS );
		\Sigil\Step_Up::record( $admin, true );

		$this->save_settings( array( 'enabled' => '1', 'passwordless' => '1' ) );

		$this->assertFalse( \Sigil\Policy::get()['limit_passwords'] );
	}

	public function test_tightening_needs_no_confirmation(): void {
		$admin = $this->admin_with_totp();
		$this->sign_in( $admin, HOUR_IN_SECONDS );

		$this->save_settings( array( 'enabled' => '1', 'passwordless' => '1', 'limit_passwords' => '1', 'enforce_all' => '1' ) );

		$this->assertTrue( \Sigil\Policy::get()['enforce_all'] );
	}

	/**
	 * @param array<string, mixed> $extra
	 */
	private function save_with( array $extra ): string {
		$_POST                = array_merge( array( 'sigil_policy' => array( 'enabled' => '1', 'passwordless' => '1', 'limit_passwords' => '1' ) ), $extra );
		$_REQUEST             = $_POST;
		$_REQUEST['_wpnonce'] = wp_create_nonce( 'sigil_save_settings' );

		add_filter(
			'wp_redirect',
			static function ( $location ) {
				throw new \RuntimeException( (string) $location );
			}
		);

		try {
			\Sigil\Settings::instance()->handle_save();
		} catch ( \RuntimeException $e ) {
			return $e->getMessage();
		}

		return '';
	}

	/**
	 * @return array<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
	 */
	public static function loosening_saves(): array {
		return array(
			'longer trust'      => array( array( 'trusted_days' => 30 ), array( 'sigil_trusted_days' => '365', 'sigil_trusted_enabled' => '1' ) ),
			'trusted devices on' => array( array( 'trusted_enabled' => false ), array( 'sigil_trusted_days' => '30', 'sigil_trusted_enabled' => '1' ) ),
			'more trusting roles' => array( array( 'trusted_roles' => array( 'editor' => true ) ), array( 'sigil_trusted_days' => '30', 'sigil_trusted_enabled' => '1', 'sigil_trusted_roles' => array( 'editor' => '1', 'author' => '1' ) ) ),
			'zero setup on'     => array( array(), array( 'sigil_zero_setup' => '1' ) ),
		);
	}

	/**
	 * @dataProvider loosening_saves
	 * @param array<string, mixed> $start
	 * @param array<string, mixed> $post
	 */
	public function test_loosening_the_switches_beside_the_policy_is_held_too( array $start, array $post ): void {
		\Sigil\Policy::update( array_merge( array( 'trusted_enabled' => true, 'trusted_days' => 30, 'trusted_roles' => array(), 'zero_setup' => false ), $start ) );
		$this->sent = array();
		$before     = \Sigil\Policy::protections();

		$admin = $this->admin_with_totp();
		$this->sign_in( $admin, HOUR_IN_SECONDS );

		$this->assertStringContainsString( 'stepup=1', $this->save_with( $post ) );
		$this->assertSame( $before, \Sigil\Policy::protections(), 'nothing was saved' );

		\Sigil\Step_Up::record( $admin, true );
		$this->save_with( $post );

		$this->assertNotSame( $before, \Sigil\Policy::protections() );
		$this->assertNotEmpty( $this->sent, 'the site contact is told' );
	}

	public function test_unblocking_application_passwords_and_narrowing_the_capability_count_as_loosening(): void {
		\Sigil\Policy::update( array( 'block_app_passwords' => array( 'editor' => true ), 'min_capability' => 'edit_posts' ) );

		$this->assertSame( array( 'Blocking application passwords for the editor role' ), \Sigil\Policy::weakened_by( array( 'block_app_passwords' => array() ) ) );
		$this->assertNotSame( array(), \Sigil\Policy::weakened_by( array( 'min_capability' => 'manage_options' ) ), 'fewer roles are covered' );
		$this->assertSame( array(), \Sigil\Policy::weakened_by( array( 'min_capability' => 'read' ) ), 'more roles are covered' );
	}

	public function test_tightening_the_switches_beside_the_policy_needs_no_confirmation(): void {
		\Sigil\Policy::update( array( 'trusted_enabled' => true, 'trusted_days' => 30, 'trusted_roles' => array(), 'zero_setup' => true ) );
		$admin = $this->admin_with_totp();
		$this->sign_in( $admin, HOUR_IN_SECONDS );

		$this->save_with( array( 'sigil_trusted_days' => '7', 'sigil_trusted_enabled' => '1' ) );

		$this->assertSame( 7, \Sigil\Trusted_Devices::trust_days() );
		$this->assertFalse( \Sigil\Zero_Setup::is_enabled() );
	}
}
