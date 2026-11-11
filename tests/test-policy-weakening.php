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
}
