<?php

declare( strict_types=1 );

/**
 * People who never visit the dashboard never see the admin notice, so without an
 * email their first knowledge of the policy is the day it stops them.
 */
class Test_Deadline_Warning extends WP_UnitTestCase {

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

		\Sigil\Policy::update(
			array(
				'enabled'    => true,
				'roles'      => array( 'subscriber' => true ),
				'grace_days' => 7,
			)
		);
	}

	public function tear_down(): void {
		\Sigil\Network::delete_option( \Sigil\Policy::OPTION_KEY );
		parent::tear_down();
	}

	public function test_the_user_is_told_when_a_deadline_is_set(): void {
		$user = self::factory()->user->create_and_get( array( 'role' => 'subscriber' ) );

		$deadline = \Sigil\Policy::deadline_for( (int) $user->ID );

		$this->assertCount( 1, $this->sent );
		$this->assertSame( $user->user_email, $this->sent[0]['to'] );

		// Compared against the same formatter rather than a guess at its wording:
		// WordPress renders seven days as "1 week".
		$this->assertStringContainsString(
			human_time_diff( time(), (int) $deadline ),
			$this->sent[0]['message']
		);
		$this->assertStringContainsString( 'sigil-2fa-setup', $this->sent[0]['message'] );
	}

	// The deadline is assigned once and read on every request afterwards. Mailing
	// on each read would be a message per page view.
	public function test_it_is_sent_once_and_not_on_every_read(): void {
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		\Sigil\Policy::deadline_for( $user );
		\Sigil\Policy::deadline_for( $user );
		\Sigil\Policy::deadline_for( $user );

		$this->assertCount( 1, $this->sent );
	}

	public function test_nobody_outside_the_policy_is_warned(): void {
		$editor = self::factory()->user->create( array( 'role' => 'editor' ) );

		$this->assertNull( \Sigil\Policy::deadline_for( $editor ) );
		$this->assertSame( array(), $this->sent );
	}

	public function test_the_warning_can_be_turned_off(): void {
		add_filter( 'sigil_send_deadline_warning', '__return_false' );
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		\Sigil\Policy::deadline_for( $user );

		$this->assertSame( array(), $this->sent );
	}

	// Listing users used to assign every listed account a deadline and mail it,
	// inline, on the admin's page view.
	public function test_listing_users_starts_no_clocks_and_sends_no_mail(): void {
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		\Sigil\Users_Column::instance()->render_column( '', 'sigil', $user );

		$this->assertSame( '', (string) get_user_meta( $user, \Sigil\Policy::DEADLINE_META, true ) );
		$this->assertSame( array(), $this->sent );
	}

	public function test_the_users_own_request_still_starts_the_clock(): void {
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$this->assertNotNull( \Sigil\Policy::deadline_for( $user ) );
		$this->assertCount( 1, $this->sent );
	}
}
