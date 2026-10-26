<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Tell the account holder when their second factor changes.
 *
 * Adding a factor is how an attacker who already has the password makes their
 * access permanent, and it is silent: nothing about the account looks different
 * afterwards. The person who notices is the owner, and only if someone tells
 * them. Removing one is worth the same message for the same reason.
 *
 * A reset already sends its own notice, so this stays out of the way when one is
 * in progress rather than sending two mails about the same event.
 */
final class Alerts {

	private static ?Alerts $instance = null;

	/**
	 * What the account held before the change, so the mail can say what it was.
	 *
	 * @var array<int, array{methods: list<string>, passkeys: array<int, array{label: string, second_factor_only: bool}>, totp: string, backup: string}>
	 */
	private array $before = array();

	public static function instance(): Alerts {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'sigil_before_methods_change', array( $this, 'remember' ) );
		add_action( 'sigil_methods_changed', array( $this, 'notify' ) );
		add_action( 'sigil_deadline_assigned', array( $this, 'warn_of_deadline' ), 10, 2 );
	}

	public function remember( int $user_id ): void {
		$this->before[ $user_id ] = self::snapshot( $user_id );
	}

	/**
	 * Down to the credential, because the method list alone cannot see the
	 * changes that matter most: a second passkey, a replaced one, a new
	 * authenticator secret or a fresh set of backup codes all leave it as it
	 * was.
	 *
	 * @return array{methods: list<string>, passkeys: array<int, array{label: string, second_factor_only: bool}>, totp: string, backup: string}
	 */
	private static function snapshot( int $user_id ): array {
		$methods  = Store::methods( $user_id );
		$passkeys = array();
		foreach ( Credentials::for_user( $user_id ) as $row ) {
			$passkeys[ (int) $row->id ] = array(
				'label'              => (string) $row->label,
				'second_factor_only' => 1 === (int) ( $row->second_factor_only ?? 0 ),
			);
		}

		return array(
			'methods'  => array_keys( $methods ),
			'passkeys' => $passkeys,
			'totp'     => isset( $methods['totp']['secret'] ) ? hash( 'sha256', (string) wp_json_encode( $methods['totp']['secret'] ) ) : '',
			'backup'   => isset( $methods['backup']['codes'] ) ? hash( 'sha256', (string) wp_json_encode( $methods['backup']['codes'] ) ) : '',
		);
	}

	public function notify( int $user_id ): void {
		if ( $user_id <= 0 ) {
			return;
		}

		/**
		 * Filter whether the account holder is told their factors changed.
		 *
		 * @param bool $send
		 * @param int  $user_id
		 */
		if ( ! apply_filters( 'sigil_send_change_alert', true, $user_id ) ) {
			return;
		}

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User || ! is_email( $user->user_email ) ) {
			return;
		}

		$before = $this->before[ $user_id ] ?? null;
		$after  = self::snapshot( $user_id );
		unset( $this->before[ $user_id ] );

		// Nothing observable changed, so there is nothing worth a mail.
		if ( null !== $before && $before === $after ) {
			return;
		}

		$lines = null === $before ? self::method_lines( $after['methods'], array() ) : self::change_lines( $before, $after );
		if ( array() === $lines ) {
			return;
		}

		$current = (int) get_current_user_id();
		$actor   = $current > 0 && $current !== $user_id ? get_userdata( $current ) : null;
		if ( $actor instanceof \WP_User ) {
			$lines[] = sprintf(
				/* translators: %s: display name of the person who made the change */
				__( 'Changed by %s, not from your own account.', 'sigil-2fa' ),
				$actor->display_name
			);
		}

		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $site_name ) {
			$site_name = home_url();
		}

		$subject = sprintf(
			/* translators: %s: site name */
			__( 'Your sign-in methods changed on %s', 'sigil-2fa' ),
			$site_name
		);

		$message = sprintf(
			/* translators: 1: site name, 2: list of changes, 3: request origin */
			__(
				"The two-factor methods on your %1\$s account were changed.\n\n%2\$s\n\n%3\$s\n\nIf this was not you, change your password and contact a site administrator immediately: someone with your password can use a second factor of their own to keep access.",
				'sigil-2fa'
			),
			$site_name,
			implode( "\n", $lines ),
			self::origin_line()
		);

		wp_mail( $user->user_email, $subject, $message );
	}

	/**
	 * Tell someone they now have to set up a second factor, and by when.
	 *
	 * The admin notice this accompanies is only seen by people who visit the
	 * dashboard. Subscribers and shop customers never do, so without this their
	 * first knowledge of the policy is the day it stops them.
	 */
	public function warn_of_deadline( int $user_id, int $deadline ): void {
		/**
		 * Filter whether someone is told a deadline has been set for them.
		 *
		 * @param bool $send
		 * @param int  $user_id
		 */
		if ( ! apply_filters( 'sigil_send_deadline_warning', true, $user_id ) ) {
			return;
		}

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User || ! is_email( $user->user_email ) ) {
			return;
		}

		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $site_name ) {
			$site_name = home_url();
		}

		/** This filter is documented in includes/class-enforcement.php */
		$setup_url = apply_filters( 'sigil_setup_url', admin_url( 'users.php?page=' . Enrolment::PAGE_SLUG ) );

		$subject = sprintf(
			/* translators: %s: site name */
			__( 'Set up two-factor authentication on %s', 'sigil-2fa' ),
			$site_name
		);

		if ( $deadline <= time() ) {
			$when = __( 'You need to do this before your next sign-in.', 'sigil-2fa' );
		} else {
			$when = sprintf(
				/* translators: %s: human-readable time difference, e.g. "6 days" */
				__( 'You have %s to do this.', 'sigil-2fa' ),
				human_time_diff( time(), $deadline )
			);
		}

		$message = sprintf(
			/* translators: 1: site name, 2: how long they have, 3: setup URL */
			__(
				"%1\$s now requires a second step when you sign in.\n\n%2\$s After that you will be asked to set it up before you can continue.\n\nSet it up here:\n%3\$s",
				'sigil-2fa'
			),
			$site_name,
			$when,
			$setup_url
		);

		wp_mail( $user->user_email, $subject, $message );
	}

	/**
	 * Where the request came from, as far as the server can tell.
	 *
	 * Hedged rather than stated: behind a proxy REMOTE_ADDR is the proxy, and a
	 * reader who trusts a wrong address draws a wrong conclusion.
	 */
	public static function origin_line(): string {
		$ip = self::request_ip();

		if ( '' === $ip ) {
			return __( 'The request origin could not be determined.', 'sigil-2fa' );
		}

		return sprintf(
			/* translators: %s: IP address */
			__( 'Requested from %s, which may be a proxy rather than the device itself.', 'sigil-2fa' ),
			$ip
		);
	}

	public static function request_ip(): string {
		return Request::client_ip();
	}

	/**
	 * @param array{methods: list<string>, passkeys: array<int, array{label: string, second_factor_only: bool}>, totp: string, backup: string} $before
	 * @param array{methods: list<string>, passkeys: array<int, array{label: string, second_factor_only: bool}>, totp: string, backup: string} $after
	 * @return list<string>
	 */
	private static function change_lines( array $before, array $after ): array {
		$lines = self::method_lines(
			array_values( array_diff( $after['methods'], $before['methods'] ) ),
			array_values( array_diff( $before['methods'], $after['methods'] ) )
		);

		foreach ( array_diff_key( $after['passkeys'], $before['passkeys'] ) as $passkey ) {
			$lines[] = $passkey['second_factor_only']
				? sprintf(
					/* translators: %s: passkey label */
					__( 'A passkey named "%s" was added. It was registered for you, so it only works after your password.', 'sigil-2fa' ),
					$passkey['label']
				)
				: sprintf(
					/* translators: %s: passkey label */
					__( 'A passkey named "%s" was added.', 'sigil-2fa' ),
					$passkey['label']
				);
		}
		foreach ( array_diff_key( $before['passkeys'], $after['passkeys'] ) as $passkey ) {
			$lines[] = sprintf(
				/* translators: %s: passkey label */
				__( 'A passkey named "%s" was removed.', 'sigil-2fa' ),
				$passkey['label']
			);
		}

		if ( '' !== $before['totp'] && '' !== $after['totp'] && $before['totp'] !== $after['totp'] ) {
			$lines[] = __( 'Your authenticator app was replaced with a new one.', 'sigil-2fa' );
		}
		if ( '' !== $before['backup'] && '' !== $after['backup'] && $before['backup'] !== $after['backup'] ) {
			$lines[] = __( 'New backup codes were generated, and the old ones stopped working.', 'sigil-2fa' );
		}

		return $lines;
	}

	/**
	 * @param list<string> $added
	 * @param list<string> $removed
	 * @return list<string>
	 */
	private static function method_lines( array $added, array $removed ): array {
		$lines = array();
		if ( array() !== $added ) {
			$lines[] = sprintf(
				/* translators: %s: comma-separated list of method names */
				__( 'Added: %s', 'sigil-2fa' ),
				implode( ', ', self::labels( $added ) )
			);
		}
		if ( array() !== $removed ) {
			$lines[] = sprintf(
				/* translators: %s: comma-separated list of method names */
				__( 'Removed: %s', 'sigil-2fa' ),
				implode( ', ', self::labels( $removed ) )
			);
		}

		return $lines;
	}

	/**
	 * @param list<string> $ids
	 * @return list<string>
	 */
	private static function labels( array $ids ): array {
		$out = array();
		foreach ( $ids as $id ) {
			$provider = Providers::instance()->get( (string) $id );
			$out[]    = $provider ? $provider->label() : (string) $id;
		}

		return $out;
	}
}
