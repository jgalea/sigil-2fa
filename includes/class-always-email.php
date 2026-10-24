<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * The email provider, counting an account's own address as enrolment.
 *
 * A wrapper rather than a subclass: the core provider is final, which is the
 * right call for something holding one-time codes. Every method delegates to the
 * real one, so the code, the expiry, the cooldown and the validation are all
 * unchanged. The only different answer is to "is this set up", because under
 * zero-setup that is yes for anyone who can receive mail.
 */
final class Always_Email implements Provider {

	private Provider $inner;

	public function __construct( Provider $inner ) {
		$this->inner = $inner;
	}

	public function id(): string {
		return $this->inner->id();
	}

	public function label(): string {
		return $this->inner->label();
	}

	public function priority(): int {
		return $this->inner->priority();
	}

	public function is_available(): bool {
		return $this->inner->is_available();
	}

	public function is_enrolled( int $user_id ): bool {
		// Deliberately chosen email is still email, whatever else is set up.
		if ( $this->inner->is_enrolled( $user_id ) ) {
			return true;
		}

		if ( $user_id <= 0 ) {
			return false;
		}

		// A floor, not a ceiling. Offering the inbox as an alternative to an
		// account that already holds a passkey or an authenticator lowers that
		// account to whoever can read its mail, which is the opposite of the
		// point. Automatic email exists only where there is nothing else.
		if ( array() !== Store::methods( $user_id ) ) {
			return false;
		}

		$user = get_userdata( $user_id );

		// No deliverable address means no factor. Claiming otherwise would lock
		// the account into a login it can never complete.
		return $user instanceof \WP_User && is_email( $user->user_email );
	}

	public function render_enrol( int $user_id ): void {
		$this->inner->render_enrol( $user_id );
	}

	/**
	 * @param array<string, mixed> $input
	 * @return true|\WP_Error
	 */
	public function handle_enrol( int $user_id, array $input ) {
		return $this->inner->handle_enrol( $user_id, $input );
	}

	public function render_challenge( int $user_id ): void {
		$this->inner->render_challenge( $user_id );
	}

	/**
	 * @param array<string, mixed> $input
	 */
	public function validate( int $user_id, array $input ): bool {
		return $this->inner->validate( $user_id, $input );
	}

	public function unenrol( int $user_id ): void {
		$this->inner->unenrol( $user_id );
	}
}
