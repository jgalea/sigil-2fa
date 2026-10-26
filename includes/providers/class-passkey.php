<?php

declare( strict_types=1 );

namespace Sigil\Providers;

use Sigil\Credentials;
use Sigil\Provider;
use Sigil\Store;

defined( 'ABSPATH' ) || exit;

require_once SIGIL_DIR . 'includes/class-credentials.php';

final class Passkey implements Provider {

	private const CHALLENGE_TTL = 300;

	// Enough for a refresh or a second tab, small enough that a page-reload loop
	// cannot grow the stored payload.
	private const MAX_OPEN_CHALLENGES = 3;

	private static bool $booted = false;

	public function __construct() {
		self::boot();
		$this->register_hooks();
	}

	/**
	 * Load the WebAuthn library only on PHP 8.0+ so PHP 7.4 never parses it.
	 */
	public static function boot(): void {
		if ( self::$booted ) {
			return;
		}
		self::$booted = true;

		if ( PHP_VERSION_ID < 80000 ) {
			return;
		}

		$lib = SIGIL_DIR . 'vendor/lbuchs/webauthn/WebAuthn.php';
		if ( is_readable( $lib ) ) {
			require_once $lib;
		}
	}

	public function id(): string {
		return 'passkey';
	}

	public function label(): string {
		return __( 'Passkey', 'sigil-2fa' );
	}

	public function priority(): int {
		return 10;
	}

	public function is_available(): bool {
		return PHP_VERSION_ID >= 80000
			&& extension_loaded( 'openssl' )
			&& extension_loaded( 'mbstring' );
	}

	public function is_enrolled( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$methods = Store::methods( $user_id );
		if ( ! isset( $methods[ $this->id() ] ) ) {
			return false;
		}

		return [] !== Credentials::for_user( $user_id );
	}

	public function render_enrol( int $user_id ): void {
		if ( ! $this->is_available() || $user_id <= 0 ) {
			echo '<p>' . esc_html__( 'Passkeys are not available in this environment.', 'sigil-2fa' ) . '</p>';
			return;
		}

		$this->enqueue_script( $user_id, true );

		echo '<div class="sigil-passkey-enrol" data-user-id="' . esc_attr( (string) $user_id ) . '">';
		echo '<p>' . esc_html__( 'Register a passkey for this account. You will be prompted by your browser or device.', 'sigil-2fa' ) . '</p>';
		echo '<p><label for="sigil-passkey-label">' . esc_html__( 'Device label', 'sigil-2fa' ) . '</label> ';
		echo '<input type="text" id="sigil-passkey-label" name="sigil_passkey_label" class="regular-text" value="" maxlength="190" /></p>';
		echo '<p><button type="button" class="button button-primary sigil-passkey-register">' . esc_html__( 'Register passkey', 'sigil-2fa' ) . '</button></p>';
		echo '<p class="sigil-passkey-status" role="status" aria-live="polite"></p>';
		$this->render_upgrades( $user_id );
		echo '</div>';
	}

	/**
	 * Passkeys registered without a resident key cannot start a sign-in on
	 * their own. Older registrations never asked the browser, so those are
	 * listed too until one signs in by itself and proves otherwise.
	 */
	private function render_upgrades( int $user_id ): void {
		if ( ! \Sigil\Passwordless::enabled() ) {
			return;
		}

		$rows = array_filter(
			Credentials::for_user( $user_id ),
			static function ( $row ): bool {
				return 1 !== (int) $row->discoverable || 1 === (int) ( $row->second_factor_only ?? 0 );
			}
		);
		if ( [] === $rows ) {
			return;
		}

		echo '<div class="sigil-passkey-upgrade">';
		echo '<p>' . esc_html__( 'These passkeys may only work after your password. Register one again on the same device to sign in with the passkey alone.', 'sigil-2fa' ) . '</p>';
		echo '<ul>';
		foreach ( $rows as $row ) {
			echo '<li>' . esc_html( (string) $row->label ) . ' ';
			echo '<button type="button" class="button sigil-passkey-register" data-replace="' . esc_attr( (string) (int) $row->id ) . '">' . esc_html__( 'Register again', 'sigil-2fa' ) . '</button>';
			echo '</li>';
		}
		echo '</ul>';
		echo '</div>';
	}

	/**
	 * @param array<string, mixed> $input
	 * @return true|\WP_Error
	 */
	public function handle_enrol( int $user_id, array $input ) {
		if ( ! $this->is_available() ) {
			return new \WP_Error( 'sigil_passkey_unavailable', __( 'Passkeys are not available in this environment.', 'sigil-2fa' ) );
		}

		if ( $user_id <= 0 || ! $this->user_can_manage( $user_id ) ) {
			return new \WP_Error( 'sigil_forbidden', __( 'You are not allowed to enrol a passkey for this user.', 'sigil-2fa' ) );
		}

		$client_data_json  = $this->decode_binary_field( $input['clientDataJSON'] ?? '' );
		$attestation_object = $this->decode_binary_field( $input['attestationObject'] ?? '' );
		$label             = isset( $input['label'] ) ? sanitize_text_field( (string) $input['label'] ) : '';
		$transports_raw    = $input['transports'] ?? '';
		$transports        = $this->sanitize_transports( $transports_raw );
		$replace           = isset( $input['replace'] ) ? (int) $input['replace'] : 0;

		// What the browser said through the credProps extension. Only ever a hint
		// for the enrolment screen; sign-in trusts the signature, not this.
		$discoverable = null;
		if ( isset( $input['discoverable'] ) && in_array( $input['discoverable'], [ '0', '1' ], true ) ) {
			$discoverable = '1' === $input['discoverable'];
		}
		if ( $replace > 0 ) {
			// Re-registration demands a resident key, so the authenticator either made one or refused.
			$discoverable = true;
		}

		if ( '' === $client_data_json || '' === $attestation_object ) {
			return new \WP_Error( 'sigil_passkey_invalid', __( 'Invalid passkey registration data.', 'sigil-2fa' ) );
		}

		$challenges = $this->get_challenges( $user_id, 'register' );
		if ( [] === $challenges ) {
			return new \WP_Error( 'sigil_passkey_challenge', __( 'Registration challenge expired. Please try again.', 'sigil-2fa' ) );
		}

		$data = null;
		foreach ( $challenges as $challenge ) {
			try {
				$webauthn = $this->webauthn();
				// failIfRootMismatch=false: browser "none" attestation is common without a CA chain.
				$data = $webauthn->processCreate(
					$client_data_json,
					$attestation_object,
					$challenge,
					false,
					true,
					false
				);
				break;
			} catch ( \Throwable $e ) {
				continue;
			}
		}

		$this->clear_challenge( $user_id, 'register' );

		if ( null === $data ) {
			return new \WP_Error( 'sigil_passkey_verify', __( 'Passkey registration failed verification.', 'sigil-2fa' ) );
		}

		$credential_id = is_string( $data->credentialId ) ? $data->credentialId : '';
		$public_key    = is_string( $data->credentialPublicKey ) ? $data->credentialPublicKey : '';
		$sign_count    = isset( $data->signatureCounter ) && is_int( $data->signatureCounter ) ? $data->signatureCounter : 0;

		if ( '' === $credential_id || '' === $public_key ) {
			return new \WP_Error( 'sigil_passkey_invalid', __( 'Invalid passkey registration data.', 'sigil-2fa' ) );
		}

		if ( null !== Credentials::by_credential_id( $credential_id ) ) {
			return new \WP_Error( 'sigil_passkey_duplicate', __( 'This passkey is already registered.', 'sigil-2fa' ) );
		}

		if ( '' === $label ) {
			$label = __( 'Passkey', 'sigil-2fa' );
		}

		// A passkey somebody else registered for this account, an administrator
		// at their desk, is held by them and not by the owner. It can stand in
		// for the owner's second step, which still follows their password, but
		// never for the whole sign-in.
		$second_factor_only = get_current_user_id() !== $user_id;

		$id = Credentials::add( $user_id, $credential_id, $public_key, $sign_count, $label, $transports, (string) $user_id, $discoverable, $second_factor_only );
		if ( $id <= 0 ) {
			return new \WP_Error( 'sigil_passkey_store', __( 'Could not store the passkey.', 'sigil-2fa' ) );
		}

		if ( $replace > 0 ) {
			Credentials::delete( $replace, $user_id );
		}

		Store::set_method(
			$user_id,
			$this->id(),
			[
				'enrolled_at' => time(),
			]
		);

		return true;
	}

	public function render_challenge( int $user_id ): void {
		if ( ! $this->is_available() || $user_id <= 0 ) {
			echo '<p>' . esc_html__( 'Passkeys are not available in this environment.', 'sigil-2fa' ) . '</p>';
			return;
		}

		// The challenge screen runs logged out, so the assertion options cannot come
		// from an authenticated admin-ajax call. They are minted here and read back
		// from the page; the assertion travels with the login POST.
		$options = $this->auth_options( $user_id );
		if ( null === $options ) {
			echo '<p>' . esc_html__( 'No passkeys are registered for this account.', 'sigil-2fa' ) . '</p>';
			return;
		}

		$this->enqueue_script( $user_id, false );

		echo '<div class="sigil-passkey-challenge" data-user-id="' . esc_attr( (string) $user_id ) . '" data-options="' . esc_attr( (string) wp_json_encode( $options ) ) . '">';
		echo '<p>' . esc_html__( 'Use your passkey to continue.', 'sigil-2fa' ) . '</p>';
		echo '<p><button type="button" class="button button-primary button-large sigil-passkey-authenticate">' . esc_html__( 'Use passkey', 'sigil-2fa' ) . '</button></p>';
		echo '<p class="sigil-passkey-status" role="status" aria-live="polite"></p>';
		echo '<input type="hidden" name="passkey_assertion" id="sigil-passkey-assertion" value="" />';
		echo '</div>';
	}

	/**
	 * Build the WebAuthn assertion options and store the matching challenge.
	 * Public so a headless client can fetch what the rendered screen embeds.
	 *
	 * @return \stdClass|null Null when the account has no passkeys or the library fails.
	 */
	public function auth_options( int $user_id ): ?\stdClass {
		$ids = [];
		foreach ( Credentials::for_user( $user_id ) as $row ) {
			$ids[] = $row->credential_id;
		}

		if ( [] === $ids ) {
			return null;
		}

		try {
			$webauthn  = $this->webauthn();
			$args      = $webauthn->getGetArgs( $ids, self::CHALLENGE_TTL, true, true, true, true, true, 'preferred' );
			$challenge = $webauthn->getChallenge()->getBinaryString();
		} catch ( \Throwable $e ) {
			return null;
		}

		$this->store_challenge( $user_id, 'auth', $challenge );

		return $args instanceof \stdClass ? $args : null;
	}

	/**
	 * @param array<string, mixed> $input
	 */
	public function validate( int $user_id, array $input ): bool {
		if ( ! $this->is_available() || $user_id <= 0 ) {
			return false;
		}

		$assertion = $this->assertion_fields( $input );

		$cred = Credentials::by_credential_id( $this->decode_binary_field( $assertion['id'] ) );
		if ( null === $cred || (int) $cred->user_id !== $user_id ) {
			return false;
		}

		$challenges = $this->get_challenges( $user_id, 'auth' );
		if ( [] === $challenges ) {
			return false;
		}

		$verified = $this->verify_assertion( $cred, $assertion, $challenges, false );
		$this->clear_challenge( $user_id, 'auth' );

		return $verified;
	}

	/**
	 * Options for a sign-in that starts with no account at all. There is no
	 * allow list, so the browser offers whichever passkeys it holds for this
	 * site, and user verification is required: the passkey is the whole
	 * sign-in here, so it has to bring the second factor (the PIN or biometric
	 * that unlocks it) as well as the first.
	 *
	 * @param string $binding Hash of the value tying the ceremony to the browser
	 *                        that asked for it, kept in the same stored row.
	 * @return array{ceremony: string, options: \stdClass}|null
	 */
	public function discoverable_options( string $binding = '' ): ?array {
		if ( ! $this->is_available() ) {
			return null;
		}

		try {
			$webauthn  = $this->webauthn();
			$args      = $webauthn->getGetArgs( [], self::CHALLENGE_TTL, true, true, true, true, true, 'required' );
			$challenge = $webauthn->getChallenge()->getBinaryString();
		} catch ( \Throwable $e ) {
			return null;
		}

		// Nobody is signed in yet, so the challenge is bound to an opaque
		// ceremony id instead of a user, and only its holder can spend it.
		$ceremony = bin2hex( random_bytes( 32 ) );
		set_transient(
			self::ceremony_key( $ceremony ),
			[
				'c' => base64_encode( $challenge ),
				'b' => $binding,
			],
			self::CHALLENGE_TTL
		);

		return [
			'ceremony' => $ceremony,
			'options'  => $args,
		];
	}

	/**
	 * Whose passkey signed a passwordless assertion.
	 *
	 * The account is whichever user owns the stored credential the signature
	 * verifies against. Nothing the client says about who it is decides that;
	 * a user handle it sends can only veto.
	 *
	 * @param array<string, mixed> $assertion id, clientDataJSON, authenticatorData, signature, userHandle.
	 * @param string               $binding   The browser binding's hash, which must match the one minted with the ceremony.
	 * @return int User ID, or 0 when the assertion does not verify.
	 */
	public function discoverable_owner( string $ceremony, array $assertion, string $binding = '' ): int {
		if ( ! $this->is_available() || ! preg_match( '/^[a-f0-9]{64}$/', $ceremony ) ) {
			return 0;
		}

		// Claimed by whichever request manages the delete, so one challenge buys
		// one assertion even when the same one is posted twice at once.
		$key    = self::ceremony_key( $ceremony );
		$stored = get_transient( $key );
		if ( ! is_array( $stored ) || ! isset( $stored['c'], $stored['b'] ) || ! delete_transient( $key ) ) {
			return 0;
		}

		if ( ! hash_equals( (string) $stored['b'], $binding ) ) {
			return 0;
		}

		$challenge = base64_decode( (string) $stored['c'], true );
		if ( ! is_string( $challenge ) || '' === $challenge ) {
			return 0;
		}

		$fields = [];
		foreach ( [ 'id', 'clientDataJSON', 'authenticatorData', 'signature', 'userHandle' ] as $field ) {
			$fields[ $field ] = isset( $assertion[ $field ] ) && is_string( $assertion[ $field ] ) ? $assertion[ $field ] : '';
		}

		$cred = Credentials::by_credential_id( $this->decode_binary_field( $fields['id'] ) );
		if ( null === $cred ) {
			return 0;
		}

		$user_id = (int) $cred->user_id;
		if ( ! $this->is_enrolled( $user_id ) || 1 === (int) ( $cred->second_factor_only ?? 0 ) ) {
			return 0;
		}

		// Only a handle we recorded can veto. Older and imported passkeys carry
		// whatever handle they were registered with, which was never stored.
		$handle        = $this->decode_binary_field( $fields['userHandle'] );
		$stored_handle = (string) $cred->user_handle;
		if ( '' !== $handle && '' !== $stored_handle && ! hash_equals( $stored_handle, $handle ) ) {
			return 0;
		}

		if ( ! $this->verify_assertion( $cred, $fields, [ $challenge ], true ) ) {
			return 0;
		}

		if ( 1 !== (int) $cred->discoverable ) {
			Credentials::mark_discoverable( (int) $cred->id );
		}

		return $user_id;
	}

	/**
	 * Check an assertion against one stored credential, and move its signature
	 * counter on when it verifies.
	 *
	 * @param array<string, string> $assertion
	 * @param list<string>          $challenges Raw binary, any of which may be the one signed.
	 */
	private function verify_assertion( object $cred, array $assertion, array $challenges, bool $require_uv ): bool {
		$client_data_json   = $this->decode_binary_field( $assertion['clientDataJSON'] );
		$authenticator_data = $this->decode_binary_field( $assertion['authenticatorData'] );
		$signature          = $this->decode_binary_field( $assertion['signature'] );

		if ( '' === $client_data_json || '' === $authenticator_data || '' === $signature ) {
			return false;
		}

		$user_id    = (int) $cred->user_id;
		$prev_count = (int) $cred->sign_count;
		$verified   = null;

		// The library checks the challenge before it checks the signature or the
		// counter, so a mismatch here only means this assertion belongs to one of
		// the user's other open ceremonies. Anything else is a real failure.
		foreach ( $challenges as $challenge ) {
			try {
				$webauthn = $this->webauthn();
				$webauthn->processGet(
					$client_data_json,
					$authenticator_data,
					$signature,
					(string) $cred->public_key,
					$challenge,
					$prev_count,
					$require_uv,
					true
				);
				$verified = $webauthn;
				break;
			} catch ( \Throwable $e ) {
				if ( $this->is_sign_count_error( $e ) ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
					error_log(
						sprintf(
							'Sigil: passkey sign count regression for user %d credential %d',
							$user_id,
							(int) $cred->id
						)
					);
					break;
				}
			}
		}

		if ( null === $verified ) {
			return false;
		}

		$new_count = $verified->getSignatureCounter();
		if ( ! is_int( $new_count ) ) {
			$new_count = $prev_count;
		}

		// Defence in depth: library already checks, but plan requires explicit refuse when stored is non-zero and new is not greater.
		if ( $prev_count > 0 && $new_count <= $prev_count ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log(
				sprintf(
					'Sigil: passkey sign count regression for user %d credential %d (stored=%d new=%d)',
					$user_id,
					(int) $cred->id,
					$prev_count,
					$new_count
				)
			);
			return false;
		}

		Credentials::touch( (int) $cred->id, $new_count > 0 ? $new_count : $prev_count );

		return true;
	}

	/**
	 * The login form posts the whole assertion as one JSON field, because the
	 * challenge screen has no logged-in session to POST discrete fields against.
	 *
	 * @param array<string, mixed> $input
	 * @return array{id: string, clientDataJSON: string, authenticatorData: string, signature: string}
	 */
	private function assertion_fields( array $input ): array {
		$raw = isset( $input['passkey_assertion'] ) && is_string( $input['passkey_assertion'] )
			? json_decode( $input['passkey_assertion'], true )
			: null;

		$out = [];
		foreach ( [ 'id', 'clientDataJSON', 'authenticatorData', 'signature' ] as $key ) {
			$out[ $key ] = is_array( $raw ) && isset( $raw[ $key ] ) && is_string( $raw[ $key ] ) ? $raw[ $key ] : '';
		}

		return $out;
	}

	public function unenrol( int $user_id ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		Credentials::delete_for_user( $user_id );
		Store::remove_method( $user_id, $this->id() );
	}

	private function register_hooks(): void {
		add_action( 'wp_ajax_sigil_passkey_register_options', [ $this, 'ajax_register_options' ] );
		add_action( 'wp_ajax_sigil_passkey_register', [ $this, 'ajax_register' ] );
	}

	public function ajax_register_options(): void {
		$this->ajax_guard();

		$user_id = $this->request_user_id();
		if ( null === $user_id || ! $this->user_can_manage( $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'You are not allowed to enrol a passkey for this user.', 'sigil-2fa' ) ], 403 );
		}

		if ( ! $this->is_available() ) {
			wp_send_json_error( [ 'message' => __( 'Passkeys are not available in this environment.', 'sigil-2fa' ) ], 400 );
		}

		if ( ! \Sigil\Step_Up::allows( $user_id ) || ! \Sigil\Step_Up::allows_passkey( $user_id ) ) {
			wp_send_json_error( [ 'message' => \Sigil\Step_Up::passkey_reason() ], 403 );
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			wp_send_json_error( [ 'message' => __( 'User not found.', 'sigil-2fa' ) ], 404 );
		}

		// The passkey being replaced is left off the exclude list so the device
		// that holds it may register again; every other one stays on it.
		$replace = $this->replace_target( $user_id );
		$exclude = [];
		foreach ( Credentials::for_user( $user_id ) as $row ) {
			if ( (int) $row->id !== $replace ) {
				$exclude[] = $row->credential_id;
			}
		}

		// A resident key is preferred rather than required, so a security key
		// with no room for one still enrols as a second factor. Re-registering
		// for passwordless sign-in is the one case where only a resident key
		// will do. The user handle stays the user ID that earlier registrations
		// used, so a device replaces its old entry for this account rather than
		// listing the account twice.
		try {
			$webauthn = $this->webauthn();
			$args     = $webauthn->getCreateArgs(
				(string) $user_id,
				$user->user_login,
				$user->display_name,
				self::CHALLENGE_TTL,
				$replace > 0 ? 'required' : 'preferred',
				'preferred',
				null,
				$exclude
			);
			$args->publicKey->extensions = (object) [ 'credProps' => true ];
			$challenge = $webauthn->getChallenge()->getBinaryString();
		} catch ( \Throwable $e ) {
			wp_send_json_error( [ 'message' => __( 'Could not start passkey registration.', 'sigil-2fa' ) ], 500 );
		}

		$this->store_challenge( $user_id, 'register', $challenge );

		wp_send_json_success( $args );
	}

	public function ajax_register(): void {
		$this->ajax_guard();

		$user_id = $this->request_user_id();
		if ( null === $user_id || ! $this->user_can_manage( $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'You are not allowed to enrol a passkey for this user.', 'sigil-2fa' ) ], 403 );
		}

		// The nonce is verified by ajax_guard() above via check_ajax_referer, and the
		// capability by user_can_manage(). These four values are base64 and JSON blobs
		// the WebAuthn library parses and verifies cryptographically; running them
		// through sanitize_text_field would corrupt the signature payload.
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$input = [
			'clientDataJSON'    => isset( $_POST['clientDataJSON'] ) ? wp_unslash( (string) $_POST['clientDataJSON'] ) : '',
			'attestationObject' => isset( $_POST['attestationObject'] ) ? wp_unslash( (string) $_POST['attestationObject'] ) : '',
			'label'             => isset( $_POST['label'] ) ? wp_unslash( (string) $_POST['label'] ) : '',
			'transports'        => isset( $_POST['transports'] ) ? wp_unslash( (string) $_POST['transports'] ) : '',
			'discoverable'      => isset( $_POST['discoverable'] ) ? sanitize_key( wp_unslash( (string) $_POST['discoverable'] ) ) : '',
			'replace'           => $this->replace_target( $user_id ),
		];
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		// Through the same door as every other method, so the change alert, the
		// trusted-device revocation, backup codes and the confirmation step all
		// apply to a passkey as well.
		$result = \Sigil\Enrolment::instance()->complete_method( $user_id, $this->id(), $input );
		if ( is_wp_error( $result ) ) {
			$status = in_array( $result->get_error_code(), [ 'sigil_step_up_required', 'sigil_forbidden' ], true ) ? 403 : 400;
			wp_send_json_error( [ 'message' => $result->get_error_message() ], $status );
		}

		wp_send_json_success( [ 'message' => __( 'Passkey registered.', 'sigil-2fa' ) ] );
	}

	private function ajax_guard(): void {
		if ( ! is_user_logged_in() ) {
			wp_send_json_error( [ 'message' => __( 'You must be logged in.', 'sigil-2fa' ) ], 401 );
		}

		check_ajax_referer( 'sigil_passkey', 'nonce' );
	}

	private function request_user_id(): ?int {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce checked in ajax_guard.
		$raw = isset( $_REQUEST['user_id'] ) ? absint( wp_unslash( $_REQUEST['user_id'] ) ) : get_current_user_id();
		return $raw > 0 ? $raw : null;
	}

	/**
	 * The passkey this registration replaces, when the request names one this user owns.
	 */
	private function replace_target( int $user_id ): int {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce checked in ajax_guard.
		$id = isset( $_REQUEST['replace'] ) ? absint( wp_unslash( $_REQUEST['replace'] ) ) : 0;
		if ( $id <= 0 ) {
			return 0;
		}

		foreach ( Credentials::for_user( $user_id ) as $row ) {
			if ( (int) $row->id === $id ) {
				return $id;
			}
		}

		return 0;
	}

	private function user_can_manage( int $user_id ): bool {
		if ( get_current_user_id() === $user_id ) {
			return current_user_can( 'read' );
		}
		return current_user_can( 'edit_user', $user_id );
	}

	/**
	 * Registration talks to admin-ajax; the login challenge does not, so the
	 * logged-out screen is not handed an ajax URL and a live nonce it never uses.
	 */
	private function enqueue_script( int $user_id, bool $with_ajax ): void {
		wp_enqueue_script(
			'sigil-passkey',
			SIGIL_URL . 'assets/js/passkey.js',
			[],
			SIGIL_VERSION,
			true
		);

		$data = [];
		if ( $with_ajax ) {
			$data['ajaxUrl'] = admin_url( 'admin-ajax.php' );
			$data['nonce']   = wp_create_nonce( 'sigil_passkey' );
			$data['userId']  = $user_id;
		}

		wp_localize_script(
			'sigil-passkey',
			'sigilPasskey',
			$data + [
				'i18n' => [
					'unsupported'   => __( 'Passkeys are not supported in this browser or context. Use HTTPS and a modern browser.', 'sigil-2fa' ),
					'registering'   => __( 'Follow the browser prompt to register your passkey…', 'sigil-2fa' ),
					'registered'    => __( 'Passkey registered.', 'sigil-2fa' ),
					'authenticating'=> __( 'Follow the browser prompt to use your passkey…', 'sigil-2fa' ),
					'verifying'     => __( 'Verifying…', 'sigil-2fa' ),
					'failed'        => __( 'Something went wrong. Please try again.', 'sigil-2fa' ),
				],
			]
		);
	}

	/**
	 * @return \lbuchs\WebAuthn\WebAuthn
	 */
	private function webauthn() {
		$rp_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $rp_name ) {
			$rp_name = 'WordPress';
		}

		$formats = [ 'none', 'packed', 'apple', 'android-key', 'android-safetynet', 'fido-u2f', 'tpm' ];

		return new \lbuchs\WebAuthn\WebAuthn( $rp_name, self::rp_id(), $formats, true );
	}

	public static function rp_id(): string {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		$host = is_string( $host ) ? strtolower( $host ) : '';

		/**
		 * Filter the WebAuthn relying-party ID (registrable domain).
		 *
		 * Defaults to this site's own host, which is what the credential was
		 * created for. A network that wants one passkey to cover its subdomain
		 * sites can widen it deliberately:
		 *
		 *     add_filter( 'sigil_rp_id', static function ( $host ) {
		 *         return \Sigil\Providers\Passkey::resolve_rp_id( $host, \Sigil\Network::primary_host() );
		 *     } );
		 *
		 * Widening is opt-in because it cuts both ways: it makes every existing
		 * credential on the old host unusable, and it lets any site under that
		 * domain ask for assertions, which matters on a network whose sites have
		 * different administrators.
		 *
		 * @param string $host Hostname derived from home_url().
		 */
		$rp_id = apply_filters( 'sigil_rp_id', $host );

		return is_string( $rp_id ) && '' !== $rp_id ? $rp_id : $host;
	}

	/**
	 * Widen a host to the network domain where the site sits under it, for sites
	 * that opt into network-wide passkeys through the sigil_rp_id filter.
	 *
	 * A mapped domain is a different registrable suffix, so it keeps its own
	 * host: the browser would refuse to sign for anything else.
	 */
	public static function resolve_rp_id( string $host, string $network_host ): string {
		if ( '' === $host || '' === $network_host ) {
			return $host;
		}

		if ( $host === $network_host ) {
			return $network_host;
		}

		$suffix = '.' . $network_host;
		if ( substr( $host, -strlen( $suffix ) ) === $suffix ) {
			return $network_host;
		}

		return $host;
	}

	private static function ceremony_key( string $ceremony ): string {
		return 'sigil_pk_pl_' . hash( 'sha256', $ceremony );
	}

	private function challenge_key( int $user_id, string $purpose ): string {
		return 'sigil_pk_' . $purpose . '_' . $user_id;
	}

	/**
	 * A user can have more than one ceremony open at once: two tabs on the login
	 * screen, or a plain refresh. Keeping the last few outstanding challenges means
	 * the older tab still verifies instead of failing and burning a rate-limit
	 * attempt on a challenge the newer render overwrote.
	 */
	private function store_challenge( int $user_id, string $purpose, string $challenge ): void {
		$open   = $this->open_challenges( $user_id, $purpose );
		$open[] = [
			'c' => base64_encode( $challenge ),
			'e' => time() + self::CHALLENGE_TTL,
		];

		set_transient(
			$this->challenge_key( $user_id, $purpose ),
			array_slice( $open, -self::MAX_OPEN_CHALLENGES ),
			self::CHALLENGE_TTL
		);
	}

	/**
	 * Appending refreshes the transient's own TTL, so each entry carries the expiry
	 * it was minted with and is dropped on its own schedule.
	 *
	 * @return list<array{c: string, e: int}>
	 */
	private function open_challenges( int $user_id, string $purpose ): array {
		$raw = get_transient( $this->challenge_key( $user_id, $purpose ) );
		if ( ! is_array( $raw ) ) {
			return [];
		}

		$now  = time();
		$open = [];
		foreach ( $raw as $entry ) {
			if ( is_array( $entry ) && isset( $entry['c'], $entry['e'] ) && is_string( $entry['c'] ) && (int) $entry['e'] > $now ) {
				$open[] = [
					'c' => $entry['c'],
					'e' => (int) $entry['e'],
				];
			}
		}

		return $open;
	}

	/**
	 * @return list<string> Outstanding challenges as raw binary, oldest first.
	 */
	private function get_challenges( int $user_id, string $purpose ): array {
		$out = [];
		foreach ( $this->open_challenges( $user_id, $purpose ) as $entry ) {
			$decoded = base64_decode( $entry['c'], true );
			if ( is_string( $decoded ) && '' !== $decoded ) {
				$out[] = $decoded;
			}
		}

		return $out;
	}

	private function clear_challenge( int $user_id, string $purpose ): void {
		delete_transient( $this->challenge_key( $user_id, $purpose ) );
	}

	/**
	 * @param mixed $value Base64 or base64url encoded binary, or raw binary string.
	 */
	private function decode_binary_field( $value ): string {
		if ( ! is_string( $value ) || '' === $value ) {
			return '';
		}

		// Prefer strict base64, then base64url.
		$decoded = base64_decode( $value, true );
		if ( false !== $decoded && '' !== $decoded ) {
			return $decoded;
		}

		$b64 = strtr( $value, '-_', '+/' );
		$pad = strlen( $b64 ) % 4;
		if ( $pad > 0 ) {
			$b64 .= str_repeat( '=', 4 - $pad );
		}
		$decoded = base64_decode( $b64, true );
		return false === $decoded ? '' : $decoded;
	}

	/**
	 * @param mixed $raw
	 */
	private function sanitize_transports( $raw ): string {
		if ( is_array( $raw ) ) {
			$parts = array_map( 'sanitize_text_field', $raw );
			return implode( ',', array_filter( $parts ) );
		}
		if ( is_string( $raw ) ) {
			// JSON array from the client.
			if ( '' !== $raw && ( '[' === $raw[0] || '{' === $raw[0] ) ) {
				$decoded = json_decode( $raw, true );
				if ( is_array( $decoded ) ) {
					return $this->sanitize_transports( $decoded );
				}
			}
			return sanitize_text_field( $raw );
		}
		return '';
	}

	private function is_sign_count_error( \Throwable $e ): bool {
		$msg = strtolower( $e->getMessage() );
		return false !== strpos( $msg, 'signature counter' ) || false !== strpos( $msg, 'sign count' );
	}
}
