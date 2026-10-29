<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Enrolment {

	public const PAGE_SLUG = 'sigil-2fa-setup';

	private static ?Enrolment $instance = null;

	public static function instance(): Enrolment {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_post_sigil_enrol', array( $this, 'handle_enrol_post' ) );
		add_action( 'admin_post_sigil_remove_method', array( $this, 'handle_remove_post' ) );
		add_action( 'admin_post_sigil_remove_passkey', array( $this, 'handle_remove_passkey_post' ) );
		add_action( 'admin_post_sigil_prefer_method', array( $this, 'handle_prefer_post' ) );
		add_action( 'admin_post_sigil_regenerate_backup', array( $this, 'handle_regenerate_backup_post' ) );
		add_action( 'admin_post_sigil_step_up', array( $this, 'handle_step_up_post' ) );
		add_action( 'admin_post_sigil_forget_devices', array( $this, 'handle_forget_devices_post' ) );
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
	}

	public function register_menu(): void {
		add_users_page(
			__( 'Two-Factor Authentication', 'sigil-2fa' ),
			__( 'Two-Factor Auth', 'sigil-2fa' ),
			'read',
			self::PAGE_SLUG,
			array( $this, 'render_setup_page' )
		);
	}

	/**
	 * @param string $hook_suffix Current admin page hook.
	 */
	public function enqueue_assets( string $hook_suffix ): void {
		$load = false;

		if ( false !== strpos( $hook_suffix, self::PAGE_SLUG ) || in_array( $hook_suffix, array( 'profile.php', 'user-edit.php' ), true ) ) {
			$load = true;
		}

		if ( ! $load ) {
			return;
		}

		wp_enqueue_style(
			'sigil-admin',
			SIGIL_URL . 'assets/css/admin.css',
			array(),
			SIGIL_VERSION
		);

		self::enqueue_enrol_assets();
	}

	/**
	 * The QR renderer and the strings its fallback needs. Bundled rather than
	 * fetched: the provisioning secret must not travel to a third party, and the
	 * screen has to work on an install with no outbound network.
	 */
	public static function enqueue_enrol_assets(): void {
		wp_enqueue_script(
			'sigil-qrcode',
			SIGIL_URL . 'assets/js/vendor/qrcode.js',
			array(),
			'2.0.4',
			true
		);

		wp_enqueue_script(
			'sigil-enrol',
			SIGIL_URL . 'assets/js/enrol.js',
			array( 'sigil-qrcode' ),
			SIGIL_VERSION,
			true
		);

		wp_localize_script(
			'sigil-enrol',
			'sigilEnrol',
			array(
				'i18n' => array(
					'qrAlt'         => __( 'Authenticator setup QR code', 'sigil-2fa' ),
					'qrUnavailable' => __( 'Scanning is unavailable here. Enter the secret key manually in your authenticator app.', 'sigil-2fa' ),
				),
			)
		);
	}


	public function render_setup_page(): void {
		$user_id = (int) get_current_user_id();
		if ( $user_id <= 0 || ! current_user_can( 'read' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'sigil-2fa' ) );
		}

		$this->render_enrol_ui( $user_id, true );
	}

	/**
	 * A summary only. The profile screen is one big form, and a form inside it
	 * is dropped by the browser, so any button here would submit the profile
	 * instead of doing what it says. Changes happen on the setup page, and an
	 * administrator's reset is a link.
	 *
	 * @param \WP_User $user Profile user.
	 */
	public function render_profile_section( $user ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}

		$user_id = (int) $user->ID;
		if ( ! $this->can_manage_methods( $user_id ) ) {
			return;
		}

		$labels = array();
		foreach ( Providers::instance()->enrolled_for( $user_id ) as $provider ) {
			$labels[] = $provider->label();
		}
		$preferred = array() !== $labels ? Providers::instance()->preferred_for( $user_id ) : null;
		$devices   = Trusted_Devices::instance()->count_for( $user_id );

		echo '<h2>' . esc_html__( 'Two-Factor Authentication', 'sigil-2fa' ) . '</h2>';
		echo '<div class="sigil-profile-card"><table class="form-table sigil-profile" role="presentation"><tbody>';

		echo '<tr><th scope="row">' . esc_html__( 'Methods', 'sigil-2fa' ) . '</th><td>';
		echo esc_html( array() !== $labels ? implode( ', ', $labels ) : __( 'None set up yet.', 'sigil-2fa' ) );
		echo '</td></tr>';

		if ( null !== $preferred ) {
			echo '<tr><th scope="row">' . esc_html__( 'Asked for first', 'sigil-2fa' ) . '</th><td>' . esc_html( $preferred->label() ) . '</td></tr>';
		}

		echo '<tr><th scope="row">' . esc_html__( 'Trusted devices', 'sigil-2fa' ) . '</th><td>';
		echo esc_html(
			sprintf(
				/* translators: %d: number of trusted devices */
				_n( '%d trusted device', '%d trusted devices', $devices, 'sigil-2fa' ),
				$devices
			)
		);
		echo '</td></tr>';

		echo '<tr><th scope="row"></th><td>';
		if ( (int) get_current_user_id() === $user_id ) {
			echo '<a class="button" href="' . esc_url( admin_url( 'users.php?page=' . self::PAGE_SLUG ) ) . '">' . esc_html__( 'Manage two-factor authentication', 'sigil-2fa' ) . '</a>';
		} elseif ( current_user_can( 'edit_users' ) && array() !== $labels ) {
			echo '<a class="button sigil-reset-2fa" href="' . esc_url( Recovery::reset_url( $user_id ) ) . '" onclick="return confirm( \'' . esc_js( Recovery::reset_confirmation() ) . '\' );">' . esc_html__( 'Reset two-factor authentication', 'sigil-2fa' ) . '</a>';
		}
		echo '</td></tr>';

		echo '</tbody></table></div>';
	}

	/**
	 * Enrol a method and force-generate backup codes the first time any
	 * non-backup method is added.
	 *
	 * @param array<string, mixed> $input
	 * @return true|\WP_Error
	 */
	public function complete_method( int $user_id, string $provider_id, array $input ) {
		/**
		 * Filter whether a user may set up this method.
		 *
		 * The place to refuse a method is here, when someone is choosing it, not
		 * at the login that follows. A rule applied at authentication cannot
		 * tell "you may not use this" apart from "you have nothing", and the
		 * second answer skips the challenge altogether.
		 *
		 * @param bool   $allowed
		 * @param int    $user_id
		 * @param string $provider_id
		 */
		if ( ! apply_filters( 'sigil_can_enrol', true, $user_id, $provider_id ) ) {
			return new \WP_Error(
				'sigil_method_not_allowed',
				__( 'That authentication method is not available for this account.', 'sigil-2fa' )
			);
		}

		/**
		 * Fires before a user's methods are about to change, so a listener can
		 * see what they were.
		 *
		 * @param int $user_id
		 */
		do_action( 'sigil_before_methods_change', $user_id );

		if ( ! $this->can_manage_methods( $user_id ) ) {
			return new \WP_Error(
				'sigil_forbidden',
				__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' )
			);
		}

		if ( ! Step_Up::allows( $user_id ) ) {
			return Step_Up::error();
		}

		$provider_id = sanitize_key( $provider_id );
		if ( '' === $provider_id ) {
			return new \WP_Error(
				'sigil_unknown_provider',
				__( 'Unknown authentication method.', 'sigil-2fa' )
			);
		}

		if ( 'passkey' === $provider_id && ( ! Step_Up::allows_passkey( $user_id ) || ! Step_Up::claim( $user_id ) ) ) {
			return Step_Up::passkey_error();
		}

		$first = (int) get_current_user_id() === $user_id && ! Providers::instance()->has_usable( $user_id );

		$provider = Providers::instance()->get( $provider_id );
		if ( null === $provider ) {
			return new \WP_Error(
				'sigil_unknown_provider',
				__( 'Unknown authentication method.', 'sigil-2fa' )
			);
		}

		$passkeys_before = 'passkey' === $provider_id ? self::credential_ids( $user_id ) : array();

		$result = $provider->handle_enrol( $user_id, $input );

		if ( is_wp_error( $result ) ) {
			// Forms that post validation fields (TOTP code, passkey attestation)
			// must not fall through to raw storage on failure.
			if ( $this->input_requires_provider_validation( $input ) ) {
				return $result;
			}

			// Programmatic / unit-test path: storage-shaped stubs (e.g. secret => x).
			Store::set_method( $user_id, $provider_id, $input );
		}

		if ( 'backup' !== $provider_id ) {
			$this->ensure_backup_codes( $user_id );
		}

		/**
		 * Fires when a user's enrolled factors change. Add-ons that cache a
		 * trust decision (e.g. trusted devices) revoke it here, so a device
		 * trusted under old factors cannot survive a credential change.
		 *
		 * @param int $user_id
		 */
		do_action( 'sigil_methods_changed', $user_id );

		if ( $first ) {
			Step_Up::record_setup( $user_id );
		}

		$factors = array();
		if ( 'totp' === $provider_id ) {
			$factors[] = 'totp';
		} elseif ( 'passkey' === $provider_id ) {
			foreach ( array_diff( self::credential_ids( $user_id ), $passkeys_before ) as $id ) {
				$factors[] = 'passkey:' . $id;
			}
		}
		Step_Up::enrolled( $user_id, $factors );

		return true;
	}

	/**
	 * @return list<int>
	 */
	private static function credential_ids( int $user_id ): array {
		return array_map(
			static function ( $row ): int {
				return (int) $row->id;
			},
			Credentials::for_user( $user_id )
		);
	}

	/**
	 * @return true|\WP_Error
	 */
	public function remove_method( int $user_id, string $provider_id ) {
		/** This action is documented in includes/class-enrolment.php */
		do_action( 'sigil_before_methods_change', $user_id );

		if ( ! $this->can_manage_methods( $user_id ) ) {
			return new \WP_Error(
				'sigil_forbidden',
				__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' )
			);
		}

		if ( ! Step_Up::allows( $user_id ) ) {
			return Step_Up::error();
		}

		$provider_id = sanitize_key( $provider_id );
		if ( '' === $provider_id ) {
			return new \WP_Error(
				'sigil_unknown_provider',
				__( 'Unknown authentication method.', 'sigil-2fa' )
			);
		}

		$methods = Store::methods( $user_id );
		if ( ! isset( $methods[ $provider_id ] ) ) {
			return new \WP_Error(
				'sigil_not_enrolled',
				__( 'That authentication method is not set up.', 'sigil-2fa' )
			);
		}

		// Count what would still be usable, not what rows would remain. A row
		// whose provider is unavailable or whose credentials are gone is not a
		// second factor, and leaving on that basis strands the user.
		$remaining = array();
		foreach ( Providers::instance()->enrolled_for( $user_id ) as $provider ) {
			if ( $provider->id() !== $provider_id ) {
				$remaining[ $provider->id() ] = true;
			}
		}

		if ( array() === $remaining && Policy::required_for( $user_id ) ) {
			return new \WP_Error(
				'sigil_last_method',
				__( 'You cannot remove your last authentication method while two-factor authentication is required.', 'sigil-2fa' )
			);
		}

		$factors = array();
		if ( 'totp' === $provider_id ) {
			$factors[] = 'totp';
		} elseif ( 'passkey' === $provider_id ) {
			foreach ( self::credential_ids( $user_id ) as $id ) {
				$factors[] = 'passkey:' . $id;
			}
		}

		$provider = Providers::instance()->get( $provider_id );
		if ( $provider ) {
			$provider->unenrol( $user_id );
		} else {
			Store::remove_method( $user_id, $provider_id );
		}

		if ( Providers::preference( $user_id ) === $provider_id ) {
			Providers::set_preference( $user_id, '' );
		}

		do_action( 'sigil_methods_changed', $user_id );

		Step_Up::removed( $user_id, $factors );

		return true;
	}

	/**
	 * Remove one passkey and keep the rest. Removing the last one is the same
	 * as removing the method, so it goes through remove_method() and its
	 * last-method guard.
	 *
	 * @return true|\WP_Error
	 */
	public function remove_passkey( int $user_id, int $credential_id ) {
		if ( ! $this->can_manage_methods( $user_id ) ) {
			return new \WP_Error(
				'sigil_forbidden',
				__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' )
			);
		}

		if ( ! Step_Up::allows( $user_id ) ) {
			return Step_Up::error();
		}

		$ids = self::credential_ids( $user_id );
		if ( ! in_array( $credential_id, $ids, true ) ) {
			return new \WP_Error(
				'sigil_unknown_passkey',
				__( 'That passkey is not registered on this account.', 'sigil-2fa' )
			);
		}

		if ( 1 === count( $ids ) ) {
			return $this->remove_method( $user_id, 'passkey' );
		}

		/** This action is documented in includes/class-enrolment.php */
		do_action( 'sigil_before_methods_change', $user_id );

		Credentials::delete( $credential_id, $user_id );

		do_action( 'sigil_methods_changed', $user_id );

		Step_Up::removed( $user_id, array( 'passkey:' . $credential_id ) );

		return true;
	}

	public function handle_remove_passkey_post(): void {
		$user_id       = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
		$credential_id = isset( $_POST['credential'] ) ? absint( wp_unslash( $_POST['credential'] ) ) : 0;

		check_admin_referer( 'sigil_remove_passkey_' . $user_id . '_' . $credential_id );

		if ( ! $this->can_manage_methods( $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		$result = $this->remove_passkey( $user_id, $credential_id );
		if ( is_wp_error( $result ) ) {
			$this->redirect_with_status( $user_id, 'error', $result->get_error_code(), $result->get_error_message(), 'passkey' );
		}

		$this->redirect_with_status( $user_id, 'success', 'passkey_removed', '', 'passkey' );
	}

	public function handle_enrol_post(): void {
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : (int) get_current_user_id();

		check_admin_referer( 'sigil_enrol_' . $user_id );

		if ( ! $this->can_manage_methods( $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		$provider_id = isset( $_POST['provider'] ) ? sanitize_key( wp_unslash( (string) $_POST['provider'] ) ) : '';
		if ( '' === $provider_id ) {
			$this->redirect_with_status( $user_id, 'error', 'missing_provider' );
		}

		$input  = $this->collect_provider_input( $provider_id );
		$result = $this->complete_method( $user_id, $provider_id, $input );

		if ( is_wp_error( $result ) ) {
			$this->redirect_with_status( $user_id, 'error', $result->get_error_code(), $result->get_error_message() );
		}

		$show_backup = ( 'backup' !== $provider_id && $this->backup_codes_pending_display( $user_id ) );
		$this->redirect_with_status(
			$user_id,
			'success',
			$show_backup ? 'enrolled_backup' : 'enrolled',
			'',
			$provider_id
		);
	}

	public function handle_remove_post(): void {
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
		$provider_id = isset( $_POST['provider'] ) ? sanitize_key( wp_unslash( (string) $_POST['provider'] ) ) : '';

		check_admin_referer( 'sigil_remove_' . $user_id . '_' . $provider_id );

		if ( ! $this->can_manage_methods( $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		$result = $this->remove_method( $user_id, $provider_id );
		if ( is_wp_error( $result ) ) {
			$this->redirect_with_status( $user_id, 'error', $result->get_error_code(), $result->get_error_message() );
		}

		$this->redirect_with_status( $user_id, 'success', 'removed', '', $provider_id );
	}

	public function handle_prefer_post(): void {
		$user_id     = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
		$provider_id = isset( $_POST['provider'] ) ? sanitize_key( wp_unslash( (string) $_POST['provider'] ) ) : '';

		check_admin_referer( 'sigil_prefer_' . $user_id . '_' . $provider_id );

		if ( ! $this->can_manage_methods( $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		$result = Providers::set_preference( $user_id, $provider_id );
		if ( is_wp_error( $result ) ) {
			$this->redirect_with_status( $user_id, 'error', $result->get_error_code(), $result->get_error_message(), $provider_id );
		}

		$this->redirect_with_status( $user_id, 'success', 'preferred', '', $provider_id );
	}

	public function handle_regenerate_backup_post(): void {
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;

		check_admin_referer( 'sigil_regenerate_backup_' . $user_id );

		if ( ! $this->can_manage_methods( $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		$result = $this->regenerate_backup_codes( $user_id );
		if ( is_wp_error( $result ) ) {
			$this->redirect_with_status( $user_id, 'error', $result->get_error_code(), $result->get_error_message(), 'backup' );
		}

		$this->redirect_with_status( $user_id, 'success', 'enrolled_backup', '', 'backup' );
	}

	/**
	 * Replace the backup codes. A fresh set is as good as a factor of its own
	 * to whoever reads it, so it is guarded and announced like one.
	 *
	 * @return true|\WP_Error
	 */
	public function regenerate_backup_codes( int $user_id ) {
		if ( ! $this->can_manage_methods( $user_id ) ) {
			return new \WP_Error(
				'sigil_forbidden',
				__( 'You are not allowed to change two-factor methods for this user.', 'sigil-2fa' )
			);
		}

		if ( ! Step_Up::allows( $user_id ) ) {
			return Step_Up::error();
		}

		$backup = Providers::instance()->get( 'backup' );
		if ( ! $backup instanceof Providers\Backup_Codes ) {
			return new \WP_Error( 'backup_unavailable', __( 'Backup codes are not available.', 'sigil-2fa' ) );
		}

		/** This action is documented in includes/class-enrolment.php */
		do_action( 'sigil_before_methods_change', $user_id );
		$backup->generate( $user_id );
		/** This action is documented in includes/class-enrolment.php */
		do_action( 'sigil_methods_changed', $user_id );

		Step_Up::enrolled( $user_id, array() );

		return true;
	}

	public function handle_step_up_post(): void {
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;

		check_admin_referer( 'sigil_step_up_' . $user_id );

		if ( $user_id <= 0 || (int) get_current_user_id() !== $user_id ) {
			wp_die( esc_html__( 'You can only confirm your own account.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		// A password is compared, never stored or echoed, and sanitising it
		// would change what is compared. The assertion is JSON the passkey
		// provider decodes and verifies field by field.
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$input = array(
			'password'          => isset( $_POST['sigil_step_up_password'] ) ? (string) wp_unslash( $_POST['sigil_step_up_password'] ) : '',
			'code'              => isset( $_POST['sigil_step_up_code'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['sigil_step_up_code'] ) ) : '',
			'passkey_assertion' => isset( $_POST['passkey_assertion'] ) ? (string) wp_unslash( $_POST['passkey_assertion'] ) : '',
		);
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		// Back to the tab they were on.
		$method = isset( $_POST['method'] ) ? sanitize_key( wp_unslash( (string) $_POST['method'] ) ) : '';

		$result = Step_Up::prove( $user_id, $input );
		if ( is_wp_error( $result ) ) {
			$this->redirect_with_status( $user_id, 'error', $result->get_error_code(), $result->get_error_message(), $method );
		}

		$this->redirect_with_status( $user_id, 'success', 'confirmed', '', $method );
	}

	/**
	 * Forgetting trusted devices only ever takes access away, so it needs no
	 * confirmation, but it is the owner's own call: an administrator who wants
	 * it done resets the account instead.
	 */
	public function handle_forget_devices_post(): void {
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;

		check_admin_referer( 'sigil_forget_devices_' . $user_id );

		if ( $user_id <= 0 || (int) get_current_user_id() !== $user_id ) {
			wp_die( esc_html__( 'You can only forget the devices trusted on your own account.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		Trusted_Devices::instance()->forget( $user_id );

		$this->redirect_with_status( $user_id, 'success', 'devices_forgotten' );
	}

	/**
	 * Where the submission came from, when that was a page outside wp-admin.
	 * wp_nonce_field() already carries the referer on every one of these forms.
	 * wp_safe_redirect() rejects off-site values, so a forged referer cannot
	 * send anyone anywhere but this site.
	 */
	private function frontend_referer(): string {
		$referer = wp_get_referer();
		if ( ! is_string( $referer ) || '' === $referer ) {
			return '';
		}

		if ( 0 === strpos( $referer, admin_url() ) || 0 === strpos( $referer, network_admin_url() ) ) {
			return '';
		}

		$validated = wp_validate_redirect( $referer, '' );

		return is_string( $validated ) ? $validated : '';
	}

	public function can_manage_methods( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$current = (int) get_current_user_id();
		if ( $current <= 0 ) {
			return false;
		}

		if ( $current === $user_id ) {
			return current_user_can( 'read' );
		}

		return current_user_can( 'edit_user', $user_id );
	}

	/**
	 * Force-generate backup codes when none are enrolled yet.
	 * Codes are stored hashed; plaintext lives in a short-lived transient for one-time display.
	 */
	public function ensure_backup_codes( int $user_id ): void {
		$backup = Providers::instance()->get( 'backup' );
		if ( ! $backup instanceof Providers\Backup_Codes ) {
			return;
		}

		if ( $backup->is_enrolled( $user_id ) ) {
			return;
		}

		$backup->generate( $user_id );
	}

	/**
	 * @param array<string, mixed> $input
	 */
	private function input_requires_provider_validation( array $input ): bool {
		if ( array_key_exists( 'code', $input ) || array_key_exists( 'sigil_totp_code', $input ) ) {
			return true;
		}
		if ( array_key_exists( 'clientDataJSON', $input ) || array_key_exists( 'attestationObject', $input ) ) {
			return true;
		}
		return false;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function collect_provider_input( string $provider_id ): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified by caller.
		$post = wp_unslash( $_POST );

		switch ( $provider_id ) {
			case 'totp':
				return array(
					'secret' => isset( $post['sigil_totp_secret'] ) ? (string) $post['sigil_totp_secret'] : '',
					'code'   => isset( $post['sigil_totp_code'] ) ? (string) $post['sigil_totp_code'] : '',
				);
			case 'email':
				return array();
			case 'backup':
				return array();
			case 'passkey':
				return array(
					'clientDataJSON'    => isset( $post['clientDataJSON'] ) ? (string) $post['clientDataJSON'] : '',
					'attestationObject' => isset( $post['attestationObject'] ) ? (string) $post['attestationObject'] : '',
					'label'             => isset( $post['sigil_passkey_label'] ) ? (string) $post['sigil_passkey_label'] : '',
					'transports'        => isset( $post['transports'] ) ? $post['transports'] : '',
				);
			default:
				return array();
		}
	}

	private function backup_codes_pending_display( int $user_id ): bool {
		$backup = Providers::instance()->get( 'backup' );
		return $backup instanceof Providers\Backup_Codes && $backup->has_pending_display( $user_id );
	}

	public function render_enrol_ui( int $user_id, bool $is_setup_page ): void {
		// Named, because an administrator can be looking at somebody else's
		// profile and it is that account's rules that decide what it may enrol.
		$providers = Providers::instance()->all( $user_id );
		$methods   = Store::methods( $user_id );
		$notices   = $this->consume_notices();

		// A passkey method whose credentials are all gone is not a method.
		if ( isset( $methods['passkey'] ) && array() === Credentials::for_user( $user_id ) ) {
			unset( $methods['passkey'] );
		}
		$passkeys = isset( $methods['passkey'] ) ? Credentials::for_user( $user_id ) : array();

		$backup_provider = Providers::instance()->get( 'backup' );
		$show_backup     = $backup_provider instanceof Providers\Backup_Codes
			&& $this->backup_codes_pending_display( $user_id );

		$needs_step_up = Step_Up::required( $user_id ) && ! Step_Up::satisfied( $user_id );
		$own_account   = (int) get_current_user_id() === $user_id;
		$passkey_proof = ! Step_Up::allows_passkey( $user_id );
		$trusted_count = $own_account ? Trusted_Devices::instance()->count_for( $user_id ) : 0;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only query flag.
		$active = isset( $_GET['method'] ) ? sanitize_key( wp_unslash( (string) $_GET['method'] ) ) : '';
		if ( '' === $active || null === Providers::instance()->get( $active ) ) {
			$active = $this->default_method_tab( $providers, $methods );
		}

		require SIGIL_DIR . 'templates/enrol.php';
	}

	/**
	 * The confirm form: the password, and whichever current factors can
	 * confirm. Posts to the step-up handler, which comes back to $method's tab.
	 *
	 * @param array<string, string> $hidden Extra fields, such as the wizard's step.
	 */
	public function render_step_up_form( int $user_id, string $method = '', array $hidden = array() ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="sigil-enrol__form sigil-step-up-form">';
		echo '<input type="hidden" name="action" value="sigil_step_up" />';
		echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $user_id ) . '" />';
		echo '<input type="hidden" name="method" value="' . esc_attr( $method ) . '" />';
		foreach ( $hidden as $name => $value ) {
			echo '<input type="hidden" name="' . esc_attr( (string) $name ) . '" value="' . esc_attr( (string) $value ) . '" />';
		}
		wp_nonce_field( 'sigil_step_up_' . $user_id );

		echo '<p><label for="sigil-step-up-password">' . esc_html__( 'Password', 'sigil-2fa' ) . '</label> ';
		echo '<input type="password" name="sigil_step_up_password" id="sigil-step-up-password" class="regular-text" autocomplete="current-password" /></p>';

		foreach ( Step_Up::factors( $user_id ) as $factor ) {
			if ( 'totp' === $factor->id() ) {
				echo '<p><label for="sigil-step-up-code">' . esc_html__( 'Or a code from your authenticator app', 'sigil-2fa' ) . '</label> ';
				echo '<input type="text" name="sigil_step_up_code" id="sigil-step-up-code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" /></p>';
			} elseif ( 'passkey' === $factor->id() ) {
				$factor->render_challenge( $user_id );
			}
		}

		echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Confirm', 'sigil-2fa' ) . '</button></p>';
		echo '</form>';
	}

	/**
	 * @param list<Provider>               $providers
	 * @param array<string, array<string, mixed>> $methods
	 */
	private function default_method_tab( array $providers, array $methods ): string {
		foreach ( $providers as $provider ) {
			if ( 'backup' === $provider->id() ) {
				continue;
			}
			if ( ! isset( $methods[ $provider->id() ] ) ) {
				return $provider->id();
			}
		}
		return isset( $providers[0] ) ? $providers[0]->id() : 'totp';
	}

	/**
	 * @return array{type: string, code: string, message: string}
	 */
	private function consume_notices(): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only status after redirect.
		$type = isset( $_GET['sigil_status'] ) ? sanitize_key( wp_unslash( (string) $_GET['sigil_status'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$code = isset( $_GET['sigil_code'] ) ? sanitize_key( wp_unslash( (string) $_GET['sigil_code'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$message = isset( $_GET['sigil_msg'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['sigil_msg'] ) ) : '';

		return array(
			'type'    => $type,
			'code'    => $code,
			'message' => $message,
		);
	}

	private function redirect_with_status( int $user_id, string $status, string $code, string $message = '', string $provider_id = '' ): void {
		$current = (int) get_current_user_id();
		$args    = array(
			'sigil_status' => $status,
			'sigil_code'   => $code,
		);

		if ( '' !== $message ) {
			$args['sigil_msg'] = $message;
		}
		if ( '' !== $provider_id ) {
			$args['method'] = $provider_id;
		}

		$front = $this->frontend_referer();
		if ( '' !== $front ) {
			$url = add_query_arg( $args, $front );
		} elseif ( $current === $user_id ) {
			$url = add_query_arg(
				array_merge(
					array( 'page' => self::PAGE_SLUG ),
					$args
				),
				admin_url( 'users.php' )
			);
		} else {
			$url = add_query_arg(
				$args,
				get_edit_user_link( $user_id )
			);
		}

		/**
		 * Filter where the user lands after changing their 2FA methods.
		 *
		 * Runs through wp_safe_redirect(), so an off-site value is refused.
		 *
		 * @param string $url         Where they would have gone.
		 * @param int    $user_id     Whose methods changed.
		 * @param string $status      'success' or 'error'.
		 * @param string $code        Machine-readable outcome, e.g. 'enrolled'.
		 * @param string $provider_id The method involved, when there is one.
		 */
		$url = (string) apply_filters( 'sigil_enrol_redirect', $url, $user_id, $status, $code, $provider_id );

		wp_safe_redirect( $url );
		exit;
	}
}
