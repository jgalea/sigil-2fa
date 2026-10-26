<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * Fresh proof before an account's methods change.
 *
 * A session is a bearer value. Whoever holds one for a minute, on a shared
 * computer or through a stolen cookie, could otherwise register a passkey of
 * their own, and with passwordless sign-in that passkey is the whole
 * credential: access that outlives the session, the password and the
 * owner's suspicion. So once an account has a method, adding, replacing or
 * removing one needs something only the owner has, and recently: the
 * password, a current factor, or a sign-in in the last few minutes.
 *
 * The proof is kept in the session it was given in, so it covers that
 * browser and no other session on the account. An account with no method yet
 * needs only the session, or nobody could set up their first one, and an
 * administrator acting on someone else's account is governed by edit_user as
 * before.
 */
final class Step_Up {

	public const WINDOW = 10 * MINUTE_IN_SECONDS;

	private const SESSION_KEY = 'sigil_step_up';

	/**
	 * Proof given during this request, for requests with no session to keep
	 * it in, such as a REST call made with an application password. Keyed by
	 * account and session, so switching sessions mid-request counts for
	 * nothing.
	 *
	 * @var array<string, true>
	 */
	private static array $proven = array();

	/**
	 * Whether a change to this account's methods by the current user needs
	 * fresh proof at all.
	 */
	public static function required( int $user_id ): bool {
		$current = (int) get_current_user_id();
		if ( $user_id <= 0 || $current !== $user_id ) {
			return false;
		}

		// Stored, not merely usable: under zero-setup every account counts as
		// having email, and the first method a person chooses is still their
		// first.
		return Store::has_any( $user_id ) && Providers::instance()->has_usable( $user_id );
	}

	public static function satisfied( int $user_id ): bool {
		if ( isset( self::$proven[ self::request_key( $user_id ) ] ) ) {
			return true;
		}

		$session = self::session( $user_id );
		if ( null === $session ) {
			return false;
		}

		$at = max( (int) ( $session['login'] ?? 0 ), (int) ( $session[ self::SESSION_KEY ] ?? 0 ) );

		return $at > 0 && time() - $at <= self::WINDOW;
	}

	public static function allows( int $user_id ): bool {
		return ! self::required( $user_id ) || self::satisfied( $user_id );
	}

	/**
	 * Note fresh proof for the current session.
	 *
	 * Also used straight after someone enrols their first method, which needed
	 * no proof: whoever could do that could have set up the next one as part of
	 * it, so asking now would only get in the way of finishing setup.
	 */
	public static function record( int $user_id ): void {
		self::$proven[ self::request_key( $user_id ) ] = true;

		$token = wp_get_session_token();
		if ( '' === $token ) {
			return;
		}

		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$session = $manager->get( $token );
		if ( ! is_array( $session ) ) {
			return;
		}

		$session[ self::SESSION_KEY ] = time();
		$manager->update( $token, $session );
	}

	/**
	 * Check a proof and, when it holds, record it.
	 *
	 * Takes the account password (`password`), a code from the authenticator
	 * app (`code`), or a passkey assertion (`passkey_assertion`, the JSON the
	 * challenge screen posts). Guesses are limited per account, in an
	 * allowance of their own so a mistyped confirmation never costs a sign-in.
	 *
	 * @param array<string, mixed> $input
	 * @return true|\WP_Error
	 */
	public static function prove( int $user_id, array $input ) {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User || (int) get_current_user_id() !== $user_id ) {
			return self::failed();
		}

		$key = 'su:' . $user_id;
		if ( Rate_Limit::reserve( $key ) > Rate_Limit::max_attempts() ) {
			return new \WP_Error(
				'sigil_rate_limited',
				__( 'Too many failed attempts. Please wait before trying again.', 'sigil-2fa' ),
				array( 'status' => 429 )
			);
		}

		if ( ! self::check( $user, $input ) ) {
			return self::failed();
		}

		Rate_Limit::clear( $key );
		self::record( $user_id );

		return true;
	}

	public static function error(): \WP_Error {
		return new \WP_Error(
			'sigil_step_up_required',
			__( 'Confirm it is you before changing your sign-in methods.', 'sigil-2fa' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * The current factors that can confirm, for the confirm form to offer.
	 *
	 * @return list<Provider>
	 */
	public static function factors( int $user_id ): array {
		return array_values(
			array_filter(
				Providers::instance()->enrolled_for( $user_id ),
				static function ( Provider $provider ): bool {
					return in_array( $provider->id(), array( 'totp', 'passkey' ), true );
				}
			)
		);
	}

	/**
	 * @param array<string, mixed> $input
	 */
	private static function check( \WP_User $user, array $input ): bool {
		$password = isset( $input['password'] ) && is_string( $input['password'] ) ? $input['password'] : '';
		if ( '' !== $password ) {
			return wp_check_password( $password, $user->user_pass, (int) $user->ID );
		}

		foreach ( self::factors( (int) $user->ID ) as $provider ) {
			if ( 'totp' === $provider->id() && isset( $input['code'] ) && is_string( $input['code'] ) && '' !== $input['code'] ) {
				return $provider->validate( (int) $user->ID, array( 'code' => $input['code'] ) );
			}
			if ( 'passkey' === $provider->id() && isset( $input['passkey_assertion'] ) && is_string( $input['passkey_assertion'] ) && '' !== $input['passkey_assertion'] ) {
				return $provider->validate( (int) $user->ID, array( 'passkey_assertion' => $input['passkey_assertion'] ) );
			}
		}

		return false;
	}

	private static function failed(): \WP_Error {
		return new \WP_Error(
			'sigil_step_up_failed',
			__( 'That did not confirm it is you. Please try again.', 'sigil-2fa' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * @return array<string, mixed>|null
	 */
	private static function session( int $user_id ): ?array {
		$token = wp_get_session_token();
		if ( '' === $token ) {
			return null;
		}

		$session = \WP_Session_Tokens::get_instance( $user_id )->get( $token );

		return is_array( $session ) ? $session : null;
	}

	private static function request_key( int $user_id ): string {
		return $user_id . ':' . hash( 'sha256', wp_get_session_token() );
	}
}
