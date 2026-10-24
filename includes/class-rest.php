<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * REST surface for reading 2FA state, managing methods, editing the policy, and
 * completing a pending challenge from a decoupled front end.
 *
 * What this does not do: add a second factor to token-based authentication.
 * A request that authenticates with an application password never reaches the
 * interactive login, so it is not challenged here or anywhere else. Disable
 * application passwords for a role if that matters.
 */
final class REST {

	public const NAMESPACE_V1 = 'sigil/v1';

	private static ?REST $instance = null;

	public static function instance(): REST {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE_V1,
			'/me',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_me' ),
				'permission_callback' => static function () {
					return is_user_logged_in();
				},
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/users/(?P<id>\d+)',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_user' ),
				'permission_callback' => array( $this, 'can_read_user' ),
				'args'                => array(
					'id' => array(
						'type'     => 'integer',
						'required' => true,
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/users/(?P<id>\d+)/methods',
			array(
				'methods'             => \WP_REST_Server::DELETABLE,
				'callback'            => array( $this, 'reset_user' ),
				'permission_callback' => array( $this, 'can_edit_user' ),
				'args'                => array(
					'id' => array(
						'type'     => 'integer',
						'required' => true,
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/users/(?P<id>\d+)/methods/(?P<provider>[a-z0-9_-]+)',
			array(
				'methods'             => \WP_REST_Server::DELETABLE,
				'callback'            => array( $this, 'remove_method' ),
				'permission_callback' => array( $this, 'can_manage_own_or_edit_user' ),
				'args'                => array(
					'id'       => array(
						'type'     => 'integer',
						'required' => true,
					),
					'provider' => array(
						'type'     => 'string',
						'required' => true,
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/policy',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_policy' ),
					'permission_callback' => array( $this, 'can_manage' ),
				),
				array(
					'methods'             => \WP_REST_Server::EDITABLE,
					'callback'            => array( $this, 'update_policy' ),
					'permission_callback' => array( $this, 'can_manage' ),
				),
			)
		);

		// The challenge token is the credential here, exactly as it is on the
		// login form. There is no session to authenticate against: the password
		// step has run and the auth cookie has been cleared.
		register_rest_route(
			self::NAMESPACE_V1,
			'/challenge',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_challenge' ),
					'permission_callback' => '__return_true',
					'args'                => array(
						'token' => array(
							'type'     => 'string',
							'required' => true,
						),
					),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'complete_challenge' ),
					'permission_callback' => '__return_true',
					'args'                => array(
						'token'    => array(
							'type'     => 'string',
							'required' => true,
						),
						'provider' => array(
							'type'     => 'string',
							'required' => true,
						),
					),
				),
			)
		);
	}

	public function can_manage(): bool {
		return current_user_can( Network::manage_capability() );
	}

	public function can_read_user( \WP_REST_Request $request ): bool {
		$id = (int) $request['id'];

		if ( ! is_user_logged_in() ) {
			return false;
		}

		if ( get_current_user_id() === $id ) {
			return true;
		}

		if ( ! current_user_can( 'list_users' ) ) {
			return false;
		}

		// list_users is a site capability but accounts are network-wide, so
		// without this a site administrator could walk the whole network and
		// learn which accounts, including ones with no membership here, are
		// missing a second factor.
		if ( Network::is_network()
			&& ! current_user_can( 'manage_network_users' )
			&& ! is_user_member_of_blog( $id, get_current_blog_id() ) ) {
			return false;
		}

		return true;
	}

	public function can_edit_user( \WP_REST_Request $request ): bool {
		$id = (int) $request['id'];

		return is_user_logged_in()
			&& current_user_can( 'edit_users' )
			&& current_user_can( 'edit_user', $id );
	}

	/**
	 * Removing a single method is something a user may do to their own account,
	 * or an administrator to someone else's.
	 */
	public function can_manage_own_or_edit_user( \WP_REST_Request $request ): bool {
		$id = (int) $request['id'];

		if ( ! is_user_logged_in() ) {
			return false;
		}

		return get_current_user_id() === $id || $this->can_edit_user( $request );
	}

	/**
	 * @return \WP_REST_Response
	 */
	public function get_me() {
		return rest_ensure_response( $this->status_for( get_current_user_id() ) );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function get_user( \WP_REST_Request $request ) {
		$id = (int) $request['id'];
		if ( ! get_userdata( $id ) ) {
			return new \WP_Error( 'sigil_no_user', __( 'User not found.', 'sigil-2fa' ), array( 'status' => 404 ) );
		}

		return rest_ensure_response( $this->status_for( $id ) );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function reset_user( \WP_REST_Request $request ) {
		$id     = (int) $request['id'];
		$result = Recovery::reset_user( $id, get_current_user_id() );

		if ( is_wp_error( $result ) ) {
			return $this->as_rest_error( $result, 403 );
		}

		return rest_ensure_response( $this->status_for( $id ) );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function remove_method( \WP_REST_Request $request ) {
		$id     = (int) $request['id'];
		$result = Enrolment::instance()->remove_method( $id, (string) $request['provider'] );

		if ( is_wp_error( $result ) ) {
			$status = 'sigil_forbidden' === $result->get_error_code() ? 403 : 400;
			return $this->as_rest_error( $result, $status );
		}

		return rest_ensure_response( $this->status_for( $id ) );
	}

	/**
	 * @return \WP_REST_Response
	 */
	public function get_policy() {
		return rest_ensure_response( Policy::get() );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function update_policy( \WP_REST_Request $request ) {
		$body  = $request->get_json_params();
		$body  = is_array( $body ) ? $body : $request->get_body_params();
		$patch = array();

		if ( isset( $body['enabled'] ) ) {
			$patch['enabled'] = (bool) $body['enabled'];
		}
		if ( isset( $body['grace_days'] ) ) {
			$patch['grace_days'] = max( 0, (int) $body['grace_days'] );
		}
		if ( isset( $body['min_capability'] ) && is_string( $body['min_capability'] ) ) {
			$patch['min_capability'] = sanitize_key( $body['min_capability'] );
		}
		foreach ( array( 'roles', 'block_app_passwords' ) as $map ) {
			if ( isset( $body[ $map ] ) && is_array( $body[ $map ] ) ) {
				$clean = array();
				foreach ( $body[ $map ] as $role => $on ) {
					$role = sanitize_key( (string) $role );
					if ( '' !== $role ) {
						$clean[ $role ] = (bool) $on;
					}
				}
				$patch[ $map ] = $clean;
			}
		}

		if ( Policy::would_lock_out( get_current_user_id(), $patch ) ) {
			return new \WP_Error( 'sigil_lockout', Policy::lockout_message(), array( 'status' => 409 ) );
		}

		Policy::update( $patch );

		return rest_ensure_response( Policy::get() );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function get_challenge( \WP_REST_Request $request ) {
		$token = (string) $request['token'];
		$user  = Challenge::user_for( $token );
		if ( null === $user ) {
			return new \WP_Error(
				'sigil_invalid_token',
				__( 'This verification session has expired. Please log in again.', 'sigil-2fa' ),
				array( 'status' => 401 )
			);
		}

		$enrolled = Providers::instance()->enrolled_for( $user->ID );
		$active   = Providers::instance()->preferred_for( $user->ID );
		if ( null === $active && array() !== $enrolled ) {
			$active = $enrolled[0];
		}

		$methods = array();
		foreach ( $enrolled as $provider ) {
			$methods[] = array(
				'id'    => $provider->id(),
				'label' => $provider->label(),
			);
		}

		// Minting assertion options is not free: each one occupies a slot in the
		// user's small set of open challenges, so describing the login three
		// times would evict the challenge a waiting tab is holding. Only mint
		// when passkey is the method in play.
		$wants_passkey = 'passkey' === sanitize_key( (string) $request->get_param( 'provider' ) )
			|| ( $active && 'passkey' === $active->id() );

		return rest_ensure_response(
			array(
				'user_id'         => (int) $user->ID,
				'user_login'      => $user->user_login,
				'methods'         => $methods,
				'active'          => $active ? $active->id() : null,
				'passkey_options' => $wants_passkey ? $this->passkey_options( (int) $user->ID ) : null,
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function complete_challenge( \WP_REST_Request $request ) {
		$token = (string) $request['token'];
		$user  = Challenge::user_for( $token );
		if ( null === $user ) {
			return new \WP_Error(
				'sigil_invalid_token',
				__( 'This verification session has expired. Please log in again.', 'sigil-2fa' ),
				array( 'status' => 401 )
			);
		}

		$context = Challenge::context_for( $token );

		$input = $request->get_json_params();
		$input = is_array( $input ) ? $input : $request->get_body_params();
		$input = is_array( $input ) ? $input : array();

		$result = Challenge::complete( $token, (string) $request['provider'], $input );
		if ( is_wp_error( $result ) ) {
			$status = 'sigil_rate_limited' === $result->get_error_code() ? 429 : 401;
			$next   = Challenge::next_token( $result, '' );

			// One guess per token, so a client that wants another attempt needs
			// the replacement rather than the token it just spent.
			return new \WP_Error(
				$result->get_error_code(),
				$result->get_error_message(),
				array(
					'status' => $status,
					'token'  => '' !== $next ? $next : null,
				)
			);
		}

		$remember = $context ? $context['remember'] : false;
		wp_set_auth_cookie( (int) $user->ID, $remember );
		wp_set_current_user( (int) $user->ID );

		/** This action is documented in includes/class-challenge.php */
		do_action( 'sigil_challenge_passed', (int) $user->ID, sanitize_key( (string) $request['provider'] ) );

		return rest_ensure_response(
			array(
				'success'     => true,
				'user_id'     => (int) $user->ID,
				'redirect_to' => $context && '' !== $context['redirect_to'] ? $context['redirect_to'] : admin_url(),
			)
		);
	}

	/**
	 * @return array<string, mixed>|null
	 */
	private function passkey_options( int $user_id ): ?array {
		$provider = Providers::instance()->get( 'passkey' );
		if ( ! $provider instanceof Providers\Passkey || ! $provider->is_enrolled( $user_id ) ) {
			return null;
		}

		$options = $provider->auth_options( $user_id );
		if ( null === $options ) {
			return null;
		}

		$encoded = wp_json_encode( $options );
		$decoded = is_string( $encoded ) ? json_decode( $encoded, true ) : null;

		return is_array( $decoded ) ? $decoded : null;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function status_for( int $user_id ): array {
		$stored  = Store::methods( $user_id );
		$methods = array();

		foreach ( Providers::instance()->enrolled_for( $user_id ) as $provider ) {
			$data      = $stored[ $provider->id() ] ?? array();
			$methods[] = array(
				'id'          => $provider->id(),
				'label'       => $provider->label(),
				'enrolled_at' => isset( $data['enrolled_at'] ) ? (int) $data['enrolled_at'] : null,
			);
		}

		$available = array();
		foreach ( Providers::instance()->all( $user_id ) as $provider ) {
			$available[] = array(
				'id'    => $provider->id(),
				'label' => $provider->label(),
			);
		}

		return array(
			'user_id'   => $user_id,
			'enrolled'  => array() !== $methods,
			'methods'   => $methods,
			'available' => $available,
			'required'  => Policy::required_for( $user_id ),
			'deadline'  => Policy::deadline_for( $user_id ),
		);
	}

	private function as_rest_error( \WP_Error $error, int $status ): \WP_Error {
		return new \WP_Error(
			$error->get_error_code(),
			$error->get_error_message(),
			array( 'status' => $status )
		);
	}
}
