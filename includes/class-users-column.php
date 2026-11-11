<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

final class Users_Column {

	private static ?Users_Column $instance = null;

	public static function instance(): Users_Column {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'manage_users_columns', array( $this, 'add_column' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'render_column' ), 10, 3 );
		add_filter( 'user_row_actions', array( $this, 'row_actions' ), 10, 2 );
		add_action( 'admin_post_sigil_unlock', array( $this, 'handle_unlock' ) );
		add_action( 'admin_notices', array( $this, 'unlock_notice' ) );
		add_filter( 'views_users', array( $this, 'add_views' ) );
		add_action( 'pre_get_users', array( $this, 'filter_users' ) );
	}

	/**
	 * @param array<string, string> $columns
	 * @return array<string, string>
	 */
	public function add_column( array $columns ): array {
		$columns['sigil'] = __( '2FA', 'sigil-2fa' );
		return $columns;
	}

	/**
	 * @param string $output      Custom column output.
	 * @param string $column_name Column name.
	 * @param int    $user_id     User ID.
	 */
	public function render_column( $output, $column_name, $user_id ): string {
		if ( 'sigil' !== $column_name ) {
			return (string) $output;
		}

		$user_id = (int) $user_id;
		$text    = $this->status_text( $user_id );

		$user = get_userdata( $user_id );
		$wait = $user instanceof \WP_User ? Password_Limit::locked_for( $user ) : 0;
		if ( $wait > 0 ) {
			$text .= ' <strong>' . esc_html(
				sprintf(
					/* translators: %s: time left, e.g. "12 minutes" */
					__( 'Locked, %s left', 'sigil-2fa' ),
					human_time_diff( time(), time() + $wait )
				)
			) . '</strong>';
		}

		return $text;
	}

	private function status_text( int $user_id ): string {
		$enrolled = Providers::instance()->enrolled_for( $user_id );

		if ( [] !== $enrolled ) {
			$labels = array();
			foreach ( $enrolled as $provider ) {
				$labels[] = $provider->label();
			}
			return esc_html( implode( ', ', $labels ) );
		}

		if ( ! Policy::required_for( $user_id ) ) {
			return esc_html__( 'Not set up', 'sigil-2fa' );
		}

		$deadline = Policy::recorded_deadline( $user_id );
		if ( null === $deadline ) {
			return esc_html__( 'Not set up', 'sigil-2fa' );
		}

		$formatted = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $deadline );
		if ( ! is_string( $formatted ) || '' === $formatted ) {
			$formatted = (string) $deadline;
		}

		return esc_html(
			sprintf(
				/* translators: %s: local deadline date/time */
				__( 'Not set up (due %s)', 'sigil-2fa' ),
				$formatted
			)
		);
	}

	/**
	 * @param array<string, string> $actions
	 * @return array<string, string>
	 */
	public function row_actions( array $actions, \WP_User $user ): array {
		if ( ! current_user_can( 'edit_user', $user->ID ) || Password_Limit::locked_for( $user ) <= 0 ) {
			return $actions;
		}

		$url = wp_nonce_url(
			add_query_arg(
				array(
					'action'  => 'sigil_unlock',
					'user_id' => (int) $user->ID,
				),
				admin_url( 'admin-post.php' )
			),
			'sigil_unlock_' . (int) $user->ID
		);

		$actions['sigil_unlock'] = '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Unlock sign-in', 'sigil-2fa' ) . '</a>';

		return $actions;
	}

	public function handle_unlock(): void {
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		check_admin_referer( 'sigil_unlock_' . $user_id );

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User || ! current_user_can( 'edit_user', $user_id ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'sigil-2fa' ), '', array( 'response' => 403 ) );
		}

		Password_Limit::unlock( $user, '', true );

		wp_safe_redirect( add_query_arg( 'sigil_unlocked', $user_id, admin_url( 'users.php' ) ) );
		exit;
	}

	public function unlock_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag set by our own redirect.
		$user = isset( $_GET['sigil_unlocked'] ) ? get_userdata( absint( $_GET['sigil_unlocked'] ) ) : false;
		if ( ! $user instanceof \WP_User || ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}

		echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(
			sprintf(
				/* translators: %s: username */
				__( 'Sign-in reopened for %s.', 'sigil-2fa' ),
				$user->user_login
			)
		) . '</p></div>';
	}

	/**
	 * @param array<string, string> $views
	 * @return array<string, string>
	 */
	public function add_views( array $views ): array {
		$current = $this->requested_filter();
		$base    = admin_url( 'users.php' );
		$labels  = array(
			'set_up'     => __( '2FA set up', 'sigil-2fa' ),
			'not_set_up' => __( '2FA not set up', 'sigil-2fa' ),
			'overdue'    => __( '2FA overdue', 'sigil-2fa' ),
		);

		foreach ( $labels as $key => $label ) {
			$query = new \WP_User_Query(
				array_merge( $this->query_for( $key ), array( 'fields' => 'ID', 'number' => 1, 'count_total' => true, 'sigil_counting' => true ) )
			);

			$views[ 'sigil_' . $key ] = sprintf(
				'<a href="%s"%s>%s <span class="count">(%s)</span></a>',
				esc_url( add_query_arg( 'sigil_2fa', $key, $base ) ),
				$current === $key ? ' class="current" aria-current="page"' : '',
				esc_html( $label ),
				esc_html( number_format_i18n( $query->get_total() ) )
			);
		}

		return $views;
	}

	public function filter_users( \WP_User_Query $query ): void {
		$filter = $this->requested_filter();
		if ( '' === $filter || $query->get( 'sigil_counting' ) || ! is_admin() || ! current_user_can( 'list_users' ) ) {
			return;
		}

		$existing = $query->get( 'meta_query' );
		$query->set( 'meta_query', array_merge( is_array( $existing ) ? $existing : array(), $this->query_for( $filter )['meta_query'] ) );
	}

	private function requested_filter(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only list filter.
		$filter = isset( $_GET['sigil_2fa'] ) ? sanitize_key( wp_unslash( (string) $_GET['sigil_2fa'] ) ) : '';

		return in_array( $filter, array( 'set_up', 'not_set_up', 'overdue' ), true ) ? $filter : '';
	}

	/**
	 * Enrolment is the method list on the user's meta, and a deadline only
	 * exists for accounts the policy has covered, so each view is one meta query.
	 *
	 * @return array{meta_query: list<array<string, mixed>>}
	 */
	private function query_for( string $filter ): array {
		$has_methods = array(
			'key'     => Store::META_KEY,
			'compare' => 'EXISTS',
		);
		$no_methods  = array(
			'key'     => Store::META_KEY,
			'compare' => 'NOT EXISTS',
		);

		if ( 'set_up' === $filter ) {
			return array( 'meta_query' => array( $has_methods ) );
		}

		if ( 'not_set_up' === $filter ) {
			return array( 'meta_query' => array( $no_methods ) );
		}

		return array(
			'meta_query' => array(
				$no_methods,
				array(
					'key'     => Policy::DEADLINE_META,
					'value'   => time(),
					'compare' => '<',
					'type'    => 'NUMERIC',
				),
			),
		);
	}
}
