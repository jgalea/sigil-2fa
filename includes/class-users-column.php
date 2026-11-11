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

		$user_id  = (int) $user_id;
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
}
