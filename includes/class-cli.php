<?php

declare( strict_types=1 );

namespace Sigil;

defined( 'ABSPATH' ) || exit;

/**
 * WP-CLI commands under `wp sigil`.
 *
 * Registered only when WP-CLI is present. reset skips capability checks because
 * shell access already implies full control of the site.
 */
final class CLI {

	private static ?CLI $instance = null;

	public static function instance(): CLI {
		if ( null === self::$instance ) {
			self::$instance = new self();
			if ( defined( 'WP_CLI' ) && WP_CLI ) {
				// Pass the instance: WP-CLI cannot construct a private-constructor class.
				\WP_CLI::add_command( 'sigil', self::$instance );
			}
		}
		return self::$instance;
	}

	private function __construct() {
	}

	/**
	 * Reset a user's two-factor authentication methods.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login, or email.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sigil reset 12
	 *     wp sigil reset admin
	 *
	 * @param list<string>             $args
	 * @param array<string, string|bool> $assoc_args
	 */
	public function reset( array $args, array $assoc_args = [] ): void {
		$user = $this->resolve_user( $args[0] ?? '' );
		if ( null === $user ) {
			\WP_CLI::error( 'User not found.' );
		}

		$result = Recovery::reset_as_system( (int) $user->ID );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}

		\WP_CLI::success(
			sprintf(
				'Two-factor authentication reset for user %s (ID %d).',
				$user->user_login,
				(int) $user->ID
			)
		);
	}

	/**
	 * Show 2FA enrolment status for one user, or list all users when omitted.
	 *
	 * ## OPTIONS
	 *
	 * [<user>]
	 * : Optional user ID, login, or email.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sigil status
	 *     wp sigil status admin
	 *
	 * @param list<string>               $args
	 * @param array<string, string|bool> $assoc_args
	 */
	public function status( array $args, array $assoc_args = [] ): void {
		if ( empty( $args[0] ) ) {
			$this->list( [], $assoc_args );
			return;
		}

		$user = $this->resolve_user( $args[0] );
		if ( null === $user ) {
			\WP_CLI::error( 'User not found.' );
		}

		$methods = $this->method_labels( (int) $user->ID );
		\WP_CLI::log(
			sprintf(
				'User: %s (ID %d)',
				$user->user_login,
				(int) $user->ID
			)
		);
		\WP_CLI::log(
			'Methods: ' . ( [] === $methods ? '(none)' : implode( ', ', $methods ) )
		);
	}

	/**
	 * List users and their enrolled 2FA methods.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sigil list
	 *
	 * @param list<string>               $args
	 * @param array<string, string|bool> $assoc_args
	 */
	public function list( array $args = [], array $assoc_args = [] ): void {
		$users = get_users(
			[
				'fields'  => [ 'ID', 'user_login', 'user_email' ],
				'orderby' => 'ID',
				'order'   => 'ASC',
			]
		);

		$items = [];
		foreach ( $users as $user ) {
			$methods = $this->method_labels( (int) $user->ID );
			$items[] = [
				'ID'      => (int) $user->ID,
				'login'   => $user->user_login,
				'email'   => $user->user_email,
				'methods' => [] === $methods ? '(none)' : implode( ', ', $methods ),
			];
		}

		if ( [] === $items ) {
			\WP_CLI::log( 'No users found.' );
			return;
		}

		\WP_CLI\Utils\format_items( 'table', $items, [ 'ID', 'login', 'email', 'methods' ] );
	}

	/**
	 * Import users' two-factor methods from another plugin.
	 *
	 * Reads the source plugin's data and never changes or deletes it. Anything
	 * already set up in Sigil is left alone, so it is safe to run again.
	 *
	 * ## OPTIONS
	 *
	 * <source>
	 * : Plugin to import from.
	 * ---
	 * options:
	 *   - two-factor
	 *   - wp-2fa
	 *   - wordfence
	 * ---
	 *
	 * [--dry-run]
	 * : Report what would be imported without writing anything.
	 *
	 * [--user=<user>]
	 * : Only this user (ID, login, or email).
	 *
	 * [--policy]
	 * : wp-2fa only. Also switch Sigil's policy on for the roles WP 2FA enforced.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sigil import two-factor --dry-run
	 *     wp sigil import wp-2fa
	 *     wp sigil import wordfence --user=12
	 *     wp sigil import wp-2fa --policy
	 *
	 * @param list<string>               $args
	 * @param array<string, string|bool> $assoc_args
	 */
	public function import( array $args, array $assoc_args = [] ): void {
		$sources = Import::sources();
		$slug    = $args[0] ?? '';
		if ( ! isset( $sources[ $slug ] ) ) {
			\WP_CLI::error( 'Unknown source. Supported: ' . implode( ', ', array_keys( $sources ) ) );
		}
		$label = $sources[ $slug ]['label'];

		$dry_run = ! empty( $assoc_args['dry-run'] );
		$ids     = null;

		if ( isset( $assoc_args['user'] ) ) {
			$user = $this->resolve_user( (string) $assoc_args['user'] );
			if ( null === $user ) {
				\WP_CLI::error( 'User not found.' );
			}
			$ids = [ (int) $user->ID ];
		}

		$report = Import::run( $sources[ $slug ]['class'], $ids, $dry_run );

		$items = [];
		foreach ( $report['users'] as $row ) {
			$items[] = [
				'ID'        => $row['user_id'],
				'login'     => $row['login'],
				'status'    => $row['status'],
				'imported'  => implode( ',', $row['imported'] ),
				'already'   => implode( ',', $row['already'] ),
				'preferred' => $row['preferred'],
				'flags'     => implode( ',', $row['flags'] ),
			];
		}

		if ( [] !== $items ) {
			\WP_CLI\Utils\format_items( 'table', $items, [ 'ID', 'login', 'status', 'imported', 'already', 'preferred', 'flags' ] );
		}

		$c = $report['counts'];
		\WP_CLI::log(
			sprintf(
				'%sUsers: %d, not using %s: %d, email: %d, authenticator: %d, backup codes: %d, already in Sigil: %d, flagged: %d, needs attention: %d, passkeys: %d',
				$dry_run ? '[dry run] ' : '',
				$c['users'],
				$label,
				$c['not_using'],
				$c['email'],
				$c['totp'],
				$c['backup'],
				$c['already'],
				$c['flagged'],
				$c['attention'],
				$c['passkey']
			)
		);

		if ( 'wp-2fa' === $slug ) {
			$this->import_policy( ! empty( $assoc_args['policy'] ) && ! $dry_run );
		}

		if ( $c['attention'] > 0 ) {
			\WP_CLI::warning( sprintf( 'Some users had a method Sigil could not carry over. %1$s keeps protecting them while it is active, so leave it active until they have set up a method in Sigil.', $label ) );
			return;
		}

		\WP_CLI::success( $dry_run ? 'Dry run complete. Nothing was written.' : sprintf( 'Import complete. %1$s data was left in place; deactivate %1$s once you have checked the result.', $label ) );
	}

	private function import_policy( bool $apply ): void {
		$mapped = WP_2FA_Import::policy();
		if ( null === $mapped['policy'] ) {
			\WP_CLI::log( 'WP 2FA policy: no role is required to use two-factor, nothing to bring across.' );
		} else {
			\WP_CLI::log(
				sprintf(
					'WP 2FA policy: required for %s, %d days to set up. %s',
					implode( ', ', array_keys( $mapped['policy']['roles'] ) ),
					$mapped['policy']['grace_days'],
					$apply ? ( WP_2FA_Import::apply_policy() ? 'Applied to Sigil.' : 'Not applied.' ) : 'Pass --policy to apply it to Sigil.'
				)
			);
		}

		if ( [] !== $mapped['skipped'] ) {
			\WP_CLI::log( 'Not brought across (Sigil\'s policy works by role): ' . implode( ', ', $mapped['skipped'] ) );
		}
	}

	/**
	 * @return list<string>
	 */
	private function method_labels( int $user_id ): array {
		$labels = [];

		foreach ( Providers::instance()->all() as $provider ) {
			if ( $provider->is_enrolled( $user_id ) ) {
				$labels[] = $provider->id();
			}
		}

		// Store methods that may not map to an available provider on this runtime.
		foreach ( array_keys( Store::methods( $user_id ) ) as $id ) {
			if ( ! in_array( $id, $labels, true ) ) {
				$labels[] = $id;
			}
		}

		require_once SIGIL_DIR . 'includes/class-credentials.php';
		if ( [] !== Credentials::for_user( $user_id ) && ! in_array( 'passkey', $labels, true ) ) {
			$labels[] = 'passkey';
		}

		sort( $labels );

		return $labels;
	}

	private function resolve_user( string $ref ): ?\WP_User {
		$ref = trim( $ref );
		if ( '' === $ref ) {
			return null;
		}

		if ( ctype_digit( $ref ) ) {
			$user = get_userdata( (int) $ref );
			if ( $user instanceof \WP_User ) {
				return $user;
			}
		}

		$user = get_user_by( 'login', $ref );
		if ( $user instanceof \WP_User ) {
			return $user;
		}

		$user = get_user_by( 'email', $ref );
		if ( $user instanceof \WP_User ) {
			return $user;
		}

		return null;
	}
}
