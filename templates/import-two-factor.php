<?php
/**
 * Import from Two Factor, shown at the foot of the settings screen.
 *
 * @var array<string, mixed>|null $report
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

// Function-scoped variables; see templates/settings.php.
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$report  = isset( $report ) && is_array( $report ) ? $report : null;
$counts  = is_array( $report['counts'] ?? null ) ? $report['counts'] : array();
$dry_run = ! empty( $report['dry_run'] );
$rows    = array();

if ( null !== $report && is_array( $report['users'] ?? null ) ) {
	foreach ( $report['users'] as $row ) {
		if ( is_array( $row ) && ( ! empty( $row['flags'] ) || ! empty( $row['needs_attention'] ) ) ) {
			$rows[] = $row;
		}
	}
}
?>
<h2 id="sigil-import-two-factor"><?php echo esc_html__( 'Import from Two Factor', 'sigil-2fa' ); ?></h2>
<p style="max-width:720px;">
	<?php echo esc_html__( 'Copies each user\'s email codes, authenticator app and backup codes from the Two Factor plugin into Sigil. Two Factor\'s own data is left untouched. Users with a method that cannot be carried over are listed below, and Two Factor keeps protecting them while it is active. Running it again skips anything already in Sigil.', 'sigil-2fa' ); ?>
</p>
<p style="max-width:720px;">
	<?php echo esc_html__( 'Once the import looks right, deactivate Two Factor. Until then Sigil asks the users it covers and Two Factor asks everyone else, so nobody is asked twice.', 'sigil-2fa' ); ?>
</p>

<?php if ( null !== $report ) : ?>
	<div class="notice <?php echo esc_attr( $dry_run ? 'notice-info' : 'notice-success' ); ?> inline" style="max-width:720px;">
		<p><strong>
			<?php echo esc_html( $dry_run ? __( 'Preview: nothing was changed.', 'sigil-2fa' ) : __( 'Import finished.', 'sigil-2fa' ) ); ?>
		</strong></p>
		<ul style="list-style:disc;margin-left:20px;">
			<?php
			$lines = array(
				/* translators: %d: number of users */
				'users'          => __( 'Users with Two Factor data: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'not_using'      => __( 'Not using Two Factor (skipped): %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'email'          => __( 'Email codes set up: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'totp'           => __( 'Authenticator apps imported: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'backup'         => __( 'Backup code sets imported: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'already'        => __( 'Users with a method already in Sigil: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'attention'      => __( 'Need attention, still protected by Two Factor: %d', 'sigil-2fa' ),
			);
			foreach ( $lines as $key => $format ) :
				?>
				<li><?php echo esc_html( sprintf( $format, (int) ( $counts[ $key ] ?? 0 ) ) ); ?></li>
			<?php endforeach; ?>
		</ul>
	</div>

	<?php if ( array() !== $rows ) : ?>
		<table class="widefat striped" style="max-width:960px;margin-top:12px;">
			<thead>
				<tr>
					<th><?php echo esc_html__( 'User', 'sigil-2fa' ); ?></th>
					<th><?php echo esc_html__( 'Methods', 'sigil-2fa' ); ?></th>
					<th><?php echo esc_html__( 'Needs attention', 'sigil-2fa' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $rows as $row ) : ?>
					<tr>
						<td><?php echo esc_html( sprintf( '%s (#%d)', (string) ( $row['login'] ?? '' ), (int) ( $row['user_id'] ?? 0 ) ) ); ?></td>
						<td><?php echo esc_html( implode( ', ', array_merge( (array) ( $row['imported'] ?? array() ), (array) ( $row['already'] ?? array() ) ) ) ); ?></td>
						<td>
							<?php
							$notes = array();
							if ( ! empty( $row['needs_attention'] ) ) {
								$notes[] = __( 'Ask this user to set up a method in Sigil before Two Factor is deactivated', 'sigil-2fa' );
							}
							foreach ( (array) ( $row['flags'] ?? array() ) as $flag ) {
								$notes[] = \Sigil\Two_Factor_Import::flag_label( (string) $flag );
							}
							echo esc_html( implode( '; ', $notes ) );
							?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
<?php endif; ?>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:12px;">
	<input type="hidden" name="action" value="<?php echo esc_attr( \Sigil\Two_Factor_Migration::action() ); ?>" />
	<?php wp_nonce_field( \Sigil\Two_Factor_Migration::action() ); ?>
	<?php submit_button( __( 'Preview import', 'sigil-2fa' ), 'secondary', 'sigil_import_preview', false ); ?>
	<?php submit_button( __( 'Import now', 'sigil-2fa' ), 'primary', 'sigil_import_run', false ); ?>
</form>
