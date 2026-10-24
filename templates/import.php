<?php
/**
 * One import section per source plugin, shown at the foot of the settings screen.
 *
 * @var string                    $slug
 * @var string                    $label
 * @var class-string              $importer
 * @var array<string, mixed>|null $report
 * @var array<string, mixed>|null $policy
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

$what = array(
	'two-factor' => __( 'Copies each user\'s email codes, authenticator app, backup codes and WebAuthn passkeys from the Two Factor plugin into Sigil.', 'sigil-2fa' ),
	'wp-2fa'     => __( 'Copies each user\'s authenticator app, email codes, passkeys and backup codes from WP 2FA into Sigil.', 'sigil-2fa' ),
	'wordfence'  => __( 'Copies each user\'s authenticator app, recovery codes and passkeys from Wordfence Login Security into Sigil.', 'sigil-2fa' ),
);
?>
<h2 id="<?php echo esc_attr( 'sigil-import-' . $slug ); ?>">
	<?php
	/* translators: %s: name of the other two-factor plugin */
	echo esc_html( sprintf( __( 'Import from %s', 'sigil-2fa' ), $label ) );
	?>
</h2>
<p style="max-width:720px;">
	<?php
	echo esc_html( $what[ $slug ] ?? '' ) . ' ';
	/* translators: %s: name of the other two-factor plugin */
	echo esc_html( sprintf( __( '%s\'s own data is left untouched. Users with a method that cannot be carried over are listed below, and it keeps protecting them while it is active. Running it again skips anything already in Sigil.', 'sigil-2fa' ), $label ) );
	?>
</p>
<p style="max-width:720px;">
	<?php
	/* translators: %s: name of the other two-factor plugin */
	echo esc_html( sprintf( __( 'Once the import looks right, deactivate %s. Until then Sigil asks the users it covers and it asks everyone else, so nobody is asked twice.', 'sigil-2fa' ), $label ) );
	?>
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
				'users'     => __( 'Users with data to look at: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'not_using' => __( 'Not using it (skipped): %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'email'     => __( 'Email codes set up: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'totp'      => __( 'Authenticator apps imported: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'passkey'   => __( 'Users with passkeys imported: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'backup'    => __( 'Backup code sets imported: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'already'   => __( 'Users with a method already in Sigil: %d', 'sigil-2fa' ),
				/* translators: %d: number of users */
				'attention' => __( 'Need attention, still protected by the other plugin: %d', 'sigil-2fa' ),
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
								/* translators: %s: name of the other two-factor plugin */
								$notes[] = sprintf( __( 'Ask this user to set up a method in Sigil before %s is deactivated', 'sigil-2fa' ), $label );
							}
							foreach ( (array) ( $row['flags'] ?? array() ) as $flag ) {
								$notes[] = $importer::flag_label( (string) $flag );
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
	<input type="hidden" name="action" value="<?php echo esc_attr( \Sigil\Import_Migration::action() ); ?>" />
	<input type="hidden" name="sigil_import_source" value="<?php echo esc_attr( $slug ); ?>" />
	<?php wp_nonce_field( \Sigil\Import_Migration::nonce_action( $slug ) ); ?>
	<?php submit_button( __( 'Preview import', 'sigil-2fa' ), 'secondary', 'sigil_import_preview', false, array( 'id' => 'sigil-import-preview-' . $slug ) ); ?>
	<?php submit_button( __( 'Import now', 'sigil-2fa' ), 'primary', 'sigil_import_run', false, array( 'id' => 'sigil-import-run-' . $slug ) ); ?>
</form>

<?php if ( is_array( $policy ) ) : ?>
	<h3 id="sigil-import-wp-2fa-policy"><?php echo esc_html__( 'WP 2FA policy', 'sigil-2fa' ); ?></h3>
	<?php if ( is_array( $policy['policy'] ?? null ) ) : ?>
		<p style="max-width:720px;">
			<?php
			echo esc_html(
				sprintf(
					/* translators: 1: comma-separated role names, 2: number of days */
					__( 'WP 2FA requires two-factor for these roles: %1$s, with %2$d days to set it up. Applying it switches Sigil\'s requirement on for the same roles. Nothing changes until you choose to.', 'sigil-2fa' ),
					implode( ', ', array_keys( $policy['policy']['roles'] ) ),
					(int) $policy['policy']['grace_days']
				)
			);
			?>
		</p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="<?php echo esc_attr( \Sigil\Import_Migration::policy_action() ); ?>" />
			<?php wp_nonce_field( \Sigil\Import_Migration::policy_action() ); ?>
			<?php submit_button( __( 'Apply WP 2FA policy to Sigil', 'sigil-2fa' ), 'secondary', 'sigil_import_policy', false ); ?>
		</form>
	<?php else : ?>
		<p style="max-width:720px;"><?php echo esc_html__( 'WP 2FA does not require two-factor for any role, so there is no policy to bring across.', 'sigil-2fa' ); ?></p>
	<?php endif; ?>
	<?php if ( array() !== ( $policy['skipped'] ?? array() ) ) : ?>
		<p style="max-width:720px;"><?php echo esc_html__( 'WP 2FA also enforces or exempts individual users, or only super administrators. Sigil\'s policy works by role, so those settings are not brought across; set them up again in Sigil if you still need them.', 'sigil-2fa' ); ?></p>
	<?php endif; ?>
<?php endif; ?>
