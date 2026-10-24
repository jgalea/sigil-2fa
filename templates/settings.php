<?php
/**
 * Settings page template. Variables: $policy, $roles, $updated.
 *
 * @var array  $policy
 * @var array  $roles
 * @var bool   $updated
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

// This template is require()d from inside a method, so the variables below are
// function-scoped, not globals. The PrefixAllGlobals sniff cannot see the
// including scope and reports them as unprefixed globals.
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! isset( $policy ) || ! is_array( $policy ) ) {
	$policy = \Sigil\Policy::get();
}
if ( ! isset( $roles ) || ! is_array( $roles ) ) {
	$roles = array();
}
$updated = ! empty( $updated );
?>
<div class="wrap">
	<h1><?php echo esc_html__( 'Sigil', 'sigil-2fa' ); ?></h1>

	<?php if ( $updated ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php echo esc_html__( 'Settings saved.', 'sigil-2fa' ); ?></p></div>
	<?php endif; ?>

	<?php if ( \Sigil\Network::is_network() ) : ?>
		<div class="notice notice-info" style="padding:12px 16px;max-width:720px;">
			<p style="margin:0;">
				<?php
				echo esc_html__(
					'This policy applies to every site on the network. Accounts are network-wide, so a passkey or authenticator enrolled on one site works on all of them, and only Network Admins can reset another account.',
					'sigil-2fa'
				);
				?>
			</p>
		</div>
	<?php endif; ?>

	<div class="notice notice-info" style="padding:12px 16px;max-width:720px;">
		<p style="margin:0 0 8px;">
			<strong><?php echo esc_html__( 'What 2FA protects', 'sigil-2fa' ); ?></strong>
		</p>
		<p style="margin:0;">
			<?php
			echo esc_html__(
				'Sigil protects interactive logins (the normal WordPress login form and the challenge that follows). It does not apply to application passwords. REST API and XML-RPC requests authenticated with an application password bypass two-factor authentication entirely. If a role should not use that hole, disable application passwords for that role below.',
				'sigil-2fa'
			);
			?>
		</p>
	</div>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<input type="hidden" name="action" value="sigil_save_settings" />
		<?php wp_nonce_field( 'sigil_save_settings' ); ?>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php echo esc_html__( 'Enforcement', 'sigil-2fa' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="sigil_policy[enabled]" value="1" <?php checked( ! empty( $policy['enabled'] ) ); ?> />
						<?php echo esc_html__( 'Require two-factor authentication for selected roles', 'sigil-2fa' ); ?>
					</label>
				</td>
			</tr>

			<tr>
				<th scope="row"><?php echo esc_html__( 'Roles that must enrol', 'sigil-2fa' ); ?></th>
				<td>
					<?php if ( array() === $roles ) : ?>
						<p class="description"><?php echo esc_html__( 'No roles found.', 'sigil-2fa' ); ?></p>
					<?php else : ?>
						<fieldset>
							<?php foreach ( $roles as $role_slug => $role_obj ) : ?>
								<?php
								$role_slug  = (string) $role_slug;
								$role_label = is_array( $role_obj ) && isset( $role_obj['name'] ) ? translate_user_role( $role_obj['name'] ) : $role_slug;
								$checked    = ! empty( $policy['roles'][ $role_slug ] );
								?>
								<label style="display:block;margin-bottom:4px;">
									<input type="checkbox" name="sigil_policy[roles][<?php echo esc_attr( $role_slug ); ?>]" value="1" <?php checked( $checked ); ?> />
									<?php echo esc_html( $role_label ); ?>
								</label>
							<?php endforeach; ?>
						</fieldset>
					<?php endif; ?>
				</td>
			</tr>

			<tr>
				<th scope="row">
					<label for="sigil-min-capability"><?php echo esc_html__( 'Minimum capability', 'sigil-2fa' ); ?></label>
				</th>
				<td>
					<input type="text" class="regular-text" id="sigil-min-capability" name="sigil_policy[min_capability]" value="<?php echo esc_attr( (string) $policy['min_capability'] ); ?>" />
					<p class="description">
						<?php echo esc_html__( 'Optional. Any user with this capability is covered regardless of role. Roles and capability are combined with OR.', 'sigil-2fa' ); ?>
					</p>
				</td>
			</tr>

			<tr>
				<th scope="row">
					<label for="sigil-grace-days"><?php echo esc_html__( 'Grace period (days)', 'sigil-2fa' ); ?></label>
				</th>
				<td>
					<input type="number" min="0" step="1" id="sigil-grace-days" name="sigil_policy[grace_days]" value="<?php echo esc_attr( (string) (int) $policy['grace_days'] ); ?>" class="small-text" />
					<p class="description">
						<?php echo esc_html__( 'Days after first coverage before enrolment is forced. Zero means enrol on next login.', 'sigil-2fa' ); ?>
					</p>
				</td>
			</tr>

			<tr>
				<th scope="row"><?php echo esc_html__( 'Passwordless sign-in', 'sigil-2fa' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="sigil_policy[passwordless]" value="1" <?php checked( ! empty( $policy['passwordless'] ) ); ?> />
						<?php echo esc_html__( 'Let anyone with a passkey sign in with it alone, without a password', 'sigil-2fa' ); ?>
					</label>
					<p class="description">
						<?php echo esc_html__( 'The passkey must verify the person with a PIN or biometric, so it counts as two-factor authentication on its own. Needs PHP 8.0 or later.', 'sigil-2fa' ); ?>
					</p>
				</td>
			</tr>

			<tr>
				<th scope="row"><?php echo esc_html__( 'Disable application passwords', 'sigil-2fa' ); ?></th>
				<td>
					<?php if ( array() === $roles ) : ?>
						<p class="description"><?php echo esc_html__( 'No roles found.', 'sigil-2fa' ); ?></p>
					<?php else : ?>
						<fieldset>
							<?php foreach ( $roles as $role_slug => $role_obj ) : ?>
								<?php
								$role_slug  = (string) $role_slug;
								$role_label = is_array( $role_obj ) && isset( $role_obj['name'] ) ? translate_user_role( $role_obj['name'] ) : $role_slug;
								$checked    = ! empty( $policy['block_app_passwords'][ $role_slug ] );
								?>
								<label style="display:block;margin-bottom:4px;">
									<input type="checkbox" name="sigil_policy[block_app_passwords][<?php echo esc_attr( $role_slug ); ?>]" value="1" <?php checked( $checked ); ?> />
									<?php echo esc_html( $role_label ); ?>
								</label>
							<?php endforeach; ?>
						</fieldset>
						<p class="description">
							<?php echo esc_html__( 'Blocks creating and using application passwords for the selected roles. Use this when interactive 2FA alone is not enough for that role.', 'sigil-2fa' ); ?>
						</p>
					<?php endif; ?>
				</td>
			</tr>
		</table>

		<?php submit_button( __( 'Save settings', 'sigil-2fa' ) ); ?>
	</form>

	<?php
	/**
	 * Fires at the end of the Sigil settings screen. Extension point for
	 * add-ons (Pro license entry, trusted-device controls).
	 */
	do_action( 'sigil_settings_after' );
	?>
</div>
