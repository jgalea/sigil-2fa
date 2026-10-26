<?php
/**
 * Enrolment UI. Variables set by Enrolment::render_enrol_ui().
 *
 * @var int                $user_id
 * @var bool               $is_setup_page
 * @var list<\Sigil\Provider> $providers
 * @var array<string, array<string, mixed>> $methods
 * @var array{type: string, code: string, message: string} $notices
 * @var bool               $show_backup
 * @var string             $active
 * @var \Sigil\Provider|null $backup_provider
 * @var bool               $needs_step_up
 * @var bool               $passkey_proof
 * @var bool               $own_account
 * @var int                $trusted_count
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

// This template is require()d from inside a method, so the variables below are
// function-scoped, not globals. The PrefixAllGlobals sniff cannot see the
// including scope and reports them as unprefixed globals.
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$user_id       = isset( $user_id ) ? (int) $user_id : 0;
$is_setup_page = ! empty( $is_setup_page );
$providers     = isset( $providers ) && is_array( $providers ) ? $providers : array();
$methods       = isset( $methods ) && is_array( $methods ) ? $methods : array();
$notices       = isset( $notices ) && is_array( $notices ) ? $notices : array( 'type' => '', 'code' => '', 'message' => '' );
$show_backup   = ! empty( $show_backup );
$active        = isset( $active ) ? (string) $active : '';
$needs_step_up = ! empty( $needs_step_up );
$passkey_proof = ! empty( $passkey_proof );
$own_account   = ! empty( $own_account );
$trusted_count = isset( $trusted_count ) ? (int) $trusted_count : 0;
$post_url      = admin_url( 'admin-post.php' );
?>
<div class="sigil-enrol<?php echo $is_setup_page ? ' wrap' : ''; ?>">
	<?php if ( $is_setup_page ) : ?>
		<h1><?php echo esc_html__( 'Two-Factor Authentication', 'sigil-2fa' ); ?></h1>
		<p class="sigil-enrol__intro">
			<?php echo esc_html__( 'Add a second step to your sign-in. Passkeys are the simplest option when your device supports them; an authenticator app works everywhere.', 'sigil-2fa' ); ?>
		</p>
	<?php endif; ?>

	<?php if ( 'success' === ( $notices['type'] ?? '' ) ) : ?>
		<div class="notice notice-success is-dismissible"><p>
			<?php
			switch ( $notices['code'] ?? '' ) {
				case 'enrolled_backup':
					echo esc_html__( 'Method saved. Save your backup codes below, they will not be shown again.', 'sigil-2fa' );
					break;
				case 'enrolled':
					echo esc_html__( 'Authentication method saved.', 'sigil-2fa' );
					break;
				case 'removed':
					echo esc_html__( 'Authentication method removed.', 'sigil-2fa' );
					break;
				case 'preferred':
					echo esc_html__( 'You will be asked for this method first from now on.', 'sigil-2fa' );
					break;
				case 'confirmed':
					echo esc_html__( 'Confirmed. You can change your sign-in methods for the next few minutes.', 'sigil-2fa' );
					break;
				case 'devices_forgotten':
					echo esc_html__( 'Every trusted device has been forgotten. Each one will be asked for a second factor at its next sign-in.', 'sigil-2fa' );
					break;
				default:
					echo esc_html__( 'Saved.', 'sigil-2fa' );
			}
			?>
		</p></div>
	<?php elseif ( 'error' === ( $notices['type'] ?? '' ) ) : ?>
		<div class="notice notice-error is-dismissible"><p>
			<?php
			if ( ! empty( $notices['message'] ) ) {
				echo esc_html( (string) $notices['message'] );
			} else {
				echo esc_html__( 'Could not update two-factor authentication.', 'sigil-2fa' );
			}
			?>
		</p></div>
	<?php endif; ?>

	<?php if ( $show_backup && isset( $backup_provider ) && $backup_provider instanceof \Sigil\Provider ) : ?>
		<div class="sigil-enrol__backup-once notice notice-warning">
			<?php $backup_provider->render_enrol( $user_id ); ?>
		</div>
	<?php endif; ?>

	<?php
	$enrolled_labels = array();
	foreach ( $providers as $provider ) {
		if ( isset( $methods[ $provider->id() ] ) ) {
			$enrolled_labels[] = $provider->label();
		}
	}
	?>
	<?php if ( array() !== $enrolled_labels ) : ?>
		<div class="sigil-enrol__status">
			<p>
				<strong><?php echo esc_html__( 'Active methods:', 'sigil-2fa' ); ?></strong>
				<?php echo esc_html( implode( ', ', $enrolled_labels ) ); ?>
			</p>
		</div>
	<?php else : ?>
		<div class="sigil-enrol__status">
			<p><?php echo esc_html__( 'No authentication methods are set up yet.', 'sigil-2fa' ); ?></p>
		</div>
	<?php endif; ?>

	<nav class="sigil-enrol__tabs" aria-label="<?php echo esc_attr__( 'Authentication methods', 'sigil-2fa' ); ?>">
		<ul>
			<?php foreach ( $providers as $provider ) : ?>
				<?php
				$id      = $provider->id();
				$is_on   = $id === $active;
				$tab_url = $is_setup_page
					? add_query_arg(
						array(
							'page'   => \Sigil\Enrolment::PAGE_SLUG,
							'method' => $id,
						),
						admin_url( 'users.php' )
					)
					: add_query_arg( 'method', $id );
				?>
				<li>
					<a class="sigil-enrol__tab<?php echo $is_on ? ' is-active' : ''; ?>" href="<?php echo esc_url( $tab_url ); ?>"<?php echo $is_on ? ' aria-current="page"' : ''; ?>>
						<?php echo esc_html( $provider->label() ); ?>
						<?php if ( isset( $methods[ $id ] ) ) : ?>
							<span class="sigil-enrol__badge"><?php echo esc_html__( 'On', 'sigil-2fa' ); ?></span>
						<?php endif; ?>
					</a>
				</li>
			<?php endforeach; ?>
		</ul>
	</nav>

	<?php
	$active_provider = null;
	foreach ( $providers as $provider ) {
		if ( $provider->id() === $active ) {
			$active_provider = $provider;
			break;
		}
	}
	?>

	<?php if ( $needs_step_up || ( 'passkey' === $active && $passkey_proof ) ) : ?>
		<div class="sigil-enrol__panel sigil-enrol__step-up">
			<h3><?php echo esc_html__( 'Confirm it is you', 'sigil-2fa' ); ?></h3>
			<?php if ( $needs_step_up ) : ?>
				<p><?php echo esc_html__( 'Before adding, replacing or removing a sign-in method, confirm it is you with your password or one of your current methods. Signing in again works too.', 'sigil-2fa' ); ?></p>
			<?php else : ?>
				<p><?php echo esc_html( \Sigil\Step_Up::passkey_reason() ); ?></p>
			<?php endif; ?>
			<?php \Sigil\Enrolment::instance()->render_step_up_form( $user_id, $active ); ?>
		</div>
	<?php elseif ( $active_provider ) : ?>
		<div class="sigil-enrol__panel" data-provider="<?php echo esc_attr( $active_provider->id() ); ?>">
			<h3><?php echo esc_html( $active_provider->label() ); ?></h3>

			<?php if ( 'backup' === $active_provider->id() ) : ?>
				<?php if ( ! $show_backup ) : ?>
					<?php $active_provider->render_enrol( $user_id ); ?>
				<?php endif; ?>

				<?php if ( isset( $methods['backup'] ) ) : ?>
					<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="sigil-enrol__form">
						<input type="hidden" name="action" value="sigil_regenerate_backup" />
						<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
						<?php wp_nonce_field( 'sigil_regenerate_backup_' . $user_id ); ?>
						<p>
							<button type="submit" class="button">
								<?php echo esc_html__( 'Generate new backup codes', 'sigil-2fa' ); ?>
							</button>
						</p>
						<p class="description">
							<?php echo esc_html__( 'Generating new codes invalidates any codes you still have written down.', 'sigil-2fa' ); ?>
						</p>
					</form>
				<?php else : ?>
					<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="sigil-enrol__form">
						<input type="hidden" name="action" value="sigil_enrol" />
						<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
						<input type="hidden" name="provider" value="backup" />
						<?php wp_nonce_field( 'sigil_enrol_' . $user_id ); ?>
						<p>
							<button type="submit" class="button button-primary">
								<?php echo esc_html__( 'Generate backup codes', 'sigil-2fa' ); ?>
							</button>
						</p>
					</form>
				<?php endif; ?>
			<?php else : ?>
				<?php if ( isset( $methods[ $active_provider->id() ] ) ) : ?>
					<p class="sigil-enrol__enrolled">
						<?php echo esc_html__( 'This method is set up on your account.', 'sigil-2fa' ); ?>
					</p>

					<?php if ( \Sigil\Providers::preference( $user_id ) === $active_provider->id() ) : ?>
						<p class="description"><?php echo esc_html__( 'This is the method you are asked for first.', 'sigil-2fa' ); ?></p>
					<?php elseif ( count( $methods ) > 1 ) : ?>
						<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="sigil-enrol__form sigil-enrol__form--prefer">
							<input type="hidden" name="action" value="sigil_prefer_method" />
							<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
							<input type="hidden" name="provider" value="<?php echo esc_attr( $active_provider->id() ); ?>" />
							<?php wp_nonce_field( 'sigil_prefer_' . $user_id . '_' . $active_provider->id() ); ?>
							<button type="submit" class="button"><?php echo esc_html__( 'Ask for this one first', 'sigil-2fa' ); ?></button>
						</form>
					<?php endif; ?>

					<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="sigil-enrol__form sigil-enrol__form--remove">
						<input type="hidden" name="action" value="sigil_remove_method" />
						<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
						<input type="hidden" name="provider" value="<?php echo esc_attr( $active_provider->id() ); ?>" />
						<?php wp_nonce_field( 'sigil_remove_' . $user_id . '_' . $active_provider->id() ); ?>
						<p>
							<button type="submit" class="button button-link-delete">
								<?php echo esc_html__( 'Remove this method', 'sigil-2fa' ); ?>
							</button>
						</p>
					</form>
					<?php if ( 'passkey' === $active_provider->id() ) : ?>
						<p class="description"><?php echo esc_html__( 'You can register another passkey below.', 'sigil-2fa' ); ?></p>
						<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="sigil-enrol__form" id="sigil-enrol-form-passkey">
							<input type="hidden" name="action" value="sigil_enrol" />
							<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
							<input type="hidden" name="provider" value="passkey" />
							<?php wp_nonce_field( 'sigil_enrol_' . $user_id ); ?>
							<?php $active_provider->render_enrol( $user_id ); ?>
						</form>
					<?php endif; ?>
				<?php else : ?>
					<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="sigil-enrol__form" id="sigil-enrol-form-<?php echo esc_attr( $active_provider->id() ); ?>">
						<input type="hidden" name="action" value="sigil_enrol" />
						<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
						<input type="hidden" name="provider" value="<?php echo esc_attr( $active_provider->id() ); ?>" />
						<?php wp_nonce_field( 'sigil_enrol_' . $user_id ); ?>
						<?php $active_provider->render_enrol( $user_id ); ?>
						<?php if ( 'passkey' !== $active_provider->id() ) : ?>
							<p class="submit">
								<button type="submit" class="button button-primary">
									<?php
									echo esc_html(
										sprintf(
											/* translators: %s: method label */
											__( 'Enable %s', 'sigil-2fa' ),
											$active_provider->label()
										)
									);
									?>
								</button>
							</p>
						<?php endif; ?>
					</form>
				<?php endif; ?>
			<?php endif; ?>
		</div>
	<?php endif; ?>

	<?php if ( $own_account && $trusted_count > 0 ) : ?>
		<div class="sigil-enrol__devices">
			<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="sigil-enrol__form">
				<input type="hidden" name="action" value="sigil_forget_devices" />
				<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
				<?php wp_nonce_field( 'sigil_forget_devices_' . $user_id ); ?>
				<p class="description">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: number of trusted devices */
							_n( '%d device skips the second step when you sign in.', '%d devices skip the second step when you sign in.', $trusted_count, 'sigil-2fa' ),
							$trusted_count
						)
					);
					?>
				</p>
				<p><button type="submit" class="button"><?php echo esc_html__( 'Forget trusted devices', 'sigil-2fa' ); ?></button></p>
			</form>
		</div>
	<?php endif; ?>
</div>
