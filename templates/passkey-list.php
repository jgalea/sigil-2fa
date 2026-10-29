<?php
/**
 * The account's passkeys, each with its own remove button once confirmed.
 *
 * @var list<object> $passkeys
 * @var bool         $show_remove
 * @var int          $user_id
 * @var string       $post_url
 */

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( array() === $passkeys ) {
	return;
}

$date_format = (string) get_option( 'date_format' );
?>
<h4><?php echo esc_html__( 'Registered passkeys', 'sigil-2fa' ); ?></h4>
<ul class="sigil-enrol__passkeys">
	<?php foreach ( $passkeys as $passkey ) : ?>
		<?php
		$added = wp_date( $date_format, (int) strtotime( $passkey->created_at . ' UTC' ) );
		$used  = empty( $passkey->last_used_at )
			? __( 'never used', 'sigil-2fa' )
			: sprintf(
				/* translators: %s: date */
				__( 'last used %s', 'sigil-2fa' ),
				wp_date( $date_format, (int) strtotime( $passkey->last_used_at . ' UTC' ) )
			);
		?>
		<li class="sigil-enrol__passkey">
			<span class="sigil-enrol__passkey-name"><?php echo esc_html( (string) $passkey->label ); ?></span>
			<span class="sigil-enrol__passkey-meta">
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: date added, 2: "last used <date>" or "never used" */
						__( 'Added %1$s, %2$s', 'sigil-2fa' ),
						$added,
						$used
					)
				);
				?>
			</span>
			<?php if ( $show_remove ) : ?>
				<form method="post" action="<?php echo esc_url( $post_url ); ?>" class="sigil-enrol__passkey-remove">
					<input type="hidden" name="action" value="sigil_remove_passkey" />
					<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
					<input type="hidden" name="credential" value="<?php echo esc_attr( (string) $passkey->id ); ?>" />
					<?php wp_nonce_field( 'sigil_remove_passkey_' . $user_id . '_' . (int) $passkey->id ); ?>
					<?php
					/* translators: %s: passkey label */
					$remove_label = sprintf( __( 'Remove %s', 'sigil-2fa' ), (string) $passkey->label );
					?>
					<button type="submit" class="button button-link-delete" aria-label="<?php echo esc_attr( $remove_label ); ?>">
						<?php echo esc_html__( 'Remove', 'sigil-2fa' ); ?>
					</button>
				</form>
			<?php endif; ?>
		</li>
	<?php endforeach; ?>
</ul>
