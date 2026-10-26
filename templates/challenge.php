<?php
/**
 * Challenge screen. Variables set by Challenge::render_screen().
 *
 * @var string             $challenge_token
 * @var \WP_User           $challenge_user
 * @var list<\Sigil\Provider> $challenge_providers
 * @var \Sigil\Provider  $challenge_active
 * @var \WP_Error|null     $challenge_error
 * @var bool               $challenge_remember
 * @var string             $challenge_redirect
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

// This template is require()d from inside a method, so the variables below are
// function-scoped, not globals. The PrefixAllGlobals sniff cannot see the
// including scope and reports them as unprefixed globals.
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$action_url = site_url( 'wp-login.php?action=sigil', 'login_post' );

/**
 * Filter the wording on the challenge screen.
 *
 * This is the most visible surface the plugin owns, and a site with a house
 * voice will want its own words on it. Values are escaped after filtering, so a
 * replacement cannot introduce markup.
 *
 * @param array<string, string> $text Keyed by slug.
 */
$sigil_text = (array) apply_filters(
	'sigil_challenge_text',
	array(
		'title'   => __( 'Two-factor authentication', 'sigil-2fa' ),
		/* translators: %s: username */
		'intro'   => __( 'Signing in as %s.', 'sigil-2fa' ),
		'verify'  => __( 'Verify', 'sigil-2fa' ),
		'methods' => __( 'Verify another way:', 'sigil-2fa' ),
		'cancel'  => __( 'Cancel and go back to login', 'sigil-2fa' ),
	)
);

$sigil_say = static function ( string $key, string $fallback ) use ( $sigil_text ): string {
	return isset( $sigil_text[ $key ] ) && is_string( $sigil_text[ $key ] ) && '' !== $sigil_text[ $key ]
		? $sigil_text[ $key ]
		: $fallback;
};

// Passkey drives the browser prompt and submits this form itself once the
// assertion is in hand, so a generic Verify button would sit there as a second,
// dead primary button.
$self_submitting = 'passkey' === $challenge_active->id();

$alternatives = array();
foreach ( $challenge_providers as $provider ) {
	if ( $provider->id() !== $challenge_active->id() ) {
		$alternatives[] = $provider;
	}
}
?>
<div class="sigil-challenge">
	<h1 class="sigil-challenge__title"><?php echo esc_html( $sigil_say( 'title', __( 'Two-factor authentication', 'sigil-2fa' ) ) ); ?></h1>
	<p class="sigil-challenge__intro">
		<?php
		/*
		 * Substituted rather than passed through sprintf. This line can come
		 * from a settings field, and sprintf throws on a bare percent sign or a
		 * second placeholder: "50% off" or "Hi %s, %s" would take the whole
		 * login screen down for everyone holding a second factor. {{login}} is
		 * the same placeholder the branded emails use; %s is still honoured for
		 * the default string and for anyone who already typed it.
		 */
		echo esc_html(
			str_replace(
				array( '{{login}}', '%1$s', '%s' ),
				$challenge_user->user_login,
				/* translators: %s: username */
				$sigil_say( 'intro', __( 'Signing in as %s.', 'sigil-2fa' ) )
			)
		);
		?>
	</p>

	<form name="sigil_challenge" id="sigil-challenge-form" method="post" action="<?php echo esc_url( $action_url ); ?>">
		<input type="hidden" name="sigil_token" value="<?php echo esc_attr( $challenge_token ); ?>" />
		<input type="hidden" name="sigil_provider" value="<?php echo esc_attr( $challenge_active->id() ); ?>" />
		<input type="hidden" name="sigil_remember" value="<?php echo $challenge_remember ? '1' : ''; ?>" />
		<input type="hidden" name="sigil_redirect_to" value="<?php echo esc_attr( $challenge_redirect ); ?>" />
		<?php wp_nonce_field( 'sigil_challenge', 'sigil_nonce' ); ?>
		<input type="text" name="sigil_username" class="sigil-challenge__username" value="<?php echo esc_attr( $challenge_user->user_login ); ?>" autocomplete="username" readonly tabindex="-1" aria-hidden="true" />

		<div class="sigil-challenge__provider">
			<?php $challenge_active->render_challenge( (int) $challenge_user->ID ); ?>
		</div>

		<?php
		/**
		 * Fires inside the challenge form, below the code field. Extension point
		 * for a trusted-device add-on to render its "trust this device" control.
		 *
		 * @param \WP_User $challenge_user The user completing the challenge.
		 */
		do_action( 'sigil_challenge_form', $challenge_user );
		?>

		<?php if ( $self_submitting ) : ?>
			<input type="hidden" name="sigil_authenticate" value="1" />
		<?php else : ?>
			<p class="sigil-challenge__submit">
				<button type="submit" name="sigil_authenticate" id="sigil-authenticate" class="button button-primary button-large" value="1">
					<?php echo esc_html( $sigil_say( 'verify', __( 'Verify', 'sigil-2fa' ) ) ); ?>
				</button>
			</p>
		<?php endif; ?>
	</form>

	<?php if ( array() !== $alternatives ) : ?>
		<form method="post" action="<?php echo esc_url( $action_url ); ?>" class="sigil-challenge__methods" aria-label="<?php echo esc_attr( $sigil_say( 'methods', __( 'Verify another way:', 'sigil-2fa' ) ) ); ?>">
			<input type="hidden" name="sigil_token" value="<?php echo esc_attr( $challenge_token ); ?>" />
			<input type="hidden" name="sigil_remember" value="<?php echo $challenge_remember ? '1' : ''; ?>" />
			<input type="hidden" name="sigil_redirect_to" value="<?php echo esc_attr( $challenge_redirect ); ?>" />
			<p class="sigil-challenge__methods-label"><?php echo esc_html( $sigil_say( 'methods', __( 'Verify another way:', 'sigil-2fa' ) ) ); ?></p>
			<?php foreach ( $alternatives as $provider ) : ?>
				<button type="submit" class="sigil-challenge__method" name="sigil_provider" value="<?php echo esc_attr( $provider->id() ); ?>">
					<?php echo esc_html( $provider->label() ); ?>
				</button>
			<?php endforeach; ?>
		</form>
	<?php endif; ?>

	<p class="sigil-challenge__cancel">
		<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php echo esc_html( $sigil_say( 'cancel', __( 'Cancel and go back to login', 'sigil-2fa' ) ) ); ?></a>
	</p>
</div>
