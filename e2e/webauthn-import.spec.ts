import { test, expect, Page, Browser } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { login, logout } from './helpers';

const USER = 'wa_key';
const PASS = 'password';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

function php(code: string): string {
	return cli(['eval', code]);
}

function userId(login: string): string {
	return cli(['user', 'get', login, '--field=ID']).split(/\s+/).filter(Boolean).pop() ?? '';
}

// The key is registered once, through the WebAuthn provider's own profile
// screen, and then has to sign in through Two Factor and later through Sigil.
// A virtual authenticator lives in one browser context, so every test here
// shares the same page.
// The imported passkeys are discoverable, so the login page's autofill would
// sign them in the moment it loads. The tests that sign in with a password
// switch passwordless off, and the one that signs in with the passkey alone
// switches it back on.
function setPasswordless(on: boolean) {
	php(`\\Sigil\\Policy::update( array( 'passwordless' => ${on ? 'true' : 'false'} ) );`);
}

let page: Page;

async function addVirtualAuthenticator(p: Page) {
	const client = await p.context().newCDPSession(p);
	await client.send('WebAuthn.enable');
	await client.send('WebAuthn.addVirtualAuthenticator', {
		options: {
			protocol: 'ctap2',
			transport: 'usb',
			hasResidentKey: true,
			hasUserVerification: true,
			isUserVerified: true,
			automaticPresenceSimulation: true,
		},
	});
}

// The provider builds its relying party from an https:// AppID and compares
// origins exactly, and its profile screen hides the register button on plain
// HTTP. The test site is http://localhost, which browsers treat as secure, so
// the AppID is pointed at the real origin and the hidden button is put back.
// Registration itself still runs through the provider's own script and AJAX.
const ORIGIN_PLUGIN = `<?php
add_filter( 'webauthn_app_id', static function () {
	$p = wp_parse_url( home_url() );
	return $p['scheme'] . '://' . $p['host'] . ( isset( $p['port'] ) ? ':' . $p['port'] : '' );
} );
`;

const ADD_KEY_MARKUP =
	'<div class="hide-if-no-js add-webauthn-key"><p><label for="webauthn-key-name"><strong>Key name:</strong></label>' +
	'<input type="text" id="webauthn-key-name" value="" maxlength="255" /> ' +
	'<button type="button" class="button button-secondary">Register New Key</button></p>' +
	'<span class="security-key-status" aria-live="polite"></span></div>';

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }: { browser: Browser }) => {
	cli(['plugin', 'install', 'two-factor', '--version=0.17.0', '--activate', '--force']);
	cli(['plugin', 'install', 'two-factor-provider-webauthn', '--version=2.6.2', '--activate', '--force']);
	php(`file_put_contents( WPMU_PLUGIN_DIR . '/e2e-webauthn-origin.php', base64_decode( '${Buffer.from(ORIGIN_PLUGIN).toString('base64')}' ) );`);

	try {
		cli(['user', 'delete', USER, '--yes']);
	} catch {
		// Not there from an earlier run.
	}
	cli(['user', 'create', USER, `${USER}@example.com`, `--user_pass=${PASS}`, '--role=editor']);

	page = await browser.newPage();
	await addVirtualAuthenticator(page);
});

test.afterAll(async () => {
	setPasswordless(true);
	await page.close();
	php(`@unlink( WPMU_PLUGIN_DIR . '/e2e-webauthn-origin.php' );`);
	for (const plugin of ['two-factor-provider-webauthn', 'two-factor']) {
		try {
			cli(['plugin', 'deactivate', plugin]);
		} catch {
			// Already inactive.
		}
	}
	try {
		cli(['user', 'delete', USER, '--yes']);
	} catch {
		// Already gone.
	}
});

test('a key registered through the WebAuthn provider puts its user behind Two Factor', async () => {
	test.setTimeout(120_000);

	await login(page, USER, PASS);
	await page.route('**/wp-admin/profile.php', async (route) => {
		const response = await route.fetch();
		const body = (await response.text()).replace(
			/<div class="notice inline notice-error">\s*<p>\s*WebAuthn requires an HTTPS connection[\s\S]*?<\/div>/,
			ADD_KEY_MARKUP
		);
		await route.fulfill({ response, body });
	});
	await page.goto('/wp-admin/profile.php');
	await page.fill('#webauthn-key-name', 'Virtual YubiKey');
	await page.locator('#webauthn-security-keys-section button', { hasText: 'Register New Key' }).click();
	await expect(page.locator('#webauthn-security-keys-section')).toContainText('Virtual YubiKey', { timeout: 15_000 });
	await page.unroute('**/wp-admin/profile.php');

	php(`Two_Factor_Core::enable_provider_for_user( ${userId(USER)}, 'TwoFactor_Provider_WebAuthn' );`);
	expect(cli(['db', 'query', `SELECT COUNT(*) FROM wp_2fa_webauthn_credentials WHERE u2f = 0`, '--skip-column-names'])).toMatch(/^[1-9]/);

	await logout(page);
	await page.goto('/wp-login.php');
	await page.locator('#user_login').fill(USER);
	await page.locator('#user_pass').fill(PASS);
	await expect(page.locator('#user_pass')).toHaveValue(PASS);
	await page.click('#wp-submit');
	// Two Factor now challenges with the key. Its WebAuthn screen refuses to go
	// further on plain HTTP, so the sign-in itself is proven through Sigil after
	// the import, with the same key.
	await expect(page.locator('body')).toContainText('WebAuthn requires an HTTPS connection');
	await expect(page.locator('#sigil-challenge-form')).toHaveCount(0);
	await logout(page);
});

test('the import carries the key across', () => {
	const dry = cli(['sigil', 'import', 'two-factor', '--dry-run', `--user=${USER}`]);
	expect(dry).toContain('[dry run] Users: 1');
	expect(dry).toMatch(/passkeys: 1$/m);
	expect(cli(['sigil', 'status', USER])).toContain('Methods: (none)');

	const out = cli(['sigil', 'import', 'two-factor', `--user=${USER}`]);
	expect(out).toMatch(/needs attention: 0, passkeys: 1/);
	expect(cli(['sigil', 'status', USER])).toContain('Methods: passkey');
	expect(php(`echo \\Sigil\\Credentials::for_user( ${userId(USER)} )[0]->label;`)).toContain('Virtual YubiKey');
	// The handle the provider gave the authenticator, decoded from base64url.
	const kept = php(`global $wpdb; $h = $wpdb->get_var( $wpdb->prepare( "SELECT user_handle FROM {$wpdb->base_prefix}2fa_webauthn_users WHERE user_id = %d", ${userId(USER)} ) ); echo \\Sigil\\Credentials::for_user( ${userId(USER)} )[0]->user_handle === \\Sigil\\Import::base64url_decode( $h ) && '' !== $h ? 'same' : 'different';`);
	expect(kept).toContain('same');
	setPasswordless(false);
});

test('the migrated key passes Sigil, and Two Factor stays out', async () => {
	test.setTimeout(120_000);

	await login(page, USER, PASS);
	await expect(page.locator('.sigil-passkey-challenge')).toBeVisible();
	await page.locator('.sigil-passkey-authenticate').click();
	await page.waitForURL(/wp-admin/);

	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	expect(php(`echo (int) \\Sigil\\Credentials::for_user( ${userId(USER)} )[0]->sign_count > 0 || null !== \\Sigil\\Credentials::for_user( ${userId(USER)} )[0]->last_used_at ? 'used' : 'unused';`)).toContain('used');
	await logout(page);
});

test('the migrated key signs in on its own, with no password', async () => {
	test.setTimeout(120_000);

	setPasswordless(true);
	await page.goto('/wp-login.php');
	// Autofill may already be signing in by the time the button can be pressed.
	await page.locator('.sigil-passwordless__button').click({ timeout: 3_000 }).catch(() => {});
	await expect(page).toHaveURL(/wp-admin/, { timeout: 60_000 });
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await expect(page.locator('#sigil-challenge-form')).toHaveCount(0);
	expect(php(`echo (int) \\Sigil\\Credentials::for_user( ${userId(USER)} )[0]->discoverable;`)).toContain('1');
	await logout(page);
});
