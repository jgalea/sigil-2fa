import { test, expect, Page, Browser } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { base32Decode, logout, totp } from './helpers';

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const WRONG_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const USER = 'wf_totp';
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

// Wordfence and Sigil both refuse a code from a step already used, so each
// sign-in waits for a step nobody has used yet.
async function freshStep(page: Page) {
	await page.waitForTimeout(30_000 - (Date.now() % 30_000) + 1_500);
}

async function password(page: Page) {
	await page.goto('/wp-login.php');
	await page.locator('#user_login').waitFor({ state: 'visible' });
	await page.waitForFunction(() => document.activeElement?.id === 'user_login', undefined, { timeout: 5_000 }).catch(() => {});
	await page.locator('#user_login').fill(USER);
	await page.locator('#user_pass').fill(PASS);
	await expect(page.locator('#user_pass')).toHaveValue(PASS);
	await page.click('#wp-submit');
}

async function sigilCode(page: Page, code: string) {
	await page.fill('#sigil-challenge-form input[name="code"]', code);
	await page.locator('#sigil-authenticate').click();
	await page.waitForLoadState('load');
}

let recovery = '';

// The passkey is registered once, through Wordfence, and has to sign in
// through Sigil afterwards. A virtual authenticator lives in one browser
// context, so every test here shares the same page.
// The imported passkeys are discoverable, so the login page's autofill would
// sign them in the moment it loads. The tests that sign in with a password
// switch passwordless off, and the one that signs in with the passkey alone
// switches it back on.
function setPasswordless(on: boolean) {
	php(`\\Sigil\\Policy::update( array( 'passwordless' => ${on ? 'true' : 'false'} ) );`);
}

let page: Page;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }: { browser: Browser }) => {
	cli(['plugin', 'install', 'wordfence', '--version=9.0.2', '--activate', '--force']);
	// A fresh Wordfence 9 install keeps two-factor and passkeys switched off
	// until an administrator turns them on.
	php(`\\WordfenceLS\\Controller_Settings::shared()->set( 'enable-2fa', true ); \\WordfenceLS\\Controller_Settings::shared()->set( 'enable-passkeys', true );`);

	try {
		cli(['user', 'delete', USER, '--yes']);
	} catch {
		// Not there from an earlier run.
	}
	cli(['user', 'create', USER, `${USER}@example.com`, `--user_pass=${PASS}`, '--role=administrator']);

	// Enrolled through Wordfence's own activation, with the codes it generates.
	const secretHex = base32Decode(SECRET).toString('hex');
	recovery = php(`
		$user  = get_user_by( 'login', '${USER}' );
		$codes = \\WordfenceLS\\Controller_Users::shared()->regenerate_recovery_codes();
		$hex   = array_map( 'bin2hex', $codes );
		\\WordfenceLS\\Controller_TOTP::shared()->activate_2fa( $user, '${secretHex}', $hex );
		echo implode( ' ', str_split( $hex[0], 4 ) );
	`).split('\n').pop() ?? '';
	expect(recovery).toMatch(/^([0-9a-f]{4} ){3}[0-9a-f]{4}$/);

	page = await browser.newPage();
	const client = await page.context().newCDPSession(page);
	await client.send('WebAuthn.enable');
	await client.send('WebAuthn.addVirtualAuthenticator', {
		options: {
			protocol: 'ctap2',
			transport: 'internal',
			hasResidentKey: true,
			hasUserVerification: true,
			isUserVerified: true,
			automaticPresenceSimulation: true,
		},
	});
});

test.afterAll(async () => {
	setPasswordless(true);
	await page.close();
	try {
		cli(['plugin', 'deactivate', 'wordfence']);
	} catch {
		// Already inactive.
	}
	try {
		cli(['user', 'delete', USER, '--yes']);
	} catch {
		// Already gone.
	}
});

test('Wordfence really challenges the user before any import', async () => {
	test.setTimeout(180_000);
	await password(page);
	await expect(page.locator('#wfls-token')).toBeVisible({ timeout: 60_000 });
	await expect(page.locator('#sigil-challenge-form')).toHaveCount(0);

	// Wordfence marks the step it was activated in as used.
	await freshStep(page);
	await page.fill('#wfls-token', totp(SECRET));
	await page.locator('#wfls-token-submit').click();
	await page.waitForURL(/wp-admin/, { timeout: 20_000 });
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});

test('a passkey registered through Wordfence', async () => {
	test.setTimeout(180_000);
	await freshStep(page);
	await password(page);
	await expect(page.locator('#wfls-token')).toBeVisible({ timeout: 60_000 });
	await page.fill('#wfls-token', totp(SECRET));
	await page.locator('#wfls-token-submit').click();
	await page.waitForURL(/wp-admin/, { timeout: 60_000 });

	// Wordfence's own registration endpoints, driven the way its profile
	// screen drives them.
	await page.goto('/wp-admin/admin.php?page=WFLS');
	const result = await page.evaluate(async (userId) => {
		const vars = (window as any).WFLSVars;
		const post = async (data: Record<string, string>) => {
			const body = new URLSearchParams(data);
			const res = await fetch(vars.ajaxurl, { method: 'POST', body, credentials: 'same-origin' });
			return res.json();
		};
		const b64u = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
		const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));

		const begin = await post({ action: 'wordfence_ls_begin_passkey_registration', nonce: vars.nonce, user: userId, label: 'Virtual Mac' });
		if (!begin.options) {
			return { error: JSON.stringify(begin) };
		}
		const o = begin.options;
		const cred: any = await navigator.credentials.create({
			publicKey: {
				...o,
				challenge: unb64u(o.challenge),
				user: { ...o.user, id: unb64u(o.user.id) },
				excludeCredentials: (o.excludeCredentials || []).map((c: any) => ({ ...c, id: unb64u(c.id) })),
			},
		});
		const finish = await post({
			action: 'wordfence_ls_finish_passkey_registration',
			nonce: vars.nonce,
			user: userId,
			token: begin.token,
			label: 'Virtual Mac',
			'credential[id]': cred.id,
			'credential[rawId]': b64u(cred.rawId),
			'credential[type]': cred.type,
			'credential[response][clientDataJSON]': b64u(cred.response.clientDataJSON),
			'credential[response][attestationObject]': b64u(cred.response.attestationObject),
		});
		return finish;
	}, userId(USER));
	expect(result).toMatchObject({ registered: 1 });
	await logout(page);
});

test('the import carries the secret, recovery codes and passkey across', () => {
	const dry = cli(['sigil', 'import', 'wordfence', '--dry-run']);
	expect(dry).toMatch(/\[dry run\] Users: [1-9]/);
	expect(dry).toMatch(new RegExp(`${USER}\\s+ok\\s+totp,backup,passkey`));
	expect(cli(['sigil', 'status', USER])).toContain('Methods: (none)');

	const out = cli(['sigil', 'import', 'wordfence', `--user=${USER}`]);
	expect(out).toMatch(/authenticator: 1, backup codes: 1/);
	expect(out).toMatch(/needs attention: 0, passkeys: 1/);
	expect(cli(['sigil', 'status', USER])).toContain('Methods: backup, passkey, totp');

	const row = php(`global $wpdb; echo bin2hex( $wpdb->get_var( $wpdb->prepare( "SELECT secret FROM {$wpdb->base_prefix}wfls_2fa_secrets WHERE user_id = %d", ${userId(USER)} ) ) );`);
	expect(row).toContain(base32Decode(SECRET).toString('hex'));

	// Wordfence keeps the handle it gave the authenticator in the passkey row.
	const same = php(`global $wpdb; $h = $wpdb->get_var( $wpdb->prepare( "SELECT user_handle FROM {$wpdb->base_prefix}wfls_passkeys WHERE user_id = %d", ${userId(USER)} ) ); $c = \\Sigil\\Credentials::for_user( ${userId(USER)} ); echo '' !== $h && $c[0]->user_handle === $h && 1 === (int) $c[0]->discoverable ? 'same' : 'different';`);
	expect(same).toContain('same');
	setPasswordless(false);
});

test('with both active, Wordfence stands down and the original secret passes Sigil', async () => {
	test.setTimeout(180_000);
	await freshStep(page);
	await password(page);
	await expect(page.locator('#sigil-challenge-form')).toBeVisible({ timeout: 60_000 });
	await expect(page.locator('#wfls-token')).toHaveCount(0);
	await page.locator('button.sigil-challenge__method[value="totp"]').click();
	await expect(page.locator('#sigil-totp-challenge')).toBeVisible();

	await sigilCode(page, totp(WRONG_SECRET));
	await expect(page.locator('body')).toContainText(/verification failed/i);

	await sigilCode(page, totp(SECRET));
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});

test('the passkey Wordfence registered passes Sigil', async () => {
	test.setTimeout(180_000);
	await password(page);
	await expect(page.locator('.sigil-passkey-challenge')).toBeVisible({ timeout: 60_000 });
	await page.locator('.sigil-passkey-authenticate').click();
	await page.waitForURL(/wp-admin/, { timeout: 60_000 });
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});

test('a Wordfence recovery code works as a Sigil backup code', async () => {
	test.setTimeout(180_000);
	await password(page);
	await expect(page.locator('#sigil-challenge-form')).toBeVisible({ timeout: 60_000 });
	await page.locator('button.sigil-challenge__method[value="backup"]').click();
	await expect(page.locator('#sigil-backup-code')).toBeVisible();
	await page.fill('#sigil-backup-code', recovery);
	await page.locator('#sigil-authenticate').click();
	await page.waitForLoadState('load');
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});

test('the Wordfence passkey signs in on its own, with no password', async () => {
	test.setTimeout(180_000);
	setPasswordless(true);
	await page.goto('/wp-login.php');
	// Autofill may already be signing in by the time the button can be pressed.
	await page.locator('.sigil-passwordless__button').click({ timeout: 3_000 }).catch(() => {});
	await expect(page).toHaveURL(/wp-admin/, { timeout: 60_000 });
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await expect(page.locator('#sigil-challenge-form')).toHaveCount(0);
	await logout(page);
});
