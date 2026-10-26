import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { totp } from './helpers';

// Wordfence checks the password over admin-ajax before it lets wp-login.php
// submit. Sigil refuses passwords over AJAX for anyone with a second factor, so
// this is the flow that must keep working: the check passes, the form posts,
// and the real POST gets Sigil's challenge.

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const PASS = 'password';
const USER = 'wf_2fa';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

function userId(login: string): string {
	return cli(['user', 'get', login, '--field=ID']).split(/\s+/).filter(Boolean).pop() ?? '';
}

let available = true;
let provisioningError = '';

test.beforeAll(() => {
	try {
		try {
			cli(['plugin', 'install', 'wordfence', '--activate']);
		} catch {
			cli(['plugin', 'install', 'wordfence', '--activate', '--force']);
		}

		// Wordfence only loads its login script, and so only makes the AJAX
		// check, with its 2FA switched on and somebody using it. The admin does
		// here; the person signing in uses Sigil.
		cli([
			'eval',
			"\\WordfenceLS\\Controller_Settings::shared()->set( \\WordfenceLS\\Controller_Settings::OPTION_ENABLE_2FA, true );" +
				"\\WordfenceLS\\Controller_Users::shared()->import_2fa( array( 1 => array( 'secret' => bin2hex( random_bytes( 20 ) ), 'recovery' => bin2hex( random_bytes( 80 ) ), 'ctime' => time(), 'vtime' => time(), 'type' => 'authenticator' ) ) );",
		]);

		try {
			cli(['user', 'delete', USER, '--yes']);
		} catch {
			// not there yet
		}
		cli(['user', 'create', USER, `${USER}@example.com`, `--user_pass=${PASS}`, '--role=editor']);
		cli([
			'eval',
			`\\Sigil\\Store::set_method( ${userId(USER)}, 'totp', array( 'secret' => base64_encode( \\Sigil\\Crypto::encrypt( '${SECRET}' ) ), 'last_step' => 0 ) );`,
		]);
	} catch (error) {
		available = false;
		provisioningError = String(error);
	}
});

test.afterAll(() => {
	try {
		cli(['eval', '\\WordfenceLS\\Controller_Users::shared()->deactivate_2fa( new WP_User( 1 ) );']);
	} catch {
		// Wordfence never came up
	}
	try {
		cli(['plugin', 'deactivate', 'wordfence']);
	} catch {
		// not active
	}
	try {
		cli(['user', 'delete', USER, '--yes']);
	} catch {
		// already gone
	}
});

test('with Wordfence active, a Sigil user signs in through its AJAX check and gets the challenge', async ({ page }) => {
	expect(available, provisioningError).toBe(true);

	await page.goto('/wp-login.php');
	await page.locator('#user_login').waitFor({ state: 'visible' });
	await page.waitForFunction(() => document.activeElement?.id === 'user_login', undefined, { timeout: 5_000 }).catch(() => {});
	await page.locator('#user_login').fill(USER);
	await page.locator('#user_pass').fill(PASS);
	await expect(page.locator('#user_pass')).toHaveValue(PASS);

	// Read the check's answer on the way through. Once it says go ahead the
	// form submits and the browser drops the response, so it can't be read
	// afterwards.
	let answer = '';
	await page.route('**/admin-ajax.php', async (route) => {
		const res = await route.fetch();
		if ((route.request().postData() ?? '').includes('action=wordfence_ls_authenticate')) {
			answer = await res.text();
		}
		await route.fulfill({ response: res });
	});

	await page.click('#wp-submit');

	const code = page.locator('#sigil-challenge-form input[name="code"]');
	await expect(code).toBeVisible({ timeout: 30_000 });

	// The check is what Sigil lets through, and it has to say go ahead.
	expect(JSON.parse(answer)).toEqual({ login: 1 });
	await page.unrouteAll({ behavior: 'ignoreErrors' });

	await code.fill(totp(SECRET));
	await page.locator('#sigil-authenticate').click();
	await page.waitForURL(/\/wp-admin\//);

	await expect(page.locator('#wpadminbar')).toBeVisible();
	await expect(page.locator('#wpadminbar')).toContainText(USER);
});
