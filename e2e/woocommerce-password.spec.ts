import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { totp } from './helpers';

// WooCommerce's Account details form changes the password from a front-end
// page, where the browser sends only the logged_in cookie. WordPress re-issues
// the session for the new password, and that must not sign the customer out.

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const PASS = 'password';
const NEW_PASS = 'a-new-password-for-e2e-5521';
const USER = 'wc_pw_change';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

function lastLine(out: string): string {
	return out.split('\n').filter(Boolean).pop() ?? '';
}

test.beforeAll(() => {
	try {
		cli(['plugin', 'install', 'woocommerce', '--activate']);
	} catch {
		cli(['plugin', 'activate', 'woocommerce']);
	}
	cli(['wc', 'tool', 'run', 'install_pages', '--user=1']);
	try {
		cli(['transient', 'delete', '_wc_activation_redirect']);
	} catch {
		// already gone
	}
	cli(['rewrite', 'flush', '--hard']);

	try {
		cli(['user', 'delete', USER, '--yes']);
	} catch {
		// not there yet
	}
	cli(['user', 'create', USER, `${USER}@example.com`, `--user_pass=${PASS}`, '--role=customer', '--first_name=Wc', '--last_name=Customer']);
	const id = lastLine(cli(['user', 'get', USER, '--field=ID']));
	cli([
		'eval',
		`\\Sigil\\Store::set_method( ${id}, 'totp', array( 'secret' => base64_encode( \\Sigil\\Crypto::encrypt( '${SECRET}' ) ), 'last_step' => 0 ) );`,
	]);
});

test.afterAll(() => {
	try {
		cli(['user', 'delete', USER, '--yes']);
	} catch {
		// already gone
	}
});

test('a customer with a second factor stays signed in after changing their password on My Account', async ({ page }) => {
	await page.goto('/wp-login.php');
	await page.locator('#user_login').waitFor({ state: 'visible' });
	await page.waitForFunction(() => document.activeElement?.id === 'user_login', undefined, { timeout: 5_000 }).catch(() => {});
	await page.locator('#user_login').fill(USER);
	await page.locator('#user_pass').fill(PASS);
	await expect(page.locator('#user_pass')).toHaveValue(PASS);
	await page.click('#wp-submit');

	const code = page.locator('#sigil-challenge-form input[name="code"]');
	await expect(code).toBeVisible({ timeout: 30_000 });
	await code.fill(totp(SECRET));
	await page.locator('#sigil-authenticate').click();
	await page.waitForLoadState('load');

	await page.goto('/my-account/edit-account/');
	await expect(page.locator('form.woocommerce-EditAccountForm')).toBeVisible();
	await page.fill('#account_first_name', 'Wc');
	await page.fill('#account_last_name', 'Customer');
	await page.fill('#password_current', PASS);
	await page.fill('#password_1', NEW_PASS);
	await page.fill('#password_2', NEW_PASS);

	const saved = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('edit-account'));
	await page.locator('button[name="save_account_details"]').click();
	const res = await saved;

	const loggedIn = (await res.headersArray())

		.filter((h) => h.name.toLowerCase() === 'set-cookie' && /^wordpress_logged_in_[a-f0-9]{32}=/.test(h.value))
		.filter((h) => {
			const [pair, ...attrs] = h.value.split(';');
			const expires = attrs.map((a) => a.trim()).find((a) => /^expires=/i.test(a));
			return pair.slice(pair.indexOf('=') + 1).trim() !== '' && (expires === undefined || Date.parse(expires.slice(8)) > Date.now());
		});
	expect(loggedIn.length).toBeGreaterThan(0);

	await page.goto('/my-account/');
	await expect(page.locator('.woocommerce-MyAccount-navigation')).toBeVisible();
	await expect(page.locator('form.woocommerce-form-login')).toHaveCount(0);
	expect(lastLine(cli(['eval', `echo wp_check_password( '${NEW_PASS}', get_user_by( 'login', '${USER}' )->user_pass ) ? 'changed' : 'same';`]))).toBe('changed');
});
