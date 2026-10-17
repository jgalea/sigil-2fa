import { test, expect, Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { logout, totp } from './helpers';

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const WRONG_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
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

// A TOTP code is spent once its step is used, and the import carries Two
// Factor's last-used step across, so each sign-in waits for a step nobody has
// used yet.
async function freshStep(page: Page) {
	const msIntoStep = Date.now() % 30_000;
	await page.waitForTimeout(30_000 - msIntoStep + 1_500);
}

async function password(page: Page, user: string) {
	await page.goto('/wp-login.php');
	await page.locator('#user_login').waitFor({ state: 'visible' });
	await page.waitForFunction(() => document.activeElement?.id === 'user_login', undefined, { timeout: 5_000 }).catch(() => {});
	await page.locator('#user_login').fill(user);
	await page.locator('#user_pass').fill(PASS);
	await expect(page.locator('#user_pass')).toHaveValue(PASS);
	await page.click('#wp-submit');
}

async function sigilCode(page: Page, code: string) {
	await page.fill('#sigil-challenge-form input[name="code"]', code);
	await page.locator('#sigil-authenticate').click();
	await page.waitForLoadState('load');
}

let backupCode = '';

test.describe.configure({ mode: 'serial' });

test.beforeAll(() => {
	cli(['plugin', 'install', 'two-factor', '--version=0.17.0', '--activate', '--force']);
	php("delete_option('sigil_e2e_last_mail');");

	for (const login of ['tf_totp', 'tf_email', 'tf_nokey']) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// Not there from an earlier run.
		}
		cli(['user', 'create', login, `${login}@example.com`, `--user_pass=${PASS}`, '--role=editor']);
	}

	const totpUser = userId('tf_totp');
	backupCode = php(`
		$id = ${totpUser};
		Two_Factor_Core::enable_provider_for_user( $id, 'Two_Factor_Email' );
		Two_Factor_Core::enable_provider_for_user( $id, 'Two_Factor_Totp' );
		Two_Factor_Core::enable_provider_for_user( $id, 'Two_Factor_Backup_Codes' );
		Two_Factor_Totp::get_instance()->set_user_totp_key( $id, '${SECRET}' );
		update_user_meta( $id, '_two_factor_provider', 'Two_Factor_Totp' );
		$codes = Two_Factor_Backup_Codes::get_instance()->generate_codes( get_user_by( 'id', $id ) );
		echo $codes[0];
	`).split(/\s+/).pop() ?? '';
	expect(backupCode).toMatch(/^\d{8}$/);

	php(`Two_Factor_Core::enable_provider_for_user( ${userId('tf_email')}, 'Two_Factor_Email' );`);
	php(`Two_Factor_Core::enable_provider_for_user( ${userId('tf_nokey')}, 'Two_Factor_Totp' );`);
});

test.afterAll(() => {
	try {
		cli(['plugin', 'deactivate', 'two-factor']);
	} catch {
		// Already inactive.
	}
	for (const login of ['tf_totp', 'tf_email', 'tf_nokey']) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// Already gone.
		}
	}
});

test('Two Factor really challenges the seeded user before any import', async ({ page }) => {
	test.setTimeout(120_000);
	await password(page, 'tf_totp');
	await expect(page.locator('input[name="authcode"]')).toBeVisible();
	await expect(page.locator('#sigil-challenge-form')).toHaveCount(0);

	// Two Factor's script submits the form itself once six digits are in.
	await page.fill('input[name="authcode"]', totp(SECRET));
	await page.waitForURL(/wp-admin/, { timeout: 10_000 }).catch(() => page.locator('#loginform [type="submit"]').first().click());
	await page.waitForLoadState('load');
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});

test('the import carries each user across and reports the fallback', () => {
	const dry = cli(['sigil', 'import', 'two-factor', '--dry-run']);
	expect(dry).toContain('[dry run]');
	expect(cli(['sigil', 'status', 'tf_totp'])).toContain('Methods: (none)');

	const out = cli(['sigil', 'import', 'two-factor']);
	expect(out).toMatch(/email: 3, authenticator: 1, backup codes: 1/);
	expect(out).toMatch(/email fallback: 1/);
	expect(out).toMatch(/tf_nokey\s.*email_fallback/);
	expect(out).toContain('Import complete');

	expect(cli(['sigil', 'status', 'tf_totp'])).toContain('Methods: backup, email, totp');

	const again = cli(['sigil', 'import', 'two-factor']);
	expect(again).toMatch(/email: 0, authenticator: 0, backup codes: 0, already in Sigil: 3/);

	expect(php(`echo get_user_meta( ${userId('tf_totp')}, '_two_factor_totp_key', true ) === '${SECRET}' ? 'kept' : 'gone';`)).toContain('kept');
});

test('with both plugins active, Sigil asks once and Two Factor stays out', async ({ page }) => {
	test.setTimeout(120_000);
	await freshStep(page);
	await password(page, 'tf_totp');
	await expect(page.locator('#sigil-challenge-form')).toBeVisible();
	await expect(page.locator('input[name="authcode"]')).toHaveCount(0);

	await sigilCode(page, totp(SECRET));
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await expect(page.locator('input[name="authcode"]')).toHaveCount(0);
	await logout(page);
});

test('after deactivating Two Factor, the same authenticator signs in and a wrong one does not', async ({ page }) => {
	test.setTimeout(120_000);
	cli(['plugin', 'deactivate', 'two-factor']);

	await freshStep(page);
	await password(page, 'tf_totp');
	await expect(page.locator('#sigil-challenge-form')).toBeVisible();

	await sigilCode(page, totp(WRONG_SECRET));
	await expect(page.locator('#sigil-challenge-form')).toBeVisible();
	await expect(page.locator('body')).toContainText(/verification failed/i);

	await sigilCode(page, totp(SECRET));
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});

test('a Two Factor backup code works once in Sigil', async ({ page }) => {
	for (const expectIn of [true, false]) {
		await password(page, 'tf_totp');
		await expect(page.locator('#sigil-challenge-form')).toBeVisible();
		await page.locator('button.sigil-challenge__method[value="backup"]').click();
		await expect(page.locator('#sigil-backup-code')).toBeVisible();
		await sigilCode(page, backupCode);

		if (expectIn) {
			await page.goto('/wp-admin/');
			await expect(page.locator('#wpadminbar')).toBeVisible();
			await logout(page);
		} else {
			await expect(page.locator('body')).toContainText(/verification failed/i);
		}
	}
	await logout(page);
});

test('an emailed code signs in an imported email user', async ({ page }) => {
	await password(page, 'tf_email');
	await expect(page.locator('#sigil-email-code')).toBeVisible();

	await sigilCode(page, '000000');
	await expect(page.locator('body')).toContainText(/verification failed/i);

	const mail = JSON.parse(cli(['option', 'get', 'sigil_e2e_last_mail', '--format=json']).split('\n').pop() ?? '{}');
	expect(mail.to).toBe('tf_email@example.com');
	const code = (mail.message.match(/\b(\d{6})\b/) ?? [])[1];
	expect(code).toMatch(/^\d{6}$/);

	await sigilCode(page, code);
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});
