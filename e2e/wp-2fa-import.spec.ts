import { test, expect, Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { login, logout, resetTwoFactor, totp } from './helpers';

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const WRONG_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const USER = 'w2_totp';
const EMAIL_USER = 'w2_email';
const PASS = 'password';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

function php(code: string): string {
	return cli(['eval', code]);
}

// WP 2FA and Sigil both refuse a code from a step already used, so each
// sign-in waits for a step nobody has used yet.
async function freshStep(page: Page) {
	await page.waitForTimeout(30_000 - (Date.now() % 30_000) + 1_500);
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
	cli(['plugin', 'install', 'wp-2fa', '--version=4.2.1', '--activate', '--force']);

	for (const login of [USER, EMAIL_USER]) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// Not there from an earlier run.
		}
		cli(['user', 'create', login, `${login}@example.com`, `--user_pass=${PASS}`, '--role=editor']);
	}

	// Enrolled through WP 2FA's own code: it encrypts the plain secret the first
	// time it reads it back, and generates its own backup codes.
	backupCode = php(`
		$user = get_user_by( 'login', '${USER}' );
		\\WP2FA\\Methods\\TOTP::set_user_totp_key( '${SECRET}', $user );
		\\WP2FA\\Methods\\TOTP::get_totp_key( $user );
		\\WP2FA\\Admin\\Helpers\\User_Helper::set_enabled_method_for_user( 'totp', $user );
		$codes = \\WP2FA\\Methods\\Backup_Codes::generate_codes( $user );
		echo $codes[0];
	`).split(/\s+/).pop() ?? '';
	expect(backupCode).toMatch(/^\d{16}$/);

	php(`\\WP2FA\\Admin\\Helpers\\User_Helper::set_enabled_method_for_user( 'email', get_user_by( 'login', '${EMAIL_USER}' ) );`);

	// The stored secret must be WP 2FA's ciphertext, not the plain key.
	expect(php(`echo substr( get_user_meta( get_user_by( 'login', '${USER}' )->ID, 'wp_2fa_totp_key', true ), 0, 7 );`)).toContain('lsc_v2:');
});

test.afterAll(() => {
	try {
		cli(['plugin', 'deactivate', 'wp-2fa']);
	} catch {
		// Already inactive.
	}
	for (const login of [USER, EMAIL_USER]) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// Already gone.
		}
	}
});

test('WP 2FA really challenges the user before any import', async ({ page }) => {
	test.setTimeout(120_000);
	await freshStep(page);
	await password(page, USER);
	await expect(page.locator('input#authcode')).toBeVisible({ timeout: 30_000 });
	await expect(page.locator('#sigil-challenge-form')).toHaveCount(0);

	await page.fill('input#authcode', totp(SECRET));
	await page.locator('input#authcode').press('Enter');
	await page.waitForURL(/wp-admin/, { timeout: 30_000 });
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});

test('the import opens the encrypted secret and carries the codes across', () => {
	const dry = cli(['sigil', 'import', 'wp-2fa', '--dry-run']);
	expect(dry).toMatch(/\[dry run\] Users: [1-9]/);
	expect(dry).toMatch(new RegExp(`${USER}\\s+ok\\s+totp,backup`));
	expect(dry).toMatch(new RegExp(`${EMAIL_USER}\\s+ok\\s+email`));
	expect(cli(['sigil', 'status', USER])).toContain('Methods: (none)');

	const out = cli(['sigil', 'import', 'wp-2fa']);
	expect(out).toMatch(/email: 1, authenticator: 1, backup codes: 1/);
	expect(out).toMatch(/needs attention: 0/);
	expect(cli(['sigil', 'status', USER])).toContain('Methods: backup, totp');
	expect(cli(['sigil', 'status', EMAIL_USER])).toContain('Methods: email');

	expect(php(`echo substr( get_user_meta( get_user_by( 'login', '${USER}' )->ID, 'wp_2fa_totp_key', true ), 0, 7 );`)).toContain('lsc_v2:');
});

test('with both active, Sigil asks once and the original secret passes', async ({ page }) => {
	test.setTimeout(120_000);
	await freshStep(page);
	await password(page, USER);
	await expect(page.locator('#sigil-challenge-form')).toBeVisible({ timeout: 30_000 });
	await expect(page.locator('input#authcode')).toHaveCount(0);

	await sigilCode(page, totp(WRONG_SECRET));
	await expect(page.locator('body')).toContainText(/verification failed/i);

	await sigilCode(page, totp(SECRET));
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await expect(page.locator('input#authcode')).toHaveCount(0);
	await logout(page);
});

test('a WP 2FA backup code works in Sigil', async ({ page }) => {
	test.setTimeout(120_000);
	await password(page, USER);
	await expect(page.locator('#sigil-challenge-form')).toBeVisible({ timeout: 30_000 });
	await page.locator('button.sigil-challenge__method[value="backup"]').click();
	await expect(page.locator('#sigil-backup-code')).toBeVisible();
	await page.fill('#sigil-backup-code', backupCode);
	await page.locator('#sigil-authenticate').click();
	await page.waitForLoadState('load');
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await logout(page);
});

// WP 2FA keeps per-user enforcement state once a policy has applied to
// someone, so the administrator is put back to unenforced either side.
function unenforce() {
	php(`
		update_option( 'wp_2fa_policy', array_merge( (array) get_option( 'wp_2fa_policy', array() ), array( 'enforcement-policy' => 'do-not-enforce', 'enforced_roles' => array() ) ) );
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE user_id = 1 AND meta_key LIKE 'wp\\_2fa\\_%'" );
		delete_user_meta( 1, '_sigil_deadline' );
		wp_cache_flush();
	`);
}

test('the settings screen offers the import and the policy step', async ({ page }) => {
	test.setTimeout(120_000);
	// Earlier specs leave the administrator enrolled, which would stop this sign-in at a challenge.
	resetTwoFactor();
	unenforce();

	await login(page, 'admin', 'password');
	await page.goto('/wp-admin/options-general.php?page=sigil-2fa');
	await expect(page.locator('#sigil-import-wp-2fa')).toBeVisible();
	await expect(page.locator('#sigil-import-run-wp-2fa')).toBeVisible();
	await expect(page.locator('.notice-warning', { hasText: 'The WP 2FA plugin is active alongside Sigil' })).toBeVisible();

	await page.locator('#sigil-import-preview-wp-2fa').click();
	await expect(page.locator('.notice-info', { hasText: 'Preview: nothing was changed.' })).toBeVisible();

	// Set after signing in: WP 2FA would otherwise send this administrator to
	// its own setup wizard.
	php(`update_option( 'wp_2fa_policy', array_merge( (array) get_option( 'wp_2fa_policy', array() ), array( 'enforcement-policy' => 'certain-roles-only', 'enforced_roles' => array( 'administrator' ) ) ) );`);
	await page.reload();

	await expect(page.locator('body')).toContainText('WP 2FA requires two-factor for these roles: administrator');
	await page.locator('input[name="sigil_import_policy"]').click();
	await page.waitForLoadState('load');
	expect(php(`$p = \\Sigil\\Policy::get(); echo $p['enabled'] && $p['roles']['administrator'] && empty( $p['roles']['editor'] ) ? 'applied' : 'not';`)).toContain('applied');
	php(`\\Sigil\\Policy::update( array( 'enabled' => false, 'roles' => array() ) );`);
	unenforce();
	await logout(page);
});
