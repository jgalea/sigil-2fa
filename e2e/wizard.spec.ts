import { test, expect, Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resetTwoFactor, login, totp, confirmIdentity } from './helpers';

const WIZARD = '/wp-admin/options-general.php?page=sigil-2fa-wizard';
const SETTINGS = '/wp-admin/options-general.php?page=sigil-2fa';

function cli(args: string[]) {
	execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { stdio: 'ignore' });
}

function reset() {
	resetTwoFactor();
	for (const option of ['sigil_policy', 'sigil_pro_wizard_done', 'sigil_pro_trusted_days', 'sigil_pro_zero_setup']) {
		try {
			cli(['option', 'delete', option]);
		} catch {
			// not set
		}
	}
}

test.beforeEach(reset);
test.afterAll(reset);

async function addVirtualAuthenticator(page: Page) {
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
}

test('a fresh install is walked through a passkey, backup codes and a role requirement', async ({ page }) => {
	await addVirtualAuthenticator(page);
	await login(page);

	await page.goto(SETTINGS);
	await expect(page.locator('.notice-info', { hasText: /walk me through it/i })).toBeVisible();

	await page.goto(WIZARD);
	await expect(page.locator('.sigil-wizard__steps .is-current')).toContainText(/passkey/i);

	// A passkey can be a whole sign-in, so the first one needs the password.
	await expect(page.locator('.sigil-passkey-register')).toHaveCount(0);
	await confirmIdentity(page);
	await expect(page.locator('.sigil-wizard__steps .is-current')).toContainText(/passkey/i);

	await page.fill('#sigil-passkey-label', 'Virtual key');
	await page.locator('.sigil-passkey-register').click();

	// The page moves on by itself and shows the codes, once.
	await expect(page.locator('.sigil-wizard__steps .is-current')).toContainText(/backup codes/i);
	await expect(page.locator('.sigil-backup-codes-list li')).toHaveCount(10);

	await page.reload();
	await expect(page.locator('.sigil-backup-codes-list li')).toHaveCount(0);

	await page.getByRole('link', { name: /i have saved them/i }).click();
	await expect(page.locator('.sigil-wizard__steps .is-current')).toContainText(/require it/i);
	await expect(page.locator('input[name="roles[administrator]"]')).toBeChecked();

	await page.getByRole('button', { name: /require two-factor for these roles/i }).click();
	await expect(page.locator('.notice-success').first()).toContainText(/saved/i);
	await expect(page.locator('input[name="sigil_policy[roles][administrator]"]')).toBeChecked();

	// The wizard is a one-time task: it has gone from the menu.
	await page.goto(WIZARD);
	await expect(page.locator('body')).toContainText(/not allowed to access this page|do not have permission/i);
});

test('the authenticator app path reaches the same backup codes', async ({ page }) => {
	await login(page);
	await page.goto(WIZARD + '&method=totp');

	const secret = await page.locator('input[name="sigil_totp_secret"]').inputValue();
	await page.fill('input[name="sigil_totp_code"]', totp(secret));
	await page.getByRole('button', { name: /enable authenticator app/i }).click();

	await expect(page.locator('.sigil-wizard__steps .is-current')).toContainText(/backup codes/i);
	await expect(page.locator('.sigil-backup-codes-list li')).toHaveCount(10);
});

test('a wrong code stays on the first step and says so', async ({ page }) => {
	await login(page);
	await page.goto(WIZARD + '&method=totp');

	await page.fill('input[name="sigil_totp_code"]', '000000');
	await page.getByRole('button', { name: /enable authenticator app/i }).click();

	await expect(page.locator('.sigil-wizard__steps .is-current')).toContainText(/passkey/i);
	await expect(page.locator('.notice-error')).toBeVisible();
});

test('the wizard can be skipped', async ({ page }) => {
	await login(page);
	await page.goto(SETTINGS);
	await page.locator('.notice-info a', { hasText: /dismiss/i }).click();

	await expect(page).toHaveURL(/page=sigil-2fa$/);
	await expect(page.locator('.notice-info', { hasText: /walk me through it/i })).toHaveCount(0);
});

test('enforcing your own role before you have a method is refused', async ({ page }) => {
	await login(page);
	await page.goto(SETTINGS);

	await page.check('input[name="sigil_policy[enabled]"]');
	await page.check('input[name="sigil_policy[roles][administrator]"]');
	await page.getByRole('button', { name: /save settings/i }).click();

	await expect(page.locator('.notice-error')).toContainText(/locked out/i);
	await expect(page.locator('input[name="sigil_policy[enabled]"]')).not.toBeChecked();
	await expect(page.locator('input[name="sigil_policy[roles][administrator]"]')).not.toBeChecked();
});

test('the device and email-floor settings are on the free screen and persist', async ({ page }) => {
	await login(page);
	await page.goto(SETTINGS);

	await page.fill('#sigil-trusted-days', '21');
	await page.check('input[name="sigil_zero_setup"]');
	await page.getByRole('button', { name: /save settings/i }).click();

	await expect(page.locator('.notice-success').first()).toContainText(/saved/i);
	await expect(page.locator('#sigil-trusted-days')).toHaveValue('21');
	await expect(page.locator('input[name="sigil_zero_setup"]')).toBeChecked();
});
