import { execFileSync } from 'node:child_process';
import { test, expect } from '@playwright/test';
import { resetTwoFactor, login, totp, addVirtualAuthenticator } from './helpers';

test.beforeEach(() => resetTwoFactor());

function wpEval(code: string) {
	execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', 'eval', code], { stdio: 'ignore' });
}

// As if the admin signed in an hour ago and walked away from the browser,
// confirmation from setting up the first method included.
function ageSessions() {
	wpEval(
		"$id = get_user_by( 'login', 'admin' )->ID; $s = get_user_meta( $id, 'session_tokens', true ); foreach ( $s as $k => $v ) { $s[ $k ]['login'] = time() - HOUR_IN_SECONDS; unset( $s[ $k ]['sigil_step_up'] ); } update_user_meta( $id, 'session_tokens', $s );"
	);
}

async function enrolTotp(page) {
	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=totp');
	const secret = await page.locator('input[name="sigil_totp_secret"]').inputValue();
	await page.fill('input[name="sigil_totp_code"]', totp(secret));
	await page.locator('.sigil-enrol__form button[type="submit"]').filter({ hasText: /enable/i }).click();
	await expect(page.locator('.notice-success')).toBeVisible();
	return secret;
}

test('a stale session confirms with the password before adding a passkey', async ({ page }) => {
	await addVirtualAuthenticator(page);
	await login(page);
	await enrolTotp(page);
	ageSessions();

	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=passkey');
	await expect(page.locator('.sigil-enrol__step-up')).toBeVisible();
	await expect(page.locator('.sigil-passkey-register')).toHaveCount(0);

	await page.fill('#sigil-step-up-password', 'not-the-password');
	await page.locator('.sigil-enrol__step-up button[type="submit"]').click();
	await expect(page.locator('.notice-error')).toBeVisible();
	await expect(page.locator('.sigil-enrol__step-up')).toBeVisible();

	await page.fill('#sigil-step-up-password', 'password');
	await page.locator('.sigil-enrol__step-up button[type="submit"]').click();
	await expect(page.locator('.notice-success')).toContainText(/confirmed/i);

	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=passkey');
	await page.fill('#sigil-passkey-label', 'Virtual key');
	await page.locator('.sigil-passkey-register').first().click();
	await expect(page.locator('.sigil-passkey-status').first()).toContainText(/registered/i);
});

test('an authenticator code confirms too', async ({ page }) => {
	await login(page);
	const secret = await enrolTotp(page);
	ageSessions();

	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=totp');
	await page.fill('#sigil-step-up-code', totp(secret));
	await page.locator('.sigil-enrol__step-up button[type="submit"]').click();
	await expect(page.locator('.notice-success')).toContainText(/confirmed/i);
	await expect(page.locator('.sigil-enrol__form--remove')).toBeVisible();
});

test('trusted devices can be forgotten from the two-factor screen', async ({ page }) => {
	await login(page);
	wpEval("\\Sigil\\Trusted_Devices::instance()->trust_current_device( get_user_by( 'login', 'admin' )->ID );");

	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup');
	await page.getByRole('button', { name: 'Forget trusted devices' }).click();
	await expect(page.locator('.notice-success')).toContainText(/forgotten/i);
	await expect(page.getByRole('button', { name: 'Forget trusted devices' })).toHaveCount(0);
});
