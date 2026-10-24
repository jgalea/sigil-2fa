import { test, expect } from '@playwright/test';
import { resetTwoFactor, login, logout, logoutKeepingTrust, totp } from './helpers';

test.beforeEach(() => resetTwoFactor());

async function enrolTotp(page): Promise<string> {
	await login(page);
	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=totp');
	const secret = await page.locator('input[name="sigil_totp_secret"]').inputValue();
	await page.fill('input[name="sigil_totp_code"]', totp(secret));
	await page.locator('button[type="submit"], input[type="submit"]').filter({ hasText: /enrol|enable|verify|confirm|save/i }).first().click();
	await expect(page.locator('body')).toContainText(/backup code/i);
	return secret;
}

test('trusting a device skips the challenge next login, and reset revokes it', async ({ page }) => {
	const secret = await enrolTotp(page);
	await logout(page);

	// Log in and pass the challenge WITH "trust this device" ticked.
	await login(page);
	await expect(page.locator('#sigil-authenticate')).toBeVisible();
	await page.check('input[name="sigil_trust_device"]');
	await page.fill('#sigil-challenge-form input[name="code"]', totp(secret));
	await page.locator('#sigil-authenticate').click();
	await page.waitForLoadState('networkidle');
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();

	// Log out but keep the trusted-device cookie (as a real browser would).
	await logoutKeepingTrust(page);

	// Next login must skip the challenge entirely and land in admin.
	await login(page);
	await page.waitForLoadState('networkidle');
	await expect(page.locator('#sigil-authenticate')).toHaveCount(0);
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();

	// Resetting 2FA must revoke the trust: the challenge returns.
	resetTwoFactor();
	// Re-enrol so a challenge is due again, then confirm the old trust is dead.
	const secret2 = await enrolTotp(page);
	await logoutKeepingTrust(page);
	await login(page);
	await expect(page.locator('#sigil-authenticate')).toBeVisible();
});
