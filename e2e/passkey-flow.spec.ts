import { test, expect } from '@playwright/test';
import { resetTwoFactor, login, logout, addVirtualAuthenticator } from './helpers';

test.beforeEach(() => resetTwoFactor());

// The challenge screen runs logged out, so the passkey assertion cannot go through
// an authenticated admin-ajax call. This is the flow that proves it doesn't.
test('enrol a passkey, get challenged at login, and pass it', async ({ page }) => {
	await addVirtualAuthenticator(page);

	await login(page);
	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=passkey');

	await page.fill('#sigil-passkey-label', 'Virtual key');
	await page.locator('.sigil-passkey-register').click();
	await expect(page.locator('.sigil-passkey-status')).toContainText(/registered/i);

	await logout(page);
	await login(page);

	const challenge = page.locator('.sigil-passkey-challenge');
	await expect(challenge).toBeVisible();
	// The generic Verify button must not sit next to the passkey button.
	await expect(page.locator('#sigil-authenticate')).toHaveCount(0);

	await page.locator('.sigil-passkey-authenticate').click();
	await page.waitForURL(/wp-admin/);

	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
});
