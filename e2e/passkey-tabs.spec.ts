import { test, expect } from '@playwright/test';
import { resetTwoFactor, login, logout, addVirtualAuthenticator } from './helpers';

test.beforeEach(() => resetTwoFactor());

// A refresh mints a fresh challenge. The options the first render handed the page
// must still verify, or an ordinary reload costs the user a failed attempt.
test('a passkey challenge survives a later render of the same screen', async ({ page }) => {
	await addVirtualAuthenticator(page);

	await login(page);
	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=passkey');
	await page.fill('#sigil-passkey-label', 'Virtual key');
	await page.locator('.sigil-passkey-register').click();
	await expect(page.locator('.sigil-passkey-status')).toContainText(/registered/i);

	await logout(page);
	await login(page);

	const stale = await page.locator('.sigil-passkey-challenge').getAttribute('data-options');
	expect(stale).toBeTruthy();

	// Re-render the screen, which stores a second challenge for this user.
	await page.reload();
	await expect(page.locator('.sigil-passkey-challenge')).toBeVisible();
	const fresh = await page.locator('.sigil-passkey-challenge').getAttribute('data-options');
	expect(fresh).not.toBe(stale);

	// Now authenticate against the FIRST render's options, as the older tab would.
	await page.evaluate((opts) => {
		document.querySelector('.sigil-passkey-challenge')!.setAttribute('data-options', opts!);
	}, stale);

	await page.locator('.sigil-passkey-authenticate').click();
	await page.waitForURL(/wp-admin/);

	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
});
