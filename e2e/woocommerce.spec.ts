import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resetTwoFactor, login } from './helpers';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

let available = true;
let provisioningError = '';

test.beforeAll(() => {
	try {
		// Retried once: a fresh environment occasionally loses the first attempt,
		// and a silent skip here would report a green run with the feature
		// untested.
		try {
			cli(['plugin', 'install', 'woocommerce', '--activate']);
		} catch {
			cli(['plugin', 'install', 'woocommerce', '--activate']);
		}

		// A fresh install has no My Account page, so the endpoint has nothing to
		// hang off and every assertion here would be about a 404 instead. This
		// passed locally only because the page already existed.
		cli(['wc', 'tool', 'run', 'install_pages', '--user=1']);

		// A freshly activated WooCommerce hijacks the next admin page load for
		// its onboarding, so the first login lands on a setup screen instead of
		// the dashboard. Locally that was dismissed long ago; on a fresh CI
		// install it swallows the login.
		try {
			cli(['transient', 'delete', '_wc_activation_redirect']);
		} catch {
			// already gone
		}
		cli(['option', 'update', 'woocommerce_onboarding_profile', '{"completed":true,"skipped":true}', '--format=json']);

		cli(['rewrite', 'flush', '--hard']);

		const accountPage = cli(['option', 'get', 'woocommerce_myaccount_page_id']);
		if (!/^\d+$/.test(accountPage) || accountPage === '0') {
			available = false;
		}
	} catch (error) {
		available = false;
		provisioningError = String(error);
	}
});

test.beforeEach(() => resetTwoFactor());

// This tab has broken twice in ways only a real page load showed: once because
// the WooCommerce check ran while plugins were still loading, and once because
// the endpoint claimed the site root and a page shadowed it.
test('the account area gets a two-factor tab that actually resolves', async ({ page }) => {
	// A broken environment is a failure to look at, not a skip to overlook.
	if (!available) {
		throw new Error(`WooCommerce could not be provisioned, so the tab went untested: ${provisioningError}`);
	}

	await login(page);
	await page.goto('/my-account/');

	const nav = page.locator('.woocommerce-MyAccount-navigation');
	await expect(nav).toContainText(/two-factor/i);

	// Before Log out, which belongs last.
	const items = await nav.locator('a').allInnerTexts();
	const labels = items.map((t) => t.trim().toLowerCase());
	expect(labels.indexOf('two-factor')).toBeLessThan(labels.indexOf('log out'));

	await page.goto('/my-account/two-factor/');
	expect(page.url()).toContain('/my-account/two-factor');
	await expect(page.locator('.sigil-enrol--frontend')).toBeVisible();
	await expect(page.locator('link[href*="frontend.css"]')).toHaveCount(1);
});

test('a customer can enrol from the account tab', async ({ page }) => {
	// A broken environment is a failure to look at, not a skip to overlook.
	if (!available) {
		throw new Error(`WooCommerce could not be provisioned, so the tab went untested: ${provisioningError}`);
	}

	await login(page);
	await page.goto('/my-account/two-factor/');
	await page.locator('.sigil-enrol__tab', { hasText: /backup codes/i }).first().click();

	await page.locator('.sigil-enrol--frontend button[type="submit"], .sigil-enrol--frontend input[type="submit"]')
		.filter({ hasText: /generate|enrol|enable|save/i }).first().click();

	await expect(page.locator('.sigil-enrol--frontend')).toContainText(/backup code/i);
	expect(page.url()).toContain('/my-account/');
});
