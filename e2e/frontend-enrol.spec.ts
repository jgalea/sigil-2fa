import { test, expect, Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resetTwoFactor, login, logout, totp } from './helpers';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

let pageId = '';

test.beforeAll(() => {
	const existing = cli(['post', 'list', '--post_type=page', '--name=two-factor', '--field=ID', '--format=ids']);
	pageId = existing.split(/\s+/).filter(Boolean).pop() ?? '';

	if (!pageId) {
		const out = cli([
			'post', 'create', '--post_type=page', '--post_status=publish',
			'--post_title=Two Factor', '--post_name=two-factor',
			'--post_content=[sigil_2fa]', '--porcelain',
		]);
		pageId = out.split(/\s+/).filter(Boolean).pop() ?? '';
	}

	expect(pageId).toMatch(/^\d+$/);
});

test.beforeEach(() => resetTwoFactor());

// Members of a site that keeps people out of wp-admin have to be able to enrol
// somewhere. This is that somewhere.
test('a user can enrol from a front-end page without touching wp-admin', async ({ page }) => {
	await login(page);
	await page.goto('/two-factor/');

	const panel = page.locator('.sigil-enrol--frontend');
	await expect(panel).toBeVisible();
	await expect(panel).toContainText(/no authentication methods/i);

	// The shortcode renders the method switcher, so pick the authenticator app.
	await page.locator('.sigil-enrol__tab', { hasText: /authenticator/i }).first().click();

	const secret = await page.locator('input[name="sigil_totp_secret"]').inputValue();
	expect(secret.length).toBeGreaterThanOrEqual(16);
	await page.fill('input[name="sigil_totp_code"]', totp(secret));
	await page.locator('.sigil-enrol--frontend button[type="submit"], .sigil-enrol--frontend input[type="submit"]')
		.filter({ hasText: /enrol|enable|verify|confirm|save/i }).first().click();

	// Submitting must land back on the front-end page, not in wp-admin.
	await expect(page).toHaveURL(/\/two-factor\//);
	await expect(page.locator('.sigil-enrol--frontend')).toContainText(/backup code/i);

	// And the enrolment is real: the login challenge now appears.
	await logout(page);
	await login(page);
	await expect(page.locator('body')).toContainText(/two-factor|verification|authenticator/i);
	await page.fill('#sigil-challenge-form input[name="code"]', totp(secret));
	await page.locator('#sigil-authenticate').click();
	await page.waitForLoadState('networkidle');
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpadminbar')).toBeVisible();
});

// The passkey panel enqueues its script while the shortcode is rendering, which
// is after wp_enqueue_scripts has run. That only works because the handle is
// registered for the footer, so it is worth holding down.
test('passkey enrolment works from the front-end page', async ({ page }) => {
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

	const errors: string[] = [];
	page.on('pageerror', (e) => errors.push(String(e)));

	await login(page);
	await page.goto('/two-factor/');
	await page.locator('.sigil-enrol__tab', { hasText: /passkey/i }).first().click();

	// Its config has to reach the page, or the button is inert.
	expect(await page.evaluate(() => typeof (window as any).sigilPasskey)).toBe('object');

	await page.fill('#sigil-passkey-label', 'Front key');
	await page.locator('.sigil-passkey-register').click();
	await expect(page.locator('.sigil-passkey-status')).toContainText(/registered/i);
	expect(errors).toEqual([]);
});

test('the front-end page is styled rather than raw markup', async ({ page }) => {
	await login(page);
	await page.goto('/two-factor/');

	const stylesheet = page.locator('link[href*="/assets/css/frontend.css"][href*="sigil-2fa"]');
	await expect(stylesheet).toHaveCount(1);

	// The shared markup carries admin classes; on the front end they only mean
	// something if our stylesheet defines them.
	const padding = await page.locator('.sigil-enrol--frontend .sigil-enrol__panel').first()
		.evaluate((el) => getComputedStyle(el).paddingTop);
	expect(padding).not.toBe('0px');
});
