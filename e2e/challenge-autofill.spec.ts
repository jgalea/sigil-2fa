import { test, expect, Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { resetTwoFactor, login, logout, enrolTotp, totp } from './helpers';

const CODE = '#sigil-challenge-form input[name="code"]';

async function reachChallenge(page: Page): Promise<string> {
	await login(page);
	const secret = await enrolTotp(page);
	await logout(page);
	await login(page);
	await expect(page.locator(CODE)).toBeVisible();
	return secret;
}

async function expectSignedIn(page: Page) {
	await page.waitForURL(/wp-admin/);
	await expect(page.locator('#wpadminbar')).toBeVisible();
}

test.beforeEach(() => resetTwoFactor());

test('the code field carries the attributes password managers look for', async ({ page }) => {
	await reachChallenge(page);
	const code = page.locator(CODE);
	await expect(code).toHaveAttribute('autocomplete', 'one-time-code');
	await expect(code).toHaveAttribute('inputmode', 'numeric');
	await expect(code).toBeFocused();

	const username = page.locator('#sigil-challenge-form input[autocomplete="username"]');
	await expect(username).toHaveCount(1);
	await expect(username).toHaveValue('admin');
});

test('a code filled in one go is submitted untouched', async ({ page }) => {
	const secret = await reachChallenge(page);
	const code = totp(secret);
	await page.fill(CODE, code);
	await expect(page.locator(CODE)).toHaveValue(code);
	await page.locator('#sigil-authenticate').click();
	await expectSignedIn(page);
});

test('a code pasted with a space or a dash still works', async ({ page }) => {
	const secret = await reachChallenge(page);
	const code = totp(secret);
	await page.locator(CODE).focus();
	await page.keyboard.insertText(`${code.slice(0, 3)} ${code.slice(3)}`);
	await expect(page.locator(CODE)).toHaveValue(`${code.slice(0, 3)} ${code.slice(3)}`);
	await page.keyboard.press('Enter');
	await expectSignedIn(page);
});

test('the challenge can be completed from the keyboard alone', async ({ page }) => {
	const secret = await reachChallenge(page);
	await page.keyboard.type(totp(secret));
	await page.keyboard.press('Tab');
	await expect(page.locator('#sigil-authenticate')).toBeFocused();
	await page.keyboard.press('Enter');
	await expectSignedIn(page);
});

test('the method switcher is reachable by keyboard and shows focus', async ({ page }) => {
	await reachChallenge(page);
	await page.keyboard.press('Tab');
	await page.keyboard.press('Tab');
	const switcher = page.locator('.sigil-challenge__method').first();
	await expect(switcher).toBeFocused();
	const outline = await switcher.evaluate((el) => getComputedStyle(el).outlineStyle);
	expect(outline).not.toBe('none');
	await page.keyboard.press('Enter');
	await expect(page.locator('#sigil-backup-code')).toBeFocused();
});

test('a wrong code is announced and the field stays usable', async ({ page }) => {
	await reachChallenge(page);
	await page.fill(CODE, '000000');
	await page.locator('#sigil-authenticate').click();
	const error = page.locator('#login_error');
	await expect(error).toBeVisible();
	await expect(error.locator('[role="alert"]')).toBeVisible();
	await expect(page.locator(CODE)).toBeFocused();
});

for (const width of [390, 1440]) {
	test(`axe finds no serious issues at ${width}px`, async ({ page }) => {
		await page.setViewportSize({ width, height: 900 });
		await reachChallenge(page);
		const run = async () => {
			const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
			expect(results.passes.length).toBeGreaterThan(0);
			return results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
		};
		expect(await run()).toEqual([]);

		await page.click('.sigil-challenge__method');
		await expect(page.locator('#sigil-backup-code')).toBeVisible();
		expect(await run()).toEqual([]);

		await page.fill('#sigil-backup-code', 'ZZZZZZZZ');
		await page.locator('#sigil-authenticate').click();
		await expect(page.locator('#login_error')).toBeVisible();
		expect(await run()).toEqual([]);
	});
}

test('nothing overflows at 390px or at 200% zoom', async ({ page }) => {
	await reachChallenge(page);
	for (const [w, h] of [[390, 844], [640, 450]]) {
		await page.setViewportSize({ width: w, height: h });
		const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
		expect(overflow).toBeLessThanOrEqual(0);
		await expect(page.locator('#sigil-authenticate')).toBeVisible();
	}
});
