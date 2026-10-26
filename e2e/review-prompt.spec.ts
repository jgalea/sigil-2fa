import { test, expect, Page, Browser } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resetTwoFactor, login, logout, totp } from './helpers';

// The review ask is shown to an administrator who has just used a second factor,
// a week after install, on Sigil's screen and the Dashboard only.

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const SIGIL_SCREEN = '/wp-admin/options-general.php?page=sigil-2fa';
const NOTICE = '.sigil-review-prompt';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

function lastLine(out: string): string {
	return out.split('\n').filter(Boolean).pop() ?? '';
}

function php(code: string) {
	cli(['eval', code]);
}

function setActivatedDaysAgo(days: number) {
	php(`update_option( 'sigil_first_activated', time() - ${days} * DAY_IN_SECONDS );`);
}

function hiddenMeta(user: string): string {
	return lastLine(cli(['eval', `echo get_user_meta( get_user_by( 'login', '${user}' )->ID, '_sigil_review_hidden', true );`]));
}

// Signs in through the TOTP challenge. Each call within a test uses the next
// 30-second step, since a code that has been accepted once is refused a second time.
let step = 0;
async function signInWithTotp(page: Page) {
	await login(page);
	await page.fill('#sigil-challenge-form input[name="code"]', totp(SECRET, Date.now() + 30_000 * step++));
	await page.locator('#sigil-authenticate').click();
	await page.waitForURL(/wp-admin/);
}

test.beforeEach(() => {
	step = 0;
	resetTwoFactor();
	php(
		`$id = get_user_by( 'login', 'admin' )->ID;` +
			` \\Sigil\\Store::set_method( $id, 'totp', array( 'secret' => base64_encode( \\Sigil\\Crypto::encrypt( '${SECRET}' ) ), 'last_step' => 0 ) );` +
			` delete_user_meta( $id, '_sigil_review_hidden' ); delete_user_meta( $id, '_sigil_last_factor' );`
	);
	setActivatedDaysAgo(8);
});

test('shows on the Sigil screen and the Dashboard after a 2FA sign-in', async ({ page }) => {
	await signInWithTotp(page);

	await page.goto(SIGIL_SCREEN);
	const notice = page.locator(NOTICE);
	await expect(notice).toBeVisible();
	await expect(notice).toContainText('Sigil is protecting your login');
	await expect(notice).toContainText('You just signed in with your authenticator app.');
	await expect(notice).toContainText('a short review on WordPress.org helps other site owners find it.');
	await expect(page.locator('.notice', { hasText: 'not yet set up' })).toHaveCount(0);

	await page.goto('/wp-admin/');
	await expect(page.locator(NOTICE)).toBeVisible();
});

test('does not show before the plugin is a week old', async ({ page }) => {
	setActivatedDaysAgo(1);
	await signInWithTotp(page);

	await page.goto(SIGIL_SCREEN);
	await expect(page.locator('#wpbody-content')).toBeVisible();
	await expect(page.locator(NOTICE)).toHaveCount(0);

	setActivatedDaysAgo(8);
	await page.reload();
	await expect(page.locator(NOTICE)).toBeVisible();
});

test('does not show before a second factor has been used', async ({ page }) => {
	php(`\\Sigil\\Store::remove_method( get_user_by( 'login', 'admin' )->ID, 'totp' );`);
	await login(page);

	await page.goto(SIGIL_SCREEN);
	await expect(page.locator('#wpbody-content')).toBeVisible();
	await expect(page.locator(NOTICE)).toHaveCount(0);
});

test('stays off other admin pages', async ({ page }) => {
	await signInWithTotp(page);

	for (const path of ['/wp-admin/plugins.php', '/wp-admin/users.php', '/wp-admin/options-general.php', '/wp-admin/profile.php']) {
		await page.goto(path);
		await expect(page.locator('#wpbody-content')).toBeVisible();
		await expect(page.locator(NOTICE)).toHaveCount(0);
	}
});

test('Maybe later hides it without a reload and for thirty days', async ({ page }) => {
	await signInWithTotp(page);
	await page.goto(SIGIL_SCREEN);

	await page.evaluate(() => ((window as any).__sigilMarker = 1));
	await page.getByRole('link', { name: 'Maybe later' }).click();

	await expect(page.locator(NOTICE)).toHaveCount(0);
	expect(await page.evaluate(() => (window as any).__sigilMarker)).toBe(1);

	await expect.poll(() => hiddenMeta('admin')).toMatch(/^\d{10}$/);
	const until = Number(hiddenMeta('admin'));
	expect(until - Date.now() / 1000).toBeGreaterThan(29 * 86400);

	await page.reload();
	await expect(page.locator('#wpbody-content')).toBeVisible();
	await expect(page.locator(NOTICE)).toHaveCount(0);
});

test("Don't ask again stays gone, including after another sign-in", async ({ page }) => {
	await signInWithTotp(page);
	await page.goto(SIGIL_SCREEN);

	await page.getByRole('link', { name: "Don't ask again" }).click();
	await expect(page.locator(NOTICE)).toHaveCount(0);
	await expect.poll(() => hiddenMeta('admin')).toBe('never');

	await page.reload();
	await expect(page.locator(NOTICE)).toHaveCount(0);

	await logout(page);
	await signInWithTotp(page);
	await page.goto('/wp-admin/');
	await expect(page.locator('#wpbody-content')).toBeVisible();
	await expect(page.locator(NOTICE)).toHaveCount(0);
});

test('the dismiss cross hides it for thirty days', async ({ page }) => {
	await signInWithTotp(page);
	await page.goto(SIGIL_SCREEN);

	await page.locator(`${NOTICE} .notice-dismiss`).click();

	await expect(page.locator(NOTICE)).toHaveCount(0);
	await expect.poll(() => hiddenMeta('admin')).toMatch(/^\d{10}$/);
});

test('Leave a review opens WordPress.org in a new tab and hides it for good', async ({ page, context }) => {
	await context.route('https://wordpress.org/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: 'ok' }));
	await signInWithTotp(page);
	await page.goto(SIGIL_SCREEN);

	const [popup] = await Promise.all([context.waitForEvent('page'), page.getByRole('link', { name: 'Leave a review' }).click()]);
	await popup.waitForLoadState();

	expect(popup.url()).toBe('https://wordpress.org/support/plugin/sigil-2fa/reviews/#new-post');
	await expect(page.locator(NOTICE)).toHaveCount(0);
	await expect.poll(() => hiddenMeta('admin')).toBe('never');
});

async function withoutJavaScript(browser: Browser, baseURL: string | undefined) {
	const context = await browser.newContext({ baseURL, javaScriptEnabled: false });
	return { context, page: await context.newPage() };
}

test('the buttons work as plain links without JavaScript', async ({ browser, baseURL }) => {
	// Sign in with scripts on: the login screen needs them. The session cookies carry over.
	const signed = await browser.newContext({ baseURL });
	const signedPage = await signed.newPage();
	await signInWithTotp(signedPage);
	const state = await signed.storageState();
	await signed.close();

	const { context, page } = await withoutJavaScript(browser, baseURL);
	await context.addCookies(state.cookies);

	await page.goto(SIGIL_SCREEN);
	await expect(page.locator(NOTICE)).toBeVisible();

	await page.getByRole('link', { name: 'Maybe later' }).click();
	await expect(page).toHaveURL(/options-general\.php\?page=sigil-2fa/);
	await expect(page.locator('#wpbody-content')).toBeVisible();
	await expect(page.locator(NOTICE)).toHaveCount(0);
	expect(hiddenMeta('admin')).toMatch(/^\d{10}$/);

	php(`delete_user_meta( get_user_by( 'login', 'admin' )->ID, '_sigil_review_hidden' );`);
	await page.reload();
	await page.getByRole('link', { name: "Don't ask again" }).click();
	await expect(page.locator(NOTICE)).toHaveCount(0);
	expect(hiddenMeta('admin')).toBe('never');

	await context.close();
});

test('a link with a bad nonce is refused', async ({ page }) => {
	await signInWithTotp(page);

	const response = await page.goto('/wp-admin/admin-post.php?action=sigil_review_prompt&choice=never&_wpnonce=bad');
	expect(response?.status()).toBe(403);
	expect(hiddenMeta('admin')).toBe('');
});

test('an editor never sees it', async ({ page }) => {
	try {
		cli(['user', 'create', 'review_editor', 'review_editor@example.com', '--role=editor', '--user_pass=password']);
	} catch {
		// Left over from an earlier run.
	}
	php(`update_user_meta( get_user_by( 'login', 'review_editor' )->ID, '_sigil_last_factor', 'totp' );`);

	try {
		await login(page, 'review_editor', 'password');

		for (const path of ['/wp-admin/', SIGIL_SCREEN, '/wp-admin/profile.php']) {
			await page.goto(path);
			await expect(page.locator('#wpbody-content, .wp-die-message').first()).toBeVisible();
			await expect(page.locator(NOTICE)).toHaveCount(0);
		}

		const response = await page.goto('/wp-admin/admin-post.php?action=sigil_review_prompt&choice=never');
		expect(response?.status()).toBe(403);
	} finally {
		cli(['user', 'delete', 'review_editor', '--yes']);
	}
});

test('screenshots at phone and desktop width', async ({ page }) => {
	const dir = process.env.REVIEW_SHOTS;
	test.skip(!dir, 'set REVIEW_SHOTS to a folder to write them');

	await signInWithTotp(page);

	for (const [name, width, height] of [
		['390', 390, 844],
		['1440', 1440, 900],
	] as const) {
		await page.setViewportSize({ width, height });
		await page.goto(SIGIL_SCREEN);
		await expect(page.locator(NOTICE)).toBeVisible();
		await page.screenshot({ path: `${dir}/sigil-screen-${name}.png` });

		await page.goto('/wp-admin/');
		await expect(page.locator(NOTICE)).toBeVisible();
		await page.screenshot({ path: `${dir}/dashboard-${name}.png` });
	}
});
