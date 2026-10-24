import { execFileSync } from 'node:child_process';
import { test, expect, Page } from '@playwright/test';
import { resetTwoFactor, login, logout, addVirtualAuthenticator } from './helpers';

function wp(...args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

function setPasswordless(on: boolean) {
	wp('eval', `Sigil\\Policy::update( array( 'passwordless' => ${on ? 'true' : 'false'} ) );`);
}

function credentials(): string {
	return wp('eval', "echo wp_json_encode( array_map( static function ( $r ) { return array( 'id' => (int) $r->id, 'discoverable' => $r->discoverable ); }, Sigil\\Credentials::for_user( 1 ) ) );");
}

test.beforeEach(() => {
	resetTwoFactor();
	setPasswordless(true);
});

test.afterAll(() => setPasswordless(true));

async function enrolPasskey(page: Page) {
	await login(page);
	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=passkey');
	await page.fill('#sigil-passkey-label', 'Virtual key');
	await page.locator('.sigil-passkey-register').first().click();
	await expect(page.locator('.sigil-passkey-status').first()).toContainText(/registered/i);
}

test('a passkey alone signs in, with no password and no challenge screen', async ({ page }) => {
	await addVirtualAuthenticator(page);
	await enrolPasskey(page);
	await logout(page);

	await page.goto('/wp-login.php');
	await expect(page.locator('#user_login')).toHaveAttribute('autocomplete', 'username webauthn');

	const button = page.locator('.sigil-passwordless__button');
	await expect(button).toBeVisible();
	await button.click();

	await page.waitForURL(/wp-admin/);
	await expect(page.locator('#wpadminbar')).toBeVisible();
	await expect(page.locator('#sigil-challenge-form')).toHaveCount(0);
});

test('passkey autofill on the username field signs in', async ({ page }) => {
	await addVirtualAuthenticator(page, { autofill: true });
	await enrolPasskey(page);
	await logout(page);

	// The virtual authenticator picks the autofill entry the moment the request
	// starts, so loading the page is the whole gesture.
	await page.goto('/wp-login.php');
	await page.waitForURL(/wp-admin/);
	await expect(page.locator('#wpadminbar')).toBeVisible();
});

test('the password route still ends at the passkey challenge', async ({ page }) => {
	await addVirtualAuthenticator(page);
	await enrolPasskey(page);
	await logout(page);

	await login(page);
	await expect(page.locator('.sigil-passkey-challenge')).toBeVisible();
	await page.locator('.sigil-passkey-authenticate').click();
	await page.waitForURL(/wp-admin/);
	await expect(page.locator('#wpadminbar')).toBeVisible();
});

test('switched off, the login screen has no passkey button', async ({ page }) => {
	setPasswordless(false);

	await page.goto('/wp-login.php');
	await expect(page.locator('#user_login')).toBeVisible();
	await expect(page.locator('.sigil-passwordless')).toHaveCount(0);
});

test('an older passkey can be registered again for passwordless sign-in', async ({ page }) => {
	await addVirtualAuthenticator(page);
	await enrolPasskey(page);

	// Stand in for a passkey registered before resident keys were asked for.
	wp('db', 'query', 'UPDATE wp_sigil_credentials SET discoverable = 0');
	const before = JSON.parse(credentials());
	expect(before).toHaveLength(1);

	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=passkey');
	const again = page.locator('.sigil-passkey-upgrade .sigil-passkey-register');
	await expect(again).toBeVisible();
	await again.click();
	await expect(page.locator('.sigil-passkey-status').first()).toContainText(/registered/i);

	const after = JSON.parse(credentials());
	expect(after).toHaveLength(1);
	expect(after[0].id).not.toBe(before[0].id);
	expect(String(after[0].discoverable)).toBe('1');

	await logout(page);
	await page.goto('/wp-login.php');
	await page.locator('.sigil-passwordless__button').click();
	await page.waitForURL(/wp-admin/);
	await expect(page.locator('#wpadminbar')).toBeVisible();
});
