import { createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Page, expect } from '@playwright/test';

// Clears every enrolled method for a user. Also exercises the recovery CLI.
export function resetTwoFactor(user = 'admin') {
	execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', 'sigil', 'reset', user], { stdio: 'ignore' });
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(b32: string): Buffer {
	const clean = b32.toUpperCase().replace(/[^A-Z2-7]/g, '');
	let bits = '';
	for (const c of clean) {
		bits += B32.indexOf(c).toString(2).padStart(5, '0');
	}
	const bytes: number[] = [];
	for (let i = 0; i + 8 <= bits.length; i += 8) {
		bytes.push(parseInt(bits.slice(i, i + 8), 2));
	}
	return Buffer.from(bytes);
}

export function totp(secret: string, at: number = Date.now()): string {
	const counter = Math.floor(at / 1000 / 30);
	const buf = Buffer.alloc(8);
	buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
	buf.writeUInt32BE(counter >>> 0, 4);
	const hmac = createHmac('sha1', base32Decode(secret)).update(buf).digest();
	const offset = hmac[19] & 0x0f;
	const bin =
		((hmac[offset] & 0x7f) << 24) |
		((hmac[offset + 1] & 0xff) << 16) |
		((hmac[offset + 2] & 0xff) << 8) |
		(hmac[offset + 3] & 0xff);
	return (bin % 1_000_000).toString().padStart(6, '0');
}

export async function login(page: Page, user = 'admin', pass = 'password') {
	await page.goto('/wp-login.php');

	const username = page.locator('#user_login');
	const password = page.locator('#user_pass');

	await username.waitFor({ state: 'visible' });
	await password.waitFor({ state: 'visible' });

	// wp-login.php focuses the username field from an inline script. If that
	// runs between filling the first field and the second, the second value
	// lands in the username box instead: the form ends up with the password as
	// the username and no password at all. Waiting for the focus to arrive means
	// the steal has already happened before anything is typed.
	await page
		.waitForFunction(() => document.activeElement?.id === 'user_login', undefined, { timeout: 5_000 })
		.catch(() => {
			// Some themes and versions never focus it. Nothing to wait for then.
		});

	// Fill, then check the form actually holds it. A retry costs a second and
	// covers whatever else on the page might move focus; a wrong form otherwise
	// submits and waits for a screen that was never going to appear.
	for (let attempt = 0; attempt < 2; attempt++) {
		await username.fill(user);
		await password.fill(pass);

		if ((await username.inputValue()) === user && (await password.inputValue()) === pass) {
			break;
		}
	}

	await expect(username).toHaveValue(user);
	await expect(password).toHaveValue(pass);

	await page.click('#wp-submit');

	// Wait for the submit to land before anyone navigates away: a following
	// goto() can abort the login POST and the auth cookie is never set, which is
	// fast enough to hide locally and fails on slower CI.
	//
	// Waits on what the submit produces rather than on networkidle, which never
	// settles on a site with background admin requests, and not on a URL change,
	// because the 2FA challenge keeps the login form's URL.
	await page.waitForSelector('#wpadminbar, #sigil-challenge-form, #login_error, .sigil-challenge', {
		timeout: process.env.CI ? 90_000 : 30_000,
	});
}

export async function logout(page: Page) {
	// Clearing the session cookies is deterministic; the admin-bar logout link
	// depends on the bar rendering and hover state, which is flaky under test.
	await page.context().clearCookies();
}

// Logout that mimics real WordPress: clears only the WP auth cookies and leaves
// the trusted-device cookie in place, the way a browser would after logging out.
export async function logoutKeepingTrust(page: Page) {
	const ctx = page.context();
	const cookies = await ctx.cookies();
	await ctx.clearCookies();
	const keep = cookies.filter((c) => !c.name.startsWith('wordpress'));
	if (keep.length) await ctx.addCookies(keep);
}

// Enrols TOTP for the logged-in user through the setup screen and returns the
// secret.
export async function enrolTotp(page: Page): Promise<string> {
	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=totp');
	const secret = await page.locator('input[name="sigil_totp_secret"]').inputValue();
	await page.fill('input[name="sigil_totp_code"]', totp(secret));
	await page
		.locator('button[type="submit"], input[type="submit"]')
		.filter({ hasText: /enrol|enable|verify|confirm|save/i })
		.first()
		.click();
	await expect(page.locator('body')).toContainText(/backup code/i);
	return secret;
}

// A software authenticator, so the browser prompt resolves without a real device.
// It also answers passkey autofill by itself, which a person has to pick from the
// username field, so a page with it would sign in before a test could type a
// password. Autofill stays off unless a test is about autofill.
export async function addVirtualAuthenticator(page: Page, { autofill = false } = {}) {
	if (!autofill) {
		await page.addInitScript(() => {
			if (window.PublicKeyCredential) {
				window.PublicKeyCredential.isConditionalMediationAvailable = async () => false;
			}
		});
	}

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
