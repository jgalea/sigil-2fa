import { test, expect, APIResponse, APIRequestContext, Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { addVirtualAuthenticator, login, logout, resetTwoFactor } from './helpers';

// Sign-ins that skip the challenge for a reason of their own, passkey alone and
// trusted devices, read from the raw headers like login-session.spec.ts: a live
// session has to come back with the sign-in, and nothing else may get one.

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const PASS = 'password';
const USERS = ['hard_trust', 'hard_lim', 'hard_xml'];

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

function lastLine(out: string): string {
	return out.split('\n').filter(Boolean).pop() ?? '';
}

function userId(login: string): string {
	return lastLine(cli(['user', 'get', login, '--field=ID']));
}

function sessionCount(login: string): number {
	return Number(lastLine(cli(['eval', `echo count( WP_Session_Tokens::get_instance( ${userId(login)} )->get_all() );`])));
}

function forgetAttempts() {
	cli(['eval', 'global $wpdb; $wpdb->query( "DELETE FROM " . \\Sigil\\Rate_Limit::table() );']);
}

type Cookie = { name: string; value: string; live: boolean };

function setCookies(res: APIResponse): Cookie[] {
	return res
		.headersArray()
		.filter((h) => h.name.toLowerCase() === 'set-cookie')
		.map((h) => {
			const [pair, ...attrs] = h.value.split(';');
			const name = pair.slice(0, pair.indexOf('=')).trim();
			const value = pair.slice(pair.indexOf('=') + 1).trim();
			const expires = attrs.map((a) => a.trim()).find((a) => /^expires=/i.test(a));
			const expired = expires !== undefined && Date.parse(expires.slice(8)) <= Date.now();
			return { name, value, live: value !== '' && !expired };
		})
		.filter((c) => /^wordpress_(sec_|logged_in_)?[a-f0-9]{32}$/.test(c.name));
}

function live(cookies: Cookie[]): string[] {
	return cookies.filter((c) => c.live).map((c) => c.name);
}

function firstIssued(cookies: Cookie[]): string {
	const first = new Map<string, string>();
	for (const c of cookies) {
		if (c.value !== '' && !first.has(c.name)) {
			first.set(c.name, c.value);
		}
	}
	return [...first].map(([n, v]) => `${n}=${v}`).join('; ');
}

async function profileWith(playwright: any, baseURL: string, cookie: string): Promise<APIResponse> {
	const ctx = await playwright.request.newContext({ baseURL, extraHTTPHeaders: cookie ? { Cookie: cookie } : {} });
	return ctx.get('/wp-admin/profile.php', { maxRedirects: 0 });
}

async function passwordPost(request: APIRequestContext, login: string, pwd = PASS, cookie = ''): Promise<APIResponse> {
	return request.post('/wp-login.php', {
		form: { log: login, pwd, 'wp-submit': 'Log In', testcookie: '1', redirect_to: '/wp-admin/' },
		headers: { Cookie: ['wordpress_test_cookie=WP%20Cookie%20check', cookie].filter(Boolean).join('; ') },
		maxRedirects: 0,
	});
}

async function xmlrpc(request: APIRequestContext, login: string, pwd: string): Promise<string> {
	const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
	const res = await request.post('/xmlrpc.php', {
		headers: { 'Content-Type': 'text/xml' },
		data: `<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>${esc(login)}</string></value></param><param><value><string>${esc(pwd)}</string></value></param></params></methodCall>`,
	});
	return res.text();
}

// Signs a passwordless assertion in the browser, the way passwordless.js does,
// and hands it back instead of submitting the form.
async function assertion(page: Page): Promise<{ ceremony: string; assertion: string }> {
	await page.goto('/wp-login.php');
	await expect(page.locator('.sigil-passwordless__button')).toBeVisible();
	return page.evaluate(async () => {
		const cfg = (window as any).sigilPasswordless;
		const webauthn = (window as any).sigilWebAuthn;
		const data = await (await fetch(cfg.restUrl, { credentials: 'same-origin' })).json();
		const cred: any = await navigator.credentials.get({ publicKey: webauthn.decodeOptions(data.options) });
		return {
			ceremony: data.ceremony,
			assertion: JSON.stringify({
				id: webauthn.bufferToBase64Url(cred.rawId),
				clientDataJSON: webauthn.bufferToBase64Url(cred.response.clientDataJSON),
				authenticatorData: webauthn.bufferToBase64Url(cred.response.authenticatorData),
				signature: webauthn.bufferToBase64Url(cred.response.signature),
				userHandle: cred.response.userHandle ? webauthn.bufferToBase64Url(cred.response.userHandle) : '',
			}),
		};
	});
}

// Posted from the browser's own cookie jar, which holds the cookie the ceremony
// is bound to, unless a test hands in a request context without it.
async function passkeyFormPost(request: APIRequestContext, signed: { ceremony: string; assertion: string }, headers: Record<string, string> = {}) {
	return request.post('/wp-login.php', {
		form: {
			log: '',
			pwd: '',
			sigil_passwordless_ceremony: signed.ceremony,
			sigil_passwordless_assertion: signed.assertion,
			'wp-submit': 'Log In',
			testcookie: '1',
			redirect_to: '/wp-admin/',
		},
		headers,
		maxRedirects: 0,
	});
}

function trustedToken(login: string): string {
	return lastLine(cli(['eval', `echo \\Sigil\\Trusted_Devices::instance()->trust_current_device( ${userId(login)} );`]));
}

const TRUST = 'sigil_pro_trusted';

test.beforeAll(() => {
	for (const login of USERS) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// not there yet
		}
		cli(['user', 'create', login, `${login}@example.com`, `--user_pass=${PASS}`, '--role=editor']);
	}
	cli([
		'eval',
		`\\Sigil\\Store::set_method( ${userId('hard_trust')}, 'totp', array( 'secret' => base64_encode( \\Sigil\\Crypto::encrypt( '${SECRET}' ) ), 'last_step' => 0 ) );`,
	]);
	cli(['eval', "Sigil\\Policy::update( array( 'passwordless' => true, 'limit_passwords' => true ) );"]);
	forgetAttempts();
});

test.afterEach(() => forgetAttempts());

test.afterAll(() => {
	for (const login of USERS) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// already gone
		}
	}
	resetTwoFactor();
});

test.describe('passwordless', () => {
	test.beforeAll(() => resetTwoFactor());

	test.beforeEach(async ({ page }) => {
		await addVirtualAuthenticator(page);
		await login(page);
		await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=passkey');
		await page.fill('#sigil-passkey-label', 'Virtual key');
		await page.locator('.sigil-passkey-register').first().click();
		await expect(page.locator('.sigil-passkey-status').first()).toContainText(/registered/i);
		await logout(page);
	});

	test.afterEach(() => resetTwoFactor());

	test('a passkey on the login form issues exactly one live session', async ({ page, request, playwright, baseURL }) => {
		const signed = await assertion(page);
		const before = sessionCount('admin');

		const res = await passkeyFormPost(page.request, signed);
		expect(res.status()).toBe(302);

		const cookies = setCookies(res);
		expect(live(cookies).filter((n) => n.startsWith('wordpress_logged_in_')).length).toBeGreaterThan(0);
		expect((await profileWith(playwright, baseURL!, firstIssued(cookies))).status()).toBe(200);
		expect(sessionCount('admin')).toBe(before + 1);
	});

	// The REST route has no wp_login to issue the cookie again afterwards. And
	// once any account has an application password, core answers the empty
	// username on a REST request with invalid_username.
	test('a passkey over the REST route issues a live session', async ({ page, request, playwright, baseURL }) => {
		cli(['user', 'application-password', 'create', 'hard_lim', 'e2e']);
		const signed = await assertion(page);

		const res = await page.request.post('/?rest_route=/sigil/v1/passwordless', {
			data: { ceremony: signed.ceremony, assertion: JSON.parse(signed.assertion), remember: false },
		});
		expect(res.status()).toBe(200);

		const cookies = setCookies(res);
		expect(live(cookies).filter((n) => n.startsWith('wordpress_logged_in_')).length).toBeGreaterThan(0);
		expect((await profileWith(playwright, baseURL!, firstIssued(cookies))).status()).toBe(200);
	});

	test('a passkey still signs in an account locked by wrong passwords', async ({ page, request, playwright, baseURL }) => {
		for (let i = 0; i < 5; i++) {
			await passwordPost(request, 'admin', 'not-the-password');
		}
		const locked = await passwordPost(request, 'admin');
		expect(await locked.text()).toContain('Too many failed sign-in attempts');
		expect(live(setCookies(locked))).toEqual([]);

		const res = await passkeyFormPost(page.request, await assertion(page));
		expect(res.status()).toBe(302);
		expect((await profileWith(playwright, baseURL!, firstIssued(setCookies(res)))).status()).toBe(200);
	});

	// A page on another site can post an attacker's own ceremony and assertion
	// through a visitor's browser. Without the cookie the ceremony was bound to,
	// or from another origin, nobody is signed in.
	test('a ceremony posted without its browser cookie signs nobody in', async ({ page, request }) => {
		const signed = await assertion(page);
		const before = sessionCount('admin');

		const form = await passkeyFormPost(request, signed, { Cookie: 'wordpress_test_cookie=WP%20Cookie%20check' });
		expect.soft(live(setCookies(form))).toEqual([]);

		const again = await assertion(page);
		const rest = await request.post('/?rest_route=/sigil/v1/passwordless', {
			data: { ceremony: again.ceremony, assertion: JSON.parse(again.assertion), remember: false },
		});
		expect.soft(rest.status()).toBe(401);
		expect.soft(live(setCookies(rest))).toEqual([]);
		expect.soft(sessionCount('admin')).toBe(before);
	});

	test('a ceremony posted from another origin signs nobody in', async ({ page }) => {
		const signed = await assertion(page);
		const before = sessionCount('admin');

		const res = await page.request.post('/?rest_route=/sigil/v1/passwordless', {
			data: { ceremony: signed.ceremony, assertion: JSON.parse(signed.assertion), remember: false },
			headers: { Origin: 'https://attacker.example' },
		});
		expect.soft(res.status()).toBe(401);
		expect.soft(live(setCookies(res))).toEqual([]);
		expect.soft(sessionCount('admin')).toBe(before);
	});
});

test.describe('trusted devices', () => {
	test('a trusted device and the password issue exactly one live session', async ({ request, playwright, baseURL }) => {
		const token = trustedToken('hard_trust');
		expect(token).toMatch(/^[a-f0-9]{64}$/);
		const before = sessionCount('hard_trust');

		const res = await passwordPost(request, 'hard_trust', PASS, `${TRUST}=${token}`);
		expect(res.status()).toBe(302);

		const cookies = setCookies(res);
		expect(live(cookies).filter((n) => n.startsWith('wordpress_logged_in_')).length).toBeGreaterThan(0);
		expect((await profileWith(playwright, baseURL!, firstIssued(cookies))).status()).toBe(200);
		expect(sessionCount('hard_trust')).toBe(before + 1);
	});

	test('a forged trusted-device cookie and the password issue no session', async ({ request, playwright, baseURL }) => {
		trustedToken('hard_trust');
		const before = sessionCount('hard_trust');

		const res = await passwordPost(request, 'hard_trust', PASS, `${TRUST}=${randomBytes(32).toString('hex')}`);
		expect(await res.text()).toContain('sigil-challenge-form');

		const cookies = setCookies(res);
		expect.soft(live(cookies)).toEqual([]);
		expect.soft((await profileWith(playwright, baseURL!, firstIssued(cookies))).status()).toBe(302);
		expect.soft(sessionCount('hard_trust')).toBe(before);
	});

	test('an expired trusted-device cookie and the password issue no session', async ({ request, playwright, baseURL }) => {
		const token = trustedToken('hard_trust');
		cli([
			'eval',
			`$id = ${userId('hard_trust')}; $d = get_user_meta( $id, '_sigil_pro_trusted', true ); foreach ( $d as &$x ) { $x['expires'] = time() - 1; } update_user_meta( $id, '_sigil_pro_trusted', $d );`,
		]);
		const before = sessionCount('hard_trust');

		const res = await passwordPost(request, 'hard_trust', PASS, `${TRUST}=${token}`);
		expect(await res.text()).toContain('sigil-challenge-form');

		const cookies = setCookies(res);
		expect.soft(live(cookies)).toEqual([]);
		expect.soft((await profileWith(playwright, baseURL!, firstIssued(cookies))).status()).toBe(302);
		expect.soft(sessionCount('hard_trust')).toBe(before);
	});
});

test.describe('password attempts', () => {
	test('five wrong passwords and then even the right one is refused, with no session', async ({ request }) => {
		for (let i = 0; i < 5; i++) {
			const res = await passwordPost(request, 'hard_lim', 'not-the-password');
			expect(await res.text()).not.toContain('Too many failed sign-in attempts');
		}

		const res = await passwordPost(request, 'hard_lim');
		expect(await res.text()).toContain('Too many failed sign-in attempts');
		expect(live(setCookies(res))).toEqual([]);
	});

	test('an account that does not exist is refused in the same words', async ({ request }) => {
		for (let i = 0; i < 5; i++) {
			await passwordPost(request, 'hard_lim', 'not-the-password');
			await passwordPost(request, 'hard_nobody_here', 'not-the-password');
		}

		const real = await (await passwordPost(request, 'hard_lim', 'not-the-password')).text();
		const missing = await (await passwordPost(request, 'hard_nobody_here', 'not-the-password')).text();
		const message = (html: string) => html.match(/<div id="login_error"[^>]*>([\s\S]*?)<\/div>/)?.[1].trim() ?? '';

		expect(message(real)).toContain('Too many failed sign-in attempts');
		expect(message(missing)).toBe(message(real));
	});

	test('wrong passwords over XML-RPC count toward the same limit', async ({ request }) => {
		for (let i = 0; i < 5; i++) {
			expect(await xmlrpc(request, 'hard_xml', 'not-the-password')).toContain('<name>faultCode</name>');
		}
		expect(await xmlrpc(request, 'hard_xml', PASS)).toContain('<name>faultCode</name>');

		const res = await passwordPost(request, 'hard_xml');
		expect(await res.text()).toContain('Too many failed sign-in attempts');
		expect(live(setCookies(res))).toEqual([]);
	});

	test('the right password signs in again once the lockout runs out', async ({ request }) => {
		for (let i = 0; i < 6; i++) {
			await passwordPost(request, 'hard_lim', 'not-the-password');
		}
		cli(['eval', 'global $wpdb; $wpdb->query( "UPDATE " . \\Sigil\\Rate_Limit::table() . " SET expires = " . ( time() - 1 ) );']);

		const res = await passwordPost(request, 'hard_lim');
		expect(res.status()).toBe(302);
		expect(live(setCookies(res)).length).toBeGreaterThan(0);
	});
});
