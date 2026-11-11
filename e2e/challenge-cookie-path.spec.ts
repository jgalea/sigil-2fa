import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { totp } from './helpers';

// The browser binding cookie has to reach wp-login.php wherever WordPress's
// home path puts COOKIEPATH. With home at /en/ and WordPress at /, a cookie
// scoped to /en/ never came back and nobody with a second factor could sign in.

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const LOGIN = 'cookiepath_2fa';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

test.beforeAll(() => {
	try {
		cli(['user', 'delete', LOGIN, '--yes']);
	} catch {
		// not there yet
	}
	cli(['user', 'create', LOGIN, `${LOGIN}@example.com`, '--user_pass=password', '--role=editor']);
	const id = cli(['user', 'get', LOGIN, '--field=ID']).split('\n').pop();
	cli(['eval', `\\Sigil\\Store::set_method( ${id}, 'totp', array( 'secret' => base64_encode( \\Sigil\\Crypto::encrypt( '${SECRET}' ) ), 'last_step' => 0 ) );`]);
});

test.afterAll(() => {
	try {
		cli(['user', 'delete', LOGIN, '--yes']);
	} catch {
		// already gone
	}
});

test('the challenge completes on a site whose COOKIEPATH is not a prefix of wp-login.php', async ({ playwright, baseURL }) => {
	const ctx = await playwright.request.newContext({ baseURL, extraHTTPHeaders: { 'X-E2E-Cookiepath': '1' } });

	const first = await ctx.post('/wp-login.php', {
		form: { log: LOGIN, pwd: 'password', 'wp-submit': 'Log In', testcookie: '1', redirect_to: '/wp-admin/' },
		headers: { Cookie: 'wordpress_test_cookie=WP%20Cookie%20check' },
		maxRedirects: 0,
	});
	const html = await first.text();
	const token = html.match(/name="sigil_token" value="([a-f0-9]{64})"/)?.[1] ?? '';
	expect(token).toMatch(/^[a-f0-9]{64}$/);

	const nonce = html.match(/name="sigil_nonce" value="([a-f0-9]+)"/)?.[1] ?? '';
	expect(nonce).not.toBe('');

	const binding = first.headersArray().find((h) => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('sigil_challenge='));
	expect(binding?.value).toMatch(/path=\/(;|$)/i);

	const done = await ctx.post('/wp-login.php?action=sigil', {
		form: { sigil_token: token, sigil_provider: 'totp', code: totp(SECRET), sigil_nonce: nonce, sigil_authenticate: '1', sigil_redirect_to: '/wp-admin/' },
		maxRedirects: 0,
	});
	expect(done.status()).toBe(302);
	expect(done.headersArray().some((h) => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('wordpress_logged_in_') && !/expires=Thu, 01 Jan 1970/i.test(h.value))).toBe(true);

	await ctx.dispose();
});

test('the passwordless binding cookie is also sent on /', async ({ playwright, baseURL }) => {
	const ctx = await playwright.request.newContext({ baseURL, extraHTTPHeaders: { 'X-E2E-Cookiepath': '1' } });

	cli(['eval', "Sigil\\Policy::update( array( 'passwordless' => true ) );"]);
	const res = await ctx.get('/?rest_route=/sigil/v1/passwordless');
	expect(res.status()).toBe(200);

	const binding = res.headersArray().find((h) => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('sigil_passwordless='));
	expect(binding?.value).toMatch(/path=\/(;|$)/i);

	await ctx.dispose();
});

test('the trusted-device cookie is scoped to SITECOOKIEPATH and skips the challenge on the next sign-in', async ({ playwright, baseURL }) => {
	cli(['eval', "update_option( 'sigil_trusted_enabled', 1 );"]);
	const id = cli(['user', 'get', LOGIN, '--field=ID']).split('\n').pop();
	cli(['eval', `\\Sigil\\Store::set_method( ${id}, 'totp', array( 'secret' => base64_encode( \\Sigil\\Crypto::encrypt( '${SECRET}' ) ), 'last_step' => 0 ) );`]);
	const ctx = await playwright.request.newContext({ baseURL, extraHTTPHeaders: { 'X-E2E-Cookiepath': '1' } });
	const loginForm = { log: LOGIN, pwd: 'password', 'wp-submit': 'Log In', testcookie: '1', redirect_to: '/wp-admin/' };
	const testCookie = { Cookie: 'wordpress_test_cookie=WP%20Cookie%20check' };

	const first = await ctx.post('/wp-login.php', { form: loginForm, headers: testCookie, maxRedirects: 0 });
	const html = await first.text();
	const token = html.match(/name="sigil_token" value="([a-f0-9]{64})"/)?.[1] ?? '';
	const nonce = html.match(/name="sigil_nonce" value="([a-f0-9]+)"/)?.[1] ?? '';
	const trustNonce = html.match(/name="sigil_trust_nonce" value="([a-f0-9]+)"/)?.[1] ?? '';
	expect(token).not.toBe('');
	expect(trustNonce).not.toBe('');

	const done = await ctx.post('/wp-login.php?action=sigil', {
		form: { sigil_token: token, sigil_provider: 'totp', code: totp(SECRET, Date.now() - 30_000), sigil_nonce: nonce, sigil_authenticate: '1', sigil_redirect_to: '/wp-admin/', sigil_trust_device: '1', sigil_trust_nonce: trustNonce },
		maxRedirects: 0,
	});
	expect(done.status()).toBe(302);
	const trusted = done.headersArray().find((h) => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('sigil_pro_trusted='));
	expect(trusted?.value).toMatch(/path=\/(;|$)/i);
	expect(trusted?.value).not.toMatch(/path=\/en\//i);

	const again = await ctx.post('/wp-login.php', { form: loginForm, maxRedirects: 0 });
	expect(again.status()).toBe(302);
	expect(again.headers()['location']).toContain('/wp-admin');

	await ctx.dispose();
});
