import { test, expect, APIResponse, APIRequestContext } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { totp } from './helpers';

// WordPress sets the session cookie inside wp_signon(), before wp_login fires
// and Sigil's challenge runs. Clearing it afterwards only appends expiring
// headers after the live ones, so a client that keeps the first ones is signed
// in on the password alone. These read the raw headers to make sure no live
// session cookie is issued at all until the second factor is through.

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const PASS = 'password';
const USERS = ['sess_2fa', 'sess_plain', 'sess_skip', 'sess_pw'];

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

function enrolTotp(login: string) {
	cli([
		'eval',
		`\\Sigil\\Store::set_method( ${userId(login)}, 'totp', array( 'secret' => base64_encode( \\Sigil\\Crypto::encrypt( '${SECRET}' ) ), 'last_step' => 0 ) );`,
	]);
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

// The first value sent under each session cookie name, live or not: what a
// client that ignores the later clearing headers would keep.
function firstIssued(cookies: Cookie[]): string {
	const first = new Map<string, string>();
	for (const c of cookies) {
		if (c.value !== '' && !first.has(c.name)) {
			first.set(c.name, c.value);
		}
	}
	return [...first].map(([n, v]) => `${n}=${v}`).join('; ');
}

async function passwordPost(request: APIRequestContext, login: string): Promise<APIResponse> {
	return request.post('/wp-login.php', {
		form: { log: login, pwd: PASS, 'wp-submit': 'Log In', testcookie: '1', redirect_to: '/wp-admin/' },
		headers: { Cookie: 'wordpress_test_cookie=WP%20Cookie%20check' },
		maxRedirects: 0,
	});
}

async function profileWith(playwright: any, baseURL: string, cookie: string): Promise<APIResponse> {
	const ctx = await playwright.request.newContext({ baseURL, extraHTTPHeaders: cookie ? { Cookie: cookie } : {} });
	return ctx.get('/wp-admin/profile.php', { maxRedirects: 0 });
}

test.beforeAll(() => {
	for (const login of USERS) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// not there yet
		}
		cli(['user', 'create', login, `${login}@example.com`, `--user_pass=${PASS}`, '--role=editor']);
	}
	enrolTotp('sess_2fa');
	enrolTotp('sess_skip');
	enrolTotp('sess_pw');
	cli(['user', 'meta', 'update', 'sess_skip', 'sigil_e2e_skip', '1']);
});

test.afterAll(() => {
	for (const login of USERS) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// already gone
		}
	}
});

test('the password alone issues no session to someone with a second factor', async ({ request, playwright, baseURL }) => {
	const before = sessionCount('sess_2fa');

	const res = await passwordPost(request, 'sess_2fa');
	expect(await res.text()).toContain('sigil-challenge-form');

	// Soft, so a failure reports all three ways the session could leak.
	const cookies = setCookies(res);
	expect.soft(cookies.filter((c) => c.live).map((c) => c.name)).toEqual([]);

	const replay = await profileWith(playwright, baseURL!, firstIssued(cookies));
	expect.soft(replay.status()).toBe(302);
	expect.soft(replay.headers()['location'] ?? '').toContain('wp-login.php');

	expect.soft(sessionCount('sess_2fa')).toBe(before);
});

// Control: the same checks recognise a real session when one is issued.
test('someone without a second factor still gets a working session', async ({ request, playwright, baseURL }) => {
	const res = await passwordPost(request, 'sess_plain');
	expect(res.status()).toBe(302);

	const cookies = setCookies(res);
	expect(cookies.filter((c) => c.live && c.name.startsWith('wordpress_logged_in_')).length).toBeGreaterThan(0);

	const profile = await profileWith(playwright, baseURL!, firstIssued(cookies));
	expect(profile.status()).toBe(200);
	expect(await profile.text()).toContain('id="your-profile"');
});

test('completing the challenge over REST issues the session', async ({ request, playwright, baseURL }) => {
	const res = await passwordPost(request, 'sess_2fa');
	const token = (await res.text()).match(/name="sigil_token" value="([a-f0-9]{64})"/)?.[1] ?? '';
	expect(token).toMatch(/^[a-f0-9]{64}$/);

	const done = await request.post('/?rest_route=/sigil/v1/challenge', {
		data: { token, provider: 'totp', code: totp(SECRET) },
	});
	expect(done.status()).toBe(200);
	expect((await done.json()).success).toBe(true);

	const cookies = setCookies(done);
	expect(cookies.filter((c) => c.live && c.name.startsWith('wordpress_logged_in_')).length).toBeGreaterThan(0);

	const profile = await profileWith(playwright, baseURL!, firstIssued(cookies));
	expect(profile.status()).toBe(200);
});

test('a sign-in excused through sigil_skip_challenge still gets its session', async ({ request, playwright, baseURL }) => {
	const res = await passwordPost(request, 'sess_skip');
	expect(res.status()).toBe(302);

	const cookies = setCookies(res);
	expect(cookies.filter((c) => c.live && c.name.startsWith('wordpress_logged_in_')).length).toBeGreaterThan(0);

	const profile = await profileWith(playwright, baseURL!, firstIssued(cookies));
	expect(profile.status()).toBe(200);
});

// WordPress re-issues the session when someone changes their own password. They
// arrived signed in, so holding it would sign them out mid-edit.
test('changing your own password keeps you signed in', async ({ page }) => {
	await page.goto('/wp-login.php');
	await page.locator('#user_login').waitFor({ state: 'visible' });
	await page.waitForFunction(() => document.activeElement?.id === 'user_login', undefined, { timeout: 5_000 }).catch(() => {});
	await page.locator('#user_login').fill('sess_pw');
	await page.locator('#user_pass').fill(PASS);
	await expect(page.locator('#user_pass')).toHaveValue(PASS);
	await page.click('#wp-submit');

	const code = page.locator('#sigil-challenge-form input[name="code"]');
	await expect(code).toBeVisible({ timeout: 30_000 });
	await code.fill(totp(SECRET));
	await page.locator('#sigil-authenticate').click();
	await page.waitForURL(/\/wp-admin\//);

	// The form posted the way profile.php's own submit button does, with the
	// browser's cookies, so what comes back lands in the same cookie jar.
	await page.goto('/wp-admin/profile.php');
	const form = page.locator('#your-profile');
	const field = (name: string) => form.locator(`[name="${name}"]`).first().inputValue();
	const res = await page.request.post('/wp-admin/profile.php', {
		form: {
			_wpnonce: await field('_wpnonce'),
			_wp_http_referer: '/wp-admin/profile.php',
			from: 'profile',
			checkuser_id: await field('checkuser_id'),
			user_id: await field('user_id'),
			action: 'update',
			email: await field('email'),
			nickname: await field('nickname'),
			display_name: 'sess_pw',
			pass1: 'a-new-password-for-e2e-9431',
			pass2: 'a-new-password-for-e2e-9431',
		},
		maxRedirects: 0,
	});
	expect(res.status()).toBe(302);
	expect(res.headers()['location']).toContain('updated=1');
	expect(setCookies(res).filter((c) => c.live && c.name.startsWith('wordpress_logged_in_')).length).toBeGreaterThan(0);

	await page.goto('/wp-admin/profile.php');
	await expect(page).toHaveURL(/profile\.php/);
	await expect(page.locator('#your-profile')).toBeVisible();
});
