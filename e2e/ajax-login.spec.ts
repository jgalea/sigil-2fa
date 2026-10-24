import { test, expect, APIResponse } from '@playwright/test';
import { execFileSync } from 'node:child_process';

// e2e/mu-ajax-login.php registers two admin-ajax logins, one through
// wp_signon() and one that sets the cookie itself, the way popup and theme
// login forms do. Neither may hand a session to someone with a second factor.

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const PASS = 'password';

function cli(args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' }).trim();
}

function userId(login: string): string {
	return cli(['user', 'get', login, '--field=ID']).split(/\s+/).filter(Boolean).pop() ?? '';
}

// Session cookies the response actually sets, leaving out the deletions
// wp_clear_auth_cookie() sends.
function sessionCookies(res: APIResponse): string[] {
	return res
		.headersArray()
		.filter((h) => h.name.toLowerCase() === 'set-cookie')
		.map((h) => h.value)
		.filter((v) => /^wordpress_(sec_|logged_in_)?[a-f0-9]{32}=/.test(v))
		.filter((v) => !/^[^=]+=(deleted|\s*);/i.test(v) && !/expires=[^;]*1970/i.test(v));
}

async function ajaxLogin(request: any, action: string, user: string, pass: string) {
	return request.post('/wp-admin/admin-ajax.php', { form: { action, log: user, pwd: pass } });
}

test.beforeAll(() => {
	for (const login of ['ajax_2fa', 'ajax_plain']) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// not there yet
		}
		cli(['user', 'create', login, `${login}@example.com`, `--user_pass=${PASS}`, '--role=editor']);
	}

	cli([
		'eval',
		`\\Sigil\\Store::set_method( ${userId('ajax_2fa')}, 'totp', array( 'secret' => base64_encode( \\Sigil\\Crypto::encrypt( '${SECRET}' ) ), 'last_step' => 0 ) );`,
	]);
	expect(cli(['sigil', 'status', 'ajax_2fa'])).toContain('totp');
});

test.afterAll(() => {
	for (const login of ['ajax_2fa', 'ajax_plain']) {
		try {
			cli(['user', 'delete', login, '--yes']);
		} catch {
			// already gone
		}
	}
});

for (const action of ['sigil_e2e_signon', 'sigil_e2e_set_cookie']) {
	test(`${action}: the password alone gets no session for someone with a second factor`, async ({ page }) => {
		const res = await ajaxLogin(page.request, action, 'ajax_2fa', PASS);
		expect(res.status()).toBe(200);
		expect(sessionCookies(res)).toEqual([]);

		if (action === 'sigil_e2e_signon') {
			const body = await res.json();
			expect(body.success).toBe(false);
			expect(body.data.code).toBe('sigil_ajax_password_refused');
			expect(body.data.message).toMatch(/two-factor/i);
			expect(body.data.data.login_url).toContain('wp-login.php');
		}

		await page.goto('/wp-admin/');
		await expect(page).toHaveURL(/wp-login\.php/);
		await expect(page.locator('#wpadminbar')).toHaveCount(0);
	});

	test(`${action}: someone without a second factor still signs in`, async ({ page }) => {
		const res = await ajaxLogin(page.request, action, 'ajax_plain', PASS);
		expect((await res.json()).success).toBe(true);
		expect(sessionCookies(res).length).toBeGreaterThanOrEqual(2);

		await page.goto('/wp-admin/');
		await expect(page.locator('#wpadminbar')).toBeVisible();
	});
}

test('application passwords still work on REST for someone with a second factor', async ({ request }) => {
	const appPassword = cli(['user', 'application-password', 'create', 'ajax_2fa', 'e2e', '--porcelain']).split(/\s+/).pop() ?? '';
	expect(appPassword.length).toBeGreaterThan(20);

	const me = (pass: string) =>
		request.get('/?rest_route=/wp/v2/users/me', {
			headers: { Authorization: 'Basic ' + Buffer.from(`ajax_2fa:${pass}`).toString('base64') },
		});

	const ok = await me(appPassword);
	expect(ok.status()).toBe(200);
	expect((await ok.json()).id).toBe(Number(userId('ajax_2fa')));

	expect((await me(PASS)).status()).toBe(401);
});
