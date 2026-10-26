import { execFileSync } from 'node:child_process';
import { test, expect } from '@playwright/test';
import { resetTwoFactor, login, totp } from './helpers';

test.beforeEach(() => resetTwoFactor());

function wp(...args: string[]): string {
	return execFileSync('npx', ['@wordpress/env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}

async function enrolTotp(page) {
	await page.goto('/wp-admin/users.php?page=sigil-2fa-setup&method=totp');
	const secret = await page.locator('input[name="sigil_totp_secret"]').inputValue();
	await page.fill('input[name="sigil_totp_code"]', totp(secret));
	await page.locator('.sigil-enrol__form button[type="submit"]').filter({ hasText: /enable/i }).click();
	await expect(page.locator('.notice-success')).toBeVisible();
}

// profile.php is one form. Anything Sigil put inside it as a form of its own
// was swallowed into it, and its fields hijacked the save.
test('the profile saves normally with the two-factor section on it', async ({ page }) => {
	await login(page);
	await enrolTotp(page);

	// The method tab with the most forms on it, which is the state where the
	// old section closed the profile form early and left Update orphaned.
	await page.goto('/wp-admin/profile.php?method=totp');
	expect(await page.evaluate(() => (document.getElementById('submit') as HTMLButtonElement).form?.id)).toBe('your-profile');
	const section = page.locator('.sigil-profile');
	await expect(section).toContainText('Authenticator app');
	await expect(section.locator('button, input, form')).toHaveCount(0);

	const name = `Sigil ${Date.now()}`;
	await page.fill('#first_name', name);
	await page.locator('#submit').click();
	await expect(page.locator('#message, .notice-success').first()).toContainText(/profile updated/i);

	await page.reload();
	await expect(page.locator('#first_name')).toHaveValue(name);
	await expect(page.locator('.sigil-profile')).toContainText('Authenticator app');
});

test('the profile links to the two-factor page', async ({ page }) => {
	await login(page);
	await page.goto('/wp-admin/profile.php');
	await page.getByRole('link', { name: 'Manage two-factor authentication' }).click();
	await expect(page).toHaveURL(/users\.php\?page=sigil-2fa-setup/);
	await expect(page.locator('.sigil-enrol h1')).toContainText(/two-factor/i);
});

test("an administrator resets someone else's two-factor from their profile", async ({ page }) => {
	const login_name = `profile_${Date.now()}`;
	const id = wp('user', 'create', login_name, `${login_name}@example.com`, '--role=subscriber', '--porcelain');
	wp('eval', `\\Sigil\\Store::set_method( ${id}, 'totp', array( 'secret' => 'x' ) );`);

	await login(page);
	await page.goto(`/wp-admin/user-edit.php?user_id=${id}`);
	const section = page.locator('.sigil-profile');
	await expect(section.locator('button, input, form')).toHaveCount(0);

	page.once('dialog', (dialog) => dialog.accept());
	await section.getByRole('link', { name: 'Reset two-factor authentication' }).click();
	await expect(page.locator('.notice-success')).toContainText(/was reset/i);
	expect(wp('eval', `echo \\Sigil\\Store::has_any( ${id} ) ? 'yes' : 'no';`)).toBe('no');

	wp('user', 'delete', id, '--yes');
});

test('a session that signed in a while ago confirms before setting a new password', async ({ page }) => {
	await login(page);
	await enrolTotp(page);
	wp(
		'eval',
		"$id = get_user_by( 'login', 'admin' )->ID; $s = get_user_meta( $id, 'session_tokens', true ); foreach ( $s as $k => $v ) { $s[ $k ]['login'] = time() - HOUR_IN_SECONDS; unset( $s[ $k ]['sigil_step_up'], $s[ $k ]['sigil_setup'] ); } update_user_meta( $id, 'session_tokens', $s );"
	);

	await page.goto('/wp-admin/profile.php');
	await page.locator('.wp-generate-pw').click();
	await page.fill('#pass1', 'a-new-password-1234!');
	await page.locator('#submit').click();

	await expect(page.getByText(/confirm it is you before changing your password/i)).toBeVisible();
	expect(wp('eval', "echo wp_check_password( 'password', get_user_by( 'login', 'admin' )->user_pass ) ? 'old' : 'changed';")).toBe('old');
});
