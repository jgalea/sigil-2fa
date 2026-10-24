import { defineConfig } from '@playwright/test';

export default defineConfig({
	testDir: './e2e',
	// CI runners are slower and share a machine with whatever else the job is
	// doing, and every failure so far under load has been a wait expiring rather
	// than anything asserting wrongly.
	timeout: process.env.CI ? 150_000 : 60_000,
	expect: { timeout: process.env.CI ? 20_000 : 5_000 },
	fullyParallel: false,
	workers: 1,
	retries: 0,
	use: {
		baseURL: process.env.WP_BASE_URL || 'http://localhost:8877',
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
	},
});
