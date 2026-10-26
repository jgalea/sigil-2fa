# Release smoke test

Installs a built Sigil zip on a real WordPress (Apache, MySQL 8, `WP_DEBUG` and `WP_DEBUG_LOG` on) in Docker and checks that it doesn't break a site or weaken a login. It runs before every wordpress.org deploy (`deploy.yml` calls `smoke.yml` and deploys only if it passes) and on pull requests to `main`.

## Run it

```
bash build/build-free.sh
bash tests/smoke/run.sh dist/sigil-2fa.zip                # newest PHP (8.5)
bash tests/smoke/run.sh dist/sigil-2fa.zip --php min      # Requires PHP from the plugin header
```

It works with any zip that has a `sigil-2fa/` folder. It needs Docker and curl, and downloads WordPress, the current wordpress.org release and Plugin Check on each run.

Options: `--php min|max|X.Y`, `--port 8977`, `--baseline-zip old.zip` (upgrade from this zip instead of the wordpress.org release), `--skip-upgrade`, `--skip-plugin-check`, `--keep` (leave the site running), `--update-baseline` (rewrite the Plugin Check baseline).

It takes about 2 minutes per PHP version, most of it the upgrade scenario (60s) and Plugin Check (16s). Exit status is non-zero if anything fails.

## What it checks

Fresh install:

- the zip installs and activates, creates its tables, and logs no PHP fatal, warning, notice or deprecation from the plugin's own files
- the front page returns 200; `wp-login.php` shows the login form and, on PHP 8+, the "Sign in with a passkey" button (below PHP 8 the button must be absent)
- every Sigil screen in the admin menu, plus the profile screen, returns 200 with no critical error; the settings screen renders the policy form

Second factor, read from the raw `Set-Cookie` headers the way `e2e/login-session.spec.ts` does:

- a user with an authenticator and backup codes who posts a password gets the challenge page, no live session cookie, no session token, and the cookies WordPress sent can't open the dashboard
- a wrong code is refused and issues nothing; a correct code, computed by the test's own TOTP, gives a live session that opens the profile
- controls: an administrator the policy doesn't cover gets a live session from the password alone, and so does the second-factor user once the plugin is deactivated, which proves the cookie check can see a session

Deactivate and reactivate: front end and wp-admin load with the plugin off, the data stays, and after reactivating the challenge is back.

Upgrade: installs the current wordpress.org release (or `--baseline-zip`), enrols an authenticator and ten backup codes, sets a policy and a setting, installs the new zip over it, and checks that the first admin request runs the schema upgrade (db version and new credential columns), the policy, setting and factors survive, the authenticator and a backup code both still sign in, and nothing is logged.

Plugin Check, one check at a time, fails on errors that aren't in `plugin-check-baseline.txt`.

Uninstall: `uninstall.php`, run through `wp eval-file`, drops both tables and removes every `sigil_` option and transient and every `_sigil_` user meta key. The test first asserts there was something to remove.

The error check is only as good as the log: each scenario starts by writing a canary line and fails if it can't read it back.

## Plugin Check baseline

Plugin Check reports a few errors today, so the gate is a ratchet: `plugin-check-baseline.txt` lists each known error as `count check code file`, and a run fails if any count rises or a new one appears. Fix some and run with `--update-baseline` to shrink the file. The five runtime checks (script and style size and scope, loading strategy) are skipped: they only raise performance warnings and crash intermittently on PHP 7.4.

## Notes

The tests run on the zip from `build/build-free.sh`. The wordpress.org deploy step ships the `.distignore` tree, which has the same files but isn't the same bytes.
