<div align="center">

# Sigil

[![License](https://img.shields.io/badge/LICENSE-GPL--3.0-5C9E31?style=for-the-badge)](LICENSE)
[![Built by](https://img.shields.io/badge/BUILT%20BY-JEAN%20GALEA-8A2BE2?style=for-the-badge)](https://jeangalea.com)

**Two-factor authentication for WordPress: passkeys, authenticator apps, backup codes and email codes, with per-role enforcement and recovery that actually works.**

</div>

Sigil does one job completely instead of holding half of it back. Passkeys, per-role enforcement, backup codes and lockout recovery are all in the free plugin. There is no account to create and nothing phones home.

## Methods

- Passkeys (WebAuthn): Face ID, Touch ID, Windows Hello, or a hardware key. Needs PHP 8.0+; on older PHP the method is hidden and the rest still works.
- Authenticator app (TOTP), any RFC 6238 app.
- Backup codes: ten single-use codes, generated at first enrolment.
- Email codes: six digits to the account email, as a fallback.

## Enforcement

Require 2FA per role or by capability, with a grace period so existing users get time to enrol. A "2FA" column on the Users screen shows who has set it up.

Authenticator setup shows a scannable QR, drawn in the browser by a bundled MIT library so the provisioning secret never leaves the page.

## Enrolment without the dashboard

Put `[sigil_2fa]` on a page and users manage their methods there. Sites that keep members out of wp-admin need this, and anyone required to enrol is sent to that page instead of an admin screen they cannot open.

## Multisite

WordPress accounts are network-wide, so second factors are too. An authenticator or backup codes cover every site, the policy is set once under Network Admin, and the rate limiter counts across the network rather than per site.

Passkeys are bound to the domain they were created for, so each site gets its own by default. A network under a single operator can widen that with the `sigil_rp_id` filter so one passkey covers every subdomain site. Opt-in, because widening lets any site under that domain request assertions.

Resetting another user's 2FA is a Network Admin action on a network, matching how WordPress governs user editing there.

## REST API

Routes under `sigil/v1`:

| Route | Method | Who |
|---|---|---|
| `/me` | GET | any logged-in user |
| `/users/<id>` | GET | the user themselves, or `list_users` |
| `/users/<id>/methods` | DELETE | `edit_users` on that user |
| `/users/<id>/methods/<provider>` | DELETE | the user themselves, or `edit_users` |
| `/policy` | GET, POST | `manage_options`, or `manage_network_options` on a network |
| `/challenge` | GET, POST | the challenge token issued after the password step |

The challenge routes let a decoupled front end run the second step itself, including passkeys. None of this adds a second factor to token authentication: a request authenticated with an application password never reaches the interactive login.

## Recovery

Backup codes are shown at first enrolment. An administrator can reset another user's 2FA from the Users screen, and `wp sigil reset <user>` clears a second factor from the command line when nobody can reach the dashboard.

## Application passwords

Application passwords authenticate the REST API and XML-RPC, and 2FA does not apply to them. Sigil says so on its settings screen and lets you disable them per role.

## Integrating

A sign-in that sets the auth cookie without `wp_signon()` (social login, magic links) is held for accounts with a second factor, and the `sigil_session_held` action fires with the user ID. Once your code has verified the person itself, call `\Sigil\Login_Guard::grant( $user_id )` before `wp_set_auth_cookie()`.

Changes to the password and email of your own account are confirmed through `\Sigil\Step_Up::allows( $user_id )`. Core, the REST users endpoint and WooCommerce are covered; a front-end account form from another plugin can call it before `wp_update_user()` or `wp_set_password()`.

## Development

```
composer install && npm install
composer test                              # unit tests, single site
vendor/bin/phpunit -c phpunit-multisite.xml.dist   # unit tests, network install
npx wp-env start && npx playwright test    # end-to-end, on localhost:8877
./build/build-free.sh                      # dist/sigil-2fa.zip
```

Requires WordPress 6.9+ and PHP 7.4+.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
