=== Sigil – Passkeys and Two-Factor Authentication ===
Contributors: jeangalea
Tags: two-factor, 2fa, passkeys, authentication, security
Requires at least: 6.9
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.4.1
License: GPL-3.0-or-later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Add two-factor authentication to WordPress logins: passkeys, authenticator apps, backup codes and email codes, with per-role enforcement.

== Description ==

Sigil adds a second authentication step to WordPress logins. Users enrol a passkey, an authenticator app, backup codes or email codes from their profile, and administrators can require 2FA for chosen roles with a grace period.

**Methods**

* Passkeys (WebAuthn), using a platform authenticator such as Face ID, Touch ID or Windows Hello, or a hardware security key. Requires PHP 8.0 or newer.
* Authenticator app (TOTP), compatible with any RFC 6238 application.
* Backup codes: ten single-use codes, generated the first time any method is set up.
* Email codes: a six-digit code sent to the account email address.

**Enforcement**

* Require 2FA per role, or for everyone with a chosen capability.
* Set a grace period so existing users get time to enrol instead of being locked out on the next login.
* A "2FA" column on the Users screen shows who has set it up and who has not.

**Enrolment without the dashboard**

Put `[sigil_2fa]` on any page and users can set up and manage their methods there. Sites that keep members out of wp-admin need this, and enforcement redirects to that page when it exists instead of to an admin screen the user cannot open.

**Multisite**

Accounts are network-wide in WordPress, so second factors are too. An authenticator or backup codes cover every site on the network, the policy is set once under Network Admin, and the rate limiter counts across the network rather than per site. On a network, resetting another user's 2FA is a Network Admin action, which is how WordPress governs user editing there.

Passkeys are bound to the domain they were created for, so by default a passkey covers the site it was registered on. A network under one operator can widen that to cover every subdomain site with the `sigil_rp_id` filter. It is opt-in because widening lets any site under that domain request assertions, which matters when sites have different administrators.

**REST API**

Routes under `sigil/v1` read a user's methods, reset or remove them, read and edit the policy, and describe or complete a pending login challenge so a decoupled front end can run the second step itself. The challenge routes are authenticated by the challenge token issued after the password step. Reading and changing anything else requires the same capability as the equivalent screen.

This does not add a second factor to token authentication. A request that authenticates with an application password never reaches the interactive login, so it is not challenged.

**Recovery**

Three ways back in if a second factor is lost:

* Backup codes are generated and displayed at first enrolment.
* A user with the `edit_users` capability can reset another user's 2FA from the Users screen.
* `wp sigil reset <user>` clears a user's second factor from the command line when no one can reach the dashboard.
* `wp sigil unlock <user> [--ip=<address>] [--challenge]` reopens password sign-in for an account paused by too many wrong passwords.

**Application passwords**

Two-factor authentication does not apply to application passwords, which authenticate REST API and XML-RPC requests. The settings screen documents this, and application passwords can be disabled per role.

== Third-party libraries ==

* QR Code Generator for JavaScript 2.0.4 by Kazuhiko Arase, MIT licensed, bundled unmodified at `assets/js/vendor/qrcode.js` (https://github.com/kazuhikoarase/qrcode-generator). Draws the authenticator QR in the browser.
* WebAuthn by Lukas Buchs, bundled in `vendor/`, used to verify passkey registrations and assertions.

Neither contacts an external service.

== Installation ==

1. Install through Plugins → Add New and search for "Sigil", or upload the plugin files to `/wp-content/plugins/sigil-2fa/`.
2. Activate it through the Plugins menu.
3. Go to Users → Two-Factor Setup and enrol your first method. Save the backup codes it shows you.
4. To require 2FA for other users, open Settings → Sigil and choose the roles and grace period. On a network, that screen is under Network Admin → Settings → Sigil.
5. If your users do not have dashboard access, create a page containing `[sigil_2fa]` and they can enrol there.

== Frequently Asked Questions ==

= What happens if I lose my phone and get locked out? =

Use one of the backup codes shown when you first set up 2FA. If you did not keep those, another administrator can reset your account from the Users screen. If nobody can get in at all, anyone with server access runs `wp sigil reset <your-username>` and your second factor is cleared.

= Someone keeps guessing my password and now I can't sign in. =

After five wrong passwords, password sign-in for that account pauses for 15 minutes, longer if it keeps happening, up to an hour. A passkey still signs you in during the pause. To reopen it straight away, anyone with server access runs `wp sigil unlock <your-username>`. Add `--ip=<address>` to clear an address that was paused too, and `--challenge` to clear wrong second-factor codes as well.

= Does the plugin require an external account or service? =

No. All authentication happens on your own site. The plugin does not contact any external service and does not require an account.

= Does this work with application passwords, the REST API, and XML-RPC? =

Application passwords bypass 2FA by design, as that is how WordPress authenticates automated requests. The settings screen documents this, and application passwords can be disabled per role to close that path. The account password itself is refused on XML-RPC and REST for anyone with a second factor, because those requests never reach the challenge.

= Which PHP version do I need for passkeys? =

Passkeys need PHP 8.0 or newer. On older PHP the plugin still runs and offers authenticator apps, backup codes, and email; only the passkey method is hidden.

= Does it work on multisite? =

Yes. The policy is set once for the network under Network Admin → Settings → Sigil, and a user's authenticator or backup codes work on every site because WordPress accounts are network-wide. Passkeys are bound to the domain they were created for, so each site gets its own unless you widen that with the `sigil_rp_id` filter.

= Can users set up 2FA without access to wp-admin? =

Yes. Put `[sigil_2fa]` on a page. Users manage their methods from there, and anyone required to enrol is sent to that page rather than to the dashboard.

= Can I switch from the Two Factor plugin? =

Yes. With both plugins active, open Settings → Sigil and use Import from Two Factor, or run `wp sigil import two-factor` (add `--dry-run` to preview). Email codes, authenticator apps and backup codes come across, so people keep signing in with the same app. Anyone with a method that cannot be carried over is listed in the report, and Two Factor keeps protecting them while it stays active. Two Factor's own data is not changed. Once everyone on that list has set up a method in Sigil, deactivate Two Factor.

= Can I enforce 2FA only for administrators? =

Yes. Settings → Sigil lets you pick exactly which roles are required, and set a grace period so people are prompted to enrol rather than locked out immediately.

== Changelog ==

= 0.4.1 =
* Security: a password alone no longer creates a session before the second step. Please update.
* Security: AJAX login forms no longer accept a password alone from users with a second factor.
* Sign-ins that skip the password (user switching, SSO, magic links) now require the second step. Integrations can call `Sigil\Login_Guard::grant()`.

= 0.4.0 =
* Moving from the Two Factor plugin no longer means everyone enrols again. Settings → Sigil and `wp sigil import two-factor` carry each user's email codes, authenticator app and backup codes across, so the same authenticator keeps working. Anyone with a method that cannot be carried over is named in the report and stays with Two Factor until they set one up in Sigil. Nobody is moved to email codes they did not already use, and Two Factor's own data is left as it was.
* While both plugins are active, Two Factor stands down for anyone Sigil already covers, so nobody is asked for a code twice. A notice offers the import until Two Factor is deactivated.
* Security: XML-RPC and REST no longer accept the account password from someone with a second factor. Those requests never reach the two-factor challenge, so a password alone was enough there. Application passwords still work.

= 0.3.3 =
* Everyone sharing one address, as an office, a school or a mobile network does, is no longer held to a single person's allowance of attempts. A few colleagues mistyping could stop everybody else signing in. Guessing any one account is bounded by the same five attempts as before.
* A site behind a proxy can now tell the plugin the real visitor address with the sigil_client_ip filter, instead of counting every visitor as the proxy.
* An account keeps only its newest few unspent verification sessions rather than an unlimited pile of them.
* The allowed-methods screen now says when a role was left with every method because nothing was ticked for it, rather than appearing to have discarded the save.

= 0.3.2 =
* A percent sign in the challenge wording no longer breaks the login screen. The line naming the person signing in was formatted rather than substituted, so wording like "50% off" stopped anybody with a second factor from completing a sign-in.
* An account holding only passkeys is no longer asked for a code when resetting its password. It was being emailed one that could never be accepted, which left the account unrecoverable.
* The two-factor column on the users list now reads each account's own rules rather than those of the administrator looking at the page, so an account no longer shows as having nothing set up when it has.
* Importing settings now says what happened, including when the imported policy is switched on but names nobody.
* The page carrying the enrolment form is only adopted when an administrator wrote it.

= 0.3.1 =
* Repeated login guesses are now counted in a way that a burst of simultaneous requests cannot outrun. The previous counter read a number, added one and wrote it back, so guesses arriving together all read the same number, and the real limit became however many requests could be made at once rather than the five it promised.
* A server that does not report the visitor's address no longer counts everybody together, where five failures anywhere would have held up every account on the site.
* Failed attempts are cleared out daily instead of being kept indefinitely.
* If the table the counter lives in goes missing, it is rebuilt rather than being allowed to refuse every sign-in.

= 0.3.0 =
* You are now emailed when a second factor is added to or removed from your account. Adding one is how somebody who already has your password keeps access, and nothing about the account looks different afterwards, so the only person who can notice is you.
* Anyone who becomes subject to a 2FA requirement is emailed once, when their deadline is set. People who never open the dashboard never saw the notice there, so the first they knew of a policy was the day it stopped them.
* The login code email now says where the code was requested from. It says "may be a proxy" rather than naming a location, because that is all the server actually knows.
* Administrators are warned when the server clock has drifted far enough to reject correct authenticator codes. Without it, a clock problem looks exactly like every user mistyping at once.
* You can choose which method you are asked for first, if you have set up more than one.

= 0.2.2 =
* Adds two extension points: `sigil_challenge_text` for the wording of the two-factor screen, and `sigil_manage_capability` for which capability reaches the settings. Values are escaped after filtering, and the capability filter only narrows, never widens.
* Nothing user-facing changed. Existing installs need do nothing.

= 0.2.1 =
* Multisite: when an upgrade merges per-site passkey tables, the highest signature counter for each credential is kept. Where the same authenticator was registered on two sites, the lower one could otherwise win and the clone check would have less to work with.
* Adds extension points so an add-on can rewrite the login code email, change where enrolment sends people afterwards, and load the front-end styles outside the shortcode. Nothing in the plugin behaves differently on its own.
* Nothing user-facing changed. Existing installs need do nothing.

= 0.2.0 =
* Authenticator setup now shows a scannable QR code. It is drawn in the browser by a bundled MIT-licensed library, so the provisioning secret is never sent anywhere.
* Security: a verification attempt now consumes its challenge token before the code is checked, so a burst of parallel guesses cannot outrun the attempt counter, and two simultaneous completions cannot both start a session. Mistyping a code still lets you try again; the screen carries a fresh token.
* Multisite support. One set of credentials and one policy for the whole network, edited under Network Admin, with rate limiting that counts across sites. Upgrading an existing install carries its policy and passkeys up to network scope.
* Front-end enrolment with the `[sigil_2fa]` shortcode, for sites whose users have no dashboard access. Enforcement sends people there when the page exists.
* A REST API under `sigil/v1` for reading 2FA state, managing methods, editing the policy, and completing a login challenge from a decoupled front end.
* Security: resetting a user's 2FA treated a missing actor as an exemption rather than as nobody. That was reachable only from the command line before this release, but it is now refused outright, with the unattended path named separately.
* Fixed the enrolment redirect pointing at the wrong admin screen, and the provisioning URI appearing twice during authenticator setup.

= 0.1.3 =
* Fixed the two-factor screen at login: it had no stylesheet, so the method switcher rendered as a bare list and the buttons overlapped.
* Fixed passkey sign-in, which could never complete. The browser prompt was requested through an authenticated endpoint the logged-out challenge screen could not reach.
* Email codes are now actually sent when the screen asks for one, and a wrong code no longer invalidates the code already in your inbox.
* A refresh or a second tab no longer invalidates an outstanding passkey prompt.

= 0.1.2 =
* Author attribution updated to Jean Galea.

= 0.1.1 =
* Renamed the plugin to Sigil. The text domain is now `sigil-2fa` and the WP-CLI command is `wp sigil`.
* Translations are no longer bundled; they come from translate.wordpress.org.

= 0.1.0 =
* First release: passkeys, authenticator apps, backup codes, and email codes.
* Per-role enforcement with a configurable grace period.
* Lockout recovery: backup codes, admin reset, and a WP-CLI reset command.
* Per-role application-password control.
