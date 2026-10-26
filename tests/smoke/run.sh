#!/usr/bin/env bash
# Smoke test for a built Sigil zip on a real WordPress (MySQL, Apache, WP_DEBUG
# on). See tests/smoke/README.md.
#
#   tests/smoke/run.sh path/to/sigil-2fa.zip [--php min|max|X.Y] [--port 8977]
#                      [--baseline-zip old.zip] [--skip-upgrade] [--skip-plugin-check]
#                      [--update-baseline] [--keep]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEWEST_PHP="8.5"
PLUGIN_DIR="wp-content/plugins/sigil-2fa"
ADMIN_PW="smoke-admin-pass"
USER_PW="smoke-user-pass"
SECRET="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

ZIP=""
PHP_VERSION="max"
PORT="8977"
BASELINE_ZIP=""
SKIP_UPGRADE=0
SKIP_PLUGIN_CHECK=0
UPDATE_BASELINE=0
KEEP=0

while [ $# -gt 0 ]; do
	case "$1" in
		--php) PHP_VERSION="$2"; shift 2 ;;
		--port) PORT="$2"; shift 2 ;;
		--baseline-zip) BASELINE_ZIP="$2"; shift 2 ;;
		--skip-upgrade) SKIP_UPGRADE=1; shift ;;
		--skip-plugin-check) SKIP_PLUGIN_CHECK=1; shift ;;
		--update-baseline) UPDATE_BASELINE=1; shift ;;
		--keep) KEEP=1; shift ;;
		-h|--help) sed -n 2,9p "${BASH_SOURCE[0]}"; exit 0 ;;
		-*) echo "Unknown option: $1" >&2; exit 2 ;;
		*) ZIP="$1"; shift ;;
	esac
done

[ -f "$ZIP" ] || { echo "Usage: $0 path/to/sigil-2fa.zip [options]" >&2; exit 2; }
ZIP="$(cd "$(dirname "$ZIP")" && pwd)/$(basename "$ZIP")"
[ "$(unzip -Z1 "$ZIP" | grep -cx 'sigil-2fa/sigil-2fa.php')" -eq 1 ] || { echo "$ZIP has no sigil-2fa/sigil-2fa.php" >&2; exit 2; }

ZIP_VERSION="$(unzip -p "$ZIP" sigil-2fa/sigil-2fa.php | sed -n 's/^ \* Version:[[:space:]]*//p' | head -1 | tr -d '\r')"
MIN_PHP="$(unzip -p "$ZIP" sigil-2fa/sigil-2fa.php | sed -n 's/^ \* Requires PHP:[[:space:]]*//p' | head -1 | tr -d '\r')"
[ -n "$ZIP_VERSION" ] && [ -n "$MIN_PHP" ] || { echo "Could not read Version / Requires PHP from the zip's plugin header" >&2; exit 2; }
case "$PHP_VERSION" in
	min) PHP_VERSION="$MIN_PHP" ;;
	max) PHP_VERSION="$NEWEST_PHP" ;;
esac

BASE="http://localhost:$PORT"
PROJECT="sigil-smoke-${PHP_VERSION//./}-$PORT"
WORK="$(mktemp -d)"
JAR="$WORK/jar.txt"
PASSED=0
FAILED=0
STARTED=$SECONDS

export SMOKE_PHP="$PHP_VERSION" SMOKE_PORT="$PORT"

dc() { docker compose -p "$PROJECT" -f "$WORK/docker-compose.yml" "$@"; }
wp() { dc exec -T -e "SMOKE_TOTP_SECRET=$SECRET" -e "SMOKE_TOTP_STEPS=${SMOKE_TOTP_STEPS:-0}" cli wp "$@"; }

cleanup() {
	if [ "$KEEP" -eq 1 ]; then
		echo "Left running: $BASE (admin / $ADMIN_PW), project $PROJECT, files in $WORK"
		return
	fi
	dc down -v --remove-orphans >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

ok() { PASSED=$((PASSED + 1)); echo "  ok    $1"; }
bad() { FAILED=$((FAILED + 1)); echo "  FAIL  $1"; }
check() { # description, status
	if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi
}
phase() { PHASE_START=$SECONDS; echo; echo "== $1"; }
phase_end() { echo "   ($((SECONDS - PHASE_START))s)"; }

state() { wp eval-file /smoke/php/state.php 2>/dev/null | sed -n "s/^$1=//p"; }

http_code() { curl -s -o "$WORK/body.html" -w '%{http_code}' "$@"; }

body_is_clean() { # no critical-error page, no fatal text, document was not cut short
	! grep -qiE 'critical error on this website|Fatal error:|Parse error:' "$WORK/body.html" && grep -qi '</html>' "$WORK/body.html"
}

prepare_work_dir() {
	mkdir -p "$WORK/zips" "$WORK/smoke"
	cp "$HERE/docker-compose.yml" "$WORK/"
	cp -R "$HERE/php" "$HERE/plugin-check.sh" "$WORK/smoke/"
	cp "$ZIP" "$WORK/zips/new.zip"
	[ -n "$BASELINE_ZIP" ] && cp "$BASELINE_ZIP" "$WORK/zips/baseline.zip"
	printf 'Listen %s\n<VirtualHost *:%s>\n\tDocumentRoot /var/www/html\n</VirtualHost>\n' "$PORT" "$PORT" > "$WORK/apache-port.conf"
}

clear_log() { dc exec -T cli sh -c ': > /var/www/html/wp-content/debug.log'; }

start_stack() {
	dc down -v --remove-orphans >/dev/null 2>&1
	dc up -d >/dev/null 2>&1 || { echo "docker compose up failed" >&2; exit 1; }
	local i
	for i in $(seq 1 60); do
		dc exec -T cli test -f /var/www/html/wp-includes/version.php 2>/dev/null && break
		sleep 1
	done
	# The php7.4 image is frozen on an old WordPress; the plugin needs a current one.
	wp core download --version=latest --force --skip-content >/dev/null 2>&1 || { echo "wp core download failed" >&2; exit 1; }
	wp config create --dbhost=db --dbuser=root --dbpass=root --dbname=wp --skip-check --extra-php >/dev/null <<'PHP'
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
define( 'WP_ENVIRONMENT_TYPE', 'local' );
define( 'DISABLE_WP_CRON', true );
PHP
	wp core install --url="$BASE" --title=Smoke --admin_user=admin --admin_password="$ADMIN_PW" --admin_email=smoke@example.com --skip-email >/dev/null 2>&1 || { echo "wp core install failed" >&2; exit 1; }
	for i in $(seq 1 30); do
		[ "$(http_code "$BASE/wp-login.php")" = "200" ] && break
		sleep 1
	done

	# Control for the log filter: a line written the way PHP writes one must be readable here.
	wp eval 'error_log( "SMOKE-CANARY" );' >/dev/null 2>&1
	if dc exec -T cli grep -q SMOKE-CANARY /var/www/html/wp-content/debug.log 2>/dev/null; then
		ok "debug.log is writable and readable (WP $(wp core version), PHP $(dc exec -T cli php -r 'echo PHP_VERSION;'))"
	else
		bad "debug.log canary did not appear, so the error checks below would pass vacuously"
	fi
	clear_log
}

# Entries from the plugin's own files, any PHP fatal anywhere, and database errors that name the plugin.
check_log() { # label
	local found
	found="$(dc exec -T cli cat /var/www/html/wp-content/debug.log 2>/dev/null | awk -v pat="$PLUGIN_DIR/" '
		function flush() {
			if (entry == "") return
			if (entry ~ /PHP (Fatal error|Parse error|Catchable fatal error)/) print entry
			else if (entry ~ /PHP (Warning|Notice|Deprecated|Strict Standards)/ && (index(entry, pat) || tolower(entry) ~ /sigil/)) print entry
			else if (entry ~ /WordPress database error/ && (index(entry, pat) || tolower(entry) ~ /sigil/)) print entry
		}
		/^\[[0-9][0-9]-[A-Za-z][A-Za-z][A-Za-z]-[0-9][0-9][0-9][0-9] / { flush(); entry = $0; next }
		{ entry = entry "\n" $0 }
		END { flush() }
	')"
	if [ -z "$found" ]; then
		ok "no PHP errors from the plugin in debug.log ($1)"
	else
		bad "PHP errors from the plugin in debug.log ($1)"
		printf '%s\n' "$found" | head -6 | cut -c1-300 | sed 's/^/        /'
	fi
	clear_log
}

login() {
	rm -f "$JAR"
	curl -s -c "$JAR" -b "$JAR" -H 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' -o /dev/null \
		-d "log=admin&pwd=$ADMIN_PW&wp-submit=Log+In&redirect_to=$BASE/wp-admin/&testcookie=1" "$BASE/wp-login.php"
	local code
	code="$(http_code -b "$JAR" "$BASE/wp-admin/")"
	check "administrator can log in and open /wp-admin/" "$([ "$code" = "200" ] && echo 0 || echo 1)"
}

# Raw Set-Cookie handling, as e2e/login-session.spec.ts does it: WordPress sets
# the session cookie before the challenge runs, and clearing it afterwards only
# appends expiring headers after the live ones.
auth_cookie_re='^wordpress_(sec_|logged_in_)?[a-f0-9]{32}$'
max_age_zero_re='[Mm]ax-[Aa]ge=(0|-)'
expires_re='[Ee]xpires=[A-Za-z]+, [0-9]+[ -][A-Za-z]+[ -]([0-9]+)'

live_cookies() { # header file: names of live session cookies
	local line pair name val
	tr -d '\r' < "$1" | grep -i '^set-cookie:' | sed 's/^[Ss]et-[Cc]ookie: *//' | while IFS= read -r line; do
		pair="${line%%;*}"; name="${pair%%=*}"; val="${pair#*=}"
		[[ "$name" =~ $auth_cookie_re ]] || continue
		[ -z "${val// /}" ] || [ "$val" = "deleted" ] || [ "$val" = "+" ] && continue
		[[ "$line" =~ $max_age_zero_re ]] && continue
		if [[ "$line" =~ $expires_re ]] && [ "${BASH_REMATCH[1]}" -lt "$(date +%Y)" ]; then continue; fi
		echo "$name"
	done
}

first_issued() { # header file: the first value sent under each session cookie name, live or not
	local line pair name val seen=" " out=""
	while IFS= read -r line; do
		pair="${line%%;*}"; name="${pair%%=*}"; val="${pair#*=}"
		[[ "$name" =~ $auth_cookie_re ]] || continue
		[ -n "${val// /}" ] || continue
		case "$seen" in *" $name "*) continue ;; esac
		seen="$seen$name "
		out="$out${out:+; }$name=$val"
	done < <(tr -d '\r' < "$1" | grep -i '^set-cookie:' | sed 's/^[Ss]et-[Cc]ookie: *//')
	printf '%s' "$out"
}

live_logged_in() { live_cookies "$1" | grep -c '^wordpress_logged_in_'; }

sessions() { wp eval "echo count( WP_Session_Tokens::get_instance( (int) get_user_by( 'login', '$1' )->ID )->get_all() );" 2>/dev/null; }

password_post() { # user, password -> headers in $WORK/h.txt, body in $WORK/pw.html
	curl -s -D "$WORK/h.txt" -o "$WORK/pw.html" -w '%{http_code}' -H 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' \
		--data-urlencode "log=$1" --data-urlencode "pwd=$2" -d "wp-submit=Log+In&testcookie=1&redirect_to=$BASE/wp-admin/" "$BASE/wp-login.php"
}

submit_challenge() { # provider, code -> headers in $WORK/h2.txt, body in $WORK/ch.html
	local token nonce action
	token="$(grep -o 'name="sigil_token" value="[a-f0-9]*"' "$WORK/pw.html" | head -1 | sed 's/.*value="//; s/"$//')"
	nonce="$(grep -o 'name="sigil_nonce" value="[^"]*"' "$WORK/pw.html" | head -1 | sed 's/.*value="//; s/"$//')"
	action="$(grep -o '<form name="sigil_challenge"[^>]*' "$WORK/pw.html" | head -1 | sed 's/.*action="//; s/".*//; s/&#038;/\&/g; s/&amp;/\&/g')"
	if [ -z "$token" ] || [ -z "$nonce" ] || [ -z "$action" ]; then
		: > "$WORK/h2.txt"; : > "$WORK/ch.html"
		echo "000"
		return
	fi
	curl -s -D "$WORK/h2.txt" -o "$WORK/ch.html" -w '%{http_code}' -H 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' \
		--data-urlencode "sigil_token=$token" --data-urlencode "sigil_nonce=$nonce" --data-urlencode "sigil_provider=$1" \
		--data-urlencode "code=$2" -d 'sigil_authenticate=1&sigil_remember=&sigil_redirect_to=' "$action"
}

totp_code() { SMOKE_TOTP_STEPS="${1:-0}" wp eval-file /smoke/php/totp-code.php 2>/dev/null | tr -d '\r\n'; }

profile_code() { curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $1" "$BASE/wp-admin/profile.php"; }

# The password alone must not buy a session for someone with a second factor.
check_password_only_blocked() { # label
	local code before after live replay
	before="$(sessions smoke_2fa)"
	code="$(password_post smoke_2fa "$USER_PW")"
	live="$(live_cookies "$WORK/h.txt" | wc -l | tr -d ' ')"
	check "$1: password alone shows the challenge page (HTTP $code)" "$(grep -q 'id="sigil-challenge-form"' "$WORK/pw.html" && echo 0 || echo 1)"
	check "$1: password alone issues no live session cookie ($live)" "$([ "$live" -eq 0 ] && echo 0 || echo 1)"
	replay="$(profile_code "$(first_issued "$WORK/h.txt")")"
	check "$1: cookies from the password step don't open the dashboard (HTTP $replay)" "$([ "$replay" = "302" ] && echo 0 || echo 1)"
	after="$(sessions smoke_2fa)"
	check "$1: password alone creates no session token ($before -> $after)" "$([ -n "$before" ] && [ "$before" = "$after" ] && echo 0 || echo 1)"
}

check_second_factor() {
	local code live replay

	# Control: someone the policy doesn't cover gets a session from the password alone,
	# so a "no cookie" result above means something.
	code="$(password_post admin "$ADMIN_PW")"
	check "control: an administrator with no second factor gets a live session from the password ($code)" "$([ "$(live_logged_in "$WORK/h.txt")" -ge 1 ] && echo 0 || echo 1)"

	check_password_only_blocked "second factor"

	code="$(submit_challenge totp 000000)"
	live="$(live_cookies "$WORK/h2.txt" | wc -l | tr -d ' ')"
	check "a wrong code is refused and issues no session (HTTP $code, $live live cookies)" "$([ "$live" -eq 0 ] && [ "$code" = "200" ] && echo 0 || echo 1)"

	password_post smoke_2fa "$USER_PW" >/dev/null
	code="$(submit_challenge totp "$(totp_code)")"
	live="$(live_logged_in "$WORK/h2.txt")"
	replay="$(profile_code "$(first_issued "$WORK/h2.txt")")"
	check "a correct authenticator code gives a live session (HTTP $code, profile $replay)" "$([ "$code" = "302" ] && [ "$live" -ge 1 ] && [ "$replay" = "200" ] && echo 0 || echo 1)"
}

check_login_page() {
	local code want
	code="$(http_code "$BASE/wp-login.php")"
	check "wp-login.php: 200 with the login form" "$([ "$code" = "200" ] && body_is_clean && grep -q 'id="loginform"' "$WORK/body.html" && echo 0 || echo 1)"
	if [ "$(dc exec -T cli php -r 'echo PHP_MAJOR_VERSION;')" -ge 8 ]; then
		check "wp-login.php offers \"Sign in with a passkey\" (PHP 8+)" "$(grep -q 'Sign in with a passkey' "$WORK/body.html" && echo 0 || echo 1)"
	else
		check "wp-login.php hides the passkey button below PHP 8" "$(grep -q 'Sign in with a passkey' "$WORK/body.html" && echo 1 || echo 0)"
	fi
}

check_front() {
	local code
	code="$(http_code -L "$BASE/")"
	check "front page: 200, no critical error" "$([ "$code" = "200" ] && body_is_clean && echo 0 || echo 1)"
	check_login_page
}

check_admin() {
	local menu pages page code
	menu="$(curl -s -b "$JAR" "$BASE/wp-admin/index.php")"
	pages="$( { printf '%s' "$menu" | grep -o "href='[^']*page=sigil[^']*'" | sed "s/^href='//; s/'$//"; echo profile.php; } | sed 's/&#038;/\&/g; s/&amp;/\&/g' | sort -u)"
	if [ "$(printf '%s\n' "$pages" | grep -c 'page=sigil')" -lt 2 ]; then
		bad "admin menu discovery found fewer than 2 Sigil screens: [$(printf '%s' "$pages" | tr '\n' ' ')]"
		return
	fi
	ok "admin menu lists $(printf '%s\n' "$pages" | grep -c 'page=sigil') Sigil screens"
	for page in $pages; do
		code="$(http_code -b "$JAR" "$BASE/wp-admin/$page")"
		if [ "$code" = "200" ] && body_is_clean; then
			ok "admin screen $page: 200, no critical error"
		else
			bad "admin screen $page: HTTP $code, clean=$(body_is_clean && echo yes || echo no)"
		fi
		case "$page" in
			*page=sigil-2fa)
				check "settings screen renders the policy form" "$(grep -q 'sigil_policy\[' "$WORK/body.html" && echo 0 || echo 1)"
				;;
		esac
	done
}

install_zip() { # zip-in-container, label
	local out
	out="$(wp plugin install "$1" --force --activate 2>&1)"
	if printf '%s' "$out" | grep -q 'Installed 1 of 1 plugins' && [ "$(wp plugin get sigil-2fa --field=status 2>/dev/null)" = "active" ]; then
		ok "$2 installs and activates"
	else
		bad "$2 installs and activates"
		printf '%s\n' "$out" | tail -4 | sed 's/^/        /'
	fi
}

# Users, a second factor, backup codes and a policy, written the way the plugin stores them.
seed() {
	wp eval-file /smoke/php/seed.php 2>/dev/null | sed -n 's/^backup_code=//p' | tr -d '\r\n'
}

scenario_fresh() {
	phase "Fresh install on PHP $PHP_VERSION"
	start_stack
	install_zip /zips/new.zip "the zip"
	check "active plugin version is $ZIP_VERSION" "$([ "$(wp plugin get sigil-2fa --field=version 2>/dev/null)" = "$ZIP_VERSION" ] && echo 0 || echo 1)"
	check "plugin tables were created" "$([ "$(state tables | tr ',' '\n' | grep -c .)" -ge 2 ] && echo 0 || echo 1)"
	check_log "install and activation"

	login
	check_front
	check_admin
	check_log "front end, login page and admin screens"
	phase_end

	phase "Second factor on PHP $PHP_VERSION"
	local backup
	backup="$(seed)"
	check "seeded an authenticator and backup codes for smoke_2fa" "$([ -n "$backup" ] && state methods | grep -q totp && state methods | grep -q backup && echo 0 || echo 1)"
	check_second_factor
	check_log "password and second-factor sign-ins"
	phase_end

	phase "Deactivate and reactivate"
	local code live
	wp plugin deactivate sigil-2fa >/dev/null 2>&1
	check "front end and wp-admin load while the plugin is off" "$([ "$(http_code "$BASE/")" = "200" ] && body_is_clean && [ "$(http_code -b "$JAR" "$BASE/wp-admin/")" = "200" ] && body_is_clean && echo 0 || echo 1)"
	check "deactivating keeps the data (methods: $(state methods))" "$([ -n "$(state methods)" ] && [ "$(state tables | tr ',' '\n' | grep -c .)" -ge 2 ] && echo 0 || echo 1)"
	# Control: with the plugin off nothing challenges, so the cookie check can see a session.
	code="$(password_post smoke_2fa "$USER_PW")"
	check "control: with the plugin off the password alone gets a session ($code)" "$([ "$(live_logged_in "$WORK/h.txt")" -ge 1 ] && echo 0 || echo 1)"
	wp plugin activate sigil-2fa >/dev/null 2>&1
	check_front
	login
	check_admin
	check_password_only_blocked "after reactivation"
	check_log "deactivate and reactivate"
	phase_end

	if [ "$SKIP_PLUGIN_CHECK" -eq 0 ]; then
		phase "WordPress Plugin Check"
		phase_plugin_check
		phase_end
	fi

	phase "Uninstall"
	wp plugin deactivate sigil-2fa >/dev/null 2>&1
	check "before uninstall there is something to remove ($(state options) options, $(state usermeta) user meta)" "$([ "$(state options)" -gt 0 ] && [ "$(state usermeta)" -gt 0 ] && echo 0 || echo 1)"
	wp eval-file /smoke/php/uninstall.php >/dev/null 2>&1
	check "uninstall.php dropped every plugin table (left: $(state tables))" "$([ -z "$(state tables)" ] && echo 0 || echo 1)"
	check "uninstall.php removed the plugin's options (left: $(state option_names))" "$([ "$(state options)" = "0" ] && echo 0 || echo 1)"
	check "uninstall.php removed the plugin's user meta (left: $(state usermeta_keys))" "$([ "$(state usermeta)" = "0" ] && echo 0 || echo 1)"
	check_log "uninstall"
	phase_end
}

phase_plugin_check() {
	local out rows counts ran
	out="$(dc exec -T cli sh /smoke/plugin-check.sh 2>&1)"
	ran="$(printf '%s\n' "$out" | sed -n 's/^#checks=//p')"
	if [ -z "$ran" ] || [ "$ran" -lt 20 ]; then
		bad "Plugin Check ran ${ran:-no} checks, expected 20 or more"
		printf '%s\n' "$out" | tail -5 | cut -c1-200 | sed 's/^/        /'
		return
	fi
	ok "Plugin Check ran $ran checks"
	counts="$(printf '%s\n' "$out" | awk -F, '$3 == "ERROR" { c[$1 " " $2 " " $4]++ } END { for (k in c) print c[k], k }' | sort -k2)"
	if [ "$UPDATE_BASELINE" -eq 1 ]; then
		{ echo "# count check code file"; printf '%s\n' "$counts" | grep .; } > "$HERE/plugin-check-baseline.txt"
		ok "baseline rewritten: $(grep -vc '^#' "$HERE/plugin-check-baseline.txt") entries"
		return
	fi
	rows="$(awk 'NR == FNR { if ($0 !~ /^#/) b[$2 " " $3 " " $4] = $1; next } { k = $2 " " $3 " " $4; if ($1 > b[k] + 0) print $1 " (baseline " b[k] + 0 ") " k }' "$HERE/plugin-check-baseline.txt" - <<< "$counts")"
	if [ -z "$rows" ]; then
		ok "Plugin Check: no errors beyond the baseline ($(printf '%s\n' "$counts" | awk '{ n += $1 } END { print n + 0 }') known, see tests/smoke/plugin-check-baseline.txt)"
	else
		bad "Plugin Check: errors beyond the baseline"
		printf '%s\n' "$rows" | head -15 | sed 's/^/        /'
	fi
}

scenario_upgrade() {
	phase "Upgrade from the current release on PHP $PHP_VERSION"
	start_stack
	local old src out backup cols_before cols_after
	if [ -n "$BASELINE_ZIP" ]; then src=/zips/baseline.zip; else src=sigil-2fa; fi
	out="$(wp plugin install "$src" --force --activate 2>&1)"
	if ! printf '%s' "$out" | grep -q "Plugin '.*' activated"; then
		bad "could not install the baseline release ($src)"
		printf '%s\n' "$out" | tail -4 | sed 's/^/        /'
		return
	fi
	old="$(wp plugin get sigil-2fa --field=version)"
	ok "baseline installed: $old"
	backup="$(seed)"
	cols_before="$(state columns)"
	check "baseline holds a second factor, backup codes and a policy to carry over (methods $(state methods), $(state backup_unused) codes, grace $(state policy_grace))" \
		"$([ -n "$backup" ] && [ "$(state backup_unused)" = "10" ] && [ "$(state policy_enabled)" = "1" ] && [ "$(state policy_grace)" = "11" ] && [ "$(state trusted_days)" = "21" ] && echo 0 || echo 1)"
	clear_log

	install_zip /zips/new.zip "the new zip over $old"
	if [ "$old" = "$ZIP_VERSION" ]; then
		echo "  note  baseline and zip are both $ZIP_VERSION, so the schema upgrade has nothing to do"
	elif [ "$(printf '%s\n%s\n' "$old" "$ZIP_VERSION" | sort -V | tail -1)" = "$old" ]; then
		echo "  note  the zip ($ZIP_VERSION) is older than the release it replaces ($old), so this is a downgrade"
	fi
	check "active plugin version is $ZIP_VERSION" "$([ "$(wp plugin get sigil-2fa --field=version 2>/dev/null)" = "$ZIP_VERSION" ] && echo 0 || echo 1)"

	# The schema upgrade hooks admin_init, so it runs on the first admin request.
	login
	check_admin
	cols_after="$(state columns)"
	check "schema upgrade ran: db version $(state db_version) = $ZIP_VERSION" "$([ "$(state db_version)" = "$ZIP_VERSION" ] && echo 0 || echo 1)"
	if [ "$old" != "$ZIP_VERSION" ]; then
		check "credential table gained columns ($(comm -13 <(printf '%s\n' "$cols_before" | tr ',' '\n' | sort) <(printf '%s\n' "$cols_after" | tr ',' '\n' | sort) | tr '\n' ' '))" \
			"$([ -n "$(comm -13 <(printf '%s\n' "$cols_before" | tr ',' '\n' | sort) <(printf '%s\n' "$cols_after" | tr ',' '\n' | sort))" ] && echo 0 || echo 1)"
	fi
	check "no credential column was lost" "$([ -z "$(comm -23 <(printf '%s\n' "$cols_before" | tr ',' '\n' | sort) <(printf '%s\n' "$cols_after" | tr ',' '\n' | sort))" ] && echo 0 || echo 1)"
	check "policy survived (enabled $(state policy_enabled), grace $(state policy_grace), editors $(state policy_editor))" "$([ "$(state policy_enabled)" = "1" ] && [ "$(state policy_grace)" = "11" ] && [ "$(state policy_editor)" = "1" ] && echo 0 || echo 1)"
	check "settings survived (trusted device days $(state trusted_days))" "$([ "$(state trusted_days)" = "21" ] && echo 0 || echo 1)"
	check "factors survived (methods $(state methods), $(state backup_unused) unused backup codes)" "$([ "$(state backup_unused)" = "10" ] && state methods | grep -q totp && echo 0 || echo 1)"

	check_front
	check_password_only_blocked "after the upgrade"
	local code live replay
	code="$(submit_challenge totp "$(totp_code)")"
	live="$(live_logged_in "$WORK/h2.txt")"
	replay="$(profile_code "$(first_issued "$WORK/h2.txt")")"
	check "the authenticator enrolled before the upgrade still signs in (HTTP $code, profile $replay)" "$([ "$code" = "302" ] && [ "$live" -ge 1 ] && [ "$replay" = "200" ] && echo 0 || echo 1)"
	password_post smoke_2fa "$USER_PW" >/dev/null
	code="$(submit_challenge backup "$backup")"
	live="$(live_logged_in "$WORK/h2.txt")"
	check "a backup code issued before the upgrade still signs in (HTTP $code)" "$([ "$code" = "302" ] && [ "$live" -ge 1 ] && echo 0 || echo 1)"
	check "the backup code was consumed ($(state backup_unused) left)" "$([ "$(state backup_unused)" = "9" ] && echo 0 || echo 1)"
	check_log "upgrade"
	phase_end
}

echo "Sigil smoke test: $(basename "$ZIP") $ZIP_VERSION, PHP $PHP_VERSION (header requires $MIN_PHP), port $PORT"
prepare_work_dir

scenario_fresh
[ "$SKIP_UPGRADE" -eq 1 ] || scenario_upgrade

echo
echo "$PASSED passed, $FAILED failed, $((SECONDS - STARTED))s (PHP $PHP_VERSION)"
[ "$FAILED" -eq 0 ] && [ "$PASSED" -gt 0 ]
