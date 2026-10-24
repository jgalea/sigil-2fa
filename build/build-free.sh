#!/usr/bin/env bash
# Produces sigil-2fa.zip for wordpress.org submission.
#
# Ships everything at the plugin root EXCEPT dev tooling and test scaffolding.
# vendor/ is deliberately kept: lbuchs/webauthn is a runtime dependency the
# passkey provider loads at request time, not a build-time-only package.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
SOURCE_VERSION="$(sed -n 's/^ \* Version:[[:space:]]*//p' "$ROOT/sigil-2fa.php" | head -1)"
RELEASE_VERSION="${SIGIL_RELEASE_VERSION:-${SOURCE_VERSION}}"
if [ -z "$RELEASE_VERSION" ]; then
	echo "Could not resolve a version from sigil-2fa.php" >&2
	exit 1
fi

rm -rf "$DIST/sigil-2fa" "$DIST/sigil-2fa.zip"
mkdir -p "$DIST/sigil-2fa"

# One source of truth for what ships: .distignore, which the wordpress.org
# deploy action also reads. Duplicating the list here is how assets/js/vendor and
# a tool cache each nearly reached a package.
#
# vendor/ and languages/ are excluded on top of it and rebuilt below, because
# both hold more locally than belongs in a release.
rsync -a \
    --exclude-from="$ROOT/.distignore" \
    --exclude='/vendor/' \
    --exclude='/languages/' \
    "$ROOT/" "$DIST/sigil-2fa/"

# Translations are not shipped. Plugins hosted on wordpress.org receive their
# .po/.mo/.l10n.php files from translate.wordpress.org, so bundling compiled
# catalogues here would shadow the community ones. The .pot is kept as the
# template translators work from; everything else in languages/ stays in the
# repo for the GlotPress import and never enters the zip.
mkdir -p "$DIST/sigil-2fa/languages"
cp "$ROOT/languages/sigil-2fa.pot" "$DIST/sigil-2fa/languages/"

# The exclusions above are anchored with a leading slash so they only match at
# the plugin root. Unanchored, 'vendor/' would also drop assets/js/vendor/.
# vendor/ is excluded wholesale because a local `composer install` fills it
# with PHPUnit and the Composer autoloader, none of which ships. The passkey
# provider loads lbuchs/webauthn by direct require, so that one committed package
# is the only vendored code the plugin needs at runtime.
mkdir -p "$DIST/sigil-2fa/vendor"
rsync -a --exclude='*.md' "$ROOT/vendor/lbuchs" "$DIST/sigil-2fa/vendor/"

MAIN="$DIST/sigil-2fa/sigil-2fa.php"
README="$DIST/sigil-2fa/readme.txt"

python3 - "$MAIN" "$README" "$RELEASE_VERSION" <<'PY'
import re
import sys

main_path, readme_path, version = sys.argv[1], sys.argv[2], sys.argv[3]

with open(main_path, 'r', encoding='utf-8') as f:
    main = f.read()
main = re.sub(r"(?m)^(\s*\*\s*Version:\s*).+$", r"\g<1>" + version, main, count=1)
main = re.sub(r"define\(\s*'SIGIL_VERSION',\s*'[^']+'\s*\);", f"define( 'SIGIL_VERSION', '{version}' );", main, count=1)
with open(main_path, 'w', encoding='utf-8') as f:
    f.write(main)

with open(readme_path, 'r', encoding='utf-8') as f:
    readme = f.read()
readme = re.sub(r"(?m)^Stable tag:.*$", f"Stable tag: {version}", readme, count=1)
with open(readme_path, 'w', encoding='utf-8') as f:
    f.write(readme)
PY

# A missing runtime file makes a feature quietly do nothing rather than fail, so
# check the package holds what the plugin loads before sealing it.
REQUIRED=(
  "sigil-2fa.php"
  "uninstall.php"
  "readme.txt"
  "assets/js/enrol.js"
  "assets/js/passkey.js"
  "assets/js/vendor/qrcode.js"
  "assets/css/admin.css"
  "assets/css/login.css"
  "assets/css/frontend.css"
  "includes/class-plugin.php"
  "includes/class-trusted-devices.php"
  "includes/class-woocommerce.php"
  "includes/class-zero-setup.php"
  "includes/class-always-email.php"
  "templates/challenge.php"
  "templates/enrol.php"
  "templates/settings.php"
  "vendor/lbuchs/webauthn/WebAuthn.php"
  "languages/sigil-2fa.pot"
)
for file in "${REQUIRED[@]}"; do
  if [ ! -f "$DIST/sigil-2fa/$file" ]; then
    echo "Missing from the package: $file" >&2
    exit 1
  fi
done

# Nothing from the development tree should reach the package.
for unwanted in tests e2e pro node_modules .git .github .claude .impeccable build dist \
                package.json composer.json phpunit.xml.dist phpunit-multisite.xml.dist \
                .phpunit.result.cache playwright.config.ts .distignore; do
  if [ -e "$DIST/sigil-2fa/$unwanted" ]; then
    echo "Development path leaked into the package: $unwanted" >&2
    exit 1
  fi
done

cd "$DIST"
zip -rqX sigil-2fa.zip sigil-2fa/

echo "Built: $DIST/sigil-2fa.zip (version $RELEASE_VERSION)"
du -h "$DIST/sigil-2fa.zip" | awk '{print "Size:", $1}'
