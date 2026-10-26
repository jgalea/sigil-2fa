#!/bin/sh
# Runs inside the cli container. One wp invocation per check: the full set in a
# single run dies with a bare exit 255 when the runtime checks and the PHPCS
# checks share a process, and a crash must surface as a finding, not as silence.
# The five runtime checks (script/style size and scope, loading strategy) only
# raise performance warnings and crash intermittently on PHP 7.4, so they are skipped.
cd /var/www/html || exit 1

wp plugin is-installed plugin-check || wp plugin install plugin-check >/dev/null || exit 1
wp plugin is-active plugin-check || wp plugin activate plugin-check >/dev/null || exit 1

n=0
for check in $(wp plugin list-checks --format=csv --fields=slug | tail -n +2 | grep -vxE 'enqueued_(scripts|styles)_(size|scope)|non_blocking_scripts'); do
	n=$((n + 1))
	out=$(wp plugin check sigil-2fa --checks="$check" --format=csv --fields=code,type,file,line 2>&1)
	case "$out" in
		Error*|*"critical error"*) echo "$check,CHECK_CRASHED,ERROR,-,0"; continue ;;
	esac
	printf '%s\n' "$out" | tail -n +2 | sed "s/^/$check,/"
done
echo "#checks=$n"
