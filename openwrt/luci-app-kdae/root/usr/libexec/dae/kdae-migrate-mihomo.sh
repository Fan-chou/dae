#!/bin/sh
# One-time move from the dae-rule-sync generation layout to the built-in
# Mihomo source. Safe to run again. It
#   - drops current/nodes.dae, current/groups.dae and routing.dae from the
#     include {} block of config.dae (a backup is kept),
#   - removes the obsolete generation_dir UCI option,
#   - writes local.dae (with mihomo {}) from UCI and validates the result.
# The old current/ and generations/ directories are left alone; delete them
# once the new setup has proven itself.

set -eu

CONFIG=${KDAE_CONFIG:-$(uci -q get dae.config.config_file || echo /etc/dae/config.dae)}
DAE=${KDAE_DAE:-/usr/bin/dae}
WRITE_LOCAL=${KDAE_WRITE_LOCAL:-/usr/libexec/dae/kdae-write-local.sh}

[ -f "$CONFIG" ] || {
	echo "$CONFIG not found" >&2
	exit 1
}

bak="${CONFIG}.pre-mihomo.bak"
[ -f "$bak" ] || cp -p "$CONFIG" "$bak"

tmp="${CONFIG}.tmp.$$"
trap 'rm -f "$tmp"' EXIT
awk '
	/^[[:space:]]*include[[:space:]]*\{/ { inc = 1; seen_local = 0 }
	inc && /^[[:space:]]*\}/ {
		if (!seen_local) print "    local.dae"
		inc = 0
	}
	inc {
		line = $0
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
		if (line == "current/nodes.dae" || line == "current/groups.dae" || line == "routing.dae") next
		if (line == "local.dae") seen_local = 1
	}
	{ print }
' "$CONFIG" > "$tmp"
chmod --reference="$CONFIG" "$tmp" 2>/dev/null || chmod 600 "$tmp"
mv "$tmp" "$CONFIG"

uci -q delete dae.config.generation_dir || true
uci commit dae

if ! "$WRITE_LOCAL"; then
	cp -p "$bak" "$CONFIG"
	echo "could not write local.dae; config.dae restored" >&2
	exit 1
fi

if ! "$DAE" validate -c "$CONFIG"; then
	cp -p "$bak" "$CONFIG"
	echo "dae validate failed; config.dae restored from $bak" >&2
	exit 1
fi
echo "migrated. Apply with: /etc/init.d/dae restart"
echo "old generation files are untouched under $(dirname "$CONFIG")/current and generations"
