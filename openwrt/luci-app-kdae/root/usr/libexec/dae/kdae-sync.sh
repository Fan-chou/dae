#!/bin/sh
# Write node-only subscriptions into local.dae, then run dae-rule-sync.
# Complete Mihomo YAML subscriptions are fetched by dae-rule-sync via a 0600
# URL file so the link never appears on argv. Fail-closed: previous generation
# is kept when conversion fails. Does not start tproxy.

set -eu

SYNC="/usr/libexec/dae/dae-rule-sync"
WRITE_LOCAL="/usr/libexec/dae/kdae-write-local.sh"
STATE="/var/run/kdae-last-sync.json"
ERR="/tmp/kdae-sync.err"
OUT="/tmp/kdae-sync.out"

mihomo=$(uci -q get dae.config.mihomo_config || true)
gendir=$(uci -q get dae.config.generation_dir || echo /etc/dae)
config=$(uci -q get dae.config.config_file || echo /etc/dae/config.dae)

routing_url=""
routing_count=0
node_count=0
index=0
while uci -q get "dae.@subscription[$index]" >/dev/null 2>&1; do
	url=$(uci -q get "dae.@subscription[$index].url" || true)
	role=$(uci -q get "dae.@subscription[$index].role" || true)
	index=$((index + 1))
	[ -n "$url" ] || continue
	case "$role" in
	nodes)
		node_count=$((node_count + 1))
		;;
	""|routing)
		routing_count=$((routing_count + 1))
		routing_url=$url
		;;
	*)
		echo "invalid subscription role" >&2
		exit 1
		;;
	esac
done

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

write_state() {
	ok=$1
	generation=$2
	warning=$3
	error=$4
	umask 077
	cat > "$STATE" <<EOF
{"ok": ${ok}, "generation": "$(json_escape "$generation")", "warning": "$(json_escape "$warning")", "error": "$(json_escape "$error")"}
EOF
}

if ! "$WRITE_LOCAL"; then
	write_state false "" "" "failed to write subscription into local.dae"
	exit 1
fi

if [ "$routing_count" -gt 1 ]; then
	write_state false "" "" "exactly one complete Mihomo routing subscription is allowed"
	echo "exactly one complete Mihomo routing subscription is allowed" >&2
	exit 1
fi

warning_note=""
set --
if [ -n "$mihomo" ]; then
	set -- -mihomo-routing-config "$mihomo" -generation-dir "$gendir"
	if [ "$routing_count" -eq 1 ]; then
		warning_note="local mihomo_config overrides the routing subscription"
	fi
elif [ "$routing_count" -eq 1 ]; then
	cache_dir="${gendir}/cache"
	url_file="${cache_dir}/routing.url"
	umask 077
	mkdir -p "$cache_dir"
	chmod 700 "$cache_dir"
	printf '%s\n' "$routing_url" > "$url_file"
	chmod 600 "$url_file"
	routing_url=""
	set -- -mihomo-routing-url-file "$url_file" -generation-dir "$gendir"
else
	if [ "$node_count" -ge 1 ]; then
		write_state true "" "node subscriptions written to local.dae; no routing source so skip dae-rule-sync" ""
		echo "wrote node subscriptions to /etc/dae/local.dae"
		echo "add a complete Mihomo YAML subscription or set dae.config.mihomo_config to generate groups/routes"
		exit 0
	fi
	write_state false "" "" "no Mihomo routing subscription or local routing config"
	echo "add a complete Mihomo YAML subscription in LuCI or set dae.config.mihomo_config" >&2
	exit 1
fi

if [ ! -x "$SYNC" ]; then
	write_state false "" "" "dae-rule-sync is not installed"
	echo "dae-rule-sync is not installed" >&2
	exit 1
fi

rm -f "$ERR" "$OUT"
set +e
"$SYNC" "$@" >"$OUT" 2>"$ERR"
code=$?
set -e

warning=$(cat "$ERR" 2>/dev/null || true)
if [ -n "$warning_note" ]; then
	if [ -n "$warning" ]; then
		warning="${warning_note}
${warning}"
	else
		warning=$warning_note
	fi
fi
generation=""
if [ -f "$gendir/metadata.json" ]; then
	generation=$(sed -n 's/.*"generation"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$gendir/metadata.json" | head -n1)
fi

if [ "$code" -ne 0 ]; then
	err=$(cat "$ERR" 2>/dev/null || echo "dae-rule-sync failed")
	write_state false "$generation" "$warning" "$err"
	cat "$ERR" >&2 || true
	exit "$code"
fi

# routes.dae is a routing body. Wrap it so config.dae can include a section.
# DAT paths are generated/geosite/... relative to /etc/dae, not current/.
umask 077
if [ ! -f "$gendir/current/routes.dae" ]; then
	write_state false "$generation" "$warning" "generation current/routes.dae is missing"
	echo "generation current/routes.dae is missing" >&2
	exit 1
fi
routing_tmp="$gendir/routing.dae.tmp.$$"
{
	echo "# generated from current/routes.dae; do not edit"
	echo "routing {"
	cat "$gendir/current/routes.dae"
	echo "}"
} > "$routing_tmp"
chmod 0600 "$routing_tmp"
mv "$routing_tmp" "$gendir/routing.dae"
ln -sfn current/generated "$gendir/generated"

if ! /usr/bin/dae validate -c "$config"; then
	write_state false "$generation" "$warning" "dae validate failed; previous generation kept if sync was fail-closed"
	exit 1
fi

write_state true "$generation" "$warning" ""
if [ -n "$warning" ]; then
	printf '%s\n' "$warning"
fi
if [ -n "$generation" ]; then
	echo "generation ${generation}"
fi
cat "$OUT" 2>/dev/null || true
