#!/bin/sh
# Write node-only subscriptions into local.dae, then run dae-rule-sync.
# Complete Mihomo YAML subscriptions are fetched by dae-rule-sync via a 0600
# URL file so the link never appears on argv.
# Fail-closed: local.dae is backed up before overwrite; dae-rule-sync keeps
# the previous generation on conversion failure; validate failure restores
# local.dae, routing.dae, and current/ (or removes current/ on first publish)
# so the next reload/reboot does not load a rejected candidate.
# Does not start tproxy.

set -eu

SYNC="/usr/libexec/dae/dae-rule-sync"
WRITE_LOCAL="/usr/libexec/dae/kdae-write-local.sh"
STATE="/var/run/kdae-last-sync.json"
ERR="/tmp/kdae-sync.err"
OUT="/tmp/kdae-sync.out"
# kdae-write-local.sh always writes this path; config.dae includes it.
LOCAL_DAE="/etc/dae/local.dae"

kdae_local_bak=""
kdae_routing_bak=""
kdae_old_current=""
kdae_gendir=""

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

# Restore dest from bak, or remove dest when there was no pre-write file.
restore_regular() {
	dest=$1
	bak=$2
	if [ -n "$bak" ] && [ -f "$bak" ]; then
		mv -f "$bak" "$dest"
	else
		rm -f "$dest"
	fi
}

# old_current is the pre-sync readlink of gendir/current (relative, e.g.
# generations/id), or empty when this is the first publication.
restore_generation_current() {
	gendir=$1
	old_current=$2
	if [ -n "$old_current" ]; then
		ln -sfn "$old_current" "$gendir/current"
		ln -sfn current/generated "$gendir/generated"
		return
	fi
	rm -f "$gendir/current"
	if [ -L "$gendir/generated" ]; then
		tgt=$(readlink "$gendir/generated" || true)
		if [ "$tgt" = "current/generated" ]; then
			rm -f "$gendir/generated"
		fi
	fi
}

restore_local_dae() {
	restore_regular "$LOCAL_DAE" "$kdae_local_bak"
	if [ -n "$kdae_local_bak" ]; then
		rm -f "$kdae_local_bak"
	fi
	kdae_local_bak=""
}

restore_routing_dae() {
	restore_regular "$kdae_gendir/routing.dae" "$kdae_routing_bak"
	if [ -n "$kdae_routing_bak" ]; then
		rm -f "$kdae_routing_bak"
	fi
	kdae_routing_bak=""
}

restore_publication() {
	restore_routing_dae
	restore_local_dae
	restore_generation_current "$kdae_gendir" "$kdae_old_current"
}

write_node_resolve_dns() {
	dest=$1
	umask 077
	tmp="${dest}.tmp.$$"
	{
		printf '{\n'
		first=1
		for type in mixin node_dns; do
			index=0
			while uci -q get "dae.@${type}[$index]" >/dev/null 2>&1; do
				name=$(uci -q get "dae.@${type}[$index].name" || true)
				dns=$(uci -q get "dae.@${type}[$index].resolve_dns" || true)
				index=$((index + 1))
				[ -n "$name" ] || continue
				[ -n "$dns" ] || continue
				if [ "$first" -eq 1 ]; then
					first=0
				else
					printf ',\n'
				fi
				printf '  "%s": "%s"' "$(json_escape "$name")" "$(json_escape "$dns")"
			done
		done
		printf '\n}\n'
	} > "$tmp"
	chmod 600 "$tmp"
	mv "$tmp" "$dest"
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

kdae_sync_main() {
	mihomo=$(uci -q get dae.config.mihomo_config || true)
	kdae_gendir=$(uci -q get dae.config.generation_dir || echo /etc/dae)
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

	kdae_local_bak=""
	if [ -f "$LOCAL_DAE" ]; then
		kdae_local_bak="${LOCAL_DAE}.bak.$$"
		cp -p "$LOCAL_DAE" "$kdae_local_bak"
	fi

	if ! "$WRITE_LOCAL"; then
		restore_local_dae
		write_state false "" "" "failed to write subscription into local.dae"
		exit 1
	fi

	if [ "$routing_count" -gt 1 ]; then
		restore_local_dae
		write_state false "" "" "exactly one complete Mihomo routing subscription is allowed"
		echo "exactly one complete Mihomo routing subscription is allowed" >&2
		exit 1
	fi

	warning_note=""
	set --
	if [ -n "$mihomo" ]; then
		set -- -mihomo-routing-config "$mihomo" -generation-dir "$kdae_gendir"
		if [ "$routing_count" -eq 1 ]; then
			warning_note="local mihomo_config overrides the routing subscription"
		fi
	elif [ "$routing_count" -eq 1 ]; then
		cache_dir="${kdae_gendir}/cache"
		url_file="${cache_dir}/routing.url"
		umask 077
		mkdir -p "$cache_dir"
		chmod 700 "$cache_dir"
		printf '%s\n' "$routing_url" > "$url_file"
		chmod 600 "$url_file"
		routing_url=""
		set -- -mihomo-routing-url-file "$url_file" -generation-dir "$kdae_gendir"
	else
		if [ "$node_count" -ge 1 ]; then
			if [ -n "$kdae_local_bak" ]; then
				rm -f "$kdae_local_bak"
			fi
			kdae_local_bak=""
			write_state true "" "node subscriptions written to local.dae; no routing source so skip dae-rule-sync" ""
			echo "wrote node subscriptions to /etc/dae/local.dae"
			echo "add a complete Mihomo YAML subscription or set dae.config.mihomo_config to generate groups/routes"
			exit 0
		fi
		restore_local_dae
		write_state false "" "" "no Mihomo routing subscription or local routing config"
		echo "add a complete Mihomo YAML subscription in LuCI or set dae.config.mihomo_config" >&2
		exit 1
	fi

	cache_dir="${kdae_gendir}/cache"
	umask 077
	mkdir -p "$cache_dir"
	chmod 700 "$cache_dir"
	overlay="${cache_dir}/node-resolve-dns.json"
	write_node_resolve_dns "$overlay"
	set -- "$@" -node-resolve-dns "$overlay"

	if [ ! -x "$SYNC" ]; then
		restore_local_dae
		write_state false "" "" "dae-rule-sync is not installed"
		echo "dae-rule-sync is not installed" >&2
		exit 1
	fi

	kdae_old_current=""
	if [ -L "$kdae_gendir/current" ]; then
		kdae_old_current=$(readlink "$kdae_gendir/current" || true)
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
	if [ -f "$kdae_gendir/current/metadata.json" ]; then
		generation=$(sed -n 's/.*"generation"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$kdae_gendir/current/metadata.json" | head -n1)
	elif [ -f "$kdae_gendir/metadata.json" ]; then
		generation=$(sed -n 's/.*"generation"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$kdae_gendir/metadata.json" | head -n1)
	fi

	if [ "$code" -ne 0 ]; then
		err=$(cat "$ERR" 2>/dev/null || echo "dae-rule-sync failed")
		restore_local_dae
		restore_generation_current "$kdae_gendir" "$kdae_old_current"
		write_state false "$generation" "$warning" "$err"
		cat "$ERR" >&2 || true
		exit "$code"
	fi

	# routes.dae is a routing body. Wrap it so config.dae can include a section.
	# DAT paths are generated/geosite/... relative to /etc/dae, not current/.
	umask 077
	if [ ! -f "$kdae_gendir/current/routes.dae" ]; then
		restore_local_dae
		restore_generation_current "$kdae_gendir" "$kdae_old_current"
		write_state false "$generation" "$warning" "generation current/routes.dae is missing"
		echo "generation current/routes.dae is missing" >&2
		exit 1
	fi

	kdae_routing_bak=""
	if [ -f "$kdae_gendir/routing.dae" ]; then
		kdae_routing_bak="$kdae_gendir/routing.dae.bak.$$"
		cp -p "$kdae_gendir/routing.dae" "$kdae_routing_bak"
	fi

	routing_tmp="$kdae_gendir/routing.dae.tmp.$$"
	{
		echo "# generated from current/routes.dae; do not edit"
		echo "routing {"
		cat "$kdae_gendir/current/routes.dae"
		echo "}"
	} > "$routing_tmp"
	chmod 0600 "$routing_tmp"
	mv "$routing_tmp" "$kdae_gendir/routing.dae"
	ln -sfn current/generated "$kdae_gendir/generated"

	if ! /usr/bin/dae validate -c "$config"; then
		restore_publication
		write_state false "$generation" "$warning" "dae validate failed; restored previous local.dae, routing, and generation"
		exit 1
	fi
	if [ -n "$kdae_routing_bak" ]; then
		rm -f "$kdae_routing_bak"
	fi
	if [ -n "$kdae_local_bak" ]; then
		rm -f "$kdae_local_bak"
	fi

	write_state true "$generation" "$warning" ""
	if [ -n "$warning" ]; then
		printf '%s\n' "$warning"
	fi
	if [ -n "$generation" ]; then
		echo "generation ${generation}"
	fi
	cat "$OUT" 2>/dev/null || true
}

if [ -z "${KDAE_SYNC_SOURCE:-}" ]; then
	kdae_sync_main "$@"
fi
