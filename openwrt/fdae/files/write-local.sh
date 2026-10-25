#!/bin/sh
# Generate /etc/dae/local.dae from the UCI settings in /etc/config/dae. The
# file is 0600: it holds the subscription URLs and the admin secret.
#
#   subscription {}  role=nodes subscriptions (dae fetches them at start).
#   mihomo {}        the one complete Mihomo YAML: a role=routing subscription
#                    or dae.config.mihomo_config. dae fetches, converts and
#                    merges it itself on every start and reload.
#   inbound {}       the SOCKS5 listeners from the `inbound` UCI sections.
#                    Rules that use them (inbound(name)) are written in
#                    config.dae.
#
# config.dae should include { local.dae }.

set -eu

CONF=${FDAE_LOCAL_DAE:-/etc/dae/local.dae}
CFG=$(uci -q get dae.config.config_file || echo /etc/dae/config.dae)
TMP="${CONF}.tmp.$$"
trap 'rm -f "$TMP"' EXIT

lan=$(uci -q get dae.config.lan_interface || true)
wan=$(uci -q get dae.config.wan_interface || true)
listen=$(uci -q get dae.config.admin_listen || true)
secret=$(uci -q get dae.config.admin_secret || true)
mihomo_file=$(uci -q get dae.config.mihomo_config || true)
mihomo_interval=$(uci -q get dae.config.mihomo_interval || true)
isolate_groups=$(uci -q get dae.config.isolate_transport_groups || true)
geoip_url=$(uci -q get dae.config.geoip_url || true)
geosite_url=$(uci -q get dae.config.geosite_url || true)
geodata_interval=$(uci -q get dae.config.geodata_interval || true)

# dae does not interpret escapes inside a quoted string, so pick the quote
# that does not occur in the value.
quote_dae() {
	case $1 in
	*"'"*)
		case $1 in
		*'"'*)
			echo "value cannot be quoted for dae: contains both ' and \"" >&2
			return 1
			;;
		esac
		printf '"%s"' "$1"
		;;
	*)
		printf "'%s'" "$1"
		;;
	esac
}

sanitize_tag() {
	printf '%s' "$1" | grep -Eq '^[A-Za-z_][A-Za-z0-9_-]*$'
}

# Same rule as dae's inbound names: usable bare in inbound(name).
sanitize_inbound_name() {
	printf '%s' "$1" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$'
}

# A value that is written on one line of local.dae must not carry a line break.
single_line() {
	case $1 in
	*"
"*)
		echo "value cannot contain a line break: $2" >&2
		return 1
		;;
	esac
}

uci_true() {
	case $1 in
	0|no|off|false|disabled) return 1 ;;
	esac
	return 0
}

# One `name { ... }` entry of the inbound section from the UCI section at
# index $1. Prints nothing for a disabled or empty section.
render_inbound() {
	_i=$1
	_name=$(uci -q get "dae.@inbound[$_i].name" || true)
	_listen=$(uci -q get "dae.@inbound[$_i].listen" || true)
	_enabled=$(uci -q get "dae.@inbound[$_i].enabled" || echo 1)
	_user=$(uci -q get "dae.@inbound[$_i].username" || true)
	_pass=$(uci -q get "dae.@inbound[$_i].password" || true)
	_udp=$(uci -q get "dae.@inbound[$_i].udp" || echo 1)
	_adv=$(uci -q get "dae.@inbound[$_i].udp_advertise" || true)
	_sniff=$(uci -q get "dae.@inbound[$_i].sniff" || true)
	_resolve=$(uci -q get "dae.@inbound[$_i].resolve" || true)
	uci_true "$_enabled" || return 0
	[ -n "$_name" ] || [ -n "$_listen" ] || return 0
	if ! sanitize_inbound_name "$_name"; then
		echo "invalid inbound name: '$_name' (1-32 letters, digits, _ or -)" >&2
		return 1
	fi
	if [ -z "$_listen" ]; then
		echo "inbound $_name: listen is empty" >&2
		return 1
	fi
	for _v in "$_listen" "$_user" "$_pass" "$_adv"; do
		single_line "$_v" "inbound $_name" || return 1
	done
	case $_sniff in
	""|auto|off) ;;
	*) echo "inbound $_name: invalid sniff '$_sniff'" >&2; return 1 ;;
	esac
	case $_resolve in
	""|local|deferred) ;;
	*) echo "inbound $_name: invalid resolve '$_resolve'" >&2; return 1 ;;
	esac
	# Quote first: a failure inside echo "$(...)" would be swallowed.
	_q_listen=$(quote_dae "$_listen") || return 1
	_q_user="" _q_pass="" _q_adv=""
	if [ -n "$_user" ] || [ -n "$_pass" ]; then
		_q_user=$(quote_dae "$_user") || return 1
		_q_pass=$(quote_dae "$_pass") || return 1
	fi
	if [ -n "$_adv" ]; then
		_q_adv=$(quote_dae "$_adv") || return 1
	fi
	echo "    ${_name} {"
	echo "        listen: ${_q_listen}"
	if [ -n "$_q_user" ]; then
		echo "        username: ${_q_user}"
		echo "        password: ${_q_pass}"
	fi
	uci_true "$_udp" || echo "        udp: false"
	[ -z "$_q_adv" ] || echo "        udp_advertise: ${_q_adv}"
	[ -z "$_sniff" ] || [ "$_sniff" = auto ] || echo "        sniff: ${_sniff}"
	[ -z "$_resolve" ] || [ "$_resolve" = local ] || echo "        resolve: ${_resolve}"
	echo "    }"
}

# A node subscription is kept on disk, so a start without a network still has
# the nodes of the last good fetch.
persist_url() {
	case "$1" in
	https://*) printf 'https-file://%s' "${1#https://}" ;;
	http://*) printf 'http-file://%s' "${1#http://}" ;;
	*) printf '%s' "$1" ;;
	esac
}

# First pass: classify subscriptions so that an invalid layout is reported
# before anything is written.
routing_url=""
routing_count=0
index=0
while uci -q get "dae.@subscription[$index]" >/dev/null 2>&1; do
	url=$(uci -q get "dae.@subscription[$index].url" || true)
	role=$(uci -q get "dae.@subscription[$index].role" || true)
	index=$((index + 1))
	[ -n "$url" ] || continue
	case "$role" in
	""|routing)
		routing_count=$((routing_count + 1))
		routing_url=$url
		;;
	nodes) ;;
	*)
		echo "invalid subscription role: $role" >&2
		exit 1
		;;
	esac
done
if [ "$routing_count" -gt 1 ]; then
	echo "exactly one complete Mihomo routing subscription is allowed" >&2
	exit 1
fi
# dae reads the local file from inside the config directory only, and wants a
# path relative to it.
if [ -n "$mihomo_file" ]; then
	cfgdir=$(dirname "$CFG")
	case $mihomo_file in
	"$cfgdir"/*) mihomo_file=${mihomo_file#"$cfgdir"/} ;;
	/*)
		echo "dae.config.mihomo_config must be inside $cfgdir" >&2
		exit 1
		;;
	esac
fi
if [ -n "$mihomo_file" ] && [ "$routing_count" -eq 1 ]; then
	echo "note: dae.config.mihomo_config overrides the routing subscription" >&2
	routing_url=""
fi

umask 077
{
	echo "# generated by fdae from /etc/config/dae; do not edit"
	echo "global {"
	if [ -n "$lan" ]; then
		echo "    lan_interface: ${lan}"
	fi
	if [ -n "$wan" ]; then
		echo "    wan_interface: ${wan}"
	fi
	if [ -n "$listen" ]; then
		echo "    admin_listen: $(quote_dae "$listen")"
	fi
	if [ -n "$secret" ]; then
		echo "    admin_secret: $(quote_dae "$secret")"
	fi
	echo "}"

	index=0
	count=0
	opened=0
	while uci -q get "dae.@subscription[$index]" >/dev/null 2>&1; do
		tag=$(uci -q get "dae.@subscription[$index].tag" || true)
		url=$(uci -q get "dae.@subscription[$index].url" || true)
		role=$(uci -q get "dae.@subscription[$index].role" || true)
		index=$((index + 1))
		[ -n "$url" ] || continue
		[ "$role" = "nodes" ] || continue
		count=$((count + 1))
		if [ -z "$tag" ]; then
			tag="sub${count}"
		fi
		if ! sanitize_tag "$tag"; then
			echo "invalid subscription tag: $tag" >&2
			exit 1
		fi
		if [ "$opened" -eq 0 ]; then
			echo
			echo "subscription {"
			opened=1
		fi
		echo "    ${tag}: $(quote_dae "$(persist_url "$url")")"
	done
	if [ "$opened" -eq 1 ]; then
		echo "}"
	fi

	if [ -n "$mihomo_file" ] || [ -n "$routing_url" ]; then
		echo
		echo "mihomo {"
		if [ -n "$mihomo_file" ]; then
			echo "    routing_file: $(quote_dae "$mihomo_file")"
		else
			echo "    routing_subscription: $(quote_dae "$routing_url")"
		fi
		if [ -n "$mihomo_interval" ]; then
			echo "    interval: ${mihomo_interval}"
		fi
		if [ -n "$isolate_groups" ]; then
			list=""
			old_ifs=$IFS
			IFS=','
			for g in $isolate_groups; do
				g=$(printf '%s' "$g" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
				[ -n "$g" ] || continue
				list="${list:+$list, }$(quote_dae "$g")"
			done
			IFS=$old_ifs
			[ -z "$list" ] || echo "    isolate_transport_groups: ${list}"
		fi
		dns_open=0
		index=0
		while uci -q get "dae.@mixin[$index]" >/dev/null 2>&1; do
			name=$(uci -q get "dae.@mixin[$index].name" || true)
			dns=$(uci -q get "dae.@mixin[$index].resolve_dns" || true)
			index=$((index + 1))
			[ -n "$name" ] && [ -n "$dns" ] || continue
			if [ "$dns_open" -eq 0 ]; then
				echo "    node_resolve_dns {"
				dns_open=1
			fi
			echo "        $(quote_dae "${name}=${dns}")"
		done
		if [ "$dns_open" -eq 1 ]; then
			echo "    }"
		fi
		echo "}"
	fi

	# User-space SOCKS5 listeners. Each is rendered on its own first so that a
	# bad section stops the whole write instead of leaving half a block.
	index=0
	body=""
	while uci -q get "dae.@inbound[$index]" >/dev/null 2>&1; do
		entry=$(render_inbound "$index") || exit 1
		index=$((index + 1))
		[ -z "$entry" ] || body="${body:+$body
}$entry"
	done
	if [ -n "$body" ]; then
		echo
		echo "inbound {"
		printf '%s\n' "$body"
		echo "}"
	fi

	# geoip.dat / geosite.dat for geoip() and domain(geosite:) rules, fetched
	# and kept current by dae itself.
	if [ -n "$geoip_url" ] || [ -n "$geosite_url" ]; then
		echo
		echo "geodata {"
		[ -z "$geoip_url" ] || echo "    geoip: $(quote_dae "$geoip_url")"
		[ -z "$geosite_url" ] || echo "    geosite: $(quote_dae "$geosite_url")"
		[ -z "$geodata_interval" ] || echo "    interval: ${geodata_interval}"
		echo "}"
	fi
} > "$TMP"
mv "$TMP" "$CONF"
chmod 0600 "$CONF"

if [ -f "$CFG" ] && ! grep -q 'local.dae' "$CFG"; then
	echo "warning: $CFG does not include local.dae; add: include { local.dae }" >&2
fi
