#!/bin/sh
# Emergency datapath cleanup after kdae crashes (SIGKILL / panic / power loss).
# TC filters, dae0/daens, and pinned maps survive the process and can blackhole LAN.
# This script is safe to run when dae is already stopped.

set -u

log() {
	echo "$*"
}

running_dae() {
	pidof dae >/dev/null 2>&1
}

kill_leftover() {
	i=0
	while running_dae && [ "$i" -lt 5 ]; do
		sleep 1
		i=$((i + 1))
	done
	if running_dae; then
		log "killing leftover dae process"
		killall -9 dae 2>/dev/null || true
		sleep 1
	fi
}

line_pref() {
	echo "$1" | awk '{
		for (i = 1; i <= NF; i++)
			if ($i == "pref") { print $(i + 1); exit }
	}'
}

line_handle() {
	echo "$1" | awk '{
		for (i = 1; i <= NF; i++)
			if ($i == "handle") { print $(i + 1); exit }
	}'
}

is_dae_filter() {
	case "$1" in
	*dae_*|*0x2022*|*0x2023*) return 0 ;;
	esac
	return 1
}

purge_tc_dir() {
	dev=$1
	dir=$2
	pref=""
	tc filter show dev "$dev" "$dir" 2>/dev/null | while IFS= read -r line; do
		case "$line" in
		filter\ *)
			p=$(line_pref "$line")
			[ -n "$p" ] && pref=$p
			;;
		esac
		h=$(line_handle "$line")
		is_dae_filter "$line" || continue
		[ -n "$pref" ] || continue
		if [ -n "$h" ]; then
			if tc filter del dev "$dev" "$dir" pref "$pref" handle "$h" bpf 2>/dev/null ||
				tc filter del dev "$dev" "$dir" pref "$pref" handle "$h" 2>/dev/null ||
				tc filter del dev "$dev" "$dir" pref "$pref" 2>/dev/null; then
				log "removed tc $dev $dir pref=$pref handle=$h"
			fi
		elif tc filter del dev "$dev" "$dir" pref "$pref" 2>/dev/null; then
			log "removed tc $dev $dir pref=$pref"
		fi
	done
}

purge_tc() {
	if ! command -v tc >/dev/null 2>&1; then
		log "tc not found, skip filter purge"
		return
	fi
	for dev in /sys/class/net/*; do
		[ -e "$dev" ] || continue
		name=${dev##*/}
		purge_tc_dir "$name" ingress
		purge_tc_dir "$name" egress
	done
}

purge_netns() {
	if command -v ip >/dev/null 2>&1; then
		ip link del dae0 2>/dev/null && log "deleted dae0" || true
		ip netns del daens 2>/dev/null && log "deleted netns daens" || true
		ip link del dae0 2>/dev/null || true
	else
		log "ip not found, skip dae0/daens"
	fi
}

purge_pins() {
	if [ -e /sys/fs/bpf/dae ]; then
		rm -rf /sys/fs/bpf/dae
		log "removed /sys/fs/bpf/dae"
	fi
}

purge_cgroup() {
	command -v bpftool >/dev/null 2>&1 || return 0
	cg=$(awk '$3 == "cgroup2" { print $2; exit }' /proc/mounts)
	[ -n "$cg" ] || return 0
	# bpf_link usually dies with the process; leftover ids are best-effort.
	bpftool cgroup show "$cg" 2>/dev/null | awk '
		/tproxy_wan_cg_|dae_/ {
			for (i = 1; i <= NF; i++)
				if ($i == "id") print $(i + 1)
		}
	' | while read -r id; do
		[ -n "$id" ] || continue
		for attach in inet_sock_create inet_sock_release inet4_connect inet6_connect udp4_sendmsg udp6_sendmsg; do
			bpftool cgroup detach "$cg" "$attach" id "$id" 2>/dev/null &&
				log "detached cgroup prog id=$id attach=$attach" || true
		done
	done
}

log "kdae recover: purging leftover datapath"
kill_leftover
purge_tc
purge_netns
purge_pins
purge_cgroup
log "kdae recover: done"
exit 0
