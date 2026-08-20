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
			if ($i == "handle" || $i == "fh") { print $(i + 1); exit }
	}'
}

line_chain() {
	echo "$1" | awk '{
		for (i = 1; i <= NF; i++)
			if ($i == "chain") { print $(i + 1); exit }
	}'
}

# dae's TC filters use handle major 0x2022/0x2023 (see control/bpf_purge.go).
# Accept 0x20230004, 0x2023:4, 2023:0004, major-only 0x2023, and decimal
# (major<<16)|minor. Decimal packed handles are matched by 9-digit string
# range so awk integer precision cannot miss 0x2022/0x2023.
is_dae_handle() {
	echo "$1" | awk '
	{
		h = tolower($0)
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", h)
		if (h == "") exit 1
		if (index(h, "0x") == 1) h = substr(h, 3)
		n = split(h, parts, ":")
		if (n >= 2) {
			if (parts[1] == "2022" || parts[1] == "2023") exit 0
			exit 1
		}
		if (h ~ /^[0-9]+$/) {
			# Packed (major<<16)|minor as decimal. String-compare equal-length
			# digits so mawk/busybox cannot lose precision on the 9-digit values
			# 0x20220000=538968064 .. 0x2023ffff=539099135.
			if (length(h) == 9 && h >= "538968064" && h < "539033600") exit 0
			if (length(h) == 9 && h >= "539033600" && h < "539099136") exit 0
			# Fall through: iproute2 may omit 0x, e.g. 20230004.
		}
		if (h ~ /^[0-9a-f]+$/) {
			if (length(h) <= 4) {
				if (h == "2022" || h == "2023") exit 0
				exit 1
			}
			maj = substr(h, 1, length(h) - 4)
			if (maj == "2022" || maj == "2023") exit 0
		}
		exit 1
	}'
}

is_dae_name() {
	case "$1" in
	*dae_*) return 0 ;;
	esac
	return 1
}

try_del_tc() {
	dev=$1
	dir=$2
	pref=$3
	handle=$4
	chain=$5
	[ -n "$pref" ] && [ -n "$handle" ] || return 1
	if [ "${KDAE_RECOVER_DRY_RUN:-}" = 1 ]; then
		echo "DEL pref=$pref handle=$handle chain=$chain"
		return 0
	fi
	if [ -n "$chain" ]; then
		tc filter del dev "$dev" "$dir" pref "$pref" chain "$chain" handle "$handle" bpf 2>/dev/null && return 0
		tc filter del dev "$dev" "$dir" pref "$pref" chain "$chain" handle "$handle" 2>/dev/null && return 0
	fi
	tc filter del dev "$dev" "$dir" pref "$pref" handle "$handle" bpf 2>/dev/null && return 0
	tc filter del dev "$dev" "$dir" pref "$pref" handle "$handle" 2>/dev/null && return 0
	return 1
}

# Identify dae filters by handle major 0x2022/0x2023 (same as control/bpf_purge.go).
# A dae_ name is extra confirmation; it is not required. Pref+handle are required
# to delete. New "filter ..." headers reset handle/chain so a previous dae handle
# cannot leak onto the next rule.
purge_tc_show() {
	dev=$1
	dir=$2
	pref=""
	handle=""
	chain=""
	seen=""
	while IFS= read -r line; do
		case "$line" in
		filter\ *)
			p=$(line_pref "$line")
			[ -n "$p" ] && pref=$p
			handle=""
			chain=""
			;;
		esac
		h=$(line_handle "$line")
		[ -n "$h" ] && handle=$h
		c=$(line_chain "$line")
		[ -n "$c" ] && chain=$c
		if is_dae_handle "$handle" || is_dae_name "$line"; then
			if [ -z "$pref" ] || [ -z "$handle" ]; then
				log "skip tc $dev $dir: dae filter without pref/handle (pref=$pref handle=$handle)"
				continue
			fi
			if ! is_dae_handle "$handle"; then
				log "skip tc $dev $dir pref=$pref handle=$handle: name matched but handle is not dae major 0x2022/0x2023"
				continue
			fi
			key="$pref $handle $chain"
			if [ "$key" = "$seen" ]; then
				continue
			fi
			seen=$key
			if try_del_tc "$dev" "$dir" "$pref" "$handle" "$chain"; then
				log "removed tc $dev $dir pref=$pref handle=$handle"
			else
				log "skip tc $dev $dir pref=$pref handle=$handle: could not delete exactly"
			fi
		fi
	done
}

purge_tc_dir() {
	dev=$1
	dir=$2
	tc filter show dev "$dev" "$dir" 2>/dev/null | purge_tc_show "$dev" "$dir"
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

self_test_parser() {
	fail=0
	expect_handle() {
		h=$1
		want=$2
		if is_dae_handle "$h"; then
			got=1
		else
			got=0
		fi
		if [ "$got" -ne "$want" ]; then
			echo "FAIL is_dae_handle $h: got=$got want=$want"
			fail=1
		fi
	}
	expect_handle "0x20230004" 1
	expect_handle "0x20220001" 1
	expect_handle "0x2023:4" 1
	expect_handle "2023:0004" 1
	expect_handle "0x2023" 1
	expect_handle "20230004" 1
	expect_handle "539033601" 1
	expect_handle "0x1" 0
	expect_handle "1" 0
	expect_handle "0x2024" 0
	expect_handle "" 0

	got=$(KDAE_RECOVER_DRY_RUN=1 purge_tc_show dummy ingress <<'EOF' | grep '^DEL '
filter protocol all pref 2023 bpf chain 0 handle 0x20230004
	name dae_ingress_l2
filter protocol all pref 10 bpf handle 0x1
	name dae_unrelated
filter protocol all pref 2022 bpf handle 0x20220001
filter protocol all pref 2023 bpf chain 0
filter protocol all pref 2023 bpf chain 0 handle 0x2023:4
filter protocol all pref 2023 bpf
	name dae_missing_handle
EOF
)
	want=$(printf '%s\n' \
		"DEL pref=2023 handle=0x20230004 chain=0" \
		"DEL pref=2022 handle=0x20220001 chain=" \
		"DEL pref=2023 handle=0x2023:4 chain=0")
	if [ "$got" != "$want" ]; then
		echo "FAIL purge_tc_show deletes:"
		echo "got:"
		echo "$got"
		echo "want:"
		echo "$want"
		fail=1
	fi
	if [ "$fail" -eq 0 ]; then
		echo "kdae recover parser self-test: ok"
		exit 0
	fi
	exit 1
}

if [ "${1:-}" = "--self-test-parser" ]; then
	self_test_parser
fi

log "kdae recover: purging leftover datapath"
kill_leftover
purge_tc
purge_netns
purge_pins
purge_cgroup
log "kdae recover: done"
exit 0
