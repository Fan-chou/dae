#!/usr/bin/env bash
# Real-kernel functional + performance test for the direct-proof fwmark
# (egress_guard_proof_mark) together with egress-guard's nftables hook.
#
# Topology (all temporary, nothing else on the host is touched):
#   egl-cli ns (198.21.1.2, 2001:db8:21:1::2)
#      | egl-lan1 <-> egl-lan0 (host, dae lan_interface, egress-guard iif)
#   host = gateway (dae + inet egressguard table, ip_forward)
#      | egl-wan0 <-> egl-wan1
#   egl-srv ns (198.21.2.2, 2001:db8:21:2::2)  echo/iperf/HTTP servers
#
# usage: egress-proof-live-test.sh <dae-new> <dae-base> <egressguard.py> <workdir> [rounds] [mode]
#   mode: all (default) | func | perf
set -uo pipefail

dae_new=${1:?dae-new}
dae_base=${2:?dae-base}
guard_py=${3:?egressguard.py}
work=${4:?workdir}
rounds=${5:-3}
mode=${6:-all}

CLI=egl-cli
SRV=egl-srv
LAN=egl-lan0
LAN_P=egl-lan1
WAN=egl-wan0
WAN_P=egl-wan1
SRV4=198.21.2.2
SRV6=2001:db8:21:2::2
PROOF=0x40000000

[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 1; }
for c in ip nft tc iperf3 python3 ping sysctl; do command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 1; }; done
[ -x "$dae_new" ] && [ -x "$dae_base" ] && [ -f "$guard_py" ] || { echo "bad inputs" >&2; exit 1; }
for l in $LAN $WAN dae0; do ip link show "$l" >/dev/null 2>&1 && { echo "$l exists; refusing" >&2; exit 1; }; done
for n in $CLI $SRV daens; do ip netns list | grep -q "^$n\b" && { echo "netns $n exists; refusing" >&2; exit 1; }; done
[ -e /sys/fs/bpf/dae ] && { echo "/sys/fs/bpf/dae exists; refusing" >&2; exit 1; }
nft list table inet egressguard >/dev/null 2>&1 && { echo "inet egressguard exists; refusing" >&2; exit 1; }

mkdir -p "$work"
RESULTS="$work/results.log"
PERF="$work/perf.csv"
: >"$RESULTS"; : >"$PERF"
orig_v6fwd=$(sysctl -n net.ipv6.conf.all.forwarding)
orig_v4fwd=$(sysctl -n net.ipv4.ip_forward)
orig_all_redirects=$(sysctl -n net.ipv4.conf.all.send_redirects)
default_if=$(ip route show default | awk '/default/ {print $5; exit}')
orig_ra=
if [ -n "$default_if" ]; then orig_ra=$(sysctl -n "net.ipv6.conf.$default_if.accept_ra" 2>/dev/null || true); fi
echo "host: $(uname -r) cpus=$(nproc) load=$(cut -d' ' -f1-3 /proc/loadavg) default_if=$default_if orig_v6fwd=$orig_v6fwd orig_ra=$orig_ra" | tee -a "$RESULTS"

dae_pid=
bg_pids=()

############################ helpers ############################
cat >"$work/servers.py" <<'PY'
import asyncio, socket, sys

async def echo(reader, writer):
    try:
        data = await reader.read(1)
        writer.write(data or b'x')
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def http204(reader, writer):
    try:
        await reader.readuntil(b'\r\n\r\n')
        writer.write(b'HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport): self.t = transport
    def datagram_received(self, data, addr): self.t.sendto(data, addr)

async def main():
    loop = asyncio.get_running_loop()
    for port in (8042, 8044, 8045):
        await asyncio.start_server(echo, ['0.0.0.0', '::'], port, reuse_address=True, backlog=1024)
    await asyncio.start_server(http204, ['0.0.0.0', '::'], 8046, reuse_address=True)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', 9000))
    await loop.create_datagram_endpoint(UdpEcho, sock=sock)
    await asyncio.Event().wait()

asyncio.run(main())
PY

cat >"$work/probe.py" <<'PY'
import socket, subprocess, sys
kind, port = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0
V4, V6 = sys.argv[3], sys.argv[4]
try:
    if kind in ('tcp4', 'tcp6'):
        s = socket.create_connection((V4 if kind == 'tcp4' else V6, port), timeout=1.5)
        s.sendall(b'x'); assert s.recv(1) == b'x'; s.close()
    elif kind in ('udp4', 'udp6'):
        fam = socket.AF_INET if kind == 'udp4' else socket.AF_INET6
        s = socket.socket(fam, socket.SOCK_DGRAM); s.settimeout(1.0)
        for _ in range(3):
            s.sendto(b'probe', (V4 if kind == 'udp4' else V6, port))
            try:
                if s.recv(64) == b'probe': break
            except socket.timeout:
                continue
        else:
            sys.exit(1)
    elif kind in ('icmp4', 'icmp6'):
        cmd = ['ping', '-c', '2', '-W', '1', '-n', V4 if kind == 'icmp4' else V6]
        sys.exit(0 if subprocess.run(cmd, capture_output=True).returncode == 0 else 1)
    else:
        sys.exit(2)
except (OSError, AssertionError):
    sys.exit(1)
sys.exit(0)
PY

cat >"$work/connrate.py" <<'PY'
import json, socket, sys, time
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
lat = []
t0 = time.perf_counter()
for _ in range(n):
    t = time.perf_counter()
    s = socket.create_connection((host, port), timeout=3)
    s.sendall(b'x'); s.recv(1); s.close()
    lat.append(time.perf_counter() - t)
el = time.perf_counter() - t0
lat.sort()
print(json.dumps(dict(rate=n / el, p50_us=lat[n // 2] * 1e6, p99_us=lat[int(n * .99)] * 1e6)))
PY

cat >"$work/socks5.py" <<'PY'
import select, socket, struct, sys, threading

def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 30)
            if not r: break
            for s in r:
                d = s.recv(65536)
                if not d: return
                (b if s is a else a).sendall(d)
    except OSError:
        pass
    finally:
        a.close(); b.close()

def handle(c):
    try:
        c.recv(262); c.sendall(b'\x05\x00')
        h = c.recv(4)
        if h[1] != 1: c.close(); return
        if h[3] == 1: addr = socket.inet_ntoa(c.recv(4))
        elif h[3] == 3: addr = c.recv(c.recv(1)[0]).decode()
        else: addr = socket.inet_ntop(socket.AF_INET6, c.recv(16))
        port = struct.unpack('!H', c.recv(2))[0]
        up = socket.create_connection((addr, port), timeout=5)
        c.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        pipe(c, up)
    except Exception:
        c.close()

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 1080)); srv.listen(256)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY

cat >"$work/guardctl.py" <<'PY'
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location('egressguard', sys.argv[1])
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
mode = sys.argv[2]
if mode == 'on':
    cfg = g.Config(dict(enabled='1', interface=[sys.argv[3]], proof_enabled='1', proof_mark=sys.argv[4]))
    g.Nft().replace(cfg, [], [], [])
else:
    subprocess.run(['nft', 'delete', 'table', 'inet', 'egressguard'], capture_output=True)
PY

log() { echo "$*" | tee -a "$RESULTS"; }

cleanup() {
	set +e
	trap - EXIT INT TERM
	stop_dae
	for p in "${bg_pids[@]}"; do kill -TERM "$p" 2>/dev/null; done
	sleep 0.5
	for p in "${bg_pids[@]}"; do kill -KILL "$p" 2>/dev/null; done
	nft delete table inet egressguard 2>/dev/null
	ip link del $LAN 2>/dev/null
	ip link del $WAN 2>/dev/null
	ip netns del $CLI 2>/dev/null
	ip netns del $SRV 2>/dev/null
	ip link del dae0 2>/dev/null
	ip netns del daens 2>/dev/null
	rm -rf /sys/fs/bpf/dae
	sysctl -q -w net.ipv6.conf.all.forwarding="$orig_v6fwd" >/dev/null 2>&1
	if [ -n "$default_if" ] && [ -n "$orig_ra" ]; then sysctl -q -w "net.ipv6.conf.$default_if.accept_ra=$orig_ra" >/dev/null 2>&1; fi
	sysctl -q -w net.ipv4.ip_forward="$orig_v4fwd" net.ipv4.conf.all.send_redirects="$orig_all_redirects" >/dev/null 2>&1
	log "cleanup done; v6fwd=$(sysctl -n net.ipv6.conf.all.forwarding) v4fwd=$(sysctl -n net.ipv4.ip_forward) all_redirects=$(sysctl -n net.ipv4.conf.all.send_redirects) ra=$( [ -n "$default_if" ] && sysctl -n net.ipv6.conf.$default_if.accept_ra)"
}
trap cleanup EXIT INT TERM

setup_net() {
	ip netns add $CLI; ip netns add $SRV
	ip link add $LAN type veth peer name $LAN_P; ip link set $LAN_P netns $CLI
	ip link add $WAN type veth peer name $WAN_P; ip link set $WAN_P netns $SRV
	ip addr add 198.21.1.1/24 dev $LAN; ip addr add 198.21.2.1/24 dev $WAN
	ip -6 addr add 2001:db8:21:1::1/64 dev $LAN nodad; ip -6 addr add 2001:db8:21:2::1/64 dev $WAN nodad
	ip link set $LAN up; ip link set $WAN up
	ip -n $CLI link set lo up; ip -n $SRV link set lo up
	ip -n $CLI addr add 198.21.1.2/24 dev $LAN_P; ip -n $SRV addr add $SRV4/24 dev $WAN_P
	ip -n $CLI -6 addr add 2001:db8:21:1::2/64 dev $LAN_P nodad; ip -n $SRV -6 addr add $SRV6/64 dev $WAN_P nodad
	ip -n $CLI link set $LAN_P up; ip -n $SRV link set $WAN_P up
	ip -n $CLI route add default via 198.21.1.1; ip -n $SRV route add default via 198.21.2.1
	ip -n $CLI -6 route add default via 2001:db8:21:1::1; ip -n $SRV -6 route add default via 2001:db8:21:2::1
	sysctl -q -w net.ipv4.ip_forward=1
	# IPv6 forwarding is global in Linux; keep the default uplink accepting RAs while it is on.
	if [ -n "$default_if" ]; then sysctl -q -w "net.ipv6.conf.$default_if.accept_ra=2" >/dev/null 2>&1; fi
	sysctl -q -w net.ipv6.conf.all.forwarding=1
	for i in $LAN $WAN; do sysctl -q -w net.ipv4.conf.$i.rp_filter=0 >/dev/null 2>&1; done
	# dae refuses to attach to a LAN interface that sends ICMP redirects.
	sysctl -q -w net.ipv4.conf.$LAN.send_redirects=0 net.ipv4.conf.all.send_redirects=0
	# offloads off on the veths so tc/BPF sees real-size packets consistently
	ip netns exec $CLI ethtool -K $LAN_P gro off gso off tso off >/dev/null 2>&1 || true
}

start_servers() {
	ip netns exec $SRV python3 "$work/servers.py" >"$work/servers.log" 2>&1 & bg_pids+=($!)
	ip netns exec $SRV iperf3 -s -p 5201 >"$work/iperf-server.log" 2>&1 & bg_pids+=($!)
	python3 "$work/socks5.py" >"$work/socks5.log" 2>&1 & bg_pids+=($!)
	sleep 1
}

write_conf() { # $1=proof mark (0=off) $2=extended(1)/simple(0)
	local f="$work/dae-$1-$2.dae"
	{
		echo "global {"
		echo "    lan_interface: $LAN"
		echo "    disable_waiting_network: true"
		echo "    log_level: info"
		[ "$1" != 0 ] && echo "    egress_guard_proof_mark: $1"
		if [ "$2" = 1 ]; then
			echo "    tcp_check_url: 'http://$SRV4:8046/generate_204'"
			echo "    udp_check_dns: '$SRV4:9000'"
			echo "    check_interval: 5s"
		fi
		echo "}"
		if [ "$2" = 1 ]; then
			echo "node { px: 'socks5://127.0.0.1:1080' }"
			echo "group { proxy { policy: min_moving_avg } }"
			echo "routing {"
			echo "    dport(8044) -> block"
			echo "    dport(8045) -> proxy"
			echo "    fallback: direct"
			echo "}"
		else
			echo "routing { fallback: direct }"
		fi
	} >"$f"
	chmod 600 "$f"
	echo "$f"
}

start_dae() { # $1=binary $2=conf
	: >"$work/dae.log"
	"$1" run -c "$2" --disable-sudo --disable-pidfile --disable-timestamp >"$work/dae.log" 2>&1 &
	dae_pid=$!
	for _ in $(seq 1 60); do
		grep -Fq "Control plane built" "$work/dae.log" && break
		kill -0 "$dae_pid" 2>/dev/null || { log "dae exited early:"; tail -20 "$work/dae.log" | tee -a "$RESULTS"; return 1; }
		sleep 0.5
	done
	for _ in $(seq 1 20); do
		grep -Fq "Bind to LAN: $LAN" "$work/dae.log" && break
		sleep 0.3
	done
	# dae attaches with TCX on new kernels, so `tc filter show` cannot be used.
	if ! kill -0 "$dae_pid" 2>/dev/null || grep -q "level=fatal\|level=error" "$work/dae.log"; then
		log "dae failed to bind LAN:"; tail -5 "$work/dae.log" | tee -a "$RESULTS"; return 1
	fi
	sleep 3
}

stop_dae() {
	[ -n "$dae_pid" ] || return 0
	kill -TERM "$dae_pid" 2>/dev/null
	for _ in $(seq 1 20); do kill -0 "$dae_pid" 2>/dev/null || break; sleep 0.3; done
	kill -KILL "$dae_pid" 2>/dev/null
	wait "$dae_pid" 2>/dev/null
	dae_pid=
	ip link del dae0 2>/dev/null; ip netns del daens 2>/dev/null; rm -rf /sys/fs/bpf/dae
	sleep 0.5
}

guard_on() { python3 "$work/guardctl.py" "$guard_py" on $LAN $PROOF >>"$work/guard.log" 2>&1 || { log "guard on failed"; tail -5 "$work/guard.log" | tee -a "$RESULTS"; return 1; }; }
guard_off() { python3 "$work/guardctl.py" "$guard_py" off >>"$work/guard.log" 2>&1; }

probe() { ip netns exec $CLI timeout 15 python3 "$work/probe.py" "$1" "$2" "$SRV4" "$SRV6"; }

FAILS=0
expect() { # $1=label $2=expected(ok|fail) $3=kind $4=port
	local want=$2 got
	if probe "$3" "$4"; then got=ok; else got=fail; fi
	if [ "$want" = "$got" ]; then log "PASS  $1 [$3:$4] expect=$want"; else log "FAIL  $1 [$3:$4] expect=$want got=$got"; FAILS=$((FAILS+1)); fi
}

############################ functional ############################
functional() {
	log "=== FUNCTIONAL ==="
	local conf

	log "--- F1: new dae, proof OFF, guard OFF (pass-through baseline)"
	conf=$(write_conf 0 1); start_dae "$dae_new" "$conf" || return 1
	for k in tcp4 tcp6 udp4 udp6 icmp4 icmp6; do expect F1 ok $k $([ "${k#udp}" != "$k" ] && echo 9000 || echo 8042); done
	expect F1-block fail tcp4 8044
	expect F1-proxy ok tcp4 8045

	log "--- F2: new dae, proof OFF, guard ON -> guard must deny everything (dae gives no proof)"
	guard_on || return 1
	for k in tcp4 tcp6 udp4 udp6 icmp4 icmp6; do expect F2 fail $k $([ "${k#udp}" != "$k" ] && echo 9000 || echo 8042); done
	stop_dae; guard_off

	log "--- F3: new dae, proof ON, guard ON"
	conf=$(write_conf $PROOF 1); start_dae "$dae_new" "$conf" || return 1
	guard_on || return 1
	# dae never routes ICMP (non TCP/UDP), so it gets no proof; before any proof exists for this
	# source/destination pair the guard must drop it.
	for k in icmp4 icmp6; do expect F3-nonTCPUDP-first fail $k 0; done
	for k in tcp4 tcp6 udp4 udp6; do expect F3-direct ok $k $([ "${k#udp}" != "$k" ] && echo 9000 || echo 8042); done
	# egress-guard's IPv4 lease is keyed by source+destination IP (protocol independent), so after a
	# proof-carrying TCP/UDP packet ICMP to the same destination passes while the lease lives; IPv6
	# has no lease and must stay blocked.
	expect F3-icmp4-within-lease ok icmp4 0
	expect F3-icmp6-no-lease fail icmp6 0
	expect F3-block fail tcp4 8044
	expect F3-proxy ok tcp4 8045
	log "guard counters (direct proof rule):"
	nft list chain inet egressguard guard4 2>/dev/null | grep -E "fresh direct proof|default deny" | sed 's/^ */    /' | tee -a "$RESULTS"
	nft list chain inet egressguard guard6 2>/dev/null | grep -E "fresh IPv6 proof|requires current proof" | sed 's/^ */    /' | tee -a "$RESULTS"

	log "--- F3b: proxy path does not carry proof (proof ON, guard ON, many proxied flows)"
	local before after
	before=$(nft list chain inet egressguard guard4 2>/dev/null | grep "fresh direct proof" | sed -E 's/.*packets ([0-9]+).*/\1/')
	for _ in 1 2 3 4 5; do probe tcp4 8045 || true; done
	after=$(nft list chain inet egressguard guard4 2>/dev/null | grep "fresh direct proof" | sed -E 's/.*packets ([0-9]+).*/\1/')
	if [ "$before" = "$after" ]; then log "PASS  F3b proxied flows hit no proof rule (packets $before -> $after)"; else log "FAIL  F3b proxied flows reached the proof rule ($before -> $after)"; FAILS=$((FAILS+1)); fi

	log "--- F3c: stop dae while guard stays: IPv6 (no lease) must fail closed; IPv4 keeps working only within its lease"
	stop_dae
	expect F3c-ipv6-fail-closed fail tcp6 8042
	expect F3c-ipv4-lease-still-valid ok tcp4 8042
	guard_off
	log "FUNCTIONAL failures: $FAILS"
}

############################ performance ############################
iperf_json_bps() { python3 -c '
import json,sys
r=json.load(open(sys.argv[1])); e=r["end"]
s=e.get("sum_received") or e.get("sum")
extra=""
if "sum_sent" in e and "retransmits" in e["sum_sent"]: extra=e["sum_sent"]["retransmits"]
if "lost_percent" in (e.get("sum") or {}): extra=e["sum"]["lost_percent"]
print(s["bits_per_second"], extra)
' "$1"; }

measure() { # $1=label $2=round
	local label=$1 round=$2 out bps extra
	for streams in 1 4; do
		ip netns exec $CLI timeout 40 iperf3 -c $SRV4 -p 5201 -t 6 -P $streams -J >"$work/ip.json" 2>"$work/ip.err" || { log "iperf tcp P$streams failed ($label)"; continue; }
		read -r bps extra < <(iperf_json_bps "$work/ip.json")
		echo "$label,$round,tcp_P${streams}_bps,$bps" >>"$PERF"; echo "$label,$round,tcp_P${streams}_retr,$extra" >>"$PERF"
	done
	ip netns exec $CLI timeout 40 iperf3 -c $SRV4 -p 5201 -u -b 1G -l 1200 -t 6 -J >"$work/ip.json" 2>"$work/ip.err" || log "iperf udp failed ($label)"
	read -r bps extra < <(iperf_json_bps "$work/ip.json")
	echo "$label,$round,udp_bps,$bps" >>"$PERF"; echo "$label,$round,udp_loss_pct,$extra" >>"$PERF"
	out=$(ip netns exec $CLI timeout 60 python3 "$work/connrate.py" $SRV4 8042 3000)
	echo "$label,$round,conn_rate,$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["rate"])')" >>"$PERF"
	echo "$label,$round,conn_p50_us,$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["p50_us"])')" >>"$PERF"
	echo "$label,$round,conn_p99_us,$(echo "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["p99_us"])')" >>"$PERF"
}

perf_cfg() { # $1=label
	case $1 in
	P0_no_dae) guard_off; stop_dae ;;
	P1_base_dae) guard_off; stop_dae; start_dae "$dae_base" "$(write_conf 0 0)" ;;
	P2_new_proof0) guard_off; stop_dae; start_dae "$dae_new" "$(write_conf 0 0)" ;;
	P3_new_proof_on_noguard) guard_off; stop_dae; start_dae "$dae_new" "$(write_conf $PROOF 0)" ;;
	P4_new_proof_on_guard) stop_dae; start_dae "$dae_new" "$(write_conf $PROOF 0)" && guard_on ;;
	esac
}

performance() {
	log "=== PERFORMANCE (rounds=$rounds) ==="
	local r l
	for r in $(seq 1 "$rounds"); do
		for l in P0_no_dae P1_base_dae P2_new_proof0 P3_new_proof_on_noguard P4_new_proof_on_guard; do
			perf_cfg "$l" || { log "config $l failed to start"; continue; }
			measure "$l" "$r"
			log "round $r $l done"
		done
	done
	stop_dae; guard_off
	python3 - "$PERF" <<'PY' | tee -a "$RESULTS"
import csv, statistics, sys, collections
d = collections.defaultdict(list)
for label, rnd, metric, val in csv.reader(open(sys.argv[1])):
    try: d[(label, metric)].append(float(val))
    except ValueError: pass
labels = []
for (l, _m) in d:
    if l not in labels: labels.append(l)
metrics = ['tcp_P1_bps', 'tcp_P4_bps', 'tcp_P1_retr', 'tcp_P4_retr', 'udp_bps', 'udp_loss_pct', 'conn_rate', 'conn_p50_us', 'conn_p99_us']
print('median over rounds (n=%d)' % max(len(v) for v in d.values()))
print('%-26s' % 'config' + ''.join('%14s' % m for m in metrics))
for l in labels:
    row = '%-26s' % l
    for m in metrics:
        v = d.get((l, m))
        if not v: row += '%14s' % '-'; continue
        x = statistics.median(v)
        row += '%14s' % (('%.2f Gb/s' % (x / 1e9)) if m.endswith('_bps') else ('%.1f' % x))
    print(row)
base = {m: statistics.median(d[('P1_base_dae', m)]) for m in metrics if d.get(('P1_base_dae', m))}
print('\nvs P1_base_dae (relative):')
for l in labels:
    row = '%-26s' % l
    for m in ['tcp_P1_bps', 'tcp_P4_bps', 'udp_bps', 'conn_rate', 'conn_p50_us']:
        v = d.get((l, m)); b = base.get(m)
        row += '%14s' % ('-' if not v or not b else '%+.1f%%' % ((statistics.median(v) / b - 1) * 100))
    print(row)
PY
}

setup_net
start_servers
case $mode in
all) functional; performance ;;
func) functional ;;
perf) performance ;;
esac
log "DONE failures=$FAILS"
exit 0
