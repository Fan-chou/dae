package control

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// Lines are copied from a real gateway's /proc/net/nf_conntrack (acct on).
// Offloaded flows print neither timeout nor tcp state; copied from a gateway
// with flow_offloading on.
const conntrackOffloadTCP = `ipv4     2 tcp      6 src=192.168.124.126 dst=39.102.218.146 sport=44278 dport=1886 packets=1487 bytes=111360 src=39.102.218.146 dst=172.16.91.25 sport=1886 dport=44278 packets=1431 bytes=58444 [OFFLOAD] mark=0 zone=0 use=3`
const conntrackOffloadUDP = `ipv4     2 udp      17 src=192.168.124.222 dst=43.136.77.84 sport=41641 dport=33478 packets=32654 bytes=2220472 src=43.136.77.84 dst=172.16.91.25 sport=33478 dport=41641 packets=32653 bytes=2351016 [OFFLOAD] mark=0 zone=0 use=3`

const conntrackFixture = `ipv4     2 tcp      6 40 TIME_WAIT src=192.168.124.222 dst=163.142.155.2 sport=57850 dport=80 packets=4 bytes=180 src=163.142.155.2 dst=172.16.91.25 sport=80 dport=57850 packets=2 bytes=92 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 110 src=192.168.124.222 dst=43.167.220.138 sport=41641 dport=41641 packets=2005885 bytes=904891384 src=43.167.220.138 dst=172.16.91.25 sport=41641 dport=41641 packets=1566838 bytes=324282136 [OFFLOAD] mark=0 zone=0 use=3
ipv4     2 udp      17 120 src=192.168.124.200 dst=100.66.45.102 sport=51719 dport=25826 packets=407099 bytes=548836207 [UNREPLIED] src=100.66.45.102 dst=172.16.91.25 sport=25826 dport=51719 packets=0 bytes=0 [OFFLOAD] mark=0 zone=0 use=3
ipv4     2 tcp      6 431995 ESTABLISHED src=192.168.124.202 dst=104.18.1.1 sport=44444 dport=443 packets=10 bytes=2000 src=104.18.1.1 dst=172.16.91.25 sport=443 dport=44444 packets=12 bytes=9000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431995 ESTABLISHED src=172.16.91.25 dst=91.110.231.224 sport=57416 dport=50000 packets=500 bytes=70000 src=91.110.231.224 dst=172.16.91.25 sport=50000 dport=57416 packets=500 bytes=70000 [ASSURED] mark=256 zone=0 use=2
ipv4     2 tcp      6 431995 ESTABLISHED src=192.168.124.202 dst=198.51.100.10 sport=40000 dport=443 packets=3 bytes=300 src=198.51.100.10 dst=172.16.91.25 sport=443 dport=40000 packets=3 bytes=300 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431995 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=1 dport=2 packets=1 bytes=1 src=127.0.0.1 dst=127.0.0.1 sport=2 dport=1 packets=1 bytes=1 [ASSURED] mark=0 zone=0 use=2
ipv4     2 icmp     1 29 src=192.168.124.202 dst=8.8.8.8 type=8 code=0 id=1 packets=1 bytes=84 src=8.8.8.8 dst=172.16.91.25 type=0 code=0 id=1 packets=1 bytes=84 mark=0 zone=0 use=2
ipv6     10 tcp      6 431995 ESTABLISHED src=2409:8a55:358e:c970:be24:11ff:fe4d:2b90 dst=2606:b740:0001:0020:0000:0000:0000:0103 sport=42212 dport=443 packets=7 bytes=700 src=2606:b740:0001:0020:0000:0000:0000:0103 dst=2409:8a55:358e:c970:be24:11ff:fe4d:2b90 sport=443 dport=42212 packets=9 bytes=1900 [ASSURED] mark=0 zone=0 use=2
`

func TestParseConntrackLine(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(conntrackFixture), "\n")
	e, ok := parseConntrackLine([]byte(lines[1]))
	if !ok || e.proto != 17 || e.src != netip.MustParseAddrPort("192.168.124.222:41641") || e.dst != netip.MustParseAddrPort("43.167.220.138:41641") {
		t.Fatalf("udp tuple: ok=%v %+v", ok, e)
	}
	if e.upBytes != 904891384 || e.downBytes != 324282136 || e.upPackets != 2005885 || e.downPackets != 1566838 || !e.hasCounters || !e.offloaded {
		t.Fatalf("udp counters: %+v", e)
	}
	// Offloaded lines have no timeout/state: the tuple must not shift.
	e, ok = parseConntrackLine([]byte(conntrackOffloadTCP))
	if !ok || e.src != netip.MustParseAddrPort("192.168.124.126:44278") || e.dst != netip.MustParseAddrPort("39.102.218.146:1886") ||
		e.upBytes != 111360 || e.downBytes != 58444 || !e.offloaded || e.state != ctStateEstablished || e.ttl != 0 {
		t.Fatalf("offloaded tcp: ok=%v %+v", ok, e)
	}
	e, ok = parseConntrackLine([]byte(conntrackOffloadUDP))
	if !ok || e.src != netip.MustParseAddrPort("192.168.124.222:41641") || e.dst != netip.MustParseAddrPort("43.136.77.84:33478") || e.upPackets != 32654 || e.downPackets != 32653 {
		t.Fatalf("offloaded udp: ok=%v %+v", ok, e)
	}
	e, _ = parseConntrackLine([]byte(lines[2]))
	if !e.unreplied || e.downBytes != 0 || e.upBytes != 548836207 {
		t.Fatalf("unreplied: %+v", e)
	}
	e, _ = parseConntrackLine([]byte(lines[0]))
	if e.state != ctStateTimeWait || e.state.String() != "TIME_WAIT" || e.ttl != 40 {
		t.Fatalf("tcp state: %+v", e)
	}
	e, _ = parseConntrackLine([]byte(lines[4]))
	if e.mark != 256 {
		t.Fatalf("mark = %d", e.mark)
	}
	e, ok = parseConntrackLine([]byte(lines[8]))
	if !ok || !e.src.Addr().Is6() || e.dst.Port() != 443 {
		t.Fatalf("ipv6: ok=%v %+v", ok, e)
	}
	if _, ok := parseConntrackLine([]byte(lines[7])); ok {
		t.Fatal("icmp must be skipped")
	}
	// Without accounting there are no packets/bytes at all.
	e, ok = parseConntrackLine([]byte("ipv4     2 tcp      6 431998 ESTABLISHED src=192.168.124.220 dst=192.168.124.223 sport=34444 dport=22 src=192.168.124.223 dst=192.168.124.220 sport=22 dport=34444 [ASSURED] mark=0 zone=0 use=2"))
	if !ok || e.hasCounters || e.upBytes != 0 {
		t.Fatalf("no acct: ok=%v %+v", ok, e)
	}
	for _, bad := range []string{"", "ipv4 2 tcp", "ipv4 2 tcp 6 10 ESTABLISHED src=bogus dst=1.1.1.1 sport=1 dport=2", "ipv4 2 tcp 6 10 ESTABLISHED src=1.1.1.1 dst=2.2.2.2 sport=99999 dport=2"} {
		if _, ok := parseConntrackLine([]byte(bad)); ok {
			t.Fatalf("malformed line accepted: %q", bad)
		}
	}
}

func TestCollectKernelConnectionsExcludesAndRanks(t *testing.T) {
	userspace := map[kernelFlowKey]struct{}{
		{6, netip.MustParseAddrPort("192.168.124.202:40000"), netip.MustParseAddrPort("198.51.100.10:443")}: {},
	}
	entries, total, ex, acct, err := collectKernelConnections(strings.NewReader(conntrackFixture), kernelCollectInput{daeMark: 256, userspace: userspace})
	if err != nil {
		t.Fatal(err)
	}
	if !acct {
		t.Fatal("accounting not detected")
	}
	want := AdminKernelExcluded{Userspace: 1, Dae: 1, Inactive: 1, Local: 1}
	if ex != want {
		t.Fatalf("excluded = %+v, want %+v", ex, want)
	}
	// 2 offloaded udp + 1 tcp v4 + 1 tcp v6 remain, heaviest first.
	if total != 4 || len(entries) != 4 {
		t.Fatalf("total=%d entries=%d", total, len(entries))
	}
	if entries[0].upBytes != 904891384 || entries[1].upBytes != 548836207 {
		t.Fatalf("not ranked by bytes: %d, %d", entries[0].upBytes, entries[1].upBytes)
	}

	// A cap keeps the heaviest and still reports the full total.
	entries, total, _, _, _ = collectKernelConnections(strings.NewReader(conntrackFixture), kernelCollectInput{daeMark: 256, userspace: userspace, cap: 2})
	if total != 4 || len(entries) != 2 || entries[0].upBytes != 904891384 || entries[1].upBytes != 548836207 {
		t.Fatalf("capped: total=%d %+v", total, entries)
	}

	// Source filter.
	entries, total, _, _, _ = collectKernelConnections(strings.NewReader(conntrackFixture), kernelCollectInput{daeMark: 256, userspace: userspace, src: netip.MustParseAddr("192.168.124.200")})
	if total != 1 || len(entries) != 1 || entries[0].dst.Port() != 25826 {
		t.Fatalf("src filter: total=%d %+v", total, entries)
	}

	// daeMark 0 must never exclude (mark=0 is every normal flow).
	_, _, ex, _, _ = collectKernelConnections(strings.NewReader(conntrackFixture), kernelCollectInput{})
	if ex.Dae != 0 {
		t.Fatalf("daeMark 0 excluded %d flows", ex.Dae)
	}
}

func TestCollectKernelConnectionsBoundedOnHugeTable(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&sb, "ipv4     2 udp      17 100 src=10.0.%d.%d dst=1.1.1.1 sport=%d dport=53 packets=1 bytes=%d src=1.1.1.1 dst=10.0.0.1 sport=53 dport=%d packets=1 bytes=1 mark=0 zone=0 use=2\n", i/250, i%250+1, 1000+i%60000, i, 1000+i%60000)
	}
	entries, total, _, _, err := collectKernelConnections(strings.NewReader(sb.String()), kernelCollectInput{cap: 50})
	if err != nil || total != 20000 || len(entries) != 50 {
		t.Fatalf("err=%v total=%d entries=%d", err, total, len(entries))
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].upBytes+entries[i-1].downBytes < entries[i].upBytes+entries[i].downBytes {
			t.Fatal("entries not sorted heaviest first")
		}
	}
	if entries[0].upBytes != 19999 {
		t.Fatalf("heaviest = %d", entries[0].upBytes)
	}
}

func TestScanConntrackSurvivesOverlongLine(t *testing.T) {
	in := strings.Repeat("x", 200<<10) + "\n" + strings.Split(conntrackFixture, "\n")[1] + "\n"
	n := 0
	if _, err := scanConntrack(strings.NewReader(in), func(*ctEntry) { n++ }); err != nil || n != 1 {
		t.Fatalf("err=%v parsed=%d", err, n)
	}
}

func TestKernelConnectionsCollectorSharesScansWithinInterval(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "nf_conntrack")
	if err := os.WriteFile(proc, []byte(conntrackFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1000, 0)
	k := &KernelConnectionsCollector{procPath: proc, acctPath: filepath.Join(dir, "none"), minInterval: 2 * time.Second, now: func() time.Time { return clock }}

	first := k.Snapshot(nil, 0, "", "")
	// No control plane: nothing to exclude except TIME_WAIT and loopback.
	if !first.Available || !first.Accounting || first.Total != 6 {
		t.Fatalf("first = %+v", first)
	}
	// Rewrite the file: a request inside the interval must not see it.
	if err := os.WriteFile(proc, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Second)
	if again := k.Snapshot(nil, 0, "", ""); again.Total != 6 {
		t.Fatalf("scan was repeated inside the interval: %+v", again)
	}
	// A different filter is a different result and must rescan.
	if other := k.Snapshot(nil, 0, "192.168.124.200", ""); other.Total != 0 {
		t.Fatalf("filter served from another filter's cache: %+v", other)
	}
	clock = clock.Add(3 * time.Second)
	if later := k.Snapshot(nil, 0, "", ""); later.Total != 0 {
		t.Fatalf("stale after interval: %+v", later)
	}
	if bad := k.Snapshot(nil, 0, "not-an-ip", ""); bad.Error != "invalid src" {
		t.Fatalf("invalid src: %+v", bad)
	}
	k.procPath = filepath.Join(dir, "missing")
	clock = clock.Add(10 * time.Second)
	if gone := k.Snapshot(nil, 0, "", ""); gone.Available || gone.Error == "" {
		t.Fatalf("missing conntrack: %+v", gone)
	}
}

func TestKernelConnectionsTrimKeepsTotalAndTruncated(t *testing.T) {
	s := AdminKernelConnectionsSnapshot{Total: 5, Connections: make([]AdminKernelConnection, 5)}
	got := trimKernelSnapshot(s, 2)
	if len(got.Connections) != 2 || !got.Truncated || got.Total != 5 {
		t.Fatalf("%+v", got)
	}
	if len(s.Connections) != 5 {
		t.Fatal("trim must not shorten the cached snapshot")
	}
}

func TestDomainsForIPsPicksFreshestAnswer(t *testing.T) {
	c := &DnsController{dnsControllerStore: &dnsControllerStore{}}
	mk := func(name, ip string, at time.Time, routeOnly bool) {
		c.dnsCache.Store(name+ip, &DnsCache{
			RouteOnly:  routeOnly,
			ReceivedAt: at,
			Answer:     []dnsmessage.RR{&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: name}, A: netip.MustParseAddr(ip).AsSlice()}},
		})
	}
	base := time.Unix(1000, 0)
	mk("old.example.com.", "104.18.1.1", base, false)
	mk("new.example.com.", "104.18.1.1", base.Add(time.Minute), false)
	mk("route-only.example.com.", "104.18.9.9", base, true)
	mk("other.example.com.", "104.18.2.2", base, false)

	got := c.DomainsForIPs(map[netip.Addr]struct{}{
		netip.MustParseAddr("104.18.1.1"): {},
		netip.MustParseAddr("104.18.9.9"): {},
		netip.MustParseAddr("9.9.9.9"):    {},
	})
	if got[netip.MustParseAddr("104.18.1.1")] != "new.example.com" {
		t.Fatalf("freshest answer not chosen: %v", got)
	}
	if _, ok := got[netip.MustParseAddr("104.18.9.9")]; ok {
		t.Fatal("route-only entry must not be used for display")
	}
	if len(got) != 1 {
		t.Fatalf("unexpected extra mappings: %v", got)
	}
	var nilCtl *DnsController
	if nilCtl.DomainsForIPs(map[netip.Addr]struct{}{netip.MustParseAddr("1.1.1.1"): {}}) != nil {
		t.Fatal("nil controller must return nil")
	}
}

func TestKernelConnectionsBackoffScalesWithScanCost(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "nf_conntrack")
	if err := os.WriteFile(proc, []byte(conntrackFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1000, 0)
	// Every now() call advances 100ms, so the scan measures as 100ms and the
	// collector must hold the result for at least 20x that.
	k := &KernelConnectionsCollector{procPath: proc, acctPath: filepath.Join(dir, "none"), minInterval: 2 * time.Second,
		now: func() time.Time { clock = clock.Add(100 * time.Millisecond); return clock }}
	first := k.Snapshot(nil, 0, "", "")
	if first.ScanMs == 0 {
		t.Fatal("scan duration not measured")
	}
	if want := time.Duration(kernelConnectionsBackoff) * time.Duration(first.ScanMs) * time.Millisecond; k.cachedFor < want {
		t.Fatalf("cachedFor %v, want at least %v", k.cachedFor, want)
	}
}

func TestKernelConnectionsFilterAndLabelByMac(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "nf_conntrack")
	if err := os.WriteFile(proc, []byte(conntrackFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	laptop := [6]byte{0x3e, 0x0a, 0xa5, 0xde, 0xae, 0xa3}
	phone := [6]byte{0x58, 0x47, 0xca, 0x74, 0x69, 0xf8}
	macOf := map[netip.Addr][6]byte{
		netip.MustParseAddr("192.168.124.200"): laptop,
		netip.MustParseAddr("192.168.124.202"): phone,
	}
	addrsOf := map[[6]byte][]netip.Addr{
		laptop: {netip.MustParseAddr("192.168.124.200")},
		phone:  {netip.MustParseAddr("192.168.124.202")},
	}
	resolver := &kernelMacResolver{
		macOf:   func(a netip.Addr) ([6]byte, bool) { m, ok := macOf[a]; return m, ok },
		addrsOf: func(m [6]byte) []netip.Addr { return addrsOf[m] },
	}
	newCollector := func() *KernelConnectionsCollector {
		return &KernelConnectionsCollector{
			procPath: proc, acctPath: filepath.Join(dir, "none"), minInterval: time.Second,
			now:         func() time.Time { return time.Unix(1000, 0) },
			macResolver: func(*ControlPlane) *kernelMacResolver { return resolver },
		}
	}

	// Without a filter every client with a known MAC is labelled; unknown
	// clients stay unlabelled rather than being guessed.
	all := newCollector().Snapshot(nil, 0, "", "")
	labelled := map[string]string{}
	for _, c := range all.Connections {
		labelled[c.Src] = c.Mac
	}
	if labelled["192.168.124.200:51719"] != "3e:0a:a5:de:ae:a3" || labelled["192.168.124.202:44444"] != "58:47:ca:74:69:f8" {
		t.Fatalf("labels = %v", labelled)
	}
	if labelled["172.16.91.25:57416"] != "" {
		t.Fatalf("unknown client was labelled: %q", labelled["172.16.91.25:57416"])
	}

	// A MAC filter keeps only that client's flows.
	only := newCollector().Snapshot(nil, 0, "", "3E:0A:A5:DE:AE:A3")
	if only.Total != 1 || len(only.Connections) != 1 || only.Connections[0].Src != "192.168.124.200:51719" {
		t.Fatalf("mac filter: %+v", only)
	}
	// A MAC dae has not learned matches nothing (not everything).
	none := newCollector().Snapshot(nil, 0, "", "aa:bb:cc:dd:ee:ff")
	if none.Total != 0 || len(none.Connections) != 0 {
		t.Fatalf("unknown mac matched: %+v", none)
	}
	if bad := newCollector().Snapshot(nil, 0, "", "zz"); bad.Error != "invalid mac" {
		t.Fatalf("invalid mac: %+v", bad)
	}

	// Different filters must not share a cache entry.
	k := newCollector()
	_ = k.Snapshot(nil, 0, "", "")
	if got := k.Snapshot(nil, 0, "", "3e:0a:a5:de:ae:a3"); got.Total != 1 {
		t.Fatalf("mac filter served from unfiltered cache: %+v", got)
	}
}
