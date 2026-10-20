/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

// This file serves the kernel-path view of GET /v1/kernel-connections: flows
// that the kernel forwards without ever reaching dae's userspace relay (direct
// traffic on the eBPF fast path), read from the kernel's conntrack table.
//
// Cost model. Nothing here runs on the packet path. The table is read only
// when a client asks for the view, at most once per kernelConnectionsMinInterval
// no matter how many clients poll, and it is streamed line by line so memory is
// bounded by the result limit, not by the table size.

const (
	conntrackProcPath            = "/proc/net/nf_conntrack"
	conntrackAcctSysctl          = "/proc/sys/net/netfilter/nf_conntrack_acct"
	kernelConnectionsMinInterval = 2 * time.Second
)

// ctState is a TCP conntrack state, or ctStateNone for other protocols.
type ctState uint8

const (
	ctStateNone ctState = iota
	ctStateSynSent
	ctStateSynRecv
	ctStateEstablished
	ctStateFinWait
	ctStateCloseWait
	ctStateLastAck
	ctStateTimeWait
	ctStateClose
	ctStateOther
)

var ctStateNames = [...]string{
	ctStateNone:        "",
	ctStateSynSent:     "SYN_SENT",
	ctStateSynRecv:     "SYN_RECV",
	ctStateEstablished: "ESTABLISHED",
	ctStateFinWait:     "FIN_WAIT",
	ctStateCloseWait:   "CLOSE_WAIT",
	ctStateLastAck:     "LAST_ACK",
	ctStateTimeWait:    "TIME_WAIT",
	ctStateClose:       "CLOSE",
	ctStateOther:       "OTHER",
}

func (s ctState) String() string { return ctStateNames[s] }

// ctEntry is one parsed conntrack line, original direction first. Upload is
// the original direction (initiator to responder), Download the reply.
type ctEntry struct {
	proto       uint8 // 6 tcp, 17 udp
	state       ctState
	ttl         uint32
	src, dst    netip.AddrPort
	upBytes     uint64
	downBytes   uint64
	upPackets   uint64
	downPackets uint64
	hasCounters bool
	mark        uint32
	unreplied   bool
	offloaded   bool
}

func unsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

func nextCTToken(line []byte) (token, rest []byte) {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	line = line[i:]
	if len(line) == 0 {
		return nil, nil
	}
	j := 0
	for j < len(line) && line[j] != ' ' && line[j] != '\t' {
		j++
	}
	return line[:j], line[j:]
}

func parseCTUint(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		next := v*10 + uint64(c-'0')
		if next < v {
			return 0, false
		}
		v = next
	}
	return v, true
}

func parseCTState(b []byte) ctState {
	switch string(b) {
	case "SYN_SENT", "SYN_SENT2":
		return ctStateSynSent
	case "SYN_RECV":
		return ctStateSynRecv
	case "ESTABLISHED":
		return ctStateEstablished
	case "FIN_WAIT":
		return ctStateFinWait
	case "CLOSE_WAIT":
		return ctStateCloseWait
	case "LAST_ACK":
		return ctStateLastAck
	case "TIME_WAIT":
		return ctStateTimeWait
	case "CLOSE":
		return ctStateClose
	default:
		return ctStateOther
	}
}

// parseConntrackLine parses one /proc/net/nf_conntrack line. It reports
// ok=false for protocols other than tcp/udp and for malformed lines. The first
// src/dst/sport/dport/packets/bytes occurrence is the original direction, the
// second the reply direction. packets/bytes exist only with
// net.netfilter.nf_conntrack_acct=1.
func parseConntrackLine(line []byte) (e ctEntry, ok bool) {
	ok = parseConntrackInto(line, &e)
	return e, ok
}

// parseConntrackInto is parseConntrackLine writing into a reused entry, so a
// scan of a large table does not allocate per line.
func parseConntrackInto(line []byte, e *ctEntry) bool {
	*e = ctEntry{}
	var tok []byte
	rest := line
	// l3 name, l3 number, l4 name, l4 number
	var head [4][]byte
	for i := range head {
		tok, rest = nextCTToken(rest)
		if tok == nil {
			return false
		}
		head[i] = tok
	}
	switch string(head[2]) {
	case "tcp":
		e.proto = 6
	case "udp":
		e.proto = 17
	default:
		return false
	}
	// Then an optional timeout and, for tcp, an optional state, up to the
	// first key=value or [flag] token. Offloaded flows (the common case for
	// direct traffic) print neither: the kernel omits both for IPS_OFFLOAD.
	for {
		next, after := nextCTToken(rest)
		if next == nil {
			return false
		}
		if next[0] == '[' || bytes.IndexByte(next, '=') >= 0 {
			break
		}
		rest = after
		if next[0] >= '0' && next[0] <= '9' {
			if ttl, ok := parseCTUint(next); ok {
				e.ttl = uint32(ttl)
			}
		} else if e.proto == 6 {
			e.state = parseCTState(next)
		}
	}

	var srcN, dstN, sportN, dportN, pktN, bytN int
	var srcA, dstA netip.Addr
	var sport, dport uint16
	for {
		tok, rest = nextCTToken(rest)
		if tok == nil {
			break
		}
		if tok[0] == '[' {
			switch string(tok) {
			case "[UNREPLIED]":
				e.unreplied = true
			case "[OFFLOAD]", "[HW_OFFLOAD]":
				e.offloaded = true
			}
			continue
		}
		eq := -1
		for i, c := range tok {
			if c == '=' {
				eq = i
				break
			}
		}
		if eq <= 0 {
			continue
		}
		key, val := tok[:eq], tok[eq+1:]
		switch string(key) {
		case "src":
			srcN++
			if srcN == 1 {
				a, err := netip.ParseAddr(unsafeString(val))
				if err != nil {
					return false
				}
				srcA = a.Unmap()
			}
		case "dst":
			dstN++
			if dstN == 1 {
				a, err := netip.ParseAddr(unsafeString(val))
				if err != nil {
					return false
				}
				dstA = a.Unmap()
			}
		case "sport":
			sportN++
			if sportN == 1 {
				v, ok := parseCTUint(val)
				if !ok || v > 65535 {
					return false
				}
				sport = uint16(v)
			}
		case "dport":
			dportN++
			if dportN == 1 {
				v, ok := parseCTUint(val)
				if !ok || v > 65535 {
					return false
				}
				dport = uint16(v)
			}
		case "packets":
			pktN++
			if v, ok := parseCTUint(val); ok {
				if pktN == 1 {
					e.upPackets = v
				} else if pktN == 2 {
					e.downPackets = v
				}
			}
		case "bytes":
			bytN++
			e.hasCounters = true
			if v, ok := parseCTUint(val); ok {
				if bytN == 1 {
					e.upBytes = v
				} else if bytN == 2 {
					e.downBytes = v
				}
			}
		case "mark":
			if v, ok := parseCTUint(val); ok && v <= 0xffffffff {
				e.mark = uint32(v)
			}
		}
	}
	if !srcA.IsValid() || !dstA.IsValid() {
		return false
	}
	if e.proto == 6 && e.state == ctStateNone && e.offloaded {
		// Only established flows are offloaded, and their line carries no state.
		e.state = ctStateEstablished
	}
	e.src = netip.AddrPortFrom(srcA, sport)
	e.dst = netip.AddrPortFrom(dstA, dport)
	return true
}

// scanConntrack streams r line by line and calls visit for every tcp/udp
// entry. It never holds more than one line.
func scanConntrack(r io.Reader, visit func(*ctEntry)) (lines int, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var e ctEntry // reused for every line; visit must not retain the pointer
	for {
		line, rerr := br.ReadSlice('\n')
		if errors.Is(rerr, bufio.ErrBufferFull) {
			// A line this long is not conntrack output; drop its remainder.
			for errors.Is(rerr, bufio.ErrBufferFull) {
				_, rerr = br.ReadSlice('\n')
			}
			line = nil
		}
		if len(line) > 0 {
			lines++
			if parseConntrackInto(line, &e) {
				visit(&e)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return lines, nil
			}
			return lines, rerr
		}
	}
}

// AdminKernelConnection is one flow the kernel forwards on its own.
type AdminKernelConnection struct {
	ID      string `json:"id"`
	Network string `json:"network"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Domain  string `json:"domain,omitempty"`
	// Mac is the client's MAC as learned by dae's datapath (the same
	// association its MAC-based routing uses). conntrack has no L2 data, so
	// it is empty when the client has not been seen on a LAN interface.
	Mac             string `json:"mac,omitempty"`
	State           string `json:"state,omitempty"`
	Upload          uint64 `json:"upload"`
	Download        uint64 `json:"download"`
	UploadPackets   uint64 `json:"upload_packets,omitempty"`
	DownloadPackets uint64 `json:"download_packets,omitempty"`
	TTL             uint32 `json:"ttl"`
	Offloaded       bool   `json:"offloaded,omitempty"`
	Unreplied       bool   `json:"unreplied,omitempty"`
}

// AdminKernelExcluded counts what was left out of the kernel view and why, so
// the numbers can be reconciled with /v1/connections and the conntrack table.
type AdminKernelExcluded struct {
	// Userspace flows are already listed by /v1/connections.
	Userspace int `json:"userspace"`
	// Dae are dae's own sockets (upstream proxy connections, DNS), recognised
	// by so_mark_from_dae; their payload is the userspace flows above.
	Dae int `json:"dae"`
	// Inactive are TIME_WAIT/CLOSE leftovers.
	Inactive int `json:"inactive"`
	// Local are loopback flows.
	Local int `json:"local"`
}

// AdminKernelConnectionsSnapshot is the bounded kernel-path flow list. Byte
// counters are IP-layer (headers included), unlike the payload bytes of
// /v1/connections, and exist only when conntrack accounting is on.
type AdminKernelConnectionsSnapshot struct {
	// Available is false when conntrack cannot be read at all.
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
	// Accounting reports net.netfilter.nf_conntrack_acct. Without it flows
	// are listed but upload/download stay 0, and flows created before it was
	// switched on keep 0 for their whole life.
	Accounting   bool                    `json:"accounting"`
	Total        int                     `json:"total"`
	Truncated    bool                    `json:"truncated"`
	Excluded     AdminKernelExcluded     `json:"excluded"`
	Connections  []AdminKernelConnection `json:"connections"`
	SnapshotAtMs int64                   `json:"snapshot_at_ms,omitempty"`
	// ScanMs is how long reading the conntrack table took.
	ScanMs int64 `json:"scan_ms,omitempty"`
}

type kernelFlowKey struct {
	proto    uint8
	src, dst netip.AddrPort
}

// kernelCollectInput is everything a scan needs from the control plane.
type kernelCollectInput struct {
	daeMark   uint32
	userspace map[kernelFlowKey]struct{}
	src       netip.Addr // optional: only flows from this source
	// srcSet, when non-nil, restricts flows to these sources (the addresses
	// of one MAC); an empty non-nil set matches nothing.
	srcSet map[netip.Addr]struct{}
	cap    int
}

func ctLess(a, b *ctEntry) bool {
	// "a ranks above b": heavier first, then a stable order.
	if ba, bb := a.upBytes+a.downBytes, b.upBytes+b.downBytes; ba != bb {
		return ba > bb
	}
	if a.proto != b.proto {
		return a.proto < b.proto
	}
	if c := a.src.Compare(b.src); c != 0 {
		return c < 0
	}
	return a.dst.Compare(b.dst) < 0
}

// ctHeap keeps the cap highest ranked entries; the root is the lowest ranked
// one kept, so a better entry replaces it. It is hand-rolled over a slice so
// that scanning a large table does not box an entry per push.
type ctHeap []ctEntry

// worse reports whether h[i] ranks below h[j].
func (h ctHeap) worse(i, j int) bool { return ctLess(&h[j], &h[i]) }

func (h *ctHeap) push(e *ctEntry) {
	*h = append(*h, *e)
	h.up(len(*h) - 1)
}

func (h ctHeap) up(i int) {
	for i > 0 {
		parent := (i - 1) / 2
		if !h.worse(i, parent) {
			return
		}
		h[i], h[parent] = h[parent], h[i]
		i = parent
	}
}

func (h ctHeap) down(i int) {
	n := len(h)
	for {
		l := 2*i + 1
		if l >= n {
			return
		}
		w := l
		if r := l + 1; r < n && h.worse(r, l) {
			w = r
		}
		if !h.worse(w, i) {
			return
		}
		h[i], h[w] = h[w], h[i]
		i = w
	}
}

// popWorst removes and returns the lowest ranked entry.
func (h *ctHeap) popWorst() ctEntry {
	old := *h
	last := len(old) - 1
	top := old[0]
	old[0] = old[last]
	*h = old[:last]
	h.down(0)
	return top
}

// collectKernelConnections reads a conntrack dump and returns the flows that
// only the kernel handles, heaviest first, plus the entries left out.
func collectKernelConnections(r io.Reader, in kernelCollectInput) (entries []ctEntry, total int, excluded AdminKernelExcluded, accounting bool, err error) {
	if in.cap <= 0 {
		in.cap = adminConnectionsMaxLimit
	}
	h := make(ctHeap, 0, min(in.cap, 256))
	_, err = scanConntrack(r, func(e *ctEntry) {
		if e.hasCounters {
			accounting = true
		}
		if e.src.Addr().IsLoopback() || e.dst.Addr().IsLoopback() {
			excluded.Local++
			return
		}
		if e.state == ctStateTimeWait || e.state == ctStateClose {
			excluded.Inactive++
			return
		}
		if in.daeMark != 0 && e.mark == in.daeMark {
			excluded.Dae++
			return
		}
		if _, ok := in.userspace[kernelFlowKey{e.proto, e.src, e.dst}]; ok {
			excluded.Userspace++
			return
		}
		if in.src.IsValid() && e.src.Addr() != in.src {
			return
		}
		if in.srcSet != nil {
			if _, ok := in.srcSet[e.src.Addr()]; !ok {
				return
			}
		}
		total++
		if len(h) < in.cap {
			h.push(e)
		} else if ctLess(e, &h[0]) {
			h[0] = *e
			h.down(0)
		}
	})
	entries = make([]ctEntry, len(h))
	for i := len(h) - 1; i >= 0; i-- {
		entries[i] = h.popWorst()
	}
	return entries, total, excluded, accounting, err
}

func kernelConnectionID(e *ctEntry) string {
	return netNameOfProto(e.proto) + ":" + e.src.String() + ">" + e.dst.String()
}

func netNameOfProto(p uint8) string {
	if p == 6 {
		return "tcp"
	}
	return "udp"
}

func kernelConnectionFromEntry(e *ctEntry) AdminKernelConnection {
	return AdminKernelConnection{
		ID:              kernelConnectionID(e),
		Network:         netNameOfProto(e.proto),
		Src:             e.src.String(),
		Dst:             e.dst.String(),
		State:           e.state.String(),
		Upload:          e.upBytes,
		Download:        e.downBytes,
		UploadPackets:   e.upPackets,
		DownloadPackets: e.downPackets,
		TTL:             e.ttl,
		Offloaded:       e.offloaded,
		Unreplied:       e.unreplied,
	}
}

// kernelMacResolver maps between client addresses and MACs using the
// datapath's own learned associations. Lookups are bpf map reads from the
// control plane; nothing here touches the packet path.
type kernelMacResolver struct {
	macOf   func(netip.Addr) ([6]byte, bool)
	addrsOf func(mac [6]byte) []netip.Addr
}

// newKernelMacResolver reads ip_mac_assoc_map / mac_assoc_map. It returns nil
// when the datapath is not loaded.
func newKernelMacResolver(c *ControlPlane) *kernelMacResolver {
	if c == nil || c.core == nil {
		return nil
	}
	bpf := c.core.bpf.Load()
	if bpf == nil {
		return nil
	}
	return newKernelMacResolverFromMaps(bpf.IpMacAssocMap, bpf.MacAssocMap)
}

func newKernelMacResolverFromMaps(ipMac, macAssoc *ebpf.Map) *kernelMacResolver {
	if ipMac == nil || macAssoc == nil {
		return nil
	}
	return &kernelMacResolver{
		macOf: func(a netip.Addr) ([6]byte, bool) {
			key := bpfIpMacAssocKey{Ip: a.As16()}
			var val bpfMacAssocKey
			if err := ipMac.Lookup(&key, &val); err != nil {
				return [6]byte{}, false
			}
			return val.Mac, val.Mac != [6]byte{}
		},
		addrsOf: func(mac [6]byte) []netip.Addr {
			var entry bpfMacAssocEntry
			if err := macAssoc.Lookup(&bpfMacAssocKey{Mac: mac}, &entry); err != nil {
				return nil
			}
			out := make([]netip.Addr, 0, macAssocIPSlots)
			for i := range entry.Ips {
				if ip := entry.Ips[i].Ip; !ip16Unspecified(ip) {
					out = append(out, netip.AddrFrom16(ip).Unmap())
				}
			}
			return out
		},
	}
}

// KernelConnectionsCollector serves GET /v1/kernel-connections. It rate limits
// the conntrack read: concurrent and repeated requests inside the minimum
// interval share one scan.
type KernelConnectionsCollector struct {
	mu          sync.Mutex
	procPath    string
	acctPath    string
	minInterval time.Duration
	now         func() time.Time
	// macResolver is replaceable in tests; nil means newKernelMacResolver.
	macResolver func(*ControlPlane) *kernelMacResolver

	cachedAt  time.Time
	cachedSrc string
	cached    AdminKernelConnectionsSnapshot
	// cachedFor is how long the cached scan stays valid: the larger of
	// minInterval and kernelConnectionsBackoff times what the scan cost, so a
	// huge table is read less often and the view's CPU share stays bounded.
	cachedFor time.Duration
}

// kernelConnectionsBackoff caps the collector's duty cycle at 1/backoff
// (5%) of one core regardless of table size.
const kernelConnectionsBackoff = 20

func NewKernelConnectionsCollector() *KernelConnectionsCollector {
	return &KernelConnectionsCollector{
		procPath:    conntrackProcPath,
		acctPath:    conntrackAcctSysctl,
		minInterval: kernelConnectionsMinInterval,
		now:         time.Now,
	}
}

func readConntrackAccounting(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}

func (k *KernelConnectionsCollector) Snapshot(c *ControlPlane, limit int, src, mac string) AdminKernelConnectionsSnapshot {
	limit = clampAdminConnectionLimit(limit)
	src = strings.TrimSpace(src)
	var srcAddr netip.Addr
	if src != "" {
		a, err := netip.ParseAddr(src)
		if err != nil {
			return AdminKernelConnectionsSnapshot{Available: true, Error: "invalid src", Connections: []AdminKernelConnection{}}
		}
		srcAddr = a.Unmap()
	}

	var macAddr [6]byte
	mac = strings.TrimSpace(mac)
	if mac != "" {
		hw, err := net.ParseMAC(mac)
		if err != nil || len(hw) != 6 {
			return AdminKernelConnectionsSnapshot{Available: true, Error: "invalid mac", Connections: []AdminKernelConnection{}}
		}
		copy(macAddr[:], hw)
	}

	cacheKey := srcAddr.String() + "|" + macString(macAddr)
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if !k.cachedAt.IsZero() && now.Sub(k.cachedAt) < k.cachedFor && k.cachedSrc == cacheKey {
		return trimKernelSnapshot(k.cached, limit)
	}
	snap := k.collect(c, srcAddr, mac != "", macAddr)
	k.cachedAt, k.cachedSrc, k.cached = now, cacheKey, snap
	k.cachedFor = max(k.minInterval, kernelConnectionsBackoff*time.Duration(snap.ScanMs)*time.Millisecond)
	return trimKernelSnapshot(snap, limit)
}

func trimKernelSnapshot(s AdminKernelConnectionsSnapshot, limit int) AdminKernelConnectionsSnapshot {
	if len(s.Connections) > limit {
		s.Connections = s.Connections[:limit]
	}
	s.Truncated = s.Total > len(s.Connections)
	return s
}

func (k *KernelConnectionsCollector) collect(c *ControlPlane, src netip.Addr, filterMac bool, mac [6]byte) AdminKernelConnectionsSnapshot {
	snap := AdminKernelConnectionsSnapshot{Connections: []AdminKernelConnection{}}
	f, err := os.Open(k.procPath)
	if err != nil {
		snap.Error = "conntrack unavailable"
		snap.SnapshotAtMs = k.now().UnixMilli()
		return snap
	}
	defer f.Close()

	in := kernelCollectInput{src: src}
	resolve := k.macResolver
	if resolve == nil {
		resolve = newKernelMacResolver
	}
	resolver := resolve(c)
	if filterMac {
		// A MAC the datapath has not learned matches nothing.
		in.srcSet = map[netip.Addr]struct{}{}
		if resolver != nil {
			for _, a := range resolver.addrsOf(mac) {
				in.srcSet[a] = struct{}{}
			}
		}
	}
	if c != nil {
		in.daeMark = c.soMarkFromDae
		if manager, _ := c.controlPlaneSessionManager(); manager != nil {
			in.userspace = userspaceFlowKeys(manager)
		}
	}
	start := k.now()
	entries, total, excluded, accounting, err := collectKernelConnections(f, in)
	snap.ScanMs = k.now().Sub(start).Milliseconds()
	snap.SnapshotAtMs = k.now().UnixMilli()
	if err != nil {
		snap.Error = "conntrack read failed"
		return snap
	}
	snap.Available = true
	snap.Accounting = accounting || readConntrackAccounting(k.acctPath)
	snap.Total = total
	snap.Excluded = excluded
	snap.Connections = make([]AdminKernelConnection, 0, len(entries))
	wanted := make(map[netip.Addr]struct{}, len(entries))
	macs := map[netip.Addr]string{} // one lookup per distinct client
	for i := range entries {
		item := kernelConnectionFromEntry(&entries[i])
		if resolver != nil {
			a := entries[i].src.Addr()
			m, seen := macs[a]
			if !seen {
				if hw, ok := resolver.macOf(a); ok {
					m = macString(hw)
				}
				macs[a] = m
			}
			item.Mac = m
		}
		snap.Connections = append(snap.Connections, item)
		wanted[entries[i].dst.Addr()] = struct{}{}
	}
	if c != nil && c.dnsController != nil {
		if domains := c.dnsController.DomainsForIPs(wanted); len(domains) > 0 {
			for i := range entries {
				snap.Connections[i].Domain = domains[entries[i].dst.Addr()]
			}
		}
	}
	return snap
}

// AdminKernelConnections returns the kernel-path flow list for
// GET /v1/kernel-connections. src and mac optionally restrict it to one client.
func (c *ControlPlane) AdminKernelConnections(limit int, src, mac string) AdminKernelConnectionsSnapshot {
	if c == nil {
		return AdminKernelConnectionsSnapshot{Connections: []AdminKernelConnection{}}
	}
	collector := c.kernelConns.Load()
	if collector == nil {
		fresh := NewKernelConnectionsCollector()
		if c.kernelConns.CompareAndSwap(nil, fresh) {
			collector = fresh
		} else {
			collector = c.kernelConns.Load()
		}
	}
	return collector.Snapshot(c, limit, src, mac)
}

// userspaceFlowKeys lists the flows dae relays itself, keyed the way conntrack
// reports the original direction (client to original destination).
func userspaceFlowKeys(m *SessionManager) map[kernelFlowKey]struct{} {
	tcp, udp := m.snapshotFlowRuntimes()
	keys := make(map[kernelFlowKey]struct{}, len(tcp)+len(udp))
	add := func(proto uint8, src, dst netip.AddrPort) {
		if !src.IsValid() || !dst.IsValid() {
			return
		}
		keys[kernelFlowKey{proto, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())}] = struct{}{}
	}
	for _, flow := range tcp {
		if flow != nil {
			add(6, flow.src, flow.dst)
		}
	}
	for _, flow := range udp {
		if flow != nil {
			src, dst := udpFlowAddrs(flow)
			add(17, src, dst)
		}
	}
	return keys
}
