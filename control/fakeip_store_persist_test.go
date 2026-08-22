/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func crashCloseWAL(t *testing.T, s *FakeIPStore) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wal != nil {
		_ = s.wal.Sync()
		_ = s.wal.Close()
		s.wal = nil
	}
	s.ready = false
	s.closed = true
}

func TestFakeIPStoreCrashDoesNotOverwriteWAL(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")

	s1 := NewFakeIPStore(dir, 8)
	if err := s1.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	a4, _, _, err := s1.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	crashCloseWAL(t, s1)

	s2 := NewFakeIPStore(dir, 8)
	if err := s2.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	got, _, ok := s2.Lookup("chatgpt.com")
	if !ok || got != a4 {
		t.Fatalf("after crash lookup = %v %v, want %v", got, ok, a4)
	}
	b4, _, _, err := s2.Assign("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	crashCloseWAL(t, s2)

	s3 := NewFakeIPStore(dir, 8)
	if err := s3.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	got, _, ok = s3.Lookup("chatgpt.com")
	if !ok || got != a4 {
		t.Fatalf("second crash dropped old mapping: %v %v, want %v", got, ok, a4)
	}
	got, _, ok = s3.Lookup("api.openai.com")
	if !ok || got != b4 {
		t.Fatalf("second crash dropped new mapping: %v %v, want %v", got, ok, b4)
	}
}

func TestFakeIPStoreTruncatedWALKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	s1 := NewFakeIPStore(dir, 8)
	if err := s1.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	a4, _, _, err := s1.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := NewFakeIPStore(dir, 8)
	if err := s2.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s2.Assign("api.openai.com"); err != nil {
		t.Fatal(err)
	}
	crashCloseWAL(t, s2)

	walPath := filepath.Join(dir, fakeIPWalName)
	body, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 4 {
		t.Fatalf("wal too small: %d", len(body))
	}
	if err := os.WriteFile(walPath, body[:len(body)/2], 0o600); err != nil {
		t.Fatal(err)
	}

	s3 := NewFakeIPStore(dir, 8)
	if err := s3.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	got, _, ok := s3.Lookup("chatgpt.com")
	if !ok || got != a4 {
		t.Fatalf("truncated wal wiped snapshot: %v %v, want %v", got, ok, a4)
	}
}

func TestFakeIPStoreRangeChangeDoesNotAdoptOldAddresses(t *testing.T) {
	dir := t.TempDir()
	old4 := netip.MustParsePrefix("198.18.0.0/15")
	new4 := netip.MustParsePrefix("198.19.0.0/16")
	v6 := netip.MustParsePrefix("fd00:daee::/96")

	s1 := NewFakeIPStore(dir, 8)
	if err := s1.Open(old4, v6); err != nil {
		t.Fatal(err)
	}
	a4, _, _, err := s1.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := NewFakeIPStore(dir, 8)
	if err := s2.Open(new4, v6); err != nil {
		t.Fatal(err)
	}
	name, ok := s2.LookBack(a4)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("old fake IP lookback = %q %v", name, ok)
	}
	if !s2.Contains(a4) {
		t.Fatal("old fake IP must still trap after range change")
	}
	if got, _, ok := s2.Lookup("chatgpt.com"); ok {
		t.Fatalf("old mapping must not be active in new pool, got %v", got)
	}
	b4, _, _, err := s2.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if b4 == a4 {
		t.Fatal("new pool reused the retired address")
	}
	if !new4.Contains(b4) {
		t.Fatalf("new assignment %v not in %s", b4, new4)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	s3 := NewFakeIPStore(dir, 8)
	if err := s3.Open(new4, v6); err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	name, ok = s3.LookBack(a4)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("after restart lookback old = %q %v", name, ok)
	}
	got, _, ok := s3.Lookup("chatgpt.com")
	if !ok || got != b4 {
		t.Fatalf("after restart active = %v %v, want %v", got, ok, b4)
	}
	if got == a4 {
		t.Fatal("new pool reused the retired address across restart")
	}
}

func TestFakeIPV1SnapshotWithMismatchedPrefixStaysRetired(t *testing.T) {
	dir := t.TempDir()
	old4 := netip.MustParsePrefix("198.18.0.0/15")
	new4 := netip.MustParsePrefix("198.19.0.0/16")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	oldIP := netip.MustParseAddr("198.18.1.10")
	old6 := netip.MustParseAddr("fd00:daee::10")

	var buf []byte
	var hdr [12]byte
	copy(hdr[:8], fakeIPSnapshotMagic)
	binary.LittleEndian.PutUint32(hdr[8:], fakeIPStoreVersionV1)
	buf = append(buf, hdr[:]...)
	buf = appendPrefix(buf, new4)
	buf = appendPrefix(buf, v6)
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], 1)
	buf = append(buf, count[:]...)
	rec := fakeIPRecord{qname: "chatgpt.com.", ipv4: oldIP, ipv6: old6, updatedUnix: 1}
	var recBuf [128]byte
	n := encodeFakeIPV1SnapshotRecord(recBuf[:], rec)
	buf = append(buf, recBuf[:n]...)
	if err := os.WriteFile(filepath.Join(dir, fakeIPSnapshotName), buf, 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewFakeIPStore(dir, 8)
	if err := s.Open(new4, v6); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	name, ok := s.LookBack(oldIP)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("v1 orphan lookback = %q %v", name, ok)
	}
	if got, _, ok := s.Lookup("chatgpt.com"); ok {
		t.Fatalf("v1 orphan must not enter new active table, got %v", got)
	}
	if old4.Contains(oldIP) && s.active.inet4.Contains(oldIP) {
		t.Fatal("new active prefix should not contain the orphan")
	}
}

func appendPrefix(dst []byte, p netip.Prefix) []byte {
	if p.Addr().Is4() {
		var b [5]byte
		b[0] = byte(p.Bits())
		raw := p.Addr().As4()
		copy(b[1:], raw[:])
		return append(dst, b[:]...)
	}
	var b [17]byte
	b[0] = byte(p.Bits())
	raw := p.Addr().As16()
	copy(b[1:], raw[:])
	return append(dst, b[:]...)
}

func encodeFakeIPV1SnapshotRecord(dst []byte, rec fakeIPRecord) int {
	q := []byte(rec.qname)
	binary.LittleEndian.PutUint16(dst[:2], uint16(len(q)))
	copy(dst[2:], q)
	off := 2 + len(q)
	v4 := rec.ipv4.As4()
	copy(dst[off:], v4[:])
	off += 4
	v6 := rec.ipv6.As16()
	copy(dst[off:], v6[:])
	off += 16
	binary.LittleEndian.PutUint64(dst[off:], uint64(rec.updatedUnix))
	return off + 8
}

func TestRealIPFromAnswersPrefersMatchingFamily(t *testing.T) {
	v4 := &dnsmessage.A{Hdr: dnsmessage.RR_Header{Rrtype: dnsmessage.TypeA}, A: netip.MustParseAddr("203.0.113.10").AsSlice()}
	if got := realIPFromAnswers([]dnsmessage.RR{v4}, false); got.String() != "203.0.113.10" {
		t.Fatalf("got %v", got)
	}
	if got := realIPFromAnswers([]dnsmessage.RR{v4}, true); got.IsValid() {
		t.Fatalf("unexpected v6 from v4 answers: %v", got)
	}
}

func TestFakeIPStoreSyncFailureDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	prev := fakeIPFdatasync
	fakeIPFdatasync = func(int) error { return errors.New("injected fdatasync failure") }
	defer func() { fakeIPFdatasync = prev }()

	s := NewFakeIPStore(dir, 8)
	if err := s.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, _, _, err := s.Assign("chatgpt.com")
	if err == nil {
		t.Fatal("Assign must fail when wal sync fails")
	}
	if _, _, ok := s.Lookup("chatgpt.com"); ok {
		t.Fatal("undurable mapping must not be visible to Lookup")
	}
}

func TestFakeIPStoreWalWriteFailureDoesNotCommit(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	s := NewFakeIPStore(dir, 8)
	if err := s.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fakeIPWalWriteHook = func([]byte) error { return errors.New("injected wal write failure") }
	defer func() { fakeIPWalWriteHook = nil }()
	_, _, _, err := s.Assign("chatgpt.com")
	if err == nil {
		t.Fatal("Assign must fail when wal write fails")
	}
	if _, _, ok := s.Lookup("chatgpt.com"); ok {
		t.Fatal("wal-failed mapping must not be visible to Lookup")
	}
	s.mu.Lock()
	_, hit := s.active.forward["chatgpt.com."]
	s.mu.Unlock()
	if hit {
		t.Fatal("wal-failed mapping must not stay in the live table")
	}

	fakeIPWalWriteHook = nil
	a4, _, _, err := s.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := NewFakeIPStore(dir, 8)
	if err := s2.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, _, ok := s2.Lookup("chatgpt.com")
	if !ok || got != a4 {
		t.Fatalf("after restart lookup = %v %v, want %v", got, ok, a4)
	}
}

func TestFakeIPStoreDisableReenableReusesAddress(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	s := NewFakeIPStore(dir, 8)
	if err := s.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a4, _, _, err := s.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	s.RetireActive(v4, v6)
	if _, _, ok := s.Lookup("chatgpt.com"); ok {
		t.Fatal("disabled store must not advertise a live mapping")
	}
	name, ok := s.LookBack(a4)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("disabled lookback = %q %v", name, ok)
	}
	s.ApplyRanges(v4, v6)
	got, _, ok := s.Lookup("chatgpt.com")
	if !ok || got != a4 {
		t.Fatalf("re-enable lookup = %v %v, want %v", got, ok, a4)
	}
	again, _, _, err := s.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if again != a4 {
		t.Fatalf("re-enable assign = %v, want reused %v", again, a4)
	}
}

func TestFakeIPTombstoneExpiresAfterGrace(t *testing.T) {
	prev := fakeIPTombstoneGrace
	fakeIPTombstoneGrace = 0
	defer func() { fakeIPTombstoneGrace = prev }()

	dir := t.TempDir()
	store := NewFakeIPStore(dir, 1)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	v6 := netip.MustParsePrefix("fd00:daee::/112")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	a4, _, _, err := store.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Assign("api.openai.com"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.expireTombstonesLocked(time.Now())
	store.mu.Unlock()
	if _, ok := store.LookBack(a4); ok {
		t.Fatal("zero-grace tombstone must release the old fake IP")
	}
	c4, _, _, err := store.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if c4 != a4 {
		t.Fatalf("released address should be reusable, got %v want %v", c4, a4)
	}
}

func TestFakeIPBuiltinSkipList(t *testing.T) {
	m, err := buildFakeIPFilterMatcher(logrus.New(), nil, config.FakeIP{
		FilterBuiltin: true,
		FilterMode:    config.FakeIPFilterModeSkip,
	}, []string{"node.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"foo.lan",
		"stun.l.google.com",
		"time.apple.com",
		"www.msftncsi.com",
		"localhost.ptlogin2.qq.com",
		"node.example.com",
	} {
		if !m.Hit(name) {
			t.Fatalf("%s should be skipped by builtin filter", name)
		}
	}
	for _, name := range []string{"chatgpt.com", "api.openai.com", "runtime.example.com"} {
		if m.Hit(name) {
			t.Fatalf("%s must not be skipped by builtin filter", name)
		}
	}
}

func TestFakeIPUserDnsSnippetFilter(t *testing.T) {
	src := `
global {}
routing { fallback: direct }
dns {
    fakeip {
        enable: true
        inet4_range: '28.0.0.0/8'
        filter_mode: skip
        filter {
            qname(suffix: chowtaiseng.com, suffix: tailscale.com, suffix: routing)
            qname(suffix: forzamotorsport.net, suffix: elb.us-west-2.amazonaws.com)
            qname(full: lancache.steamcontent.com, full: speedtest.cros.wr.pvp.net)
            qname(full: time1.apple.com, full: time.asia.apple.com)
            qname(full: cn.ntp.org.cn, full: ntp.ntsc.ac.cn, full: time.nist.gov)
            qname(full: time1.cloud.tencent.com, full: trtc.time.tencent-cloud.com, full: time1.aliyun.com)
            qname(regex: '^[^.]+\.[^.]+\.[^.]+\.srv\.nintendo\.net$')
            qname(regex: '^xbox\.[^.]+\.[^.]+\.microsoft\.com$')
        }
    }
}
`
	sections, err := config_parser.Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	m, err := buildFakeIPFilterMatcher(logrus.New(), nil, conf.Dns.FakeIP, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"shop.chowtaiseng.com",
		"login.tailscale.com",
		"foo.routing",
		"lancache.steamcontent.com",
		"time1.apple.com",
		"a.b.c.srv.nintendo.net",
		"xbox.foo.bar.microsoft.com",
		"stun.l.google.com",
	} {
		if !m.Hit(name) {
			t.Fatalf("%s should be skipped", name)
		}
	}
	for _, name := range []string{
		"chatgpt.com",
		"api.openai.com",
		"srv.nintendo.net",
		"xbox.foo.microsoft.com",
		"music.163.com",
	} {
		if m.Hit(name) {
			t.Fatalf("%s must not be skipped by this filter", name)
		}
	}
}

func TestFakeIPStoreHotpathBudgets(t *testing.T) {
	dir := t.TempDir()
	store := NewFakeIPStore(dir, 1024)
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	addr, _, _, err := store.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	const samples = 20000
	look := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		name, ok := store.LookBack(addr)
		look[i] = time.Since(start)
		if !ok || name == "" {
			t.Fatal("lookback miss")
		}
	}
	p99 := durationP99(look)
	t.Logf("LookBack p99=%s (doc target 1µs)", p99)
	if p99 > 20*time.Microsecond {
		t.Fatalf("LookBack p99 %s exceeds 20µs CI budget (doc 1µs)", p99)
	}

	start := time.Now()
	s8 := NewFakeIPStore(t.TempDir(), 8192)
	if err := s8.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		if _, _, _, err := s8.Assign(canonicalFakeIPTestName(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s8.Close(); err != nil {
		t.Fatal(err)
	}
	loadStart := time.Now()
	s9 := NewFakeIPStore(s8.dir, 8192)
	if err := s9.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	load := time.Since(loadStart)
	s9.Close()
	t.Logf("snapshot load %s after %s populate (doc 8k P99 <20ms)", load, time.Since(start))
	if load > 50*time.Millisecond {
		t.Fatalf("snapshot load %s exceeds 50ms CI budget (doc 20ms)", load)
	}
}

func canonicalFakeIPTestName(i int) string {
	return "host" + itoa(i) + ".example.com"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

func durationP99(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := (len(cp) * 99 / 100)
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

func TestFakeIPStoreInet6OffKeepsIPv4(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	s := NewFakeIPStore(dir, 8)
	if err := s.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a4, a6, _, err := s.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if !a4.IsValid() || !a6.IsValid() {
		t.Fatalf("assign = %v %v, want dual-stack", a4, a6)
	}

	s.ApplyRanges(v4, netip.Prefix{})
	got4, got6, ok := s.Lookup("chatgpt.com")
	if !ok || got4 != a4 {
		t.Fatalf("after inet6 off lookup = %v %v %v, want live %v", got4, got6, ok, a4)
	}
	if got6.IsValid() {
		t.Fatalf("after inet6 off still advertising AAAA %v", got6)
	}
	name, ok := s.LookBack(a4)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("ipv4 lookback = %q %v", name, ok)
	}
	name, ok = s.LookBack(a6)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("old ipv6 lookback = %q %v", name, ok)
	}
	if !s.Contains(a6) {
		t.Fatal("old fake IPv6 must still trap after inet6 off")
	}
	again4, again6, _, err := s.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if again4 != a4 {
		t.Fatalf("inet6 off reassigned IPv4 %v, want %v", again4, a4)
	}
	if again6.IsValid() {
		t.Fatalf("inet6 off assign advertised AAAA %v", again6)
	}

	s.ApplyRanges(v4, v6)
	got4, got6, ok = s.Lookup("chatgpt.com")
	if !ok || got4 != a4 || got6 != a6 {
		t.Fatalf("re-enable lookup = %v %v %v, want %v %v", got4, got6, ok, a4, a6)
	}
}

func TestFakeIPStoreInet6OffKeepsIPv4AcrossRestart(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	s1 := NewFakeIPStore(dir, 8)
	if err := s1.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	a4, a6, _, err := s1.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	s1.ApplyRanges(v4, netip.Prefix{})
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := NewFakeIPStore(dir, 8)
	if err := s2.Open(v4, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got4, got6, ok := s2.Lookup("chatgpt.com")
	if !ok || got4 != a4 || got6.IsValid() {
		t.Fatalf("restart lookup = %v %v %v, want live %v invalid-v6", got4, got6, ok, a4)
	}
	name, ok := s2.LookBack(a6)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("restart old ipv6 lookback = %q %v", name, ok)
	}
	again4, _, _, err := s2.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if again4 != a4 {
		t.Fatalf("restart reassigned IPv4 %v, want %v", again4, a4)
	}
}

func TestFakeIPStoreIPv4OnlyAssignAndReload(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	s1 := NewFakeIPStore(dir, 8)
	if err := s1.Open(v4, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	a4, a6, _, err := s1.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if !a4.IsValid() || a6.IsValid() {
		t.Fatalf("assign = %v %v, want IPv4-only", a4, a6)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := NewFakeIPStore(dir, 8)
	if err := s2.Open(v4, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got4, got6, ok := s2.Lookup("chatgpt.com")
	if !ok || got4 != a4 || got6.IsValid() {
		t.Fatalf("reload lookup = %v %v %v, want %v invalid-v6", got4, got6, ok, a4)
	}
}

func TestFakeIPStoreInet6PoolSwitchAllocatesAAAA(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6a := netip.MustParsePrefix("fd00:daee::/96")
	v6b := netip.MustParsePrefix("fd00:daef::/96")
	s := NewFakeIPStore(dir, 8)
	if err := s.Open(v4, v6a); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a4, a6, _, err := s.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if !v6a.Contains(a6) {
		t.Fatalf("assign AAAA = %v, want %s", a6, v6a)
	}

	s.ApplyRanges(v4, v6b)
	got4, got6, ok := s.Lookup("chatgpt.com")
	if !ok || got4 != a4 {
		t.Fatalf("after switch lookup = %v %v %v, want live %v", got4, got6, ok, a4)
	}
	if got6.IsValid() {
		t.Fatalf("Lookup advertised parked AAAA %v", got6)
	}

	again4, again6, _, err := s.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if again4 != a4 {
		t.Fatalf("switch reassigned IPv4 %v, want %v", again4, a4)
	}
	if !again6.IsValid() || !v6b.Contains(again6) || again6 == a6 {
		t.Fatalf("switch Assign AAAA = %v, want new address in %s", again6, v6b)
	}
	name, ok := s.LookBack(a6)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("parked ipv6 lookback = %q %v", name, ok)
	}
}
