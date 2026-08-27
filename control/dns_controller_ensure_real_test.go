/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func newEnsureRealTestController(t *testing.T, store *FakeIPStore) *DnsController {
	t.Helper()
	ctrl := newCorpusDnsController(t, &config.Dns{
		Upstream: []config.KeyableString{"homedns:udp://192.0.2.53:53"},
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "homedns"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	})
	setTestDnsControllerRuntime(ctrl, func(rt *dnsControllerRuntimeState) {
		rt.bestDialerChooser = func(_ context.Context, _ DnsRequestSnapshot, _ *componentdns.Upstream) (*dialArgument, error) {
			return &dialArgument{
				l4proto:    consts.L4ProtoStr_UDP,
				ipversion:  consts.IpVersionStr_4,
				bestTarget: netip.MustParseAddrPort("192.0.2.53:53"),
			}, nil
		}
		if store != nil {
			rt.fakeIPPolicy = NewFakeIPPolicy(config.FakeIP{Enable: true}, store, nil, nil, 1)
		}
	})
	return ctrl
}

func installEnsureRealCache(ctrl *DnsController, qname string, qtype uint16, answers []dnsmessage.RR, ttl time.Duration) {
	installEnsureRealCacheAt(ctrl, ctrl.cacheKey(qname, qtype), answers, ttl)
}

func installEnsureRealCacheAt(ctrl *DnsController, cacheKey string, answers []dnsmessage.RR, ttl time.Duration) {
	cache := &DnsCache{
		Answer:           answers,
		Deadline:         time.Now().Add(ttl),
		OriginalDeadline: time.Now().Add(ttl),
	}
	cache.deadlineNano.Store(cache.Deadline.UnixNano())
	ctrl.dnsCache.Store(cacheKey, cache)
}

func withStubDnsForwarder(t *testing.T, forward func(context.Context, []byte) (*dnsmessage.Msg, error)) {
	t.Helper()
	original := dnsForwarderFactory
	dnsForwarderFactory = func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: forward}, nil
	}
	t.Cleanup(func() { dnsForwarderFactory = original })
}

func TestEnsureRealAnswersSkipsFreshNODATA(t *testing.T) {
	ctrl := newEnsureRealTestController(t, nil)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		return nil, fmt.Errorf("should not query NODATA")
	})
	installEnsureRealCache(ctrl, "empty.example.", dnsmessage.TypeA, nil, time.Minute)
	if err := ctrl.EnsureRealAnswers(context.Background(), "empty.example.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0 for fresh NODATA", got)
	}
}

func TestEnsureRealAnswersRefreshesFakeIPOnly(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "x.ss2.us")
	ctrl := newEnsureRealTestController(t, store)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		return dnsAResponseMsg("x.ss2.us.", "203.0.113.10"), nil
	})
	installEnsureRealCache(ctrl, "x.ss2.us.", dnsmessage.TypeA, []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "x.ss2.us.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: fake.AsSlice(),
	}}, time.Minute)
	if ctrl.cacheHasRealIP("x.ss2.us.", dnsmessage.TypeA) {
		t.Fatal("FakeIP-only cache must not count as a real IP")
	}
	if err := ctrl.EnsureRealAnswers(context.Background(), "x.ss2.us.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	if !ctrl.cacheHasRealIP("x.ss2.us.", dnsmessage.TypeA) {
		t.Fatal("expected real A after refresh")
	}
}

func TestEnsureRealAnswersSameIPsRefreshTTL(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "same.example")
	ctrl := newEnsureRealTestController(t, store)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		return dnsAResponseMsg("same.example.", fake.String()), nil
	})
	installEnsureRealCache(ctrl, "same.example.", dnsmessage.TypeA, []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "same.example.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: fake.AsSlice(),
	}}, time.Second)
	key := ctrl.cacheKey("same.example.", dnsmessage.TypeA)
	v, _ := ctrl.dnsCache.Load(key)
	old := v.(*DnsCache)
	oldDeadline := old.Deadline
	oldRR := old.Answer[0]
	if err := ctrl.EnsureRealAnswers(context.Background(), "same.example.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	v, _ = ctrl.dnsCache.Load(key)
	got := v.(*DnsCache)
	if got == old {
		t.Fatal("same IPs must replace the published cache object")
	}
	if got.Answer[0] != oldRR {
		t.Fatal("same IPs must keep the answers")
	}
	if !got.OriginalDeadline.After(oldDeadline) {
		t.Fatalf("TTL was not refreshed: original=%v old=%v", got.OriginalDeadline, oldDeadline)
	}
}

func TestEnsureRealAnswersFreshRealIPSkipsQuery(t *testing.T) {
	ctrl := newEnsureRealTestController(t, nil)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		return dnsAResponseMsg("fresh.example.", "203.0.113.50"), nil
	})
	installEnsureRealCache(ctrl, "fresh.example.", dnsmessage.TypeA, []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "fresh.example.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP("203.0.113.50").To4(),
	}}, time.Minute)
	if err := ctrl.EnsureRealAnswers(context.Background(), "fresh.example.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0 within TTL", got)
	}
}

func TestEnsureRealAnswersExpiredRealIPRequeries(t *testing.T) {
	ctrl := newEnsureRealTestController(t, nil)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		return dnsAResponseMsg("expired.example.", "203.0.113.60"), nil
	})
	installEnsureRealCache(ctrl, "expired.example.", dnsmessage.TypeA, []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "expired.example.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP("203.0.113.60").To4(),
	}}, -time.Second)
	if err := ctrl.EnsureRealAnswers(context.Background(), "expired.example.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 after TTL", got)
	}
	v, _ := ctrl.dnsCache.Load(ctrl.cacheKey("expired.example.", dnsmessage.TypeA))
	got := v.(*DnsCache)
	if !got.OriginalDeadline.After(time.Now()) {
		t.Fatal("expired same-IP refresh must extend upstream TTL")
	}
}

func TestEnsureRealAnswersLeavesOtherFamily(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "dual.example")
	ctrl := newEnsureRealTestController(t, store)
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		return dnsAResponseMsg("dual.example.", "203.0.113.20"), nil
	})
	installEnsureRealCache(ctrl, "dual.example.", dnsmessage.TypeA, []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "dual.example.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: fake.AsSlice(),
	}}, time.Minute)
	aaaa := &dnsmessage.AAAA{
		Hdr: dnsmessage.RR_Header{
			Name:   "dual.example.",
			Rrtype: dnsmessage.TypeAAAA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		AAAA: net.ParseIP("2001:db8::9"),
	}
	installEnsureRealCache(ctrl, "dual.example.", dnsmessage.TypeAAAA, []dnsmessage.RR{aaaa}, time.Minute)
	if err := ctrl.EnsureRealAnswers(context.Background(), "dual.example.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	if !ctrl.cacheHasRealIP("dual.example.", dnsmessage.TypeA) {
		t.Fatal("expected refreshed A")
	}
	got := realIPFromAnswers(ctrl.LookupCacheAnswers("dual.example.", dnsmessage.TypeAAAA), true)
	if got.String() != "2001:db8::9" {
		t.Fatalf("AAAA = %v, want 2001:db8::9", got)
	}
}

func TestEnsureRealAnswersSingleflight(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "burst.example")
	ctrl := newEnsureRealTestController(t, store)
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		return dnsAResponseMsg("burst.example.", "203.0.113.30"), nil
	})
	installEnsureRealCache(ctrl, "burst.example.", dnsmessage.TypeA, []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "burst.example.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: fake.AsSlice(),
	}}, time.Minute)

	errCh := make(chan error, 8)
	for range 8 {
		go func() {
			errCh <- ctrl.EnsureRealAnswers(context.Background(), "burst.example.", dnsmessage.TypeA)
		}()
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("lookup did not start")
	}
	close(release)
	for range 8 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestEnsureRealAnswersKeepsRealScopedCache(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "scoped.example")
	ctrl := newEnsureRealTestController(t, store)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		return nil, fmt.Errorf("should not query when a scoped real A exists")
	})
	installEnsureRealCache(ctrl, "scoped.example.", dnsmessage.TypeA, []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "scoped.example.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: fake.AsSlice(),
	}}, time.Minute)
	real := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "scoped.example.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP("203.0.113.40").To4(),
	}
	scoped := ctrl.cacheKey("scoped.example.", dnsmessage.TypeA) + "|upstream@homedns"
	installEnsureRealCacheAt(ctrl, scoped, []dnsmessage.RR{real}, time.Minute)
	if err := ctrl.EnsureRealAnswers(context.Background(), "scoped.example.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
	if !ctrl.cacheHasRealIP("scoped.example.", dnsmessage.TypeA) {
		t.Fatal("scoped real A must be kept")
	}
}

func TestEnsureRealAnswersMissTTL(t *testing.T) {
	ctrl := newEnsureRealTestController(t, nil)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		return nil, fmt.Errorf("upstream down")
	})
	if err := ctrl.EnsureRealAnswers(context.Background(), "down.example.", dnsmessage.TypeA); err == nil {
		t.Fatal("expected upstream error")
	}
	if err := ctrl.EnsureRealAnswers(context.Background(), "down.example.", dnsmessage.TypeA); err == nil {
		t.Fatal("expected negative-cached error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 within miss TTL", got)
	}
}

func TestEnsureRealAnswersAsIsUsesSystemDns(t *testing.T) {
	orig := lookupSystemDns
	lookupSystemDns = func() (netip.AddrPort, error) {
		return netip.MustParseAddrPort("192.0.2.53:53"), nil
	}
	t.Cleanup(func() { lookupSystemDns = orig })

	ctrl := newCorpusDnsController(t, &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "asis"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	})
	var seen netip.AddrPort
	setTestDnsControllerRuntime(ctrl, func(rt *dnsControllerRuntimeState) {
		rt.bestDialerChooser = func(_ context.Context, snap DnsRequestSnapshot, _ *componentdns.Upstream) (*dialArgument, error) {
			seen = snap.RealDst
			return &dialArgument{
				l4proto:    consts.L4ProtoStr_UDP,
				ipversion:  consts.IpVersionStr_4,
				bestTarget: snap.RealDst,
			}, nil
		}
	})
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		return dnsAResponseMsg("asis.example.", "203.0.113.80"), nil
	})
	if err := ctrl.EnsureRealAnswers(context.Background(), "asis.example.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	if seen.String() != "192.0.2.53:53" {
		t.Fatalf("asis dest = %v, want system DNS", seen)
	}
	if !ctrl.cacheHasRealIP("asis.example.", dnsmessage.TypeA) {
		t.Fatal("expected real A after asis EnsureReal")
	}
}

func TestEnsureRealAnswersSERVFAILMissTTL(t *testing.T) {
	ctrl := newEnsureRealTestController(t, nil)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		msg := new(dnsmessage.Msg)
		msg.SetReply(new(dnsmessage.Msg))
		msg.SetQuestion("servfail.example.", dnsmessage.TypeA)
		msg.Rcode = dnsmessage.RcodeServerFailure
		return msg, nil
	})
	if err := ctrl.EnsureRealAnswers(context.Background(), "servfail.example.", dnsmessage.TypeA); err == nil {
		t.Fatal("expected SERVFAIL error")
	}
	if err := ctrl.EnsureRealAnswers(context.Background(), "servfail.example.", dnsmessage.TypeA); err == nil {
		t.Fatal("expected negative-cached SERVFAIL")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 within miss TTL", got)
	}
}

func TestEnsureRealAnswersNXDOMAINMissTTL(t *testing.T) {
	ctrl := newEnsureRealTestController(t, nil)
	var calls atomic.Int32
	withStubDnsForwarder(t, func(context.Context, []byte) (*dnsmessage.Msg, error) {
		calls.Add(1)
		msg := new(dnsmessage.Msg)
		msg.SetQuestion("nx.example.", dnsmessage.TypeA)
		msg.Response = true
		msg.Rcode = dnsmessage.RcodeNameError
		return msg, nil
	})
	if err := ctrl.EnsureRealAnswers(context.Background(), "nx.example.", dnsmessage.TypeA); err == nil {
		t.Fatal("expected NXDOMAIN error")
	}
	if err := ctrl.EnsureRealAnswers(context.Background(), "nx.example.", dnsmessage.TypeA); err == nil {
		t.Fatal("expected negative-cached NXDOMAIN")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 within miss TTL", got)
	}
}

func TestEnsureRealAnswersSameIPsRefreshTTLRace(t *testing.T) {
	ctrl := newEnsureRealTestController(t, nil)
	qname := "race.example."
	installEnsureRealCache(ctrl, qname, dnsmessage.TypeA, []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   qname,
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP("203.0.113.70").To4(),
	}}, time.Minute)
	key := ctrl.cacheKey(qname, dnsmessage.TypeA)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := new(dnsmessage.Msg)
			msg.SetQuestion(qname, dnsmessage.TypeA)
			for {
				select {
				case <-stop:
					return
				default:
				}
				v, ok := ctrl.dnsCache.Load(key)
				if !ok {
					continue
				}
				cache := v.(*DnsCache)
				_ = cache.Deadline.After(time.Now())
				_ = dnsCacheFreshUpstream(cache, time.Now())
				_, _ = ctrl.LookupDnsRespCache_(msg.Copy(), key, true)
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctrl.refreshExistingDnsCacheTTL(qname, dnsmessage.TypeA, 60)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
