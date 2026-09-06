package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestRouteDialKeepsSlowSuccessfulConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	d := newDelayedTestEndpointDialer(20*time.Millisecond, client)
	other := newTestEndpointDialer()
	defer d.Close()
	defer other.Close()
	g := newTestOutboundGroup(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, d, other)
	defer g.Close()
	nt := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	for range 3 {
		d.ObserveHandshake(nt, time.Millisecond)
	}
	if !d.ObserveTTFB(nt, 20*time.Millisecond) {
		t.Fatal("fixture must classify handshake duration as slow")
	}
	g.PinSite("example.com", d, false)
	cp := newTestDialControlPlane(g)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, result, err := cp.routeDial(ctx, &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin, Domain: "example.com",
		Src: netip.MustParseAddrPort("192.0.2.10:12345"), Dest: netip.MustParseAddrPort("198.51.100.10:443"), Network: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Dialer != d || conn != client {
		t.Fatal("discarded the successful connection")
	}
	cancel()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("ok")); done <- err }()
	var got [2]byte
	if _, err := io.ReadFull(server, got[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if string(got[:]) != "ok" {
		t.Fatalf("payload = %q", got)
	}
}

func TestSiteFailDomainPrefersSniffed(t *testing.T) {
	if got := siteFailDomain(&proxyDialResult{SniffedDomain: "youtube.com"}, ""); got != "youtube.com" {
		t.Fatalf("siteFailDomain sniffed = %q, want youtube.com", got)
	}
	if got := siteFailDomain(&proxyDialResult{StickySite: "8.8.8.8", SniffedDomain: "nas"}, "nas"); got != "8.8.8.8" {
		t.Fatalf("siteFailDomain sticky = %q, want dest IP pin key", got)
	}
	if got := siteFailDomain(&proxyDialResult{}, "example.com"); got != "example.com" {
		t.Fatalf("siteFailDomain fallback = %q, want example.com", got)
	}
}

func TestStickySelectHostUsesUnicastIPWhenNoDomain(t *testing.T) {
	dst := netip.MustParseAddr("8.8.8.8")
	if got := stickySelectHost("", dst, false); got != "8.8.8.8" {
		t.Fatalf("stickySelectHost(ip-only) = %q, want 8.8.8.8", got)
	}
	if got := stickySelectHost("www.youtube.com", dst, false); got != "www.youtube.com" {
		t.Fatalf("stickySelectHost(domain) = %q, want sniffed domain", got)
	}
	if got := stickySelectHost("nas", dst, false); got != "8.8.8.8" {
		t.Fatalf("stickySelectHost(single-label) = %q, want dest IP sticky key, not a domain rewrite", got)
	}
	if got := stickySelectHost("", dst, true); got != "" {
		t.Fatalf("stickySelectHost(fakeip) = %q, want empty", got)
	}
	if got := stickySelectHost("", netip.MustParseAddr("127.0.0.1"), false); got != "" {
		t.Fatalf("stickySelectHost(loopback) = %q, want empty", got)
	}
}
