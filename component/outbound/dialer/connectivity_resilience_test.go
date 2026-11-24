package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type pipeHTTPDialer struct {
	statusCode int
}

func (d *pipeHTTPDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		buf := make([]byte, 4096)
		_, _ = c2.Read(buf)
		resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			d.statusCode, http.StatusText(d.statusCode))
		_, _ = c2.Write([]byte(resp))
	}()
	return c1, nil
}

func TestHttpCheckGenerate204StatusClassification(t *testing.T) {
	parsed, err := url.Parse("http://cp.cloudflare.com/generate_204")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	u := &netutils.URL{URL: parsed}
	cases := []struct {
		name   string
		status int
		wantOK bool
	}{
		{name: "204 No Content is alive", status: http.StatusNoContent, wantOK: true},
		{name: "403 Cloudflare WAF is alive", status: http.StatusForbidden, wantOK: true},
		{name: "429 CDN rate limit is alive", status: http.StatusTooManyRequests, wantOK: true},
		{name: "200 captive portal is dead", status: http.StatusOK, wantOK: false},
		{name: "302 captive redirect is dead", status: http.StatusFound, wantOK: false},
		{name: "502 bad gateway is dead", status: http.StatusBadGateway, wantOK: false},
		{name: "503 service unavailable is dead", status: http.StatusServiceUnavailable, wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Dialer{
				GlobalOption: &GlobalOption{Log: logrus.New()},
				Dialer:       &pipeHTTPDialer{statusCode: tc.status},
				ctx:          context.Background(),
				httpClients:  make(map[string]*http.Client),
			}
			ok, err := d.HttpCheck(context.Background(), IdxTcp4, u, netip.MustParseAddr("1.1.1.1"), http.MethodGet, 0, false)
			if ok != tc.wantOK {
				t.Fatalf("HttpCheck(status=%d) = (ok=%v, err=%v), want ok=%v", tc.status, ok, err, tc.wantOK)
			}
		})
	}
}

func TestTcpCheckOptionRawFallsBackToLastGoodOnRefreshFailure(t *testing.T) {
	raw := &TcpCheckOptionRaw{
		Log: logrus.New(),
		Raw: []string{"http://cp.cloudflare.com", "1.1.1.1"},
	}
	opt1, err := raw.Option()
	if err != nil {
		t.Fatalf("initial Option(): %v", err)
	}
	if opt1.Ip4 != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("initial Ip4 = %v, want 1.1.1.1", opt1.Ip4)
	}

	// Simulate transient parse/DNS failure on refresh after Reset().
	raw.Reset()
	raw.Raw = []string{"://invalid-url"}
	opt2, err := raw.Option()
	if err != nil {
		t.Fatalf("Option() after failure should fall back to lastGood, got err: %v", err)
	}
	if opt2 != opt1 {
		t.Fatalf("fallback option = %p, want %p", opt2, opt1)
	}

	// Once Raw is healthy again, next Option() refreshes to the new value.
	raw.Raw = []string{"http://cp.cloudflare.com", "1.0.0.1"}
	opt3, err := raw.Option()
	if err != nil {
		t.Fatalf("recovered Option(): %v", err)
	}
	if opt3.Ip4 != netip.MustParseAddr("1.0.0.1") {
		t.Fatalf("recovered Ip4 = %v, want 1.0.0.1", opt3.Ip4)
	}
}

type fakeResettableDialer struct {
	next   netproxy.Dialer
	resets int
}

func (f *fakeResettableDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("unused")
}
func (f *fakeResettableDialer) UnwrapDialer() netproxy.Dialer { return f.next }
func (f *fakeResettableDialer) ResetTransport()               { f.resets++ }

func TestDialerResetTransportWalksChainAndClasses(t *testing.T) {
	inner := &fakeResettableDialer{}
	outer := &fakeResettableDialer{next: inner}
	childInner := &fakeResettableDialer{}

	child := &Dialer{
		Dialer:      childInner,
		httpClients: make(map[string]*http.Client),
	}
	parent := &Dialer{
		Dialer:           outer,
		httpClients:      make(map[string]*http.Client),
		transportClasses: map[string]*Dialer{"cls": child},
	}

	if !parent.ResetTransport() {
		t.Fatal("ResetTransport() = false, want true")
	}
	if outer.resets != 1 || inner.resets != 1 || childInner.resets != 1 {
		t.Fatalf("resets = (outer=%d, inner=%d, child=%d), want (1, 1, 1)", outer.resets, inner.resets, childInner.resets)
	}
}
