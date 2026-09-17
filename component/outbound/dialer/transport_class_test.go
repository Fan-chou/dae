package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

func TestTransportClassReuseAndRetirement(t *testing.T) {
	D.FromLinkRegister("class-test", func(*D.ExtraOption, netproxy.Dialer, string) (netproxy.Dialer, *D.Property, error) {
		return &registrationOwnedDialer{}, &D.Property{Name: "node", Address: "proxy.example:443", Link: "class-test://node"}, nil
	})
	d, err := NewFromLinkContext(context.Background(), &GlobalOption{Log: logrus.New(), CheckInterval: time.Minute}, InstanceOption{DisableCheck: true}, "class-test://node", "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	game, err := d.transportForClass("game")
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.transportForClass("game")
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.transportForClass("voice")
	if err != nil {
		t.Fatal(err)
	}
	normal, err := d.transportForClass("")
	if err != nil {
		t.Fatal(err)
	}
	if game != again || game == other || game == d || normal != d {
		t.Fatal("transport isolation/reuse violated")
	}
	if d.proxyIpCache == nil || game.proxyIpCache != d.proxyIpCache {
		t.Fatal("isolated transport escaped node DNS invalidation")
	}
	if game.TransportCacheNamespace == other.TransportCacheNamespace {
		t.Fatal("classes share transport caches")
	}
	d.RetireForEstablishedFlows()
	if _, err = d.transportForClass("new"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired owner accepted dial: %v", err)
	}
	if len(d.transportClasses) != 2 {
		t.Fatal("retirement dropped leased transports")
	}
	d.Close()
	if len(d.transportClasses) != 0 {
		t.Fatal("close retained transports")
	}
}

func TestTransportCloneDoesNotCopyOrWaitForLazyState(t *testing.T) {
	o := &GlobalOption{TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: []string{"https://example.com"}, opt: &TcpCheckOption{}}, CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: []string{"1.1.1.1"}, opt: &CheckDnsOption{}}, TransportCacheNamespace: "owner"}
	o.TcpCheckOptionRaw.mu.Lock()
	o.CheckDnsOptionRaw.mu.Lock()
	defer o.TcpCheckOptionRaw.mu.Unlock()
	defer o.CheckDnsOptionRaw.mu.Unlock()
	done := make(chan *GlobalOption, 1)
	go func() { done <- o.cloneForTransportClass() }()
	select {
	case c := <-done:
		if c.TcpCheckOptionRaw.opt != nil || c.CheckDnsOptionRaw.opt != nil {
			t.Fatal("copied lazy state")
		}
		if c.TransportCacheNamespace == o.TransportCacheNamespace {
			t.Fatal("shared namespace")
		}
		c.TcpCheckOptionRaw.Raw[0] = "changed"
		if o.TcpCheckOptionRaw.Raw[0] == "changed" {
			t.Fatal("shared raw configuration backing array")
		}
		if !c.TcpCheckOptionRaw.mu.TryLock() {
			t.Fatal("copied locked mutex")
		}
		c.TcpCheckOptionRaw.mu.Unlock()
	case <-time.After(time.Second):
		t.Fatal("clone waited for lazy DNS parsing")
	}
}
