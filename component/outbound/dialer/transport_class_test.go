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
