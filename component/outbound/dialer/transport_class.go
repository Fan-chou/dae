package dialer

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
)

// DialContextForTransportClass keeps selection and health on the original node,
// while explicitly classified traffic uses a private, persistent transport.
// The owner remains leased by established flows, including full-cone UDP flows.
func (d *Dialer) DialContextForTransportClass(ctx context.Context, network, addr, class string) (netproxy.Conn, error) {
	transport, err := d.transportForClass(class)
	if err != nil {
		return nil, err
	}
	return transport.Dialer.DialContext(ctx, network, addr)
}

func (d *Dialer) transportForClass(class string) (*Dialer, error) {
	// Builtin direct/block have no share link or multiplexed proxy transport.
	if class == "" || d.property == nil || d.property.Link == "" {
		return d, nil
	}
	d.transportClassMu.Lock()
	defer d.transportClassMu.Unlock()
	if d.transportClassesRetired {
		return nil, net.ErrClosed
	}
	if transport := d.transportClasses[class]; transport != nil {
		return transport, nil
	}
	option := *d.GlobalOption
	option.TransportCacheNamespace = newTransportCacheNamespace()
	// Share the node's resolution cache so its existing failure/health machinery
	// invalidates the addresses used by both normal and isolated connections.
	transport, err := NewFromLinkWithProxyCacheContext(d.ctx, &option, d.InstanceOption,
		d.property.Link, d.property.SubscriptionTag, d.proxyIpCache)
	if err != nil {
		return nil, fmt.Errorf("create transport class %q: %w", class, err)
	}
	transport.resolveDNS = d.resolveDNS
	if d.transportClasses == nil {
		d.transportClasses = make(map[string]*Dialer)
	}
	d.transportClasses[class] = transport
	return transport, nil
}

func (d *Dialer) retireTransportClasses() {
	d.transportClassMu.Lock()
	defer d.transportClassMu.Unlock()
	d.transportClassesRetired = true
	for _, transport := range d.transportClasses {
		transport.RetireForEstablishedFlows()
	}
}

func (d *Dialer) closeTransportClasses() {
	d.transportClassMu.Lock()
	transports := d.transportClasses
	d.transportClasses = nil
	d.transportClassMu.Unlock()
	for _, transport := range transports {
		_ = transport.Close()
		CleanupTransportCacheNamespace(transport.TransportCacheNamespace)
	}
}
