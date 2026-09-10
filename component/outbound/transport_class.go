package outbound

import (
	"context"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

// DialContextWithSelected does not change the selected node or established-flow
// ownership. Only this group's explicit opt-in changes transport sharing.
func (g *DialerGroup) DialContextWithSelected(ctx context.Context, d *dialer.Dialer, network, addr string) (netproxy.Conn, error) {
	class := ""
	if g != nil && g.IsolateTransport {
		class = g.Name
	}
	return d.DialContextForTransportClass(ctx, network, addr, class)
}
