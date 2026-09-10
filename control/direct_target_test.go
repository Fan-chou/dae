package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	cd "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/stretchr/testify/require"
)

type targetRecordingDialer struct {
	target string
	conn   netproxy.Conn
}

func (d *targetRecordingDialer) DialContext(_ context.Context, _, target string) (netproxy.Conn, error) {
	d.target = target
	return d.conn, nil
}

func TestSelectedDirectLeafKeepsRealTarget(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, leaf := range []string{"direct", "proxy"} {
			for _, nested := range []bool{false, true} {
				name := network + "/" + leaf
				if nested {
					name += "/nested"
				}
				t.Run(name, func(t *testing.T) {
					var written string
					conn := &mockPacketConn{writeToFn: func(b []byte, addr string) (int, error) { written = addr; return len(b), nil }}
					recorder := &targetRecordingDialer{conn: conn}
					option := &cd.GlobalOption{Log: testDialControlPlane(nil).log, CheckInterval: time.Minute}
					prop := D.Property{Name: leaf}
					if leaf == "proxy" {
						prop.Address = "proxy.example:443"
					}
					d := cd.NewDialerContext(context.Background(), recorder, option, cd.InstanceOption{DisableCheck: true}, &cd.Property{Property: prop})
					group := newTestFixedOutboundGroup(d)
					if nested {
						var err error
						group, err = ob.NewNestedDialerGroup(option, "parent", []ob.NestedDialerGroupMember{{Group: group}}, ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed}, func(bool, *cd.NetworkType, bool) {})
						require.NoError(t, err)
					}
					cp := testDialControlPlane(group)
					cp.dialMode = consts.DialMode_DomainCao
					dst := netip.MustParseAddrPort("[2001:db8::20]:443")
					cp.routingMatcher = testFakeIPMatcher(t, "fallback: proxy", []string{"proxy"})
					c, res, err := cp.routeDial(context.Background(), &proxyDialParam{Outbound: consts.OutboundUserDefinedMin, Domain: "tether.edge.apple", Src: netip.MustParseAddrPort("[2001:db8::10]:40000"), Dest: dst, Network: network})
					require.NoError(t, err)
					want := "tether.edge.apple:443"
					if leaf == "direct" {
						want = dst.String()
					}
					require.Equal(t, want, recorder.target)
					require.Equal(t, "tether.edge.apple", res.SniffedDomain)
					require.Equal(t, leaf == "direct", res.IsDialIp)
					if network == "udp" {
						ue := newTestEndpoint(c.(netproxy.PacketConn))
						ue.DialTarget = res.DialTarget
						ue.poolKey.Dst = dst
						_, err = ue.WriteTo([]byte("packet"), ue.dialTargetForWrite(dst))
						require.NoError(t, err)
						require.Equal(t, want, written)
					}
				})
			}
		}
	}
}
