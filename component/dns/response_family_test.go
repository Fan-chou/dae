package dns

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"net/netip"
	"testing"
)

func TestResponseIPv6DefaultDoesNotMatchIPv4(t *testing.T) {
	for _, negate := range []bool{false, true} {
		b := &ResponseMatcherBuilder{log: logrus.New()}
		if err := b.addIp(&config_parser.Function{Not: negate}, []netip.Prefix{netip.MustParsePrefix("::/0")}, &routing.Outbound{Name: "reject"}); err != nil {
			t.Fatal(err)
		}
		if err := b.addFallback("accept"); err != nil {
			t.Fatal(err)
		}
		m, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range []string{"1.1.1.1", "2001:db8::1"} {
			ip := netip.MustParseAddr(address)
			got, err := m.Match("example.com", 1, []netip.Addr{ip}, 0)
			if err != nil {
				t.Fatal(err)
			}
			reject := !ip.Is4()
			if negate {
				reject = !reject
			}
			if (got == consts.DnsResponseOutboundIndex_Reject) != reject {
				t.Fatalf("ip=%s not=%v got=%v", ip, negate, got)
			}
		}
	}
}
