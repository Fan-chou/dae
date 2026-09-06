package control

import (
	"context"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"net"
	"testing"
	"time"
)

func TestDNSCacheRecordLifetimesAndNegativeTransitions(t *testing.T) {
	logger := newDNSListenerTestLogger()
	routing := newPhase0NamedUpstreamRouting(t, logger, "u", "192.0.2.11:53")
	c, err := NewDnsController(routing, phase0NamedUpstreamControllerOption(logger))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const key = "semantics"
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("alias.example.", dnsmessage.TypeA)
	msg.Response = true
	for _, text := range []string{"alias.example. 300 IN CNAME target.example.", "target.example. 30 IN A 192.0.2.1"} {
		rr, err := dnsmessage.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		msg.Answer = append(msg.Answer, rr)
	}
	extra, _ := dnsmessage.NewRR("target.example. 5 IN TXT \"short\"")
	msg.Extra = []dnsmessage.RR{extra}
	if err := c.NormalizeAndCacheDnsResp_(msg, key); err != nil {
		t.Fatal(err)
	}
	if msg.Answer[1].Header().Ttl != 30 {
		t.Fatal("cache mutated original response")
	}
	value, _ := c.dnsCache.Load(key)
	cached := value.(*DnsCache)
	for _, entry := range []*DnsCache{cached, cached.Clone(), cached.CloneForReload()} {
		for _, age := range []time.Duration{0, 10 * time.Second, 29 * time.Second} {
			now := cached.ReceivedAt.Add(age)
			wire := entry.GetPackedResponseWithApproximateTTL("alias.example.", dnsmessage.TypeA, now)
			var got dnsmessage.Msg
			if err := got.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			if got.Answer[1].Header().Ttl > uint32(30-age/time.Second) {
				t.Fatal("A TTL extended")
			}
			if got.Extra[0].Header().Ttl > uint32(max(int64(0), 5-int64(age/time.Second))) {
				t.Fatal("additional TTL extended")
			}
		}
	}
	msg.Answer = nil
	msg.Extra = nil
	msg.Rcode = dnsmessage.RcodeNameError
	soa, _ := dnsmessage.NewRR("example. 60 IN SOA ns.example. hostmaster.example. 1 60 60 60 30")
	msg.Ns = []dnsmessage.RR{soa}
	if err := c.NormalizeAndCacheDnsResp_(msg, key); err != nil {
		t.Fatal(err)
	}
	value, _ = c.dnsCache.Load(key)
	negative := value.(*DnsCache)
	if negative.OriginalDeadline.Sub(negative.ReceivedAt) != 30*time.Second {
		t.Fatal("negative lifetime must derive from SOA")
	}
	wire, _ := c.LookupDnsRespCache_(msg.Copy(), key, false)
	var got dnsmessage.Msg
	if err := got.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if got.Rcode != dnsmessage.RcodeNameError || len(got.Answer) != 0 || len(got.Ns) != 1 {
		t.Fatal("negative response lost Rcode or SOA")
	}
	for _, rcode := range []int{dnsmessage.RcodeSuccess, dnsmessage.RcodeNameError} {
		msg.Rcode = rcode
		cname, _ := dnsmessage.NewRR("alias.example. 300 IN CNAME missing.example.")
		msg.Answer = []dnsmessage.RR{cname}
		if err := c.NormalizeAndCacheDnsResp_(msg, key); err != nil {
			t.Fatal(err)
		}
		value, _ = c.dnsCache.Load(key)
		entry := value.(*DnsCache)
		if entry.OriginalDeadline.Sub(entry.ReceivedAt) != 30*time.Second {
			t.Fatal("CNAME must not extend negative SOA lifetime")
		}
	}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Ns = nil
	a, _ := dnsmessage.NewRR("alias.example. 0 IN A 192.0.2.2")
	msg.Answer = []dnsmessage.RR{a}
	if err := c.NormalizeAndCacheDnsResp_(msg, key); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.dnsCache.Load(key); ok {
		t.Fatal("TTL0 must not expose an old cached answer")
	}
}

func TestDNSQuerySharedSemantics(t *testing.T) {
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.", dnsmessage.TypeA)
	if !dnsQueryCanShare(query) {
		t.Fatal("ordinary query must share")
	}
	query.SetEdns0(1232, false)
	if !dnsQueryCanShare(query) {
		t.Fatal("UDP size alone must share")
	}
	cases := []func(*dnsmessage.Msg){
		func(m *dnsmessage.Msg) { m.CheckingDisabled = true },
		func(m *dnsmessage.Msg) { m.Question[0].Qclass = dnsmessage.ClassCHAOS },
		func(m *dnsmessage.Msg) { m.IsEdns0().SetDo() },
		func(m *dnsmessage.Msg) {
			m.IsEdns0().Option = []dnsmessage.EDNS0{&dnsmessage.EDNS0_COOKIE{Code: dnsmessage.EDNS0COOKIE, Cookie: "0123456789abcdef"}}
		},
	}
	for _, change := range cases {
		q := query.Copy()
		change(q)
		if dnsQueryCanShare(q) {
			t.Fatal("special semantics entered ordinary shared key")
		}
	}
}

func TestDNSSpecialQueriesDoNotReadOrPopulateOrdinaryCache(t *testing.T) {
	logger := newDNSListenerTestLogger()
	routing := newPhase0NamedUpstreamRouting(t, logger, "u", "192.0.2.11:53")
	c, err := NewDnsController(routing, phase0NamedUpstreamControllerOption(logger))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	original := dnsForwarderFactory
	defer func() { dnsForwarderFactory = original }()
	calls := 0
	dnsForwarderFactory = func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(_ context.Context, wire []byte) (*dnsmessage.Msg, error) {
			calls++
			var query dnsmessage.Msg
			if err := query.Unpack(wire); err != nil {
				return nil, err
			}
			response := new(dnsmessage.Msg)
			response.SetReply(&query)
			address := "192.0.2.1"
			if !dnsQueryCanShare(&query) {
				address = "192.0.2.2"
			}
			rr, _ := dnsmessage.NewRR(query.Question[0].Name + " 60 IN A " + address)
			rr.Header().Class = query.Question[0].Qclass
			response.Answer = []dnsmessage.RR{rr}
			return response, nil
		}}, nil
	}
	ordinary := new(dnsmessage.Msg)
	ordinary.SetQuestion(phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
	request := &udpRequest{routingResult: &bpfRoutingResult{}}
	query := func(msg *dnsmessage.Msg, want string) {
		t.Helper()
		writer := &dnsTransportResponseWriter{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
		if err := c.HandleWithResponseWriter_(context.Background(), msg, request, writer); err != nil {
			t.Fatal(err)
		}
		got := writer.Message()
		if got == nil {
			t.Fatal("no response")
		}
		if got.Question[0].Qclass != msg.Question[0].Qclass || dnsAnswerIPv4(t, got) != want {
			t.Fatal("shared response crossed query semantics")
		}
	}
	query(ordinary.Copy(), "192.0.2.1")
	for _, change := range []func(*dnsmessage.Msg){
		func(m *dnsmessage.Msg) { m.SetEdns0(1232, true) },
		func(m *dnsmessage.Msg) { m.CheckingDisabled = true },
		func(m *dnsmessage.Msg) { m.Question[0].Qclass = dnsmessage.ClassCHAOS },
		func(m *dnsmessage.Msg) {
			m.SetEdns0(1232, false)
			m.IsEdns0().Option = []dnsmessage.EDNS0{&dnsmessage.EDNS0_COOKIE{Code: dnsmessage.EDNS0COOKIE, Cookie: "0123456789abcdef"}}
		},
	} {
		special := ordinary.Copy()
		change(special)
		before := calls
		query(special.Copy(), "192.0.2.2")
		query(special.Copy(), "192.0.2.2")
		query(ordinary.Copy(), "192.0.2.1")
		if calls != before+2 {
			t.Fatalf("special/shared forward count=%d want=%d", calls, before+2)
		}
	}
	sized := ordinary.Copy()
	sized.SetEdns0(1232, false)
	before := calls
	query(sized, "192.0.2.1")
	if calls != before {
		t.Fatal("UDP size alone disabled sharing")
	}
}
