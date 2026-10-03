//go:build linux

package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/miekg/dns"
)

// A failed DNS lookup still proves packet delivery, while a different query,
// transaction or peer must not be counted as the requested probe succeeding.
func TestUDPWANReplyValidation(t *testing.T) {
	for _, kind := range []string{"success", "dns_error", "wrong_id", "wrong_question", "wrong_peer", "mapped_peer", "short_write", "synchronous_receiver"} {
		t.Run(kind, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion("one.one.one.one.", dns.TypeA)
			query.SetEdns0(4096, false)
			response := new(dns.Msg)
			response.SetReply(query)
			response = response.Copy()
			peer := netip.MustParseAddrPort("1.1.1.1:53")
			if kind == "dns_error" {
				response.Rcode = dns.RcodeServerFailure
			}
			if kind == "wrong_id" {
				response.Id++
			}
			if kind == "wrong_question" {
				response.Question[0].Name = "another.example."
			}
			if kind == "wrong_peer" {
				peer = netip.MustParseAddrPort("1.1.1.1:54")
			}
			if kind == "mapped_peer" {
				peer = netip.MustParseAddrPort("[::ffff:1.1.1.1]:53")
			}
			packet, _ := response.Pack()
			wire, _ := query.Pack()
			pc := &udpWANValidationConn{response: packet, peer: peer, short: kind == "short_write"}
			mode := "read_from"
			if kind == "synchronous_receiver" {
				mode = "packet_receiver"
			}
			result, reply := udpWANProbe(context.Background(), udpWANValidationDialer{pc}, &udpWANTrackedDialer{}, "udp", "1.1.1.1:53", mode, wire, query)
			want := kind == "success" || kind == "dns_error" || kind == "mapped_peer" || kind == "synchronous_receiver"
			if result["response_valid"] != want || (reply != nil) != want {
				t.Fatalf("unexpected validation: %+v", result)
			}
		})
	}
}

func TestUDPWANQueryPolicy(t *testing.T) {
	for _, kind := range []string{"allowed", "padding", "other_option", "nonzero_data", "other_question"} {
		t.Run(kind, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion("one.one.one.one.", dns.TypeA)
			query.SetEdns0(4096, false)
			option := &dns.EDNS0_LOCAL{Code: 65001, Data: make([]byte, 16)}
			query.IsEdns0().Option = []dns.EDNS0{option}
			switch kind {
			case "padding":
				query.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: make([]byte, 16)}}
			case "other_option":
				option.Code++
			case "nonzero_data":
				option.Data[0] = 1
			case "other_question":
				query.Question[0].Name = "other.example."
			}
			if got := udpWANAllowedQuery(query); got != (kind == "allowed") {
				t.Fatalf("query policy allowed=%v", got)
			}
		})
	}
}

type udpWANValidationDialer struct{ pc *udpWANValidationConn }

func (d udpWANValidationDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return d.pc, nil
}

type udpWANValidationConn struct {
	response []byte
	peer     netip.AddrPort
	short    bool
	handler  netproxy.PacketReceiveHandler
}

func (c *udpWANValidationConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	return copy(b, c.response), c.peer, nil
}
func (c *udpWANValidationConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}
func (c *udpWANValidationConn) Write(b []byte) (int, error) { return c.WriteTo(b, "") }
func (c *udpWANValidationConn) WriteTo(b []byte, _ string) (int, error) {
	if c.short {
		return len(b) - 1, nil
	}
	if c.handler != nil {
		c.handler(netproxy.NewReceivedPacket(c.response, c.peer, nil, nil))
	}
	return len(b), nil
}
func (c *udpWANValidationConn) Close() error                    { return nil }
func (c *udpWANValidationConn) SetDeadline(time.Time) error     { return nil }
func (c *udpWANValidationConn) SetReadDeadline(time.Time) error { return nil }
func (c *udpWANValidationConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *udpWANValidationConn) RegisterPacketReceiver(h netproxy.PacketReceiveHandler) (func(), bool) {
	c.handler = h
	return func() { c.handler = nil }, true
}
