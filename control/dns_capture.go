// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"github.com/daeuniverse/dae/component/observation"
	dnsmessage "github.com/miekg/dns"
	"time"
)

// captureDNS observes a resolver hop, never the remote resolver's cache or
// filtering logic. DNS-to-application links are candidates, not causality.
func (c *DnsController) captureDNS(kind, upstream, client, cache string, start time.Time, query, response *dnsmessage.Msg, err error) {
	rt := c.runtime()
	if rt == nil || rt.capture == nil || query == nil || len(query.Question) == 0 {
		return
	}
	trace := rt.capture.NewTrace()
	if trace == nil {
		return
	}
	c.captureDNSSampled(trace, kind, upstream, client, cache, start, query, response, err)
}

func (c *DnsController) captureDNSSampled(trace *observation.Trace, kind, upstream, client, cache string, start time.Time, query, response *dnsmessage.Msg, err error) {
	if trace == nil || query == nil || len(query.Question) == 0 {
		return
	}
	facts := observation.DNSFacts{Cache: cache, Filter: "unobserved"}
	if kind == "dns_upstream" {
		facts.Cache = "not_applicable"
	}
	facts.QType = query.Question[0].Qtype
	var ips []string
	if response != nil {
		code := response.Rcode
		facts.RCode = &code
		tc := response.Truncated
		facts.Truncated = &tc
		for _, rr := range response.Answer {
			ip, ok := dnsAnswerIP(rr)
			if !ok {
				continue
			}
			facts.AnswerIPs++
			if len(ips) < 32 {
				ips = append(ips, ip.Unmap().String())
			}
			if policy := c.fakeIPPolicy(); policy != nil && policy.store != nil && policy.store.Contains(ip) {
				facts.FakeIPs++
			}
		}
	}
	trace.DNS(kind, query.Question[0].Name, upstream, client, start, observation.ErrorOutcome(err), facts, ips)
}
func (c *DnsController) captureDNSReply(msg *dnsmessage.Msg, req *udpRequest) {
	rt := c.runtime()
	if rt == nil || rt.capture == nil {
		return
	}
	trace := rt.capture.NewTrace()
	if trace == nil {
		return
	}
	c.captureDNSReplySampled(trace, msg, req)
}
func (c *DnsController) captureDNSReplySampled(trace *observation.Trace, msg *dnsmessage.Msg, req *udpRequest) {
	client := ""
	if req != nil && req.realSrc.IsValid() {
		client = req.realSrc.Addr().String()
	}
	c.captureDNSSampled(trace, "dns_client_reply", "", client, "unknown", time.Now(), msg, msg, nil)
}

func (c *DnsController) captureDNSCache(wire []byte, req *udpRequest, stale bool) {
	rt := c.runtime()
	if rt == nil || rt.capture == nil {
		return
	}
	trace := rt.capture.NewTrace()
	if trace == nil {
		return
	}
	var msg dnsmessage.Msg
	if msg.Unpack(wire) != nil {
		return
	}
	client := ""
	if req != nil && req.realSrc.IsValid() {
		client = req.realSrc.Addr().String()
	}
	state := "hit"
	if stale {
		state = "stale_hit"
	}
	c.captureDNSSampled(trace, "dns_cache_hit", "", client, state, time.Now(), &msg, &msg, nil)
}
