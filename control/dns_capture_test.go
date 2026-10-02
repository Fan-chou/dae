// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"context"
	"encoding/json"
	"github.com/daeuniverse/dae/component/observation"
	dnsmessage "github.com/miekg/dns"
	"testing"
	"time"
)

func TestDNSCaptureDoesNotInventRemoteFilterOrCache(t *testing.T) {
	collector, err := observation.New(1000)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	c := setTestDnsControllerRuntime(nil, func(rt *dnsControllerRuntimeState) { rt.capture = collector })
	q := new(dnsmessage.Msg)
	q.SetQuestion("example.test.", dnsmessage.TypeA)
	reply := new(dnsmessage.Msg)
	reply.SetReply(q)
	c.captureDNS("dns_upstream", "udp://192.0.2.1:53", "", "not_applicable", time.Now(), q, reply, nil)
	c.captureDNS("dns_upstream", "udp://192.0.2.1:53", "", "not_applicable", time.Now(), q, nil, context.Canceled)
	wire, _ := reply.Pack()
	c.captureDNSCache(wire, nil, true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := collector.EvidenceSnapshot(0)
		if len(s.Records) == 3 {
			var a, b, d observation.Evidence
			json.Unmarshal(s.Records[0], &a)
			json.Unmarshal(s.Records[1], &b)
			json.Unmarshal(s.Records[2], &d)
			if a.DNS.RCode == nil || *a.DNS.RCode != 0 || a.DNS.AnswerIPs != 0 || a.DNS.Filter != "unobserved" {
				t.Fatal("empty response misclassified")
			}
			if b.Outcome != "canceled" || b.DNS.RCode != nil {
				t.Fatal("cancellation invented reply")
			}
			if d.DNS.Cache != "stale_hit" {
				t.Fatal("stale provenance lost")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no observations")
}
