/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

// A disjoint prefix excludes these owners from ordinary answer
// lookups, including internal lookups that enumerate a domain's cache family.
const dnsRouteOnlyPrefix = "!route|"

func (c *DnsController) publishDNSRouteOnly(msg *dnsmessage.Msg, scope string) error {
	if msg == nil || !msg.Response || msg.Rcode != dnsmessage.RcodeSuccess || len(msg.Question) != 1 {
		return nil
	}
	q := msg.Question[0]
	if q.Qclass != dnsmessage.ClassINET || (q.Qtype != dnsmessage.TypeA && q.Qtype != dnsmessage.TypeAAAA) {
		return nil
	}
	var addresses []string
	ttl := ^uint32(0)
	for _, rr := range msg.Answer {
		ttl = min(ttl, rr.Header().Ttl)
		if ip, ok := dnsAnswerIP(rr); ok && !ip.IsUnspecified() {
			addresses = append(addresses, ip.String())
		}
	}
	if len(addresses) == 0 {
		return nil
	}
	slices.Sort(addresses)
	addresses = slices.Compact(addresses)
	if scope == "" {
		scope = c.cacheKey(q.Name, q.Qtype)
	}
	// Distinct results coexist; random request IDs / Cookies don't create owners.
	key := fmt.Sprintf("%s%s|%x", dnsRouteOnlyPrefix, scope, sha256.Sum256([]byte(strings.Join(addresses, ","))))
	lifetime := time.Duration(min(ttl, uint32(31536000))) * time.Second
	if ttl == 0 {
		lifetime = consts.DefaultDialTimeout
	}
	// Keep the original question name for route matching, even with a CNAME.
	answers := make([]dnsmessage.RR, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		answers = append(answers, dnsmessage.Copy(rr))
	}
	return c.updateDnsCacheDeadline(key, q.Name, q.Qtype, answers, nil, nil,
		func(now time.Time, _ string) (time.Time, time.Time) {
			deadline := now.Add(lifetime)
			return deadline, deadline
		})
}
