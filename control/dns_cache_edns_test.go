/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestDNSCacheDoesNotShareUnsolicitedEDNS(t *testing.T) {
	for _, ttl := range []uint32{300, 86400} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			routing := newPhase0NamedUpstreamRouting(t, logger, "u", "192.0.2.11:53")
			response := dnsAResponseMsg(phase0NamedUpstreamScopeQName, "198.51.100.11")
			response.Answer[0].Header().Ttl = ttl
			response.SetEdns0(1232, true)
			opt := response.IsEdns0()
			opt.SetZ(0x0040)
			opt.Option = []dnsmessage.EDNS0{&dnsmessage.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3}}}
			extra, err := dnsmessage.NewRR("extra.scope.test. 60 IN TXT \"metadata\"")
			require.NoError(t, err)
			response.Extra = append(response.Extra, extra)
			wire, err := response.Pack()
			require.NoError(t, err)
			require.NoError(t, response.Unpack(wire))
			opt = response.IsEdns0()

			var forwards atomic.Int32
			originalFactory := dnsForwarderFactory
			dnsForwarderFactory = func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					forwards.Add(1)
					return response.Copy(), nil
				}}, nil
			}
			t.Cleanup(func() { dnsForwarderFactory = originalFactory })
			controller, err := NewDnsController(routing, phase0NamedUpstreamControllerOption(logger))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, controller.Close()) })
			req := &udpRequest{routingResult: &bpfRoutingResult{}}

			for i, path := range []string{"miss", "hit"} {
				t.Run(path, func(t *testing.T) {
					got := resolvePhase0NamedUpstreamScope(t, controller, req, uint16(i+1))
					require.EqualValues(t, 1, forwards.Load())
					require.Nil(t, got.IsEdns0(), "ordinary query must not inherit unsolicited upstream EDNS options")
				})
			}

			entries := controller.CloneCacheForReload()
			require.Len(t, entries, 1)
			for _, cache := range entries {
				require.Len(t, cache.Extra, 1, "only the ordinary additional record is shared")
				require.Equal(t, opt, response.IsEdns0(), "cache insertion must not mutate upstream OPT")
				t.Run("refresh", func(t *testing.T) {
					wire := cache.GetPackedResponseWithApproximateTTL(phase0NamedUpstreamScopeQName, dnsmessage.TypeA, cache.Deadline.Add(-30*time.Second))
					var got dnsmessage.Msg
					require.NoError(t, got.Unpack(wire))
					require.EqualValues(t, 30, got.Answer[0].Header().Ttl)
					require.Zero(t, got.Extra[0].Header().Ttl, "expired additional record must not acquire the answer lifetime")
					require.Nil(t, got.IsEdns0())
					require.EqualValues(t, 60, cache.Extra[0].Header().Ttl, "refresh must not mutate shared stored records")
				})
			}
		})
	}
}
