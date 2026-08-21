/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestDNSConfigFingerprintCoversAllDnsFields(t *testing.T) {
	excluded := map[string]struct{}{
		"OptimisticCache":    {},
		"OptimisticCacheTtl": {},
		"MaxCacheSize":       {},
	}
	covered := map[string]struct{}{
		"IpVersionPrefer": {},
		"FixedDomainTtl":  {},
		"Upstream":        {},
		"Routing":         {},
		"Bind":            {},
		"FakeIP":          {},
	}
	typ := reflect.TypeFor[config.Dns]()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		_, skip := excluded[name]
		_, include := covered[name]
		if skip == include {
			t.Fatalf("dns field %q must be listed in exactly one of fingerprint covered/excluded", name)
		}
	}
}

func TestDNSConfigFingerprintIncludesFakeIP(t *testing.T) {
	base := config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "asis"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	}
	changed := base
	changed.FakeIP = config.FakeIP{
		Enable: true,
		Filter: []*config_parser.Function{{
			Name:   "qname",
			Params: []*config_parser.Param{{Key: "suffix", Val: "openai.com"}},
		}},
	}
	require.NotEqual(t, dnsConfigFingerprint(base), dnsConfigFingerprint(changed))
}
