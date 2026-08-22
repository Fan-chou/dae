/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestParseFakeIPFilterColonQname(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    filter: qname(suffix: push.apple.com)
    filter: qname(full: localhost.ptlogin2.qq.com)
  }
}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	require.True(t, conf.Dns.FakeIP.Enable)
	require.Len(t, conf.Dns.FakeIP.Filter, 2)
	require.Equal(t, "qname", conf.Dns.FakeIP.Filter[0].Name)
	require.Equal(t, "suffix", conf.Dns.FakeIP.Filter[0].Params[0].Key)
	require.Equal(t, "push.apple.com", conf.Dns.FakeIP.Filter[0].Params[0].Val)
	require.Equal(t, "full", conf.Dns.FakeIP.Filter[1].Params[0].Key)
}

func TestParseFakeIPFilterNestedSkipOutbound(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    filter {
      qname(suffix: lan, suffix: local, keyword: stun) -> skip
      qname(full: localhost.ptlogin2.qq.com) -> skip
    }
  }
}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	require.Len(t, conf.Dns.FakeIP.Filter, 2)
	require.Equal(t, "qname", conf.Dns.FakeIP.Filter[0].Name)
	require.Len(t, conf.Dns.FakeIP.Filter[0].Params, 3)
}

func TestParseFakeIPBareQnameInFilterBlock(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    filter {
      qname(suffix: lan)
      qname(suffix: push.apple.com)
    }
  }
}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	require.Len(t, conf.Dns.FakeIP.Filter, 2)
	require.Equal(t, "qname", conf.Dns.FakeIP.Filter[0].Name)
	require.Equal(t, "lan", conf.Dns.FakeIP.Filter[0].Params[0].Val)
	require.Equal(t, "push.apple.com", conf.Dns.FakeIP.Filter[1].Params[0].Val)
}

func TestParseFakeIPRejectsWideIPv6Pool(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    inet6_range: 'fd00:daee::/48'
  }
}
`)
	require.NoError(t, err)
	_, err = New(sections)
	require.Error(t, err)
	require.Contains(t, err.Error(), "/96")
}

func TestParseFakeIPRejectsTTL1(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    ttl: 1
  }
}
`)
	require.NoError(t, err)
	_, err = New(sections)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TTL=1")
}

func TestParseFakeIPRejectsPathOutsidePersist(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    path: 'mapping.bin'
  }
}
`)
	require.NoError(t, err)
	_, err = New(sections)
	require.Error(t, err)
	require.Contains(t, err.Error(), "persist.d/fakeip")
}

func TestParseFakeIPRejectsNonQnameFilter(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    filter: domain(suffix: lan)
  }
}
`)
	require.NoError(t, err)
	_, err = New(sections)
	require.Error(t, err)
	require.Contains(t, err.Error(), "qname()")
}

func TestParseFakeIPOmitsInet6DisablesIPv6(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    inet4_range: '28.0.0.0/15'
  }
}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	p6, err := conf.Dns.FakeIP.Inet6Prefix()
	require.NoError(t, err)
	require.False(t, p6.IsValid())
	require.Equal(t, "", conf.Dns.FakeIP.Inet6Range)
}

func TestParseFakeIPExplicitInet6(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {
  fakeip {
    enable: true
    inet6_range: 'fd00:daee::/96'
  }
}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	p6, err := conf.Dns.FakeIP.Inet6Prefix()
	require.NoError(t, err)
	require.Equal(t, FakeIPDefaultInet6Range, p6.String())
}

func TestParseFakeIPDefaultsOff(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns {}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	require.False(t, conf.Dns.FakeIP.Enable)
	require.Equal(t, 32768, conf.Dns.FakeIP.ResolvedMaxEntries())
}

const userFakeIPDnsSnippet = `
global {}
routing { fallback: direct }
dns {
    upstream {
        homedns: 'udp://192.168.124.222:5354'
        alidns: 'udp://223.5.5.5:53'
    }
    routing {
        request {
            qname(suffix: lan, suffix: local, suffix: routing) -> asis
            fallback: homedns
        }
    }
    fakeip {
        enable: true
        inet4_range: '28.0.0.0/8'
        filter_mode: skip
        filter {
            qname(suffix: chowtaiseng.com, suffix: tailscale.com, suffix: routing)
            qname(suffix: forzamotorsport.net, suffix: elb.us-west-2.amazonaws.com)
            qname(full: lancache.steamcontent.com, full: speedtest.cros.wr.pvp.net)
            qname(full: time1.apple.com, full: time.asia.apple.com)
            qname(full: cn.ntp.org.cn, full: ntp.ntsc.ac.cn, full: time.nist.gov)
            qname(full: time1.cloud.tencent.com, full: trtc.time.tencent-cloud.com, full: time1.aliyun.com)
            qname(regex: '^[^.]+\.[^.]+\.[^.]+\.srv\.nintendo\.net$')
            qname(regex: '^xbox\.[^.]+\.[^.]+\.microsoft\.com$')
        }
    }
}
`

func TestParseFakeIPUserDnsSnippet(t *testing.T) {
	sections, err := config_parser.Parse(userFakeIPDnsSnippet)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	fake := conf.Dns.FakeIP
	require.True(t, fake.Enable)
	require.Equal(t, "skip", fake.ResolvedFilterMode())
	require.Len(t, fake.Filter, 8)
	p4, err := fake.Inet4Prefix()
	require.NoError(t, err)
	require.Equal(t, "28.0.0.0/8", p4.String())
	p6, err := fake.Inet6Prefix()
	require.NoError(t, err)
	require.False(t, p6.IsValid(), "omitted inet6_range must disable IPv6 FakeIP")
}
