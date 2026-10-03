// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestUDPReplyDroughtConfiguration(t *testing.T) {
	for _, tc := range []struct {
		input string
		valid bool
	}{
		{"", true},
		{"udp_reply_drought_mode: observe\nudp_reply_drought_group: proxy", true},
		{"udp_reply_drought_mode: enforce", false},
		{"udp_reply_drought_contract: request_reply", false},
		{"udp_reply_drought_contract: cs2", false},
		{"udp_reply_drought_group: typo", false},
		{"udp_reply_drought_client: '192.0.2.10'", true},
		{"udp_reply_drought_client: '0.0.0.0'", false},
		{"udp_reply_drought_client: '::ffff:0.0.0.0'", false},
		{"udp_reply_drought_client: 'client.example'", false},
		{"udp_reply_drought_peers: '192.0.2.1:53'", false},
		{"udp_reply_drought_peers: '0.0.0.0:27015'", false},
		{"udp_reply_drought_peers: '[::ffff:224.0.0.1]:27015'", false},
		{"udp_reply_drought_peers: 'example.com:27015'", false},
		{"udp_reply_drought_mode: observe\nudp_reply_drought_contract: request_reply\nudp_reply_drought_peers: '192.0.2.1:27015'", true},
	} {
		t.Run(strings.ReplaceAll(tc.input, "\n", " "), func(t *testing.T) {
			c, err := qualityConfig(tc.input, "")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if err != nil {
				return
			}
			p, err := c.Global.UDPReplyDroughtPolicy()
			if err != nil {
				t.Fatal(err)
			}
			if tc.input == "" && (p.Observe || p.RequestReply) {
				t.Fatal("unsafe defaults")
			}
			wire, err := c.Marshal(2)
			if err != nil {
				t.Fatal(err)
			}
			sections, err := config_parser.Parse(string(wire))
			if err != nil {
				t.Fatal(err)
			}
			again, err := New(sections)
			if err != nil {
				t.Fatal(err)
			}
			got, err := again.Global.UDPReplyDroughtPolicy()
			if err != nil || got.Observe != p.Observe || got.RequestReply != p.RequestReply || got.Group != p.Group || got.Client != p.Client || len(got.Peers) != len(p.Peers) {
				t.Fatalf("round trip: %+v %v", got, err)
			}
		})
	}
}
