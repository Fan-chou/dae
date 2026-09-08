package config

import "testing"

func TestUDPCrossFamilyPools(t *testing.T) {
	for _, tc := range []struct {
		name, v4, v6 string
		fake         FakeIP
		fail         bool
	}{
		{name: "disabled"},
		{name: "both", v4: "198.19.0.0/24", v6: "fd00:cafe::/96"},
		{name: "missing v6", v4: "198.19.0.0/24", fail: true},
		{name: "wrong family", v4: "fd00::/96", v6: "fd00:cafe::/96", fail: true},
		{name: "overlap fake", v4: "198.19.0.0/24", v6: "fd00:cafe::/96", fake: FakeIP{Enable: true}, fail: true},
		{name: "disjoint fake", v4: "198.19.0.0/24", v6: "fd00:cafe::/96", fake: FakeIP{Enable: true, Inet4Range: "198.18.0.0/16"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := (Global{UDPCrossFamilyInet4Range: tc.v4, UDPCrossFamilyInet6Range: tc.v6}).UDPCrossFamilyPrefixes(tc.fake)
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v want failure=%v", err, tc.fail)
			}
		})
	}
}
