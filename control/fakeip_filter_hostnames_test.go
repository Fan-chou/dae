package control

import "testing"

func TestHostnamesFromNodeListSkipsAddressLiterals(t *testing.T) {
	got := hostnamesFromNodeList(map[string][]string{
		"x": {
			"a:hysteria2://pw@[2407:cdc0:d002::1961]:58526",
			"b:hysteria2://pw@203.0.113.7:58526",
			"c:hysteria2://pw@Node.Example.com.:58526",
		},
	})
	if len(got) != 1 || got[0] != "node.example.com." {
		t.Fatalf("hostnames = %v, want only node.example.com.", got)
	}
}
