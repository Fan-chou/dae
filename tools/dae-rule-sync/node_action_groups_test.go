package main

import (
	"strings"
	"testing"
)

func TestPlanMihomoNodeActionGroupsWrapsOnlyNodeTargets(t *testing.T) {
	ir := MihomoRuleIR{Rules: []MihomoRuleIRRule{
		{Action: MihomoAction{Target: "🇭🇰 BsetVM.HKBGP | AnyTLS"}},
		{Action: MihomoAction{Target: "Proxy"}},
		{Action: MihomoAction{Target: "DIRECT"}},
		{Action: MihomoAction{Target: "REJECT-DROP"}},
		{Action: MihomoAction{Target: "🇭🇰 BsetVM.HKBGP | AnyTLS"}},
	}}
	wrappers, err := planMihomoNodeActionGroups(ir, map[string]string{
		"🇭🇰 BsetVM.HKBGP | AnyTLS": "HK_BsetVM_HKBGP_AnyTLS",
		"ss-node":                  "ss-node",
	}, map[string]string{"Proxy": "Proxy"})
	if err != nil {
		t.Fatalf("planMihomoNodeActionGroups() error = %v", err)
	}
	if len(wrappers) != 1 || wrappers[0].Original != "🇭🇰 BsetVM.HKBGP | AnyTLS" || wrappers[0].NodeName != "HK_BsetVM_HKBGP_AnyTLS" || wrappers[0].GroupName != "node_HK_BsetVM_HKBGP_AnyTLS" {
		t.Fatalf("wrappers = %#v", wrappers)
	}
}

func TestAllocateNodeActionGroupNameAvoidsCollisions(t *testing.T) {
	used := map[string]struct{}{
		"ss-node":      {},
		"node_ss_node": {},
		"Proxy":        {},
	}
	got, err := allocateNodeActionGroupName("ss-node", used)
	if err != nil {
		t.Fatalf("allocateNodeActionGroupName() error = %v", err)
	}
	if got != "node_ss_node_g" {
		t.Fatalf("allocateNodeActionGroupName() = %q, want node_ss_node_g", got)
	}
	if !daeIdentifierPattern.MatchString(got) {
		t.Fatalf("allocated name %q is not a dae identifier", got)
	}
}

func TestApplyMihomoNodeActionGroupsRewritesRoutesToWrapper(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "🇭🇰 BsetVM.HKBGP | AnyTLS"}},
		Groups:  []MihomoGroup{{Name: "Proxy", Type: "select", Proxies: []string{"🇭🇰 BsetVM.HKBGP | AnyTLS"}}},
	}
	nodeNames := map[string]string{"🇭🇰 BsetVM.HKBGP | AnyTLS": "HK_BsetVM_HKBGP_AnyTLS"}
	groupsText, report, err := generateFullMihomoGroups(config, nodeNames)
	if err != nil {
		t.Fatalf("generateFullMihomoGroups() error = %v", err)
	}
	ir := MihomoRuleIR{Rules: []MihomoRuleIRRule{
		{
			MihomoRuleSource: MihomoRuleSource{SourceIndex: 0, SourceLine: 10, Raw: "DOMAIN-SUFFIX,mytvsuper.com,🇭🇰 BsetVM.HKBGP | AnyTLS"},
			Expr:             MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "DOMAIN-SUFFIX", Value: "mytvsuper.com"}},
			Action:           MihomoAction{Target: "🇭🇰 BsetVM.HKBGP | AnyTLS"},
		},
		{
			MihomoRuleSource: MihomoRuleSource{SourceIndex: 1, SourceLine: 11, Raw: "MATCH,Proxy"},
			Expr:             MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "MATCH"}},
			Action:           MihomoAction{Target: "Proxy"},
		},
	}}
	groupsText, wrappers, err := applyMihomoNodeActionGroups(ir, groupsText, nodeNames, &report)
	if err != nil {
		t.Fatalf("applyMihomoNodeActionGroups() error = %v", err)
	}
	if len(wrappers) != 1 || report.NameMap["node_HK_BsetVM_HKBGP_AnyTLS"] != "node_HK_BsetVM_HKBGP_AnyTLS" {
		t.Fatalf("wrappers/report = %#v / %#v", wrappers, report.NameMap)
	}
	if !strings.Contains(groupsText, "    node_HK_BsetVM_HKBGP_AnyTLS {") || !strings.Contains(groupsText, "filter: name('HK_BsetVM_HKBGP_AnyTLS')") {
		t.Fatalf("groups = %q, missing node-action wrapper", groupsText)
	}

	outboundMap, err := mergeMihomoOutboundMaps(nodeNames, report.NameMap)
	if err != nil {
		t.Fatalf("mergeMihomoOutboundMaps() error = %v", err)
	}
	remapMihomoNodeActionOutbounds(outboundMap, wrappers)
	if outboundMap["🇭🇰 BsetVM.HKBGP | AnyTLS"] != "node_HK_BsetVM_HKBGP_AnyTLS" || outboundMap["Proxy"] != "Proxy" {
		t.Fatalf("outboundMap = %#v", outboundMap)
	}

	lowered, err := LowerMihomoRuleIR(ir, MihomoRuleLowererOptions{OutboundNameMap: outboundMap})
	if err != nil {
		t.Fatalf("LowerMihomoRuleIR() error = %v", err)
	}
	routes, _, err := renderMihomoLoweredRoutes(lowered)
	if err != nil {
		t.Fatalf("renderMihomoLoweredRoutes() error = %v", err)
	}
	if !strings.Contains(routes, `-> node_HK_BsetVM_HKBGP_AnyTLS`) || !strings.Contains(routes, "fallback: Proxy") {
		t.Fatalf("routes = %q", routes)
	}

	nodes := "node {\n    HK_BsetVM_HKBGP_AnyTLS: 'socks5://127.0.0.1:1080'\n}\n"
	if _, nodeSet, groupSet, err := inspectGeneratedMihomoConfig([]byte(nodes), []byte(groupsText), []byte(routes)); err != nil {
		t.Fatalf("inspectGeneratedMihomoConfig() error = %v", err)
	} else if _, ok := groupSet["node_HK_BsetVM_HKBGP_AnyTLS"]; !ok || len(nodeSet) != 1 {
		t.Fatalf("generated names nodes=%v groups=%v", nodeSet, groupSet)
	}
}
