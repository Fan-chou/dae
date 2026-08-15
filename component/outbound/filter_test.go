package outbound

import (
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
)

func namedNoopDialer(option *dialer.GlobalOption, name string) *dialer.Dialer {
	return dialer.NewDialer(
		noopTestDialer{},
		option,
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{Property: D.Property{Name: name}},
	)
}

func testDialerSet(names ...string) *DialerSet {
	option := &dialer.GlobalOption{Log: log}
	s := &DialerSet{
		log:          log,
		dialers:      make([]*dialer.Dialer, 0, len(names)),
		nodeToTagMap: make(map[*dialer.Dialer]string, len(names)),
	}
	for _, name := range names {
		d := namedNoopDialer(option, name)
		s.dialers = append(s.dialers, d)
		s.nodeToTagMap[d] = "sub"
	}
	return s
}

func exactNameFilter(names ...string) []*config_parser.Function {
	params := make([]*config_parser.Param, 0, len(names))
	for _, name := range names {
		params = append(params, &config_parser.Param{Val: name})
	}
	return []*config_parser.Function{{Name: FilterInput_Name, Params: params}}
}

func keywordNameFilter(keyword string) []*config_parser.Function {
	return []*config_parser.Function{{
		Name:   FilterInput_Name,
		Params: []*config_parser.Param{{Key: FilterKey_Name_Keyword, Val: keyword}},
	}}
}

func emptyAnnotations(n int) [][]*config_parser.Param {
	out := make([][]*config_parser.Param, n)
	for i := range out {
		out[i] = []*config_parser.Param{}
	}
	return out
}

func TestFilterAndAnnotateExactNamesFollowDeclarationOrder(t *testing.T) {
	set := testDialerSet("HK_DMIT_HK_Hysteria", "HK_GG_IPLC_Dmit_HK_gRPC", "HK_GG_IPLC_Dmit_HK")
	got, _, err := set.FilterAndAnnotate(
		[][]*config_parser.Function{exactNameFilter("HK_GG_IPLC_Dmit_HK", "HK_GG_IPLC_Dmit_HK_gRPC", "HK_DMIT_HK_Hysteria")},
		emptyAnnotations(1),
	)
	if err != nil {
		t.Fatalf("FilterAndAnnotate() error = %v", err)
	}
	want := []string{"HK_GG_IPLC_Dmit_HK", "HK_GG_IPLC_Dmit_HK_gRPC", "HK_DMIT_HK_Hysteria"}
	if len(got) != len(want) {
		t.Fatalf("got %d dialers, want %d", len(got), len(want))
	}
	for i, name := range want {
		if got[i].Property().Name != name {
			t.Fatalf("dialer[%d] = %q, want %q", i, got[i].Property().Name, name)
		}
	}
}

func TestFilterAndAnnotateExactNameLinesFollowFilterOrder(t *testing.T) {
	set := testDialerSet("HK_DMIT_HK_Hysteria", "HK_GG_IPLC_Dmit_HK")
	got, _, err := set.FilterAndAnnotate(
		[][]*config_parser.Function{
			exactNameFilter("HK_GG_IPLC_Dmit_HK"),
			exactNameFilter("HK_DMIT_HK_Hysteria"),
		},
		emptyAnnotations(2),
	)
	if err != nil {
		t.Fatalf("FilterAndAnnotate() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d dialers, want 2", len(got))
	}
	if got[0].Property().Name != "HK_GG_IPLC_Dmit_HK" || got[1].Property().Name != "HK_DMIT_HK_Hysteria" {
		t.Fatalf("got %q, %q", got[0].Property().Name, got[1].Property().Name)
	}
}

func TestFilterAndAnnotateKeywordKeepsNodeListOrder(t *testing.T) {
	set := testDialerSet("hk-z", "other", "hk-a")
	got, _, err := set.FilterAndAnnotate(
		[][]*config_parser.Function{keywordNameFilter("hk")},
		emptyAnnotations(1),
	)
	if err != nil {
		t.Fatalf("FilterAndAnnotate() error = %v", err)
	}
	if len(got) != 2 || got[0].Property().Name != "hk-z" || got[1].Property().Name != "hk-a" {
		t.Fatalf("got %#v", namesOf(got))
	}
}

func namesOf(dialers []*dialer.Dialer) []string {
	names := make([]string, 0, len(dialers))
	for _, d := range dialers {
		names = append(names, d.Property().Name)
	}
	return names
}
