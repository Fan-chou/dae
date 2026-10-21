package config

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func newConfigWithGlobal(t *testing.T, global string) (*Config, error) {
	t.Helper()
	sections, err := config_parser.Parse("global {\n" + global + "\n}\nrouting {\n    fallback: direct\n}\n")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	return New(sections)
}

func TestEgressGuardProofMarkDefaultsOff(t *testing.T) {
	conf, err := newConfigWithGlobal(t, "")
	if err != nil {
		t.Fatalf("New error = %v", err)
	}
	if conf.Global.EgressGuardProofMark != 0 {
		t.Fatalf("EgressGuardProofMark = %#x, want 0", conf.Global.EgressGuardProofMark)
	}
}

func TestEgressGuardProofMarkAcceptsSingleFreeBit(t *testing.T) {
	conf, err := newConfigWithGlobal(t, "egress_guard_proof_mark: 0x40000000")
	if err != nil {
		t.Fatalf("New error = %v", err)
	}
	if conf.Global.EgressGuardProofMark != 0x40000000 {
		t.Fatalf("EgressGuardProofMark = %#x, want 0x40000000", conf.Global.EgressGuardProofMark)
	}
}

func TestEgressGuardProofMarkRejectsInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		global string
		want   string
	}{
		"multiple bits":      {"egress_guard_proof_mark: 0xc0000000", "single fwmark bit"},
		"tproxy mark":        {"egress_guard_proof_mark: 0x8000000", "reserved"},
		"internal so mark":   {"egress_guard_proof_mark: 0x100", "reserved"},
		"so_mark_from_dae":   {"egress_guard_proof_mark: 0x40000000\n    so_mark_from_dae: 0x40000000", "so_mark_from_dae"},
		"so_mark overlapped": {"egress_guard_proof_mark: 0x20000000\n    so_mark_from_dae: 0x60000000", "so_mark_from_dae"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newConfigWithGlobal(t, tc.global)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New error = %v, want containing %q", err, tc.want)
			}
		})
	}
}
