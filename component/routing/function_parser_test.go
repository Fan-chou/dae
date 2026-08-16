package routing

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestL4ProtoParserAcceptsUppercase(t *testing.T) {
	var got consts.L4ProtoType
	parser := L4ProtoParserFactory(func(f *config_parser.Function, l4protoType consts.L4ProtoType, overrideOutbound *Outbound) error {
		got = l4protoType
		return nil
	})
	if err := parser(logrus.New(), &config_parser.Function{Name: "l4proto"}, "", []string{"UDP"}, nil); err != nil {
		t.Fatalf("parser() error = %v", err)
	}
	if got != consts.L4ProtoType_UDP {
		t.Fatalf("l4proto = %v, want UDP", got)
	}
}

func TestL4ProtoParserRejectsUnknownValue(t *testing.T) {
	parser := L4ProtoParserFactory(func(f *config_parser.Function, l4protoType consts.L4ProtoType, overrideOutbound *Outbound) error {
		return nil
	})
	if err := parser(logrus.New(), &config_parser.Function{Name: "l4proto"}, "", []string{"quic"}, nil); err == nil {
		t.Fatal("parser() error = nil, want unknown l4proto")
	}
}
