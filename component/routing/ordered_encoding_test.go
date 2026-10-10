package routing

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func bigOrderedExpr(n int) *OrderedExpr {
	root := &OrderedExpr{Op: "or"}
	for i := 0; i < n; i++ {
		root.Children = append(root.Children, &OrderedExpr{
			Op: "atom",
			Atom: &config_parser.Function{
				Name:   "domain",
				Params: []*config_parser.Param{{Key: "suffix", Val: fmt.Sprintf("host-%d.example.com", i)}},
			},
		})
	}
	return root
}

func TestOrderedExprRoundTripCompressed(t *testing.T) {
	want := bigOrderedExpr(5000)
	f, err := EncodeOrderedExpr(want)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != "route_expr" || len(f.Params) != 1 {
		t.Fatalf("unexpected function %+v", f)
	}
	got, err := DecodeOrderedExpr(f)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("round trip changed the expression")
	}
}

func TestOrderedExprEncodingIsCompact(t *testing.T) {
	e := bigOrderedExpr(5000)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	f, err := EncodeOrderedExpr(e)
	if err != nil {
		t.Fatal(err)
	}
	legacy := base64.RawURLEncoding.EncodedLen(len(raw))
	if got := len(f.Params[0].Val); got*3 > legacy {
		t.Fatalf("encoded size %d is not at least 3x smaller than the plain form %d", got, legacy)
	}
}

func TestOrderedExprDecodesLegacyPlainForm(t *testing.T) {
	want := bigOrderedExpr(3)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	f := &config_parser.Function{Name: "route_expr", Params: []*config_parser.Param{{Val: base64.RawURLEncoding.EncodeToString(raw)}}}
	got, err := DecodeOrderedExpr(f)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("legacy plain form decoded differently")
	}
}

func TestOrderedExprSmallStaysPlain(t *testing.T) {
	f, err := EncodeOrderedExpr(&OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: "l4proto", Params: []*config_parser.Param{{Val: "tcp"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Params[0].Val, ".") {
		t.Fatalf("a small expression should not be compressed: %q", f.Params[0].Val)
	}
}

func TestOrderedExprRejectsCorruptCompressed(t *testing.T) {
	for _, val := range []string{"z.", "z.!!!!", "z." + base64.RawURLEncoding.EncodeToString([]byte("not zlib"))} {
		f := &config_parser.Function{Name: "route_expr", Params: []*config_parser.Param{{Val: val}}}
		if _, err := DecodeOrderedExpr(f); err == nil {
			t.Fatalf("%q decoded without error", val)
		}
	}
}
