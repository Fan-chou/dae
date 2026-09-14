package control

import (
	"errors"
	"io"
	"testing"
)

type lookupTestLink struct{ closed int }

func (l *lookupTestLink) Close() error { l.closed++; return nil }

func TestTCPListenerLookupReloadOwnership(t *testing.T) {
	bpf := &bpfObjects{}
	l := &lookupTestLink{}
	attaches := 0
	attach := func() (io.Closer, error) { attaches++; return l, nil }
	for i := 0; i < 2; i++ {
		if err := acquireTCPListenerLookup(bpf, attach); err != nil {
			t.Fatal(err)
		}
	}
	if attaches != 1 {
		t.Fatalf("reload attached %d hooks", attaches)
	}
	if err := releaseTCPListenerLookup(bpf); err != nil {
		t.Fatal(err)
	}
	if l.closed != 0 {
		t.Fatal("retiring plane detached successor's hook")
	}
	if err := releaseTCPListenerLookup(bpf); err != nil {
		t.Fatal(err)
	}
	if l.closed != 1 {
		t.Fatalf("last plane closed hook %d times", l.closed)
	}
	if err := releaseTCPListenerLookup(bpf); err != nil {
		t.Fatal(err)
	}
	if l.closed != 1 {
		t.Fatal("duplicate cleanup closed hook again")
	}

	want := errors.New("attach failed")
	if err := acquireTCPListenerLookup(bpf, func() (io.Closer, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatalf("attach failure: %v", err)
	}
	if err := acquireTCPListenerLookup(bpf, attach); err != nil {
		t.Fatal(err)
	}
	if attaches != 2 {
		t.Fatal("failed attach prevented retry")
	}
	if err := releaseTCPListenerLookup(bpf); err != nil {
		t.Fatal(err)
	}
}
