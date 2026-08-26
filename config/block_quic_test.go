/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestBlockQuicDefaultTrue(t *testing.T) {
	t.Parallel()
	sections, err := config_parser.Parse(`
global {}
routing {
  fallback: direct
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if !conf.Global.BlockQuic {
		t.Fatal("block_quic default = false, want true")
	}
}

func TestBlockQuicExplicitFalse(t *testing.T) {
	t.Parallel()
	sections, err := config_parser.Parse(`
global {
  block_quic: false
}
routing {
  fallback: direct
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Global.BlockQuic {
		t.Fatal("block_quic = true, want explicit false")
	}
}
