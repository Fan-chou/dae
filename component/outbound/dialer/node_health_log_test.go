/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

func TestDialerLogsAdmissionChange(t *testing.T) {
	d := newNamedTestDialer(t, "hk-1")
	buf := &bytes.Buffer{}
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	log.SetOutput(buf)
	d.Log = log

	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		d.health.observeProbe(typ.Index(), true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	d.maybeLogAdmission(typ)
	if strings.Contains(buf.String(), "Node admission") {
		t.Fatalf("first observation should not log a change: %s", buf.String())
	}

	d.SetFailDegradedForTest(typ, true)
	got := buf.String()
	if !strings.Contains(got, "Node admission") {
		t.Fatalf("expected admission change log, got %q", got)
	}
	if !strings.Contains(got, "degraded") || !strings.Contains(got, "fail") {
		t.Fatalf("log missing state/reason: %s", got)
	}
	if !strings.Contains(got, "fallback skips") {
		t.Fatalf("log missing selection behavior: %s", got)
	}
}
