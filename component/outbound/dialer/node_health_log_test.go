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

func TestDialerEmitsFirstAbnormalAdmissionChangeAndTracksWithoutListeners(t *testing.T) {
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1. First abnormal transition on a brand-new dialer emits alive -> degraded.
	d1 := newNamedTestDialer(t, "hk-first")
	buf := &bytes.Buffer{}
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	log.SetOutput(buf)
	d1.Log = log

	var events []AdmissionChangeEvent
	unreg := RegisterAdmissionChangeListener(func(ev AdmissionChangeEvent) {
		if ev.Node == "hk-first" {
			events = append(events, ev)
		}
	})
	defer unreg()

	d1.SetFailDegradedForTest(typ, true)
	if len(events) != 1 || events[0].From != "alive" || events[0].To != "degraded" || events[0].Reason != "fail" {
		t.Fatalf("first abnormal listener events = %+v, want single alive->degraded(fail)", events)
	}
	if !strings.Contains(buf.String(), "Node admission") || !strings.Contains(buf.String(), "degraded") {
		t.Fatalf("first abnormal debug log missing: %q", buf.String())
	}
	unreg()

	// 2. Degrading before any listener or debug log is active must still record
	// degraded baseline so recovering after a listener registers emits degraded -> alive.
	d2 := newNamedTestDialer(t, "hk-late")
	d2.Log.SetLevel(logrus.InfoLevel)
	d2.SetFailDegradedForTest(typ, true)

	var recovered []AdmissionChangeEvent
	unreg2 := RegisterAdmissionChangeListener(func(ev AdmissionChangeEvent) {
		if ev.Node == "hk-late" {
			recovered = append(recovered, ev)
		}
	})
	defer unreg2()

	d2.SetDegradedForTest(typ, false)
	if len(recovered) != 1 || recovered[0].From != "degraded" || recovered[0].To != "alive" {
		t.Fatalf("recovery listener events = %+v, want degraded->alive", recovered)
	}
}
