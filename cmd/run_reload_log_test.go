/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestApplyReloadLogLevelKeepsLoggerIdentity(t *testing.T) {
	log := logrus.New()
	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	log.SetLevel(logrus.InfoLevel)

	std := logrus.StandardLogger()
	oldLevel := std.GetLevel()
	oldOut := std.Out
	t.Cleanup(func() {
		std.SetLevel(oldLevel)
		std.SetOutput(oldOut)
	})

	captured := log
	applyReloadLogLevel(log, "debug", true)
	if log != captured {
		t.Fatal("expected reload to reuse the original logger pointer")
	}
	if log.GetLevel() != logrus.DebugLevel {
		t.Fatalf("logger level = %v, want debug", log.GetLevel())
	}
	if log.Out != buf {
		t.Fatal("expected logger output to be preserved")
	}
	if std.GetLevel() != logrus.DebugLevel {
		t.Fatalf("standard logger level = %v, want debug", std.GetLevel())
	}
}

func TestApplyReloadLogLevelNilLogger(t *testing.T) {
	applyReloadLogLevel(nil, "debug", false)
}

func TestApplyReloadLogLevelSyncsStandardOutput(t *testing.T) {
	log := logrus.New()
	buf := &bytes.Buffer{}
	log.SetOutput(buf)

	std := logrus.StandardLogger()
	oldOut := std.Out
	t.Cleanup(func() { std.SetOutput(oldOut) })

	applyReloadLogLevel(log, "warn", false)
	if std.Out != log.Out {
		t.Fatal("expected standard logger output to follow the process logger")
	}
}
