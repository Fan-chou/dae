/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestReloadManagerFailReloadAttemptClearsBusyState(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	t.Cleanup(func() { setRunSignalProgress = oldWriter })

	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.reloadActive.Store(true)
	manager.reloadPending.Store(true)

	manager.failReloadAttempt(errors.New("boom"))

	if manager.reloadActive.Load() {
		t.Fatal("expected reloadActive to be cleared")
	}
	if manager.reloadPending.Load() {
		t.Fatal("expected reloadPending to be cleared")
	}
	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadError || content != "boom" {
		t.Fatalf("progress = (%d, %q), want (ReloadError, %q)", code, content, "boom")
	}
}

func TestReloadManagerFailPublishedReloadAttemptClearsHandoffState(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	t.Cleanup(func() { setRunSignalProgress = oldWriter })

	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.reloading.Store(true)
	manager.reloadActive.Store(true)
	manager.reloadPending.Store(true)

	manager.failPublishedReloadAttempt(errors.New("publish failed"))

	if manager.reloading.Load() {
		t.Fatal("expected reloading to be cleared after a published-path failure")
	}
	if manager.reloadActive.Load() {
		t.Fatal("expected reloadActive to be cleared")
	}
	if manager.reloadPending.Load() {
		t.Fatal("expected reloadPending to be cleared")
	}
	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadError || content != "publish failed" {
		t.Fatalf("progress = (%d, %q), want (ReloadError, %q)", code, content, "publish failed")
	}
}
