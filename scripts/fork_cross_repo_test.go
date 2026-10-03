/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestForkHarnessUsesEffectiveModuleGraph(t *testing.T) {
	output, err := runForkHarness(t, "printf '%s\\n' \"$FORK_TEST_MODULE_GRAPH\"")
	if err != nil {
		t.Fatalf("dry run failed: %v\n%s", err, output)
	}
	for _, target := range []string{
		"github.com/olicesx/outbound @ 324aa7fd9b7d",
		"github.com/olicesx/quic-go @ fbf90cb0a47d",
		"github.com/olicesx/qpack @ 0844ed36f1cd",
	} {
		if !strings.Contains(output, target) {
			t.Errorf("missing effective fork %q in output:\n%s", target, output)
		}
	}
	if strings.Count(output, "DRY-RUN:") != 3 {
		t.Errorf("expected exactly three owned forks:\n%s", output)
	}
	if !strings.Contains(output, "go test -short -race -p=1 ./...") {
		t.Errorf("forwarded test arguments were lost:\n%s", output)
	}
}

func TestForkHarnessRejectsUnsupportedOwnedVersion(t *testing.T) {
	output, err := runForkHarness(t, `printf '%s\n' 'github.com/daeuniverse/outbound github.com/olicesx/outbound v0.0.0-sticky-ip.0.20260904160206-324aa7fd9b7d' 'github.com/olicesx/qpack github.com/olicesx/qpack v1.0.0'`)
	if err == nil {
		t.Fatalf("unsupported owned fork was silently omitted:\n%s", output)
	}
	if strings.Contains(output, "DRY-RUN:") {
		t.Fatalf("tested a partial owned fork graph:\n%s", output)
	}
}

func TestForkHarnessRejectsModuleGraphFailure(t *testing.T) {
	output, err := runForkHarness(t, "exit 23")
	if err == nil {
		t.Fatalf("module graph failure was reported as success:\n%s", output)
	}
	if strings.Contains(output, "DRY-RUN:") {
		t.Fatalf("tested an incomplete module graph:\n%s", output)
	}
}

func TestForkHarnessFollowsReplacementRepositories(t *testing.T) {
	output, err := runForkHarness(t, `printf '%s\n' 'github.com/daeuniverse/outbound github.com/Fan-chou/outbound v0.0.0-sticky-ip.0.20260916163737-8a6bd0300c3f' 'github.com/olicesx/quic-go github.com/Fan-chou/quic-go v0.0.0-20260916162732-e64dc7a1252e' 'github.com/olicesx/qpack github.com/another-mirror/header-codec v0.0.0-20260831031549-0844ed36f1cd'`)
	if err != nil {
		t.Fatalf("replacement graph failed: %v\n%s", err, output)
	}
	for _, target := range []string{"github.com/Fan-chou/outbound @ 8a6bd0300c3f", "github.com/Fan-chou/quic-go @ e64dc7a1252e", "github.com/another-mirror/header-codec @ 0844ed36f1cd"} {
		if !strings.Contains(output, target) {
			t.Errorf("missing %q: %s", target, output)
		}
	}
	if strings.Count(output, "DRY-RUN:") != 3 {
		t.Fatalf("partial graph tested: %s", output)
	}
}

func TestForkHarnessRejectsMissingOrDuplicateModules(t *testing.T) {
	for _, graph := range []string{
		"github.com/olicesx/qpack github.com/olicesx/qpack v0.0.0-20260831031549-0844ed36f1cd",
		"github.com/daeuniverse/outbound github.com/Fan-chou/outbound v0.0.0-20260916163737-8a6bd0300c3f\ngithub.com/daeuniverse/outbound github.com/olicesx/outbound v0.0.0-20260916163737-8a6bd0300c3f\ngithub.com/olicesx/quic-go github.com/Fan-chou/quic-go v0.0.0-20260916162732-e64dc7a1252e\ngithub.com/olicesx/qpack github.com/olicesx/qpack v0.0.0-20260831031549-0844ed36f1cd",
	} {
		t.Run(graph, func(t *testing.T) {
			output, err := runForkHarness(t, `printf '%s\n' `+"'"+graph+"'")
			if err == nil || strings.Contains(output, "DRY-RUN:") {
				t.Fatalf("incomplete/duplicate graph accepted: %v\n%s", err, output)
			}
		})
	}
}

func runForkHarness(t *testing.T, goBody string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cmd := exec.Command("git", "init", "-q", root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
	mod := `module example.com/test

go 1.26.0

require github.com/olicesx/qpack v0.0.0-20260831031549-0844ed36f1cd

replace (
 github.com/daeuniverse/outbound => github.com/olicesx/outbound v0.0.0-sticky-ip.0.20260904160206-324aa7fd9b7d
 github.com/olicesx/quic-go => github.com/olicesx/quic-go v0.0.0-20260831031827-fbf90cb0a47d
)
`
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(mod), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/usr/bin/env bash\n"+goBody+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	graph := "github.com/daeuniverse/outbound github.com/olicesx/outbound v0.0.0-sticky-ip.0.20260904160206-324aa7fd9b7d\n" +
		"github.com/olicesx/quic-go github.com/olicesx/quic-go v0.0.0-20260831031827-fbf90cb0a47d\n" +
		"github.com/olicesx/qpack github.com/olicesx/qpack v0.0.0-20260831031549-0844ed36f1cd\n" +
		"github.com/other/unrelated github.com/other/unrelated v0.0.0-20260831031549-0844ed36f1cd"
	cmd = exec.Command("bash", filepath.Join(wd, "fork-cross-repo-test.sh"), "--dry-run", "--clone-missing", "--short", "--strict", "--", "-race", "-p=1")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "FORK_TEST_MODULE_GRAPH="+graph)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
