package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseCLIArgsRequiresManifest(t *testing.T) {
	_, err := ParseCLIArgs(nil)
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("ParseCLIArgs() error = %v, want manifest diagnostic", err)
	}
}

func TestParseCLIArgsReadsOutputsAndStrictMode(t *testing.T) {
	options, err := ParseCLIArgs([]string{
		"-manifest", "manifest.yaml",
		"-cache-dir", "cache",
		"-routes-output", "routes.dae",
		"-mihomo-config", "mihomo.yaml",
		"-groups-output", "groups.dae",
		"-nodes-output", "nodes.dae",
		"-strict",
	})
	if err != nil {
		t.Fatalf("ParseCLIArgs() error = %v", err)
	}
	if options.ManifestPath != "manifest.yaml" || options.CacheDir != "cache" || options.RoutesOutput != "routes.dae" || options.GroupsInputPath != "mihomo.yaml" || options.GroupsOutput != "groups.dae" || options.NodesOutput != "nodes.dae" || !options.Strict {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseCLIArgsReadsNodeResolveDNS(t *testing.T) {
	options, err := ParseCLIArgs([]string{
		"-mihomo-routing-config", "mihomo.yaml",
		"-generation-dir", "/tmp/gen",
		"-node-resolve-dns", "/tmp/overlay.json",
	})
	if err != nil {
		t.Fatalf("ParseCLIArgs() error = %v", err)
	}
	if options.NodeResolveDNSFile != "/tmp/overlay.json" {
		t.Fatalf("NodeResolveDNSFile = %q", options.NodeResolveDNSFile)
	}
}

func TestCLIHelpDocumentsPublicationSemantics(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	cmd := exec.Command("go", "run", ".", "-h")
	cmd.Dir = filepath.Dir(filename)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("go run . -h error = %v; output = %q", err, output.String())
	}

	help := strings.ToLower(output.String())
	hasAtomicGeneration := strings.Contains(help, "generation") && strings.Contains(help, "atomic")
	hasDirectCompatibility := strings.Contains(help, "routes") &&
		strings.Contains(help, "groups") &&
		(strings.Contains(help, "compatib") || strings.Contains(help, "non-atomic"))
	if !hasAtomicGeneration || !hasDirectCompatibility {
		t.Fatalf("CLI help = %q, want atomic generation semantics and compatibility/non-atomic routes/groups direct-output wording", output.String())
	}
}
