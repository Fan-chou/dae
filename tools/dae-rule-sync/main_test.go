package main

import (
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
		"-strict",
	})
	if err != nil {
		t.Fatalf("ParseCLIArgs() error = %v", err)
	}
	if options.ManifestPath != "manifest.yaml" || options.CacheDir != "cache" || options.RoutesOutput != "routes.dae" || options.GroupsInputPath != "mihomo.yaml" || options.GroupsOutput != "groups.dae" || !options.Strict {
		t.Fatalf("options = %#v", options)
	}
}
