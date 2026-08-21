package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func ParseCLIArgs(args []string) (SyncOptions, error) {
	return parseCLIArgs(args, io.Discard)
}

func parseCLIArgs(args []string, output io.Writer) (SyncOptions, error) {
	flags := flag.NewFlagSet("dae-rule-sync", flag.ContinueOnError)
	flags.SetOutput(output)
	var options SyncOptions
	flags.StringVar(&options.ManifestPath, "manifest", "", "provider manifest path")
	flags.StringVar(&options.MihomoRoutingPath, "mihomo-routing-config", "", "complete Mihomo routing config path; requires generation-dir")
	flags.StringVar(&options.MihomoRoutingURL, "mihomo-routing-url", "", "fetch a complete Mihomo YAML subscription; requires generation-dir")
	flags.StringVar(&options.MihomoRoutingURLFile, "mihomo-routing-url-file", "", "read the Mihomo YAML subscription URL from a 0600 file (avoids argv leaks)")
	flags.StringVar(&options.CacheDir, "cache-dir", "", "provider cache directory")
	flags.StringVar(&options.RoutesOutput, "routes-output", "", "direct routes output path (compatibility-only; non-atomic complete-state publication)")
	flags.StringVar(&options.GroupsInputPath, "mihomo-config", "", "optional Mihomo config for flat group conversion")
	flags.StringVar(&options.GroupsOutput, "groups-output", "", "direct groups output path (compatibility-only; non-atomic complete-state publication)")
	flags.StringVar(&options.NodesOutput, "nodes-output", "", "direct Mihomo node output path (compatibility-only; use generation-dir with routes)")
	flags.StringVar(&options.GenerationDir, "generation-dir", "", "generation output directory; atomically publishes nodes, routes, groups, DATs, and provider snapshots together")
	flags.StringVar(&options.NodeResolveDNSFile, "node-resolve-dns", "", "JSON overlay mapping original Mihomo node names to resolve_dns IPs")
	flags.BoolVar(&options.Strict, "strict", false, "fail when a rule cannot be converted")
	if err := flags.Parse(args); err != nil {
		return SyncOptions{}, err
	}
	if options.ManifestPath == "" && !options.hasMihomoRoutingSource() {
		return SyncOptions{}, fmt.Errorf("-manifest, -mihomo-routing-config, -mihomo-routing-url, or -mihomo-routing-url-file is required")
	}
	if options.ManifestPath != "" && options.hasMihomoRoutingSource() {
		return SyncOptions{}, fmt.Errorf("-manifest cannot be combined with Mihomo routing sources")
	}
	if options.mihomoRoutingSourceCount() > 1 {
		return SyncOptions{}, fmt.Errorf("use only one Mihomo routing source")
	}
	return options, nil
}

func main() {
	options, err := parseCLIArgs(os.Args[1:], os.Stdout)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	report, err := RunSync(context.Background(), options)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	body, err := report.JSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
