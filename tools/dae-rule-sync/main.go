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
	flags.StringVar(&options.CacheDir, "cache-dir", "", "provider cache directory")
	flags.StringVar(&options.RoutesOutput, "routes-output", "", "direct routes output path (compatibility mode; non-atomic publication)")
	flags.StringVar(&options.GroupsInputPath, "mihomo-config", "", "optional Mihomo config for flat group conversion")
	flags.StringVar(&options.GroupsOutput, "groups-output", "", "direct groups output path (compatibility mode; non-atomic publication)")
	flags.StringVar(&options.NodesOutput, "nodes-output", "", "direct Mihomo node output path (compatibility mode; non-atomic publication)")
	flags.StringVar(&options.GenerationDir, "generation-dir", "", "generation output directory; atomically publishes nodes, routes, groups, DATs, and provider snapshots together")
	flags.BoolVar(&options.Strict, "strict", false, "fail when a rule cannot be converted")
	if err := flags.Parse(args); err != nil {
		return SyncOptions{}, err
	}
	if options.ManifestPath == "" {
		return SyncOptions{}, fmt.Errorf("-manifest is required")
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
