package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
)

func ParseCLIArgs(args []string) (SyncOptions, error) {
	flags := flag.NewFlagSet("dae-rule-sync", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options SyncOptions
	flags.StringVar(&options.ManifestPath, "manifest", "", "provider manifest path")
	flags.StringVar(&options.CacheDir, "cache-dir", "", "provider cache directory")
	flags.StringVar(&options.RoutesOutput, "routes-output", "", "generated dae routes path")
	flags.StringVar(&options.GroupsInputPath, "mihomo-config", "", "optional Mihomo config for flat group conversion")
	flags.StringVar(&options.GroupsOutput, "groups-output", "", "generated dae groups path")
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
	options, err := ParseCLIArgs(os.Args[1:])
	if err != nil {
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
