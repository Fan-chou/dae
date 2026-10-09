/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/daeuniverse/dae/component/mihomo"
	"github.com/daeuniverse/dae/config"
	"github.com/spf13/cobra"
)

var (
	mihomoCmd = &cobra.Command{
		Use:   "mihomo",
		Short: "Tools for the Mihomo routing source.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	mihomoPreviewCmd = &cobra.Command{
		Use:   "preview",
		Short: "Show what the Mihomo routing source converts to and how it merges with the config.",
		Long: `Reads the config, loads the Mihomo routing source it names (the same way a
reload does, including the last good copy), converts it, and prints the nodes,
groups, rule sets, rules and fallback it adds, what was left out and why, and
the order they take after what the config already defines.

Nothing is applied. Node links and credentials are never printed.`,
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
				os.Exit(1)
			}
			if err := previewMihomo(cmd.Context(), cfgFile, os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(mihomoCmd)
	mihomoCmd.AddCommand(mihomoPreviewCmd)
	mihomoPreviewCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}

// previewMihomo prints the converted source and the merge it would take part
// in. It reads the configuration without expanding rule sets, so it neither
// downloads them nor lists their entries.
func previewMihomo(ctx context.Context, cfgPath string, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	merger := config.NewMerger(cfgPath)
	sections, _, err := merger.Merge()
	if err != nil {
		return err
	}
	conf, err := config.New(sections)
	if err != nil {
		return err
	}
	if !conf.Mihomo.Enabled() {
		fmt.Fprintln(w, "No mihomo routing source is configured (mihomo { routing_subscription / routing_file }).")
		return nil
	}

	baseDir := filepath.Dir(cfgPath)
	result, fetched, err := fetchMihomo(ctx, conf.Mihomo, baseDir, http.DefaultClient)
	if err != nil {
		return errors.New(conf.Mihomo.ScrubSecrets(fmt.Sprintf("load mihomo routing source %s: %v", conf.Mihomo.RedactedSource(), err)))
	}

	fmt.Fprintf(w, "source: %s\n", conf.Mihomo.RedactedSource())
	switch {
	case fetched.UsedLastGood:
		fmt.Fprintln(w, "using: the last good copy (the source could not be read or did not convert just now)")
	case fetched.Changed:
		fmt.Fprintln(w, "using: a newly fetched copy")
	default:
		fmt.Fprintln(w, "using: the cached copy, unchanged")
	}

	fmt.Fprintln(w, "\n== defined in the configuration (kept, and matched first) ==")
	fmt.Fprintf(w, "nodes (%d), groups (%d)\n", len(conf.Node), len(conf.Group))
	fmt.Fprintf(w, "rules (%d, matched first):\n", len(conf.Routing.Rules))
	for i, rule := range conf.Routing.Rules {
		fmt.Fprintf(w, "  %3d. %s\n", i+1, mihomo.DescribeRule(rule))
	}
	if fb, err := config.ParseFunctionOrString(conf.Routing.Fallback); err == nil {
		fmt.Fprintf(w, "fallback: %s\n", fb.Name)
	}

	fmt.Fprintln(w, "\n== added from the Mihomo source (matched after the rules above) ==")
	fmt.Fprint(w, result.Describe())

	fmt.Fprintln(w, "\n== result ==")
	if err := mergeMihomoResult(conf, result); err != nil {
		fmt.Fprintf(w, "cannot merge: %v\n", err)
		return err
	}
	fmt.Fprintf(w, "%d nodes, %d groups, %d rules in this order: the %d above first, then the %d from the Mihomo source\n",
		len(conf.Node), len(conf.Group), len(conf.Routing.Rules), len(conf.Routing.Rules)-len(result.Rules), len(result.Rules))
	if fb, err := config.ParseFunctionOrString(conf.Routing.Fallback); err == nil {
		origin := "from the configuration"
		if result.Fallback != "" {
			origin = "from the Mihomo MATCH, replacing the configured one"
		}
		fmt.Fprintf(w, "fallback: %s (%s)\n", fb.Name, origin)
	}
	return nil
}

var mihomoStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the state of the Mihomo routing source of the running dae.",
	Long: `Asks the running dae (through its admin API, using admin_listen and
admin_secret from the config) when the Mihomo routing source was last read,
whether the last good copy is in use, and why a read failed.`,
	Run: func(cmd *cobra.Command, args []string) {
		if cfgFile == "" {
			fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
			os.Exit(1)
		}
		if err := mihomoStatus(cmd.Context(), cfgFile, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	},
}

func init() {
	mihomoCmd.AddCommand(mihomoStatusCmd)
	mihomoStatusCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}

// mihomoStatus prints the Mihomo part of GET /v1/status as JSON.
func mihomoStatus(ctx context.Context, cfgPath string, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sections, _, err := config.NewMerger(cfgPath).Merge()
	if err != nil {
		return err
	}
	conf, err := config.New(sections)
	if err != nil {
		return err
	}
	listen := conf.Global.AdminListen
	if listen == "" {
		return fmt.Errorf("admin_listen is not set; the status is served by the admin API")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listen+"/v1/status", nil)
	if err != nil {
		return err
	}
	if conf.Global.AdminSecret != "" {
		req.Header.Set("Authorization", "Bearer "+conf.Global.AdminSecret)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("dae is not reachable at %s: %w", listen, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin API answered %s", resp.Status)
	}
	var body struct {
		Generation  string       `json:"generation"`
		SyncWarning string       `json:"sync_warning"`
		Mihomo      MihomoStatus `json:"mihomo"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(body)
}
