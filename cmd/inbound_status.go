/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/spf13/cobra"
)

var (
	inboundCmd = &cobra.Command{
		Use:   "inbound",
		Short: "Tools for the user-space inbounds.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	inboundStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Show the inbounds of the running dae.",
		Long: `Asks the running dae (through its admin API, using admin_listen and
admin_secret from the config) which inbounds are defined, where each one comes
from, and whether it is listening, waiting for a reload, or failed to bind.
Prints JSON; passwords are never part of it.`,
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
				os.Exit(1)
			}
			if err := inboundStatus(cmd.Context(), cfgFile, os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(inboundCmd)
	inboundCmd.AddCommand(inboundStatusCmd)
	inboundStatusCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}

// inboundStatus copies GET /v1/inbounds to w.
func inboundStatus(ctx context.Context, cfgPath string, w io.Writer) error {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listen+"/v1/inbounds", nil)
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
	_, err = io.Copy(w, io.LimitReader(resp.Body, 16<<20))
	return err
}
