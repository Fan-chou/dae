/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"

	"github.com/spf13/cobra"
)

var (
	validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "To validate dae config.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
				os.Exit(1)
			}
			// Read config from --config cfgFile.
			conf, _, err := readConfig(cfgFile)
			if err == nil {
				err = validateFixedDomainTtl(conf)
			}
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}

func validateFixedDomainTtl(conf *config.Config) error {
	if conf == nil {
		return fmt.Errorf("nil config")
	}
	if _, err := control.ParseFixedDomainTtl(conf.Dns.FixedDomainTtl); err != nil {
		return fmt.Errorf("invalid fixed_domain_ttl: %w", err)
	}
	return nil
}
