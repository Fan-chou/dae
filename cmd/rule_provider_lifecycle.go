/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

type ruleProviderLifecycleHolder struct {
	mu      sync.RWMutex
	conf    *config.Config
	baseDir string

	reloadManager *reloadManager
	log           *logrus.Logger
}

func newRuleProviderLifecycleHolder(conf *config.Config, baseDir string, interval time.Duration, reloadManager *reloadManager, log *logrus.Logger) (*ruleProviderLifecycleHolder, *ruleprovider.RefreshLifecycle, error) {
	if baseDir == "" {
		return nil, nil, errors.New("rule provider refresh requires a config file path")
	}
	if reloadManager == nil {
		return nil, nil, errors.New("rule provider refresh requires a reload manager")
	}

	holder := &ruleProviderLifecycleHolder{
		conf:          conf,
		baseDir:       baseDir,
		reloadManager: reloadManager,
		log:           log,
	}
	lifecycle, err := ruleprovider.NewRefreshLifecycle(ruleprovider.RefreshLifecycleConfig{
		Interval: interval,
		NextInterval: func() time.Duration {
			if CurrentMihomoStatus().Degraded {
				return min(interval, mihomoDegradedRetry)
			}
			return interval
		},
		Refresh: holder.refresh,
		Reload:  holder.queueReload,
		OnError: holder.logError,
	})
	if err != nil {
		return nil, nil, err
	}
	return holder, lifecycle, nil
}

func (h *ruleProviderLifecycleHolder) refresh(ctx context.Context) (ruleprovider.RefreshReport, error) {
	h.mu.RLock()
	conf := h.conf
	baseDir := h.baseDir
	h.mu.RUnlock()

	report, err := ruleprovider.Refresh(ctx, conf, baseDir, http.DefaultClient)
	// The Mihomo source is refreshed on the same schedule; either changing
	// is a reason to reload.
	mihomoReport, mihomoErr := refreshMihomoSource(ctx, conf, baseDir, http.DefaultClient)
	report.Changed = report.Changed || mihomoReport.Changed
	report.UsedLastGood = report.UsedLastGood || mihomoReport.UsedLastGood
	// The dat files are read when routing is built, so a new one needs a reload.
	geodataChanged, geodataErr := syncGeodata(ctx, conf.Geodata, baseDir, http.DefaultClient)
	report.Changed = report.Changed || geodataChanged
	return report, errors.Join(err, mihomoErr, geodataErr)
}

func (h *ruleProviderLifecycleHolder) setConfig(conf *config.Config) {
	h.mu.Lock()
	h.conf = conf
	h.mu.Unlock()
}

func (h *ruleProviderLifecycleHolder) queueReload(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if !h.reloadManager.queueReloadRequest(h.log, reloadRequest{
		isSuspend:       false,
		requestedAt:     time.Now(),
		requestedAtMono: monotonicNowNano(),
	}) {
		return errors.New("rule provider refresh reload request rejected")
	}
	return nil
}

func (h *ruleProviderLifecycleHolder) logError(err error) {
	if err != nil && h.log != nil {
		h.log.WithError(err).Errorln("[RuleProvider] Refresh lifecycle failed")
	}
}

// mihomoDegradedRetry is how soon a Mihomo source that could not be read at
// startup is tried again.
const mihomoDegradedRetry = 2 * time.Minute

func ruleProviderRefreshInterval(conf *config.Config) time.Duration {
	if conf == nil {
		return 0
	}

	var interval time.Duration
	if conf.Mihomo.Enabled() && conf.Mihomo.Interval > 0 {
		interval = conf.Mihomo.Interval
	}
	if conf.Geodata.Enabled() && conf.Geodata.Interval > 0 && (interval == 0 || conf.Geodata.Interval < interval) {
		interval = conf.Geodata.Interval
	}
	for _, provider := range conf.RuleProvider {
		if provider.Interval > 0 && (interval == 0 || provider.Interval < interval) {
			interval = provider.Interval
		}
	}
	if interval == 0 && conf.Mihomo.Enabled() && CurrentMihomoStatus().Degraded {
		// Nothing is scheduled, but the source is missing: keep trying.
		interval = time.Hour
	}
	return interval
}
