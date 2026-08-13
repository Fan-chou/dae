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
		Refresh:  holder.refresh,
		Reload:   holder.queueReload,
		OnError:  holder.logError,
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

	return ruleprovider.Refresh(ctx, conf, baseDir, http.DefaultClient)
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

func ruleProviderRefreshInterval(conf *config.Config) time.Duration {
	if conf == nil {
		return 0
	}

	var interval time.Duration
	for _, provider := range conf.RuleProvider {
		if provider.Interval > 0 && (interval == 0 || provider.Interval < interval) {
			interval = provider.Interval
		}
	}
	return interval
}
