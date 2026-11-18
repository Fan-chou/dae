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
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// RuleProviderStatus describes the last attempt to load or refresh native rule providers.
type RuleProviderStatus struct {
	CheckedAt    time.Time `json:"checked_at,omitempty"`
	UsedLastGood bool      `json:"used_last_good,omitempty"`
	Degraded     bool      `json:"degraded,omitempty"`
	Error        string    `json:"error,omitempty"`
}

var ruleProviderState struct {
	mu     sync.RWMutex
	status RuleProviderStatus
}

func setRuleProviderStatus(status RuleProviderStatus) {
	ruleProviderState.mu.Lock()
	ruleProviderState.status = status
	ruleProviderState.mu.Unlock()
}

// CurrentRuleProviderStatus returns the status of the last rule provider load or refresh.
func CurrentRuleProviderStatus() RuleProviderStatus {
	ruleProviderState.mu.RLock()
	defer ruleProviderState.mu.RUnlock()
	return ruleProviderState.status
}

type ruleProviderLifecycleHolder struct {
	mu      sync.RWMutex
	conf    *config.Config
	baseDir string

	reloadManager     *reloadManager
	log               *logrus.Logger
	lastRefreshFailed atomic.Bool
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
			if CurrentMihomoStatus().Degraded || CurrentRuleProviderStatus().Degraded || holder.lastRefreshFailed.Load() {
				return min(interval, mihomoDegradedRetry)
			}
			return interval
		},
		InitialWait: holder.initialWait(interval),
		Refresh:     holder.refresh,
		Reload:      holder.queueReload,
		OnError:     holder.logError,
	})
	if err != nil {
		return nil, nil, err
	}
	return holder, lifecycle, nil
}

// initialWait is how long after a start the first refresh is due. A start that
// fetched everything gets a whole interval, as before. One that reused cached
// copies still within their interval gets what is left of it, so the data is
// never older than one interval plus a refresh round, however often dae
// restarts. It never waits less than initialRefreshFloor, and a degraded
// Mihomo source keeps its own faster retry.
func (h *ruleProviderLifecycleHolder) initialWait(interval time.Duration) func() time.Duration {
	return func() time.Duration {
		if interval <= 0 || CurrentMihomoStatus().Degraded {
			return 0
		}
		if rpStatus := CurrentRuleProviderStatus(); rpStatus.Degraded || rpStatus.UsedLastGood {
			return min(initialRefreshFloor, interval)
		}
		h.mu.RLock()
		conf, baseDir := h.conf, h.baseDir
		h.mu.RUnlock()
		if conf.Geodata.Enabled() && conf.Geodata.Interval > 0 && !geodataFresh(conf.Geodata, baseDir) {
			return min(initialRefreshFloor, interval)
		}
		var documents []config.RuleProvider
		if conf.Mihomo.Enabled() && conf.Mihomo.RoutingSubscription != "" {
			spec := mihomoDocumentSpec(conf.Mihomo)
			spec.Interval = conf.Mihomo.Interval
			documents = append(documents, spec)
		}
		if conf.Geodata.Enabled() {
			for name, url := range map[string]string{"geodata-geoip": conf.Geodata.GeoIP, "geodata-geosite": conf.Geodata.GeoSite} {
				if url != "" {
					documents = append(documents, config.RuleProvider{
						Name:     name,
						Type:     "http",
						URL:      url,
						MaxSize:  conf.Geodata.MaxSize,
						Interval: conf.Geodata.Interval,
					})
				}
			}
		}
		oldest, ok := ruleprovider.OldestCheck(conf.RuleProvider, documents, baseDir)
		if !ok {
			return 0
		}
		return min(max(interval-time.Since(oldest), initialRefreshFloor), interval)
	}
}

// initialRefreshFloor keeps a start that reused almost-due copies from
// refreshing the moment dae comes up.
const initialRefreshFloor = 30 * time.Second

func (h *ruleProviderLifecycleHolder) refresh(ctx context.Context) (ruleprovider.RefreshReport, error) {
	h.mu.RLock()
	conf := h.conf
	baseDir := h.baseDir
	h.mu.RUnlock()

	wasDegraded := CurrentRuleProviderStatus().Degraded
	report, loadReport, err := ruleprovider.RefreshWithReport(ctx, conf, baseDir, http.DefaultClient)
	rpStatus := RuleProviderStatus{
		CheckedAt:    time.Now(),
		UsedLastGood: report.UsedLastGood || loadReport.UsedLastGood,
	}
	if err != nil {
		rpStatus.Degraded = wasDegraded
		rpStatus.Error = err.Error()
		setRuleProviderStatus(rpStatus)
	} else {
		if rpStatus.UsedLastGood && wasDegraded {
			rpStatus.Degraded = true
		}
		if loadReport.Warning != nil {
			rpStatus.Error = loadReport.Warning.Error()
			if h.log != nil {
				h.log.WithError(loadReport.Warning).Warnln("[RuleProvider] Refresh used last-good cache for some rule providers")
			}
		}
		setRuleProviderStatus(rpStatus)
		if wasDegraded && !rpStatus.UsedLastGood {
			report.Changed = true
		}
	}
	// The Mihomo source is refreshed on the same schedule; either changing
	// is a reason to reload.
	mihomoReport, mihomoErr := refreshMihomoSource(ctx, conf, baseDir, http.DefaultClient)
	report.Changed = report.Changed || mihomoReport.Changed
	report.UsedLastGood = report.UsedLastGood || mihomoReport.UsedLastGood
	// The dat files are read when routing is built, so a new one needs a reload.
	geodataChanged, geodataErr := syncGeodata(ctx, conf.Geodata, baseDir, http.DefaultClient)
	report.Changed = report.Changed || geodataChanged

	h.lastRefreshFailed.Store(err != nil || mihomoErr != nil || geodataErr != nil || rpStatus.UsedLastGood || mihomoReport.UsedLastGood)
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
		fromRefresh:     true,
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
	if interval == 0 && ((conf.Mihomo.Enabled() && CurrentMihomoStatus().Degraded) ||
		(len(conf.RuleProvider) > 0 && (CurrentRuleProviderStatus().Degraded || CurrentRuleProviderStatus().UsedLastGood))) {
		// Nothing is scheduled, but the source is missing or degraded: keep trying.
		interval = time.Hour
	}
	return interval
}
