/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/mihomo"
	_ "github.com/daeuniverse/dae/component/outbound"
	outbounddialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// mihomoDocumentName names the cache entry of the Mihomo routing document. It
// shares the rule provider cache, so a rule provider may not use it.
const mihomoDocumentName = "mihomo-routing"

// MihomoStatus describes the last attempt to load the Mihomo routing source.
// It carries no credentials: the source is shown without its query string.
type MihomoStatus struct {
	Enabled bool   `json:"enabled"`
	Source  string `json:"source,omitempty"`
	// CheckedAt is when the source was last read or refreshed.
	CheckedAt time.Time `json:"checked_at,omitempty"`
	// UsedLastGood is set when the source could not be read or was rejected
	// and the previous valid copy was used instead.
	UsedLastGood bool `json:"used_last_good"`
	// Error is the reason the last attempt failed; empty on success.
	Error     string `json:"error,omitempty"`
	Nodes     int    `json:"nodes"`
	Groups    int    `json:"groups"`
	Rules     int    `json:"rules"`
	Providers int    `json:"providers"`
	// Degraded is set when the source could not be read and there was no
	// earlier copy, so dae started without the routing the source provides.
	// It retries soon instead of waiting for the next interval.
	Degraded        bool              `json:"degraded,omitempty"`
	SkippedRules    []mihomoEventInfo `json:"skipped_rules,omitempty"`
	UnusedProviders []string          `json:"unused_providers,omitempty"`
	IgnoredFields   []string          `json:"ignored_fields,omitempty"`
}

type mihomoEventInfo struct {
	Kind   string `json:"kind"`
	Index  int    `json:"index"`
	Line   int    `json:"line"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

var mihomoState struct {
	mu     sync.RWMutex
	status MihomoStatus
}

func setMihomoStatus(status MihomoStatus) {
	mihomoState.mu.Lock()
	mihomoState.status = status
	mihomoState.mu.Unlock()
}

// CurrentMihomoStatus returns the status of the last load or refresh.
func CurrentMihomoStatus() MihomoStatus {
	mihomoState.mu.RLock()
	defer mihomoState.mu.RUnlock()
	return mihomoState.status
}

// validateNodeLink checks that dae can build a dialer from a node link, the
// same way the control plane does when it loads nodes.
func validateNodeLink(link string) error {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	option := &outbounddialer.GlobalOption{
		ExtraOption: D.ExtraOption{TlsImplementation: "tls", UtlsImitate: "chrome_auto"},
		Log:         logger,
	}
	d, err := outbounddialer.NewFromLinkContext(context.Background(), option, outbounddialer.InstanceOption{DisableCheck: true}, link, "")
	if err != nil {
		return err
	}
	if d == nil {
		return nil
	}
	return d.Close()
}

func mihomoDocumentSpec(m config.Mihomo) config.RuleProvider {
	spec := config.RuleProvider{Name: mihomoDocumentName, MaxSize: m.MaxSize}
	if m.RoutingSubscription != "" {
		spec.Type, spec.URL = "http", m.RoutingSubscription
	} else {
		spec.Type, spec.Path = "file", m.RoutingFile
	}
	return spec
}

func mihomoOptions(m config.Mihomo, baseDir string) mihomo.Options {
	return mihomo.Options{
		BaseDir:                baseDir,
		Validate:               validateNodeLink,
		ResolveDNS:             m.ResolveDNSMap(),
		IsolateTransportGroups: m.IsolateTransportGroups,
	}
}

// convertMihomoBody parses and converts a document. A body that converts is
// the only kind that may become the last-good copy.
func convertMihomoBody(body []byte, opts mihomo.Options) (*mihomo.Result, error) {
	doc, err := mihomo.Parse(body)
	if err != nil {
		return nil, err
	}
	return mihomo.Convert(doc, opts)
}

// fetchMihomo reads the source through the verified cache and converts it. The
// returned report says whether the copy changed or was the previous valid one.
func fetchMihomo(ctx context.Context, m config.Mihomo, baseDir string, client *http.Client) (*mihomo.Result, ruleprovider.Document, error) {
	opts := mihomoOptions(m, baseDir)
	var (
		lastSum    [sha256.Size]byte
		lastResult *mihomo.Result
	)
	validate := func(body []byte) error {
		result, err := convertMihomoBody(body, opts)
		if err != nil {
			return err
		}
		lastSum, lastResult = sha256.Sum256(body), result
		return nil
	}
	fetched, err := ruleprovider.FetchDocument(ctx, mihomoDocumentSpec(m), baseDir, client, validate)
	if err != nil {
		return nil, ruleprovider.Document{}, err
	}
	if lastResult != nil && sha256.Sum256(fetched.Body) == lastSum {
		return lastResult, fetched, nil
	}
	// The copy in use is an older valid one; convert it again.
	result, err := convertMihomoBody(fetched.Body, opts)
	if err != nil {
		return nil, ruleprovider.Document{}, err
	}
	return result, fetched, nil
}

// applyMihomoSource loads the configured Mihomo routing source and merges it
// into conf: its nodes, groups, rule providers and rules are added after the
// ones written in the configuration, so rules written by hand keep priority,
// and its MATCH becomes the fallback. Nothing is merged unless the whole
// source converts.
//
// With startup set, a remote source that cannot be read and has no earlier copy
// does not stop dae from starting: a router that boots before its uplink is up
// would otherwise lose all connectivity. dae then runs with what the
// configuration itself defines, says so in the status, and retries shortly.
// A reload never does this, so a mistyped URL cannot replace working routing.
func applyMihomoSource(ctx context.Context, conf *config.Config, baseDir string, client *http.Client, startup bool) (*mihomoMerge, error) {
	m := conf.Mihomo
	if !m.Enabled() {
		setMihomoStatus(MihomoStatus{})
		return nil, nil
	}
	status := MihomoStatus{Enabled: true, Source: m.RedactedSource(), CheckedAt: time.Now()}
	fail := func(err error) (*mihomoMerge, error) {
		status.Error = m.ScrubSecrets(err.Error())
		setMihomoStatus(status)
		return nil, errors.New(m.ScrubSecrets(fmt.Sprintf("load mihomo routing source %s: %v", status.Source, err)))
	}
	for _, p := range conf.RuleProvider {
		if p.Name == mihomoDocumentName {
			return fail(fmt.Errorf("rule provider name %q is reserved", mihomoDocumentName))
		}
	}

	result, fetched, err := fetchMihomo(ctx, m, baseDir, client)
	if err != nil {
		if startup && m.RoutingSubscription != "" {
			status.Error = m.ScrubSecrets(err.Error())
			status.Degraded = true
			setMihomoStatus(status)
			logrus.WithField("error", status.Error).Warnf("[Mihomo] routing source %s is unavailable and has no earlier copy; starting without it and retrying", status.Source)
			return nil, nil
		}
		return fail(err)
	}
	status.UsedLastGood = fetched.UsedLastGood
	merge := &mihomoMerge{
		Result:        result,
		nodeStart:     len(conf.Node),
		groupStart:    len(conf.Group),
		providerStart: len(conf.RuleProvider),
		ruleStart:     len(conf.Routing.Rules),
	}
	if err := mergeMihomoResult(conf, result); err != nil {
		return fail(err)
	}
	fillMihomoStatus(&status, result)
	setMihomoStatus(status)
	return merge, nil
}

// mihomoMerge records where the converted source starts in each list of the
// merged configuration, so a view can say what came from where.
type mihomoMerge struct {
	Result        *mihomo.Result
	nodeStart     int
	groupStart    int
	providerStart int
	ruleStart     int
}

func fillMihomoStatus(status *MihomoStatus, result *mihomo.Result) {
	status.Nodes, status.Groups = len(result.Nodes), len(result.Groups)
	status.Rules, status.Providers = len(result.Rules), len(result.Providers)
	status.UnusedProviders = result.Report.UnusedProviders
	status.IgnoredFields = result.Report.IgnoredFields
	for _, e := range result.Report.Events {
		status.SkippedRules = append(status.SkippedRules, mihomoEventInfo{
			Kind: string(e.Kind), Index: e.Index, Line: e.Line, Rule: e.Raw, Reason: e.Reason,
		})
	}
}

// refreshMihomoSource re-reads the source and reports whether it changed. It
// does not touch conf: a changed source takes effect through a reload, which
// runs applyMihomoSource again.
func refreshMihomoSource(ctx context.Context, conf *config.Config, baseDir string, client *http.Client) (ruleprovider.RefreshReport, error) {
	m := conf.Mihomo
	if !m.Enabled() {
		return ruleprovider.RefreshReport{}, nil
	}
	status := CurrentMihomoStatus()
	status.CheckedAt = time.Now()
	result, fetched, err := fetchMihomo(ctx, m, baseDir, client)
	if err != nil {
		status.Error = m.ScrubSecrets(err.Error())
		setMihomoStatus(status)
		return ruleprovider.RefreshReport{}, errors.New(status.Error)
	}
	status.Error, status.UsedLastGood, status.Degraded = "", fetched.UsedLastGood, false
	status.Enabled, status.Source = true, m.RedactedSource()
	status.SkippedRules = nil
	fillMihomoStatus(&status, result)
	setMihomoStatus(status)
	return ruleprovider.RefreshReport{Changed: fetched.Changed, UsedLastGood: fetched.UsedLastGood}, nil
}

// mergeMihomoResult appends a converted source to conf. Names must not clash
// with what the configuration already defines: a silent override would send
// traffic somewhere nobody asked for.
func mergeMihomoResult(conf *config.Config, result *mihomo.Result) error {
	groupNames := make(map[string]struct{}, len(conf.Group))
	for _, g := range conf.Group {
		groupNames[g.Name] = struct{}{}
	}
	for _, g := range result.Groups {
		if _, clash := groupNames[g.Safe]; clash {
			return fmt.Errorf("group %q from the Mihomo source clashes with a group defined in the configuration", g.Safe)
		}
	}
	nodeTags := make(map[string]struct{}, len(conf.Node))
	for _, n := range conf.Node {
		if tag, _, ok := strings.Cut(string(n), ":"); ok {
			nodeTags[tag] = struct{}{}
		}
	}
	for _, n := range result.Nodes {
		if _, clash := nodeTags[n.Safe]; clash {
			return fmt.Errorf("node %q from the Mihomo source clashes with a node defined in the configuration", n.Safe)
		}
	}
	providerNames := make(map[string]struct{}, len(conf.RuleProvider))
	for _, p := range conf.RuleProvider {
		providerNames[p.Name] = struct{}{}
	}
	for _, p := range result.Providers {
		if _, clash := providerNames[p.Name]; clash {
			return fmt.Errorf("rule provider %q from the Mihomo source clashes with one defined in the configuration", p.Name)
		}
	}

	for _, n := range result.Nodes {
		conf.Node = append(conf.Node, config.KeyableString(n.Safe+":"+n.Link))
	}
	for _, g := range result.Groups {
		conf.Group = append(conf.Group, g.Config)
	}
	conf.RuleProvider = append(conf.RuleProvider, result.Providers...)
	conf.Routing.Rules = append(conf.Routing.Rules, result.Rules...)
	if result.Fallback != "" {
		conf.Routing.Fallback = result.Fallback
	}
	return nil
}

// mihomoWarning says why the Mihomo routing source is not current, or "" when
// it is, or is not in use.
func mihomoWarning(status MihomoStatus) string {
	switch {
	case !status.Enabled:
		return ""
	case status.Degraded:
		return "Mihomo routing source is unavailable and has no earlier copy; running without it: " + status.Error
	case status.Error != "" && status.UsedLastGood:
		return "Mihomo routing source failed, using the last good copy: " + status.Error
	case status.Error != "":
		return "Mihomo routing source failed: " + status.Error
	case status.UsedLastGood:
		return "Mihomo routing source unchanged: using the last good copy"
	}
	return ""
}
