/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

type fakeIPFilterMatcher struct {
	user      routing.DomainMatcher
	builtin   routing.DomainMatcher
	mode      string
	builtinOn bool
}

func buildFakeIPFilterMatcher(
	log *logrus.Logger,
	locationFinder *assets.LocationFinder,
	fake config.FakeIP,
	nodeHostnames []string,
) (*fakeIPFilterMatcher, error) {
	user, err := compileFakeIPQnameMatcher(log, locationFinder, fake.Filter, true)
	if err != nil {
		return nil, fmt.Errorf("dns.fakeip.filter: %w", err)
	}
	var builtin routing.DomainMatcher
	if fake.FilterBuiltin {
		fns := builtinFakeIPFilterFunctions(nodeHostnames)
		builtin, err = compileFakeIPQnameMatcher(log, locationFinder, fns, false)
		if err != nil {
			return nil, fmt.Errorf("dns.fakeip builtin filter: %w", err)
		}
	} else if log != nil {
		log.Warn("dns.fakeip.filter_builtin is false; LAN/STUN/NTP/node-host skip list is off")
	}
	return &fakeIPFilterMatcher{
		user:      user,
		builtin:   builtin,
		mode:      fake.ResolvedFilterMode(),
		builtinOn: fake.FilterBuiltin,
	}, nil
}

func (m *fakeIPFilterMatcher) Hit(qname string) (skip bool) {
	if m == nil {
		return false
	}
	qname = canonicalizeFakeIPQname(qname)
	qname = strings.TrimSuffix(qname, ".")
	if m.builtin != nil && fakeIPMatcherHit(m.builtin, qname) {
		return true
	}
	userHit := m.user != nil && fakeIPMatcherHit(m.user, qname)
	switch m.mode {
	case config.FakeIPFilterModeOnly:
		return !userHit
	default:
		return userHit
	}
}

func fakeIPMatcherHit(m routing.DomainMatcher, qname string) bool {
	bitmap := m.MatchDomainBitmap(qname)
	for _, word := range bitmap {
		if word != 0 {
			return true
		}
	}
	return false
}

func compileFakeIPQnameMatcher(
	log *logrus.Logger,
	locationFinder *assets.LocationFinder,
	fns []*config_parser.Function,
	strict bool,
) (routing.DomainMatcher, error) {
	if len(fns) == 0 {
		return nil, nil
	}
	rules := make([]*config_parser.RoutingRule, 0, len(fns))
	for _, fn := range fns {
		if fn == nil {
			continue
		}
		if fn.Not && strict {
			return nil, fmt.Errorf("negated qname() is not supported")
		}
		if fn.Name != consts.Function_QName {
			if strict {
				return nil, fmt.Errorf("only qname() is allowed, got %q", fn.Name)
			}
			continue
		}
		rules = append(rules, &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{fn},
			Outbound:     config_parser.Function{Name: "skip"},
		})
	}
	if len(rules) == 0 {
		return nil, nil
	}
	optimizers := []routing.RulesOptimizer{
		&routing.AliasOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	}
	if locationFinder != nil {
		optimizers = []routing.RulesOptimizer{
			&routing.AliasOptimizer{},
			&routing.DatReaderOptimizer{Logger: log, LocationFinder: locationFinder},
			&routing.DeduplicateParamsOptimizer{},
		}
	} else {
		rules = rulesWithoutGeoSite(rules)
		if len(rules) == 0 {
			return nil, nil
		}
	}
	optimized, err := routing.ApplyRulesOptimizers(rules, optimizers...)
	if err != nil {
		if !strict {
			if log != nil {
				log.WithError(err).Warn("dns.fakeip builtin geosite skipped")
			}
			optimized = rulesWithoutGeoSite(rules)
		} else {
			return nil, err
		}
	}
	matcher := domain_matcher.NewAhocorasickSlimtrie(log, 32)
	for _, rule := range optimized {
		for _, fn := range rule.AndFunctions {
			if fn.Name != consts.Function_QName && fn.Name != consts.Function_Domain {
				continue
			}
			byKey := map[consts.RoutingDomainKey][]string{}
			for _, p := range fn.Params {
				key := consts.RoutingDomainKey(p.Key)
				if key == "" {
					key = consts.RoutingDomainKey_Suffix
				}
				switch key {
				case consts.RoutingDomainKey_Full, consts.RoutingDomainKey_Suffix,
					consts.RoutingDomainKey_Keyword, consts.RoutingDomainKey_Regex:
				default:
					if strings.HasPrefix(p.Key, "geosite") {
						continue
					}
					return nil, fmt.Errorf("unsupported qname key %q", p.Key)
				}
				byKey[key] = append(byKey[key], p.Val)
			}
			for key, values := range byKey {
				matcher.AddSet(0, values, key)
			}
		}
	}
	if err := matcher.Build(); err != nil {
		return nil, err
	}
	return matcher, nil
}

func rulesWithoutGeoSite(rules []*config_parser.RoutingRule) []*config_parser.RoutingRule {
	var out []*config_parser.RoutingRule
	for _, rule := range rules {
		cloned := *rule
		var fns []*config_parser.Function
		for _, fn := range rule.AndFunctions {
			keep := false
			var params []*config_parser.Param
			for _, p := range fn.Params {
				if strings.EqualFold(p.Key, "geosite") || strings.HasPrefix(p.Val, "geosite:") {
					continue
				}
				keep = true
				params = append(params, p)
			}
			if keep {
				f := *fn
				f.Params = params
				fns = append(fns, &f)
			}
		}
		if len(fns) == 0 {
			continue
		}
		cloned.AndFunctions = fns
		out = append(out, &cloned)
	}
	return out
}

func builtinFakeIPFilterFunctions(nodeHostnames []string) []*config_parser.Function {
	suffixes := []string{
		"lan", "local", "localhost", "home", "internal", "arpa", "localdomain",
		"time.apple.com", "time.windows.com", "time.google.com", "ntp.org",
		"msftconnecttest.com", "msftncsi.com", "captive.apple.com",
	}
	keywords := []string{"stun"}
	full := []string{
		"localhost.ptlogin2.qq.com",
		"stun.l.google.com",
		"stun.cloudflare.com",
		"turn.cloudflare.com",
	}
	params := make([]*config_parser.Param, 0, len(suffixes)+len(keywords)+len(full)+len(nodeHostnames)+1)
	for _, s := range suffixes {
		params = append(params, &config_parser.Param{Key: string(consts.RoutingDomainKey_Suffix), Val: s})
	}
	for _, s := range keywords {
		params = append(params, &config_parser.Param{Key: string(consts.RoutingDomainKey_Keyword), Val: s})
	}
	for _, s := range full {
		params = append(params, &config_parser.Param{Key: string(consts.RoutingDomainKey_Full), Val: s})
	}
	for _, host := range nodeHostnames {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if host == "" {
			continue
		}
		params = append(params, &config_parser.Param{Key: string(consts.RoutingDomainKey_Full), Val: host})
	}
	params = append(params, &config_parser.Param{Key: "geosite", Val: "private"})
	return []*config_parser.Function{{
		Name:   consts.Function_QName,
		Params: params,
	}}
}

func hostnamesFromNodeList(tagToNodeList map[string][]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, nodes := range tagToNodeList {
		for _, raw := range nodes {
			_, link := common.GetTagFromLinkLikePlaintext(raw)
			host := hostnameFromNodeLink(link)
			if host == "" {
				continue
			}
			host = strings.ToLower(host)
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			out = append(out, host)
		}
	}
	return out
}

func hostnameFromNodeLink(link string) string {
	if link == "" {
		return ""
	}
	u, err := url.Parse(link)
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	// scheme://host may fail if the scheme is unregistered; try after ://
	if i := strings.Index(link, "://"); i >= 0 {
		rest := link[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		if slash := strings.IndexAny(rest, "/?#"); slash >= 0 {
			rest = rest[:slash]
		}
		host, _, _ := strings.Cut(rest, ":")
		return strings.Trim(host, "[]")
	}
	return ""
}
