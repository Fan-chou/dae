/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/dlclark/regexp2"
	"github.com/sirupsen/logrus"
)

var regexpCache sync.Map

const (
	FilterInput_Name            = "name"
	FilterInput_SubscriptionTag = "subtag"
	FilterInput_Link            = "link"
	// FilterInput_Group is a control-plane-only exact reference to another
	// outbound group. It is deliberately not a node filter: accepting it in
	// filterHit would silently turn a miss into an empty node set.
	FilterInput_Group = "group"
)

const (
	FilterKey_Name_Regex   = "regex"
	FilterKey_Name_Keyword = "keyword"

	FilterInput_SubscriptionTag_Regex = "regex"
)

type DialerSet struct {
	log          *logrus.Logger
	dialers      []*dialer.Dialer
	nodeToTagMap map[*dialer.Dialer]string
}

// GroupMemberReference records one exact nested-group member. Group references
// are intentionally restricted to a standalone group(name) filter with no
// annotation. Anything more expressive would be ambiguous: it is unclear
// whether an AND/NOT/regex should apply to the group identity, its direct
// members, or the child group's final selection.
type GroupMemberReference struct {
	FilterIndex int
	Name        string
}

// ExactGroupMemberReferences separates the small, unambiguous nested-group
// syntax from ordinary node filters. Callers must remove those filter clauses
// before using FilterAndAnnotate.
func ExactGroupMemberReferences(filters [][]*config_parser.Function, annotations [][]*config_parser.Param) ([]GroupMemberReference, error) {
	if len(filters) != len(annotations) {
		return nil, fmt.Errorf("[CODE BUG]: unmatched annotations length: %v filters and %v annotations", len(filters), len(annotations))
	}
	var refs []GroupMemberReference
	for i, clause := range filters {
		containsGroup := false
		for _, filter := range clause {
			if filter != nil && filter.Name == FilterInput_Group {
				containsGroup = true
				break
			}
		}
		if !containsGroup {
			continue
		}
		if len(clause) != 1 || clause[0] == nil || clause[0].Name != FilterInput_Group || clause[0].Not || len(clause[0].Params) != 1 || clause[0].Params[0] == nil || clause[0].Params[0].Key != "" || clause[0].Params[0].Val == "" || len(annotations[i]) != 0 {
			return nil, fmt.Errorf("nested group filter at index %d must be an unannotated exact group(name) reference", i)
		}
		refs = append(refs, GroupMemberReference{FilterIndex: i, Name: clause[0].Params[0].Val})
	}
	return refs, nil
}

// AllDialers returns a snapshot of every dialer owned by the set.
func (s *DialerSet) AllDialers() []*dialer.Dialer {
	if s == nil {
		return nil
	}
	return append([]*dialer.Dialer(nil), s.dialers...)
}

func NewDialerSetFromLinksContext(ctx context.Context, option *dialer.GlobalOption, tagToNodeList map[string][]string) *DialerSet {
	s := &DialerSet{
		log:          option.Log,
		dialers:      make([]*dialer.Dialer, 0),
		nodeToTagMap: make(map[*dialer.Dialer]string),
	}
	for subscriptionTag, nodes := range tagToNodeList {
		for _, node := range nodes {
			d, err := dialer.NewFromLinkContext(ctx, option, dialer.InstanceOption{DisableCheck: false}, node, subscriptionTag)
			if err != nil {
				s.log.Infof("failed to parse node: %v", err)
				continue
			}
			s.dialers = append(s.dialers, d)
			s.nodeToTagMap[d] = subscriptionTag
		}
	}
	return s
}

func (s *DialerSet) filterHit(dialer *dialer.Dialer, filters []*config_parser.Function) (hit bool, err error) {
	if len(filters) == 0 {
		// No filter.
		return true, nil
	}

	// Example
	// filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')
	// filter: !name(regex: 'HK|TW|SG') && name(keyword: disney)
	// filter: subtag(my_sub, regex:^my_, regex:my_)

	// And
	for _, filter := range filters {
		var subFilterHit bool

		switch filter.Name {
		case FilterInput_Name:
			// Or
		loop:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterKey_Name_Regex:
					re, ok := regexpCache.Load(param.Val)
					var regex *regexp2.Regexp
					if !ok {
						var err error
						regex, err = regexp2.Compile(param.Val, 0)
						if err != nil {
							return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
						}
						regexpCache.Store(param.Val, regex)
					} else {
						regex = re.(*regexp2.Regexp)
					}
					matched, _ := regex.MatchString(dialer.Property().Name)
					// logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break loop
					}
				case FilterKey_Name_Keyword:
					if strings.Contains(dialer.Property().Name, param.Val) {
						subFilterHit = true
						break loop
					}
				case "":
					if dialer.Property().Name == param.Val {
						subFilterHit = true
						break loop
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}
		case FilterInput_SubscriptionTag:
			// Or
		loop2:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterInput_SubscriptionTag_Regex:
					re, ok := regexpCache.Load(param.Val)
					var regex *regexp2.Regexp
					if !ok {
						var err error
						regex, err = regexp2.Compile(param.Val, 0)
						if err != nil {
							return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
						}
						regexpCache.Store(param.Val, regex)
					} else {
						regex = re.(*regexp2.Regexp)
					}
					matched, _ := regex.MatchString(s.nodeToTagMap[dialer])
					if matched {
						subFilterHit = true
						break loop2
					}
					// logrus.Warnln(param.Val, matched, dialer.Name())
				case "":
					// Full
					if s.nodeToTagMap[dialer] == param.Val {
						subFilterHit = true
						break loop2
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}

		default:
			return false, fmt.Errorf(`unsupported filter input type: "%v"`, filter.Name)
		}

		if subFilterHit == filter.Not {
			return false, nil
		}
	}
	return true, nil
}

func exactNameList(filters []*config_parser.Function) ([]string, bool) {
	if len(filters) != 1 || filters[0] == nil {
		return nil, false
	}
	filter := filters[0]
	if filter.Name != FilterInput_Name || filter.Not || len(filter.Params) == 0 {
		return nil, false
	}
	names := make([]string, 0, len(filter.Params))
	for _, param := range filter.Params {
		if param == nil || param.Key != "" || param.Val == "" {
			return nil, false
		}
		names = append(names, param.Val)
	}
	return names, true
}

func allExactNameFilters(filters [][]*config_parser.Function) bool {
	if len(filters) == 0 {
		return false
	}
	for _, clause := range filters {
		if _, ok := exactNameList(clause); !ok {
			return false
		}
	}
	return true
}

func (s *DialerSet) FilterAndAnnotate(filters [][]*config_parser.Function, annotations [][]*config_parser.Param) (dialers []*dialer.Dialer, filterAnnotations []*dialer.Annotation, err error) {
	if len(filters) != len(annotations) {
		return nil, nil, fmt.Errorf("[CODE BUG]: unmatched annotations length: %v filters and %v annotations", len(filters), len(annotations))
	}
	if len(filters) == 0 {
		anno := make([]*dialer.Annotation, len(s.dialers))
		for i := range anno {
			anno[i] = &dialer.Annotation{}
		}
		return s.dialers, anno, nil
	}
	if allExactNameFilters(filters) {
		return s.filterExactNamesInDeclarationOrder(filters, annotations)
	}
nextDialerLoop:
	for _, d := range s.dialers {
		// Hit any.
		for j, f := range filters {
			hit, err := s.filterHit(d, f)
			if err != nil {
				return nil, nil, err
			}
			if hit {
				anno, err := dialer.NewAnnotation(annotations[j])
				if err != nil {
					return nil, nil, fmt.Errorf("apply filter annotation: %w", err)
				}
				dialers = append(dialers, d)
				filterAnnotations = append(filterAnnotations, anno)
				continue nextDialerLoop
			}
		}
	}
	return dialers, filterAnnotations, nil
}

func (s *DialerSet) filterExactNamesInDeclarationOrder(filters [][]*config_parser.Function, annotations [][]*config_parser.Param) ([]*dialer.Dialer, []*dialer.Annotation, error) {
	byName := make(map[string]*dialer.Dialer, len(s.dialers))
	for _, d := range s.dialers {
		if d == nil || d.Property() == nil || d.Property().Name == "" {
			continue
		}
		if _, exists := byName[d.Property().Name]; exists {
			continue
		}
		byName[d.Property().Name] = d
	}
	var dialers []*dialer.Dialer
	var filterAnnotations []*dialer.Annotation
	seen := make(map[*dialer.Dialer]struct{}, len(byName))
	for j, clause := range filters {
		names, ok := exactNameList(clause)
		if !ok {
			return nil, nil, fmt.Errorf("[CODE BUG]: expected exact name filter")
		}
		anno, err := dialer.NewAnnotation(annotations[j])
		if err != nil {
			return nil, nil, fmt.Errorf("apply filter annotation: %w", err)
		}
		for _, name := range names {
			d := byName[name]
			if d == nil {
				continue
			}
			if _, exists := seen[d]; exists {
				continue
			}
			seen[d] = struct{}{}
			dialers = append(dialers, d)
			filterAnnotations = append(filterAnnotations, anno)
		}
	}
	return dialers, filterAnnotations, nil
}

func (s *DialerSet) Close() error {
	var err error
	for _, d := range s.dialers {
		if e := d.Close(); e != nil {
			err = e
		}
	}
	return err
}
