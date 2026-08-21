/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"reflect"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

type configSectionDecoder func(conf *Config, section *config_parser.Section) error

type configSectionSpec struct {
	name     string
	required bool
	decode   configSectionDecoder
}

var configSectionSpecs = []configSectionSpec{
	{name: "global", required: true, decode: decodeGlobalSection},
	{name: "subscription", decode: decodeSubscriptionSection},
	{name: "rule_provider", decode: decodeRuleProviderSection},
	{name: "node", decode: decodeNodeSection},
	{name: "group", decode: decodeGroupSection},
	{name: "routing", required: true, decode: decodeRoutingSection},
	{name: "dns", decode: decodeDnsSection},
}

func lookupConfigSectionSpec(sectionName string) *configSectionSpec {
	for i := range configSectionSpecs {
		if configSectionSpecs[i].name == sectionName {
			return &configSectionSpecs[i]
		}
	}
	return nil
}

func decodeConfigSection(conf *Config, sectionName string, section *config_parser.Section) error {
	if conf == nil {
		return fmt.Errorf("nil config")
	}
	spec := lookupConfigSectionSpec(sectionName)
	if spec == nil {
		return fmt.Errorf("unknown section: %v", sectionName)
	}
	if section == nil {
		return fmt.Errorf("nil section: %v", sectionName)
	}
	return spec.decode(conf, section)
}

func decodeGlobalSection(conf *Config, section *config_parser.Section) error {
	if err := SectionParser(reflect.ValueOf(&conf.Global), section); err != nil {
		return err
	}
	conf.Global.SoMarkFromDaeSet = sectionHasParam(section, "so_mark_from_dae")
	return nil
}

func decodeSubscriptionSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Subscription), section)
}

func decodeRuleProviderSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.RuleProvider), section)
}

func decodeNodeSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Node), section)
}

func decodeGroupSection(conf *Config, section *config_parser.Section) error {
	if err := SectionParser(reflect.ValueOf(&conf.Group), section); err != nil {
		return err
	}
	groupIndex := 0
	for _, item := range section.Items {
		groupSection, ok := item.Value.(*config_parser.Section)
		if !ok {
			continue
		}
		if groupIndex >= len(conf.Group) {
			return fmt.Errorf("group section count changed while decoding")
		}
		conf.Group[groupIndex].CheckIntervalSet = sectionHasParam(groupSection, "check_interval")
		conf.Group[groupIndex].CheckToleranceSet = sectionHasParam(groupSection, "check_tolerance")
		conf.Group[groupIndex].LazySet = sectionHasParam(groupSection, "lazy")
		groupIndex++
	}
	return nil
}

func decodeRoutingSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Routing), section)
}

func decodeDnsSection(conf *Config, section *config_parser.Section) error {
	if section == nil {
		return fmt.Errorf("nil section: dns")
	}
	var rest []*config_parser.Item
	var fakeipSection *config_parser.Section
	for _, item := range section.Items {
		if nested, ok := item.Value.(*config_parser.Section); ok && nested.Name == "fakeip" {
			if fakeipSection != nil {
				return fmt.Errorf("duplicate dns.fakeip section")
			}
			fakeipSection = nested
			continue
		}
		rest = append(rest, item)
	}
	stripped := *section
	stripped.Items = rest
	if err := SectionParser(reflect.ValueOf(&conf.Dns), &stripped); err != nil {
		return err
	}
	if fakeipSection == nil {
		return nil
	}
	fake, err := parseFakeIPSection(fakeipSection)
	if err != nil {
		return fmt.Errorf("failed to parse fakeip: %w", err)
	}
	conf.Dns.FakeIP = fake
	return nil
}
