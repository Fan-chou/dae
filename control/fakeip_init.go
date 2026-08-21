/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

func (c *ControlPlane) initFakeIP(
	ctx context.Context,
	log *logrus.Logger,
	dnsConfig *config.Dns,
	tagToNodeList map[string][]string,
	locationFinder *assets.LocationFinder,
) error {
	if c == nil || dnsConfig == nil {
		return nil
	}
	fake := dnsConfig.FakeIP
	store := fakeIPStoreFromContext(ctx)
	inet4, err := fake.Inet4Prefix()
	if err != nil {
		return err
	}
	inet6, err := fake.Inet6Prefix()
	if err != nil {
		return err
	}
	if !fake.Enable {
		if store == nil || !store.Ready() {
			return nil
		}
		store.RetireActive(inet4, inet6)
		c.fakeIPPolicy = NewFakeIPPolicy(fake, store, c.routingMatcher, nil, uint64(c.policyIdentity.Epoch()))
		c.syncFakeIPKernelPrefixes()
		return nil
	}
	if err := fake.Validate(); err != nil {
		return err
	}
	if store == nil {
		store = NewFakeIPStore(FakeIPStorePath(".", fake.Path), fake.ResolvedMaxEntries())
		if err := store.Open(inet4, inet6); err != nil {
			return fmt.Errorf("open fakeip store: %w", err)
		}
		c.deferFuncs = append(c.deferFuncs, store.Close)
	} else if !store.Ready() {
		if err := store.Open(inet4, inet6); err != nil {
			return fmt.Errorf("open fakeip store: %w", err)
		}
	} else {
		store.ApplyRanges(inet4, inet6)
	}

	filter, err := buildFakeIPFilterMatcher(log, locationFinder, fake, hostnamesFromNodeList(tagToNodeList))
	if err != nil {
		return err
	}
	c.fakeIPPolicy = NewFakeIPPolicy(fake, store, c.routingMatcher, filter, uint64(c.policyIdentity.Epoch()))
	if log != nil && fake.Enable {
		log.Infof("selective FakeIP enabled: inet4=%s inet6=%s filter_mode=%s", inet4, inet6, fake.ResolvedFilterMode())
	}
	c.syncFakeIPKernelPrefixes()
	return nil
}

func (c *ControlPlane) fakeIPStore() *FakeIPStore {
	if c == nil || c.fakeIPPolicy == nil {
		return nil
	}
	return c.fakeIPPolicy.Store()
}
