/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "fmt"

// These adapters retain the explicit CLI opt-out. The default still uses the
// upstream epoch publication and HookSet transaction paths.
func (c *controlPlaneCore) stageConfiguredRoutingEpoch() error {
	if c == nil || !c.routingEpochEnabled() {
		return nil
	}
	return c.StageRoutingEpoch()
}

func (c *controlPlaneCore) publishConfiguredRoutingEpoch() error {
	if c == nil || !c.routingEpochEnabled() {
		return nil
	}
	return c.PublishRoutingEpoch()
}

func (c *ControlPlane) replayReloadDNSForPublication() error {
	if c.core != nil && !c.core.routingEpochEnabled() {
		if c.sharedBpfReload && c.dnsRoutingUnchanged {
			return nil
		}
		if err := clearReloadDomainRoutingMap(c.core.PeekBpf()); err != nil {
			return fmt.Errorf("clear legacy domain routing: %w", err)
		}
	}
	return c.replayDnsReloadCache()
}

func (c *ControlPlane) rebuildLegacyReloadDatapath() error {
	c.log.Warnln("[Reload] Rebuilding previous generation slot-0 datapath")
	if _, err := c.core.buildRoutingKernspaceForSlot(c.log, c.routingKernspaceSnapshot); err != nil {
		return fmt.Errorf("rebuild routing kernspace: %w", err)
	}
	if err := clearReloadDomainRoutingMap(c.core.PeekBpf()); err != nil {
		return fmt.Errorf("rebuild domain routing: %w", err)
	}
	c.pendingDnsReloadCache = c.CloneDnsCache()
	if err := c.replayDnsReloadCache(); err != nil {
		return fmt.Errorf("rebuild DNS reload cache: %w", err)
	}
	c.core.activateBpfHookFlip()
	return nil
}
