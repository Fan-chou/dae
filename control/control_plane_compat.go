/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

func NewControlPlane(
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
) (plane *ControlPlane, err error) {
	return NewControlPlaneWithContextOptions(
		context.Background(),
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		ControlPlaneBuildOptions{},
	)
}

func NewControlPlaneWithContext(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	dnsRoutingUnchanged bool,
) (plane *ControlPlane, err error) {
	return NewControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		ControlPlaneBuildOptions{
			DNSRoutingUnchanged: dnsRoutingUnchanged,
			IsReload:            _bpf != nil,
		},
	)
}

// NewReloadControlPlaneWithContext builds a control plane during reload even
// when it receives fresh BPF objects instead of shared objects from the old
// generation. Reload builds must use reload TC handle flipping and must not run
// startup-only stale hook purges.
func NewReloadControlPlaneWithContext(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	dnsRoutingUnchanged bool,
) (plane *ControlPlane, err error) {
	return NewControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		ControlPlaneBuildOptions{
			DNSRoutingUnchanged: dnsRoutingUnchanged,
			IsReload:            true,
		},
	)
}

// NewPreparedControlPlaneWithContext builds a new generation without mutating
// the shared datapath. Call CommitPreparedDatapath before switching traffic.
func NewPreparedControlPlaneWithContext(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	dnsRoutingUnchanged bool,
) (plane *ControlPlane, err error) {
	return NewControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		ControlPlaneBuildOptions{
			DelayDatapathCommit:   true,
			DelayDNSListenerStart: true,
			DNSRoutingUnchanged:   dnsRoutingUnchanged,
			IsReload:              _bpf != nil,
		},
	)
}

// NewPreparedReloadControlPlaneWithContext builds a reload generation without
// mutating the kernel datapath until CommitPreparedDatapath is called.
func NewPreparedReloadControlPlaneWithContext(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	dnsRoutingUnchanged bool,
) (plane *ControlPlane, err error) {
	return NewControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		ControlPlaneBuildOptions{
			DelayDatapathCommit:   true,
			DelayDNSListenerStart: true,
			DNSRoutingUnchanged:   dnsRoutingUnchanged,
			IsReload:              true,
		},
	)
}

// closeUniqueDialers closes construction-time parent health views that are not
// already covered by another wrapper's cleanup. CloneWithGlobalOptionContext
// may share a transport when a concrete dialer cannot be reconstructed from a
// link, so blindly closing every wrapper would close the same transport twice.
// Once egressRuntime takes ownership, it performs the equivalent identity-aware
// cleanup; this helper is only for the pre-runtime construction error path.
func closeUniqueDialers(dialers, shared []*dialer.Dialer) error {
	sharedIdentities := make(map[any]struct{}, len(shared))
	for _, d := range shared {
		if d != nil {
			sharedIdentities[egressDialerIdentity(d)] = struct{}{}
		}
	}
	closedIdentities := make(map[any]struct{}, len(dialers))
	var errs []error
	for _, d := range dialers {
		if d == nil {
			continue
		}
		identity := egressDialerIdentity(d)
		if _, alreadyShared := sharedIdentities[identity]; alreadyShared {
			continue
		}
		if _, alreadyClosed := closedIdentities[identity]; alreadyClosed {
			continue
		}
		closedIdentities[identity] = struct{}{}
		if err := d.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}
