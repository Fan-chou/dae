/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/sirupsen/logrus"
)

var ErrNoAliveDialer = fmt.Errorf("no alive dialer")

type DialerGroup struct {
	netproxy.Dialer

	log  *logrus.Logger
	Name string

	Dialers []*dialer.Dialer

	// nestedMembers is nil for the established flat fast path. When populated,
	// selection preserves each child group's own policy instead of treating its
	// leaf dialers as ordinary parent members.
	nestedMembers []dialerGroupMember
	// concreteDialers are the dialers returned by nested selection. They remain
	// distinct from Dialers when this group has a parent health view.
	concreteDialers []*dialer.Dialer
	// parentHealthViews maps concrete nested leaves to this group's private
	// health-check dialers. The clones let a parent apply its own check option
	// without changing a child's health state or check lifecycle.
	parentHealthViews map[*dialer.Dialer]*dialer.Dialer
	// skipAdmissionFallback is set when a nested health layer omitted
	// REJECT/block from Dialers so probes cannot mark the fallback dead.
	// Userspace can still select that member; BPF connectivity must stay
	// alive so new connections reach it.
	skipAdmissionFallback bool

	selectionState   atomic.Pointer[dialerGroupSelectionState]
	selectionStateMu sync.Mutex
	// kernelAliveMu serializes BPF connectivity publishes so a stale
	// SetSelectionPolicy republish or health callback cannot overwrite a
	// newer policy's live KernelOutboundAlive result.
	kernelAliveMu sync.Mutex
	// kernelAliveEpoch increments with each policy store. Publishers that
	// observed an older epoch drop their write after waiting for the mutex.
	kernelAliveEpoch atomic.Uint64
	lazyCheckOnce    sync.Once
	closeOnce        sync.Once

	dialersAnnotations  []*dialer.Annotation
	checkTolerance      time.Duration
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType, isInit bool)
	userAliveCallback   func(alive bool, networkType *dialer.NetworkType, isInit bool)
	healthCheckEnabled  bool
	lazyCheck           bool

	resuscitateLastTime atomic.Int64
	noAliveLogLastTimes [8]atomic.Int64

	cachedMinCheckInterval time.Duration
}

type dialerGroupSelectionState struct {
	policy          DialerSelectionPolicy
	aliveDialerSets [8]*dialer.AliveDialerSet
}

// ReloadSelectionFallback records the candidate selected by a fresh group
// before reload health inheritance applies the previous generation's state.
type ReloadSelectionFallback [8]*dialer.Dialer

// NestedDialerGroupMember is one ordered member of a nested group. Exactly one
// of Dialer or Group must be set. Annotations apply only to direct dialers.
type NestedDialerGroupMember struct {
	Dialer     *dialer.Dialer
	Group      *DialerGroup
	Annotation *dialer.Annotation
}

type dialerGroupMember struct {
	dialer     *dialer.Dialer
	group      *DialerGroup
	annotation *dialer.Annotation
}

// DialerGroupRuntimeOptions carries group-level health behavior that is not a
// dialer option. HealthCheckEnabled is needed for fixed Mihomo select groups
// that set tcp_check_url / check_interval / similar probe knobs. Lazy only
// defers those checks until the group participates in a real selection; it
// must not invent a second probe layer on its own.
type DialerGroupRuntimeOptions struct {
	HealthCheckEnabled bool
	Lazy               bool
	HealthDialers      *HealthDialerCache
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	p DialerSelectionPolicy,
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType, isInit bool),
) *DialerGroup {
	return NewDialerGroupWithRuntimeOptions(
		option,
		name,
		dialers,
		dialersAnnotations,
		p,
		aliveChangeCallback,
		DialerGroupRuntimeOptions{},
	)
}

func NewDialerGroupWithRuntimeOptions(
	option *dialer.GlobalOption,
	name string,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	p DialerSelectionPolicy,
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType, isInit bool),
	runtimeOptions DialerGroupRuntimeOptions,
) *DialerGroup {
	log := option.Log

	group := &DialerGroup{
		log:                log,
		Name:               name,
		Dialers:            dialers,
		dialersAnnotations: dialersAnnotations,
		checkTolerance:     option.CheckTolerance,
		healthCheckEnabled: runtimeOptions.HealthCheckEnabled,
		lazyCheck:          runtimeOptions.Lazy,
	}
	group.installAlivePublisher(aliveChangeCallback)
	state := group.buildSelectionState(p, true)
	group.registerAliveDialerSets(state.aliveDialerSets)
	group.selectionState.Store(state)
	group.cachedMinCheckInterval = group.MinCheckInterval()

	if aliveChangeCallback != nil {
		for _, nt := range standardSelectionNetworkTypes() {
			aliveChangeCallback(true, nt, true)
		}
	}

	return group
}

func (g *DialerGroup) installAlivePublisher(cb func(alive bool, networkType *dialer.NetworkType, isInit bool)) {
	g.userAliveCallback = cb
	if cb == nil {
		g.aliveChangeCallback = nil
		return
	}
	g.aliveChangeCallback = func(alive bool, networkType *dialer.NetworkType, isInit bool) {
		if isInit {
			cb(alive, networkType, isInit)
			return
		}
		g.publishLiveKernelAlive(networkType)
	}
}

// NewNestedDialerGroup builds an ordered recursive selection tree. Dialers is
// still populated with a unique leaf snapshot so the established health-check,
// reload-inheritance, and ownership paths keep operating on concrete dialers.
func NewNestedDialerGroup(
	option *dialer.GlobalOption,
	name string,
	members []NestedDialerGroupMember,
	p DialerSelectionPolicy,
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType, isInit bool),
) (*DialerGroup, error) {
	return NewNestedDialerGroupWithRuntimeOptions(
		option, name, members, p, aliveChangeCallback, DialerGroupRuntimeOptions{},
	)
}

// NewNestedDialerGroupWithRuntimeOptions builds an ordered recursive selection
// tree with optional parent-specific health views. Existing callers that do not
// need a parent health layer should keep using NewNestedDialerGroup.
func NewNestedDialerGroupWithRuntimeOptions(
	option *dialer.GlobalOption,
	name string,
	members []NestedDialerGroupMember,
	p DialerSelectionPolicy,
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType, isInit bool),
	runtimeOptions DialerGroupRuntimeOptions,
) (*DialerGroup, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("nested group %q has no members", name)
	}

	leafDialers := make([]*dialer.Dialer, 0, len(members))
	leafAnnotations := make([]*dialer.Annotation, 0, len(members))
	seenLeaves := make(map[*dialer.Dialer]struct{})
	internalMembers := make([]dialerGroupMember, 0, len(members))
	for i, member := range members {
		if (member.Dialer == nil) == (member.Group == nil) {
			return nil, fmt.Errorf("nested group %q member %d must contain exactly one dialer or child group", name, i)
		}
		if member.Dialer != nil {
			annotation := member.Annotation
			if annotation == nil {
				annotation = &dialer.Annotation{}
			}
			internalMembers = append(internalMembers, dialerGroupMember{dialer: member.Dialer, annotation: annotation})
			if _, exists := seenLeaves[member.Dialer]; !exists {
				seenLeaves[member.Dialer] = struct{}{}
				leafDialers = append(leafDialers, member.Dialer)
				leafAnnotations = append(leafAnnotations, annotation)
			}
			continue
		}
		childLeaves := member.Group.nestedConcreteDialers()
		if len(childLeaves) == 0 {
			return nil, fmt.Errorf("nested group %q references empty child group %q", name, member.Group.Name)
		}
		internalMembers = append(internalMembers, dialerGroupMember{group: member.Group})
		for _, childDialer := range childLeaves {
			if childDialer == nil {
				return nil, fmt.Errorf("nested group %q child group %q contains a nil dialer", name, member.Group.Name)
			}
			if _, exists := seenLeaves[childDialer]; exists {
				continue
			}
			seenLeaves[childDialer] = struct{}{}
			leafDialers = append(leafDialers, childDialer)
			leafAnnotations = append(leafAnnotations, &dialer.Annotation{})
		}
	}
	groupDialers := leafDialers
	groupAnnotations := leafAnnotations
	var parentHealthViews map[*dialer.Dialer]*dialer.Dialer
	skipAdmissionFallback := false
	if runtimeOptions.HealthCheckEnabled {
		groupDialers = make([]*dialer.Dialer, 0, len(leafDialers))
		groupAnnotations = make([]*dialer.Annotation, 0, len(leafDialers))
		parentHealthViews = make(map[*dialer.Dialer]*dialer.Dialer, len(leafDialers))
		for i, leaf := range leafDialers {
			if skipsParentHealthAdmission(leaf) {
				// REJECT/block cannot complete HTTP/DNS probes. Creating a
				// parent view with DisableCheck=false would mark it dead and
				// remove it from first_alive/url-test fallback. Keep it out
				// of Dialers, but remember it so an empty probe set does not
				// tell the kernel the group is unreachable when the current
				// policy can still select it.
				skipAdmissionFallback = true
				continue
			}
			view, _ := runtimeOptions.HealthDialers.CloneShared(leaf, option)
			// A parent health layer is an explicit admission policy. Built-in
			// DIRECT and other disabled concrete members may skip their own
			// checks, but that must not suppress the parent's check.
			view.DisableCheck = false
			parentHealthViews[leaf] = view
			groupDialers = append(groupDialers, view)
			groupAnnotations = append(groupAnnotations, leafAnnotations[i])
		}
	}
	group := NewDialerGroupWithRuntimeOptions(option, name, groupDialers, groupAnnotations, p, aliveChangeCallback, runtimeOptions)
	group.nestedMembers = internalMembers
	group.concreteDialers = leafDialers
	group.parentHealthViews = parentHealthViews
	group.skipAdmissionFallback = skipAdmissionFallback
	return group, nil
}

func (g *DialerGroup) nestedConcreteDialers() []*dialer.Dialer {
	if g != nil && len(g.concreteDialers) != 0 {
		return g.concreteDialers
	}
	if g == nil {
		return nil
	}
	return g.Dialers
}

// ParentHealthViewDialers returns the parent-owned dialers created for a
// nested group health layer. Control-plane construction uses this to retain
// them on error paths before egressRuntime assumes ownership.
func (g *DialerGroup) ParentHealthViewDialers() []*dialer.Dialer {
	if g == nil || len(g.parentHealthViews) == 0 {
		return nil
	}
	views := make([]*dialer.Dialer, 0, len(g.parentHealthViews))
	for _, d := range g.Dialers {
		if d != nil {
			views = append(views, d)
		}
	}
	return views
}

// IsLazyCheck reports whether ControlPlane should defer this group's health
// checks until the group is selected.
func (g *DialerGroup) IsLazyCheck() bool {
	return g != nil && g.lazyCheck
}

func (g *DialerGroup) activateChecks() {
	if g == nil {
		return
	}
	if len(g.nestedMembers) != 0 {
		for _, view := range g.parentHealthViews {
			view.ActivateCheck()
		}
		for _, member := range g.nestedMembers {
			if member.group != nil {
				member.group.ActivateCheck()
				continue
			}
			// Standalone nested leaves (Mihomo select name() members) share the
			// parent's policy. A fixed select does not need to probe every
			// alternative; the child url-test group already probes its pool.
			if member.dialer != nil && len(g.parentHealthViews) == 0 &&
				g.needsAliveState(g.currentSelectionState().policy.Policy) {
				member.dialer.ActivateCheck()
			}
		}
		return
	}
	for _, d := range g.Dialers {
		if d != nil {
			d.ActivateCheck()
		}
	}
}

// ActivateCheck starts this group's eager checks. Nested groups delegate to
// their child groups so a child's lazy setting is not bypassed by the parent's
// flattened leaf-dialer snapshot.
func (g *DialerGroup) ActivateCheck() {
	if g == nil || g.lazyCheck {
		return
	}
	g.activateChecks()
}

func (g *DialerGroup) activateLazyCheck() {
	if g == nil || !g.lazyCheck {
		return
	}
	g.lazyCheckOnce.Do(g.activateChecks)
}

func (g *DialerGroup) Close() error {
	if g == nil {
		return nil
	}
	g.closeOnce.Do(func() {
		g.unregisterAliveDialerSets(g.currentSelectionState().aliveDialerSets)
	})
	return nil
}

// SnapshotForEstablishedFlow returns a compact immutable view of the group
// decision retained by an established flow. It deliberately omits health sets
// and every unselected dialer so a long-lived flow cannot retain the full
// retired generation.
func (g *DialerGroup) SnapshotForEstablishedFlow(selected *dialer.Dialer) *DialerGroup {
	if g == nil {
		return nil
	}
	view := &DialerGroup{
		log:                    g.log,
		Name:                   g.Name,
		cachedMinCheckInterval: g.cachedMinCheckInterval,
	}
	if selected != nil {
		view.Dialer = selected
		view.Dialers = []*dialer.Dialer{selected}
	}
	view.selectionState.Store(&dialerGroupSelectionState{
		policy: g.currentSelectionState().policy,
	})
	return view
}

func (g *DialerGroup) SetSelectionPolicy(policy DialerSelectionPolicy) {
	g.selectionStateMu.Lock()
	defer func() {
		g.kernelAliveEpoch.Add(1)
		g.selectionStateMu.Unlock()
		g.republishKernelAlive()
	}()

	current := g.currentSelectionState()
	currentNeedsAliveState := g.needsAliveState(current.policy.Policy)
	newNeedsAliveState := g.needsAliveState(policy.Policy)

	switch {
	case currentNeedsAliveState && newNeedsAliveState:
		if current.policy.Policy != policy.Policy {
			for _, set := range uniqueAliveDialerSets(current.aliveDialerSets) {
				set.SetSelectionPolicy(policy.Policy)
			}
		}
		next := &dialerGroupSelectionState{
			policy:          policy,
			aliveDialerSets: current.aliveDialerSets,
		}
		g.selectionState.Store(next)

	case !currentNeedsAliveState && !newNeedsAliveState:
		g.selectionState.Store(&dialerGroupSelectionState{policy: policy})

	case !currentNeedsAliveState && newNeedsAliveState:
		next := g.buildSelectionState(policy, true)
		g.registerAliveDialerSets(next.aliveDialerSets)
		if !g.lazyCheck {
			g.activateChecks()
		}
		g.selectionState.Store(next)

	case currentNeedsAliveState && !newNeedsAliveState:
		oldSets := current.aliveDialerSets
		g.selectionState.Store(&dialerGroupSelectionState{policy: policy})
		g.unregisterAliveDialerSets(oldSets)
	}
}

func (g *DialerGroup) GetSelectionPolicy() (policy consts.DialerSelectionPolicy) {
	return g.currentSelectionState().policy.Policy
}

// CurrentSelectionPolicy returns the live selection policy, including the
// fixed-member index used by converted Mihomo select groups.
func (g *DialerGroup) CurrentSelectionPolicy() DialerSelectionPolicy {
	if g == nil {
		return DialerSelectionPolicy{}
	}
	return g.currentSelectionState().policy
}

func (g *DialerGroup) MinCheckInterval() time.Duration {
	if len(g.Dialers) == 0 {
		return 30 * time.Second
	}
	min := g.Dialers[0].CheckInterval
	for _, d := range g.Dialers[1:] {
		if d.CheckInterval < min {
			min = d.CheckInterval
		}
	}
	if min < 2*time.Second {
		return 2 * time.Second
	}
	return min
}

func (d *DialerGroup) MustGetAliveDialerSet(typ *dialer.NetworkType) *dialer.AliveDialerSet {
	return d.currentSelectionState().aliveDialerSets[typ.Index()]
}

// KernelOutboundAlive reports whether new connections should still reach
// userspace for this group. REJECT/block is excluded from parent health views,
// so an empty probe set must not mark the group dead when the current policy
// can still select that fallback.
func (g *DialerGroup) KernelOutboundAlive(networkType *dialer.NetworkType) bool {
	if g == nil {
		return true
	}
	if g.rejectReachable() {
		return true
	}
	if networkType == nil {
		return true
	}
	set := g.MustGetAliveDialerSet(networkType)
	if set == nil {
		return true
	}
	return set.Len() > 0
}

func (g *DialerGroup) republishKernelAlive() {
	if g == nil || g.userAliveCallback == nil {
		return
	}
	epoch := g.kernelAliveEpoch.Load()
	g.kernelAliveMu.Lock()
	defer g.kernelAliveMu.Unlock()
	if g.kernelAliveEpoch.Load() != epoch {
		return
	}
	for _, nt := range standardSelectionNetworkTypes() {
		if g.kernelAliveEpoch.Load() != epoch {
			return
		}
		g.userAliveCallback(g.KernelOutboundAlive(nt), nt, false)
	}
}

func (g *DialerGroup) publishLiveKernelAlive(networkType *dialer.NetworkType) {
	if g == nil || g.userAliveCallback == nil || networkType == nil {
		return
	}
	epoch := g.kernelAliveEpoch.Load()
	g.kernelAliveMu.Lock()
	defer g.kernelAliveMu.Unlock()
	if g.kernelAliveEpoch.Load() != epoch {
		return
	}
	g.userAliveCallback(g.KernelOutboundAlive(networkType), networkType, false)
}

// rejectReachable reports whether the current selection policy can still land
// on a REJECT/block member that parent health probes omitted.
func (g *DialerGroup) rejectReachable() bool {
	if g == nil {
		return false
	}
	return g.policyRejectReachable(g.CurrentSelectionPolicy())
}

func (g *DialerGroup) policyRejectReachable(policy DialerSelectionPolicy) bool {
	if len(g.nestedMembers) > 0 {
		switch policy.Policy {
		case consts.DialerSelectionPolicy_Fixed:
			if policy.FixedIndex < 0 || policy.FixedIndex >= len(g.nestedMembers) {
				return false
			}
			return memberRejectReachable(g.nestedMembers[policy.FixedIndex])
		default:
			for _, member := range g.nestedMembers {
				if memberRejectReachable(member) {
					return true
				}
			}
			return false
		}
	}
	dialers := g.concreteDialers
	if len(dialers) == 0 {
		dialers = g.Dialers
	}
	switch policy.Policy {
	case consts.DialerSelectionPolicy_Fixed:
		if policy.FixedIndex < 0 || policy.FixedIndex >= len(dialers) {
			return false
		}
		return skipsParentHealthAdmission(dialers[policy.FixedIndex])
	default:
		for _, d := range dialers {
			if skipsParentHealthAdmission(d) {
				return true
			}
		}
		return false
	}
}

func memberRejectReachable(member dialerGroupMember) bool {
	if member.dialer != nil {
		return skipsParentHealthAdmission(member.dialer)
	}
	if member.group == nil {
		return false
	}
	return member.group.rejectReachable()
}

// CaptureReloadSelectionFallback captures one fallback candidate per network
// type so reload inheritance can avoid leaving a group with no selectable dialer.
func (g *DialerGroup) CaptureReloadSelectionFallback() ReloadSelectionFallback {
	var fallback ReloadSelectionFallback
	if g == nil {
		return fallback
	}
	for _, nt := range standardSelectionNetworkTypes() {
		d, _, _, err := g.selectWithExclusionResult(nt, false, nil, false)
		if err == nil && d != nil {
			fallback[nt.Index()] = d
		}
	}
	return fallback
}

// EnsureReloadSelectionFloor keeps exactly one fallback candidate alive for
// network types whose inherited health state would otherwise be empty.
func (g *DialerGroup) EnsureReloadSelectionFloor(fallback ReloadSelectionFallback) {
	if g == nil {
		return
	}
	for _, nt := range standardSelectionNetworkTypes() {
		set := g.MustGetAliveDialerSet(nt)
		if set == nil || set.Len() > 0 {
			continue
		}
		candidate := fallback[nt.Index()]
		if candidate == nil && len(g.Dialers) > 0 {
			candidate = g.Dialers[0]
		}
		if candidate == nil {
			continue
		}
		admissionCandidate := g.parentHealthViewForConcrete(candidate)
		if admissionCandidate == nil {
			admissionCandidate = candidate
		}
		admissionCandidate.MarkAliveForReloadFallback(nt)
		if g.log != nil && g.log.IsLevelEnabled(logrus.DebugLevel) {
			dialerName := ""
			if p := admissionCandidate.Property(); p != nil {
				dialerName = p.Name
			}
			g.log.WithFields(logrus.Fields{
				"dialer":  dialerName,
				"group":   g.Name,
				"network": nt.String(),
			}).Debugln("Reload health inheritance kept a selection fallback alive")
		}
	}
}

func (g *DialerGroup) parentHealthViewForConcrete(concrete *dialer.Dialer) *dialer.Dialer {
	if g == nil || concrete == nil {
		return nil
	}
	return g.parentHealthViews[concrete]
}

// tryDoRateLimitedAction checks if an action can be performed based on a rate limit.
// It uses atomic operations to ensure thread-safety with minimal overhead.
func (g *DialerGroup) tryDoRateLimitedAction(last *atomic.Int64, interval time.Duration) bool {
	now := time.Now().UnixNano()
	l := last.Load()
	if now-l < int64(interval) {
		return false
	}
	return last.CompareAndSwap(l, now)
}

// HandleNoAliveDialer is the unified entry point for handling dialer selection failures.
// IT MUST ONLY BE CALLED ON THE ERROR PATH to ensure zero overhead for successful requests.
// It automatically triggers a resuscitation probe and logs the failure, both subject to
// their respective (cached) rate limits.
func (g *DialerGroup) HandleNoAliveDialer(
	origNetworkType string,
	selectionNetworkType *dialer.NetworkType,
	src netip.AddrPort,
	dst netip.AddrPort,
	domain string,
	strictIpVersion bool,
) {
	// 1. Attempt resuscitation (rate-limited by min check interval)
	if g.tryDoRateLimitedAction(&g.resuscitateLastTime, g.cachedMinCheckInterval) {
		g.resuscitate(selectionNetworkType)
	}

	// 2. Log the failure (rate-limited by 5x check interval, min 10s)
	idx := selectionNetworkType.Index()
	logInterval := max(g.cachedMinCheckInterval*5, 10*time.Second)

	if g.tryDoRateLimitedAction(&g.noAliveLogLastTimes[idx], logInterval) {
		g.logNoAlive(origNetworkType, selectionNetworkType, src, dst, domain, strictIpVersion, logInterval)
	}
}

// Resuscitate triggers a targeted health check for all dialers in the group.
// It is rate-limited to once per group per MinCheckInterval to prevent worker pool starvation.
// Returns true if a resuscitation probe was actually signaled.
func (g *DialerGroup) Resuscitate(networkType *dialer.NetworkType) bool {
	if g.tryDoRateLimitedAction(&g.resuscitateLastTime, g.cachedMinCheckInterval) {
		g.resuscitate(networkType)
		return true
	}
	return false
}

func (g *DialerGroup) resuscitate(networkType *dialer.NetworkType) {
	for _, d := range g.Dialers {
		if networkType.L4Proto == consts.L4ProtoStr_UDP {
			// UDP admission may recover through DNS-UDP first and then shared TCP.
			// Probe both families so emergency recovery does not wait for the next
			// periodic full check when only the TCP fallback has come back.
			d.NotifyCheckDnsUdp()
			d.NotifyCheckTcp()
			continue
		}
		d.NotifyCheckTcp()
	}
}

func (g *DialerGroup) logNoAlive(
	origNetworkType string,
	selectionNetworkType *dialer.NetworkType,
	src netip.AddrPort,
	dst netip.AddrPort,
	domain string,
	strictIpVersion bool,
	interval time.Duration,
) {
	total := len(g.Dialers)
	alive := 0
	if a := g.MustGetAliveDialerSet(selectionNetworkType); a != nil {
		alive = a.Len()
	}

	g.log.WithFields(logrus.Fields{
		"outbound":               g.Name,
		"orig_network_type":      origNetworkType,
		"selection_network_type": selectionNetworkType.String(),
		"src":                    src.String(),
		"to":                     dst.String(),
		"sniffed":                domain,
		"interval":               interval.String(),
		"total":                  total,
		"alive":                  alive,
	}).Warn("no alive dialer for selection (rate-limited)")
}

// Select is a backward-compatible wrapper for SelectWithExclusion.
func (g *DialerGroup) Select(networkType *dialer.NetworkType, strictIpVersion bool) (d *dialer.Dialer, latency time.Duration, err error) {
	d, latency, _, err = g.SelectWithExclusionResult(networkType, strictIpVersion, nil)
	return d, latency, err
}

// SelectWithExclusion selects a dialer from group according to selectionPolicy.
// The 'excluded' parameter specifies a dialer to avoid during selection (for
// failover scenarios). Note that Fixed policy ignores 'excluded' because user
// configuration takes precedence over automatic exclusion.
// If 'strictIpVersion' is false and no alive dialer, it will fallback to another ipversion.
func (g *DialerGroup) SelectWithExclusion(networkType *dialer.NetworkType, strictIpVersion bool, excluded *dialer.Dialer) (d *dialer.Dialer, latency time.Duration, err error) {
	d, latency, _, err = g.SelectWithExclusionResult(networkType, strictIpVersion, excluded)
	return d, latency, err
}

// SelectWithExclusionResult returns the chosen dialer together with the health
// domain actually used to admit that dialer. For ordinary selections this is
// the requested network type; for data-UDP recovery it may be DNS-UDP or TCP.
func (g *DialerGroup) SelectWithExclusionResult(networkType *dialer.NetworkType, strictIpVersion bool, excluded *dialer.Dialer) (d *dialer.Dialer, latency time.Duration, selectedNetworkType *dialer.NetworkType, err error) {
	return g.selectWithExclusionResult(networkType, strictIpVersion, excluded, true)
}

func (g *DialerGroup) selectWithExclusionResult(networkType *dialer.NetworkType, strictIpVersion bool, excluded *dialer.Dialer, activateLazy bool) (d *dialer.Dialer, latency time.Duration, selectedNetworkType *dialer.NetworkType, err error) {
	if activateLazy {
		g.activateLazyCheck()
	}
	if len(g.nestedMembers) != 0 {
		return g.selectNestedWithExclusionResult(networkType, strictIpVersion, excluded, activateLazy)
	}
	state := g.currentSelectionState()
	policy := state.policy
	d, latency, selectedNetworkType, err = g._select(networkType, state, policy, excluded)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		// Fallback to another ipversion. Use local copy to avoid modifying the original networkType if it's passed by reference.
		nt := *networkType
		nt.IpVersion = (consts.IpVersion_X - networkType.IpVersion.ToIpVersionType()).ToIpVersionStr()
		return g._select(&nt, state, policy, excluded)
	}
	if err == nil {
		return d, latency, selectedNetworkType, nil
	}
	if errors.Is(err, ErrNoAliveDialer) && len(g.Dialers) == 1 && policy.Policy != consts.DialerSelectionPolicy_FirstAlive {
		// There is only one dialer in this group. Just choose it instead of return error.
		if d, _, selectedNetworkType, err = g._select(networkType, state, DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}, excluded); err != nil {
			return nil, 0, nil, err
		}
		return d, dialer.Timeout, selectedNetworkType, nil
	}
	return nil, latency, selectedNetworkType, err
}

func (g *DialerGroup) selectNestedWithExclusionResult(networkType *dialer.NetworkType, strictIpVersion bool, excluded *dialer.Dialer, activateLazy bool) (d *dialer.Dialer, latency time.Duration, selectedNetworkType *dialer.NetworkType, err error) {
	policy := g.currentSelectionState().policy
	d, latency, selectedNetworkType, err = g.selectNested(networkType, policy, excluded, activateLazy)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		nt := *networkType
		nt.IpVersion = (consts.IpVersion_X - networkType.IpVersion.ToIpVersionType()).ToIpVersionStr()
		return g.selectNested(&nt, policy, excluded, activateLazy)
	}
	return d, latency, selectedNetworkType, err
}

func (g *DialerGroup) selectNested(networkType *dialer.NetworkType, policy DialerSelectionPolicy, excluded *dialer.Dialer, activateLazy bool) (d *dialer.Dialer, latency time.Duration, selectedNetworkType *dialer.NetworkType, err error) {
	if len(g.nestedMembers) == 0 {
		return nil, 0, nil, fmt.Errorf("nested group %q has no members", g.Name)
	}
	networkTypes, count := g.selectionNetworkTypes(networkType, policy)
	for i := range count {
		d, latency, selectedNetworkType, err = g.selectNestedForNetworkType(&networkTypes[i], policy, excluded, activateLazy)
		if err == nil {
			return d, latency, selectedNetworkType, nil
		}
		if !errors.Is(err, ErrNoAliveDialer) {
			return nil, latency, selectedNetworkType, err
		}
	}
	return nil, time.Hour, nil, ErrNoAliveDialer
}

func (g *DialerGroup) selectNestedForNetworkType(networkType *dialer.NetworkType, policy DialerSelectionPolicy, excluded *dialer.Dialer, activateLazy bool) (*dialer.Dialer, time.Duration, *dialer.NetworkType, error) {
	switch policy.Policy {
	case consts.DialerSelectionPolicy_Fixed:
		if policy.FixedIndex < 0 || policy.FixedIndex >= len(g.nestedMembers) {
			return nil, 0, nil, fmt.Errorf("selected nested group member index is out of range")
		}
		return g.selectNestedMember(networkType, policy.Policy, g.nestedMembers[policy.FixedIndex], excluded, true, activateLazy)

	case consts.DialerSelectionPolicy_Random:
		start := fastrand.Intn(len(g.nestedMembers))
		for offset := range len(g.nestedMembers) {
			member := g.nestedMembers[(start+offset)%len(g.nestedMembers)]
			d, latency, selectedNetworkType, err := g.selectNestedMember(networkType, policy.Policy, member, excluded, false, activateLazy)
			if err == nil {
				return d, latency, selectedNetworkType, nil
			}
			if !errors.Is(err, ErrNoAliveDialer) {
				return nil, latency, selectedNetworkType, err
			}
		}
		return nil, time.Hour, nil, ErrNoAliveDialer

	case consts.DialerSelectionPolicy_FirstAlive:
		for _, member := range g.nestedMembers {
			d, latency, selectedNetworkType, err := g.selectNestedMember(networkType, policy.Policy, member, excluded, false, activateLazy)
			if err == nil {
				return d, latency, selectedNetworkType, nil
			}
			if !errors.Is(err, ErrNoAliveDialer) {
				return nil, latency, selectedNetworkType, err
			}
		}
		return nil, time.Hour, nil, ErrNoAliveDialer

	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		var bestDialer *dialer.Dialer
		var bestNetworkType *dialer.NetworkType
		bestLatency := time.Hour
		for _, member := range g.nestedMembers {
			d, latency, memberNetworkType, err := g.selectNestedMember(networkType, policy.Policy, member, excluded, false, activateLazy)
			if err == nil {
				if bestDialer == nil || latency < bestLatency {
					bestDialer, bestLatency, bestNetworkType = d, latency, memberNetworkType
				}
				continue
			}
			if !errors.Is(err, ErrNoAliveDialer) {
				return nil, latency, memberNetworkType, err
			}
		}
		if bestDialer == nil {
			return nil, time.Hour, nil, ErrNoAliveDialer
		}
		return bestDialer, bestLatency, bestNetworkType, nil
	default:
		return nil, 0, nil, fmt.Errorf("unsupported DialerSelectionPolicy: %v", policy.Policy)
	}
}

func (g *DialerGroup) selectNestedMember(networkType *dialer.NetworkType, policy consts.DialerSelectionPolicy, member dialerGroupMember, excluded *dialer.Dialer, fixed bool, activateLazy bool) (*dialer.Dialer, time.Duration, *dialer.NetworkType, error) {
	d, latency, selectedNetworkType, err := member.selectForNestedGroup(networkType, policy, excluded, fixed, activateLazy)
	if err == nil && d != nil && activateLazy {
		d.ActivateCheck()
	}
	// Fixed parent selection keeps the established flat-group contract: the
	// explicit user choice is returned even when a health view currently marks
	// it unavailable. The parent view still runs for observability and reload.
	if err != nil || len(g.parentHealthViews) == 0 || policy == consts.DialerSelectionPolicy_Fixed {
		return d, latency, selectedNetworkType, err
	}
	if g.parentHealthViewAlive(d, selectedNetworkType) {
		latency = g.parentHealthViewSelectionLatency(d, selectedNetworkType, policy, latency, member.annotation)
		return d, latency, selectedNetworkType, nil
	}

	// A parent rejection is local to the parent health view. Give a non-fixed
	// child one opportunity to select another concrete leaf before this parent
	// proceeds to its next declared member. A fixed child remains fixed intent.
	if member.group != nil && member.group.GetSelectionPolicy() != consts.DialerSelectionPolicy_Fixed {
		d, latency, selectedNetworkType, err = member.selectForNestedGroup(networkType, policy, d, false, activateLazy)
		if err == nil && d != excluded && g.parentHealthViewAlive(d, selectedNetworkType) {
			latency = g.parentHealthViewSelectionLatency(d, selectedNetworkType, policy, latency, member.annotation)
			return d, latency, selectedNetworkType, nil
		}
		if err != nil && !errors.Is(err, ErrNoAliveDialer) {
			return nil, latency, selectedNetworkType, err
		}
	}
	return nil, time.Hour, nil, ErrNoAliveDialer
}

func (g *DialerGroup) parentHealthViewAlive(concrete *dialer.Dialer, networkType *dialer.NetworkType) bool {
	if concrete == nil || networkType == nil {
		return false
	}
	if skipsParentHealthAdmission(concrete) {
		return true
	}
	view, ok := g.parentHealthViews[concrete]
	return ok && view != nil && view.MustGetAlive(networkType)
}

// skipsParentHealthAdmission reports leaves that a parent HTTP/DNS health
// layer must not admit or reject. Builtin REJECT/block is constructed with
// DisableCheck and has no proxy link; probing it can only fail, which would
// drop the Mihomo fallback member. DIRECT remains probeable.
func skipsParentHealthAdmission(d *dialer.Dialer) bool {
	if d == nil || !d.DisableCheck {
		return false
	}
	property := d.Property()
	return property != nil && property.Name == consts.OutboundBlock.String() && property.Link == ""
}

func (g *DialerGroup) parentHealthViewSelectionLatency(concrete *dialer.Dialer, networkType *dialer.NetworkType, policy consts.DialerSelectionPolicy, fallback time.Duration, annotation *dialer.Annotation) time.Duration {
	switch policy {
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
	default:
		return fallback
	}
	view := g.parentHealthViews[concrete]
	if view == nil {
		return fallback
	}
	latency, ok := view.SelectionLatency(networkType, policy)
	if !ok {
		return fallback
	}
	if annotation != nil {
		latency += annotation.AddLatency
	}
	return latency
}

func (m dialerGroupMember) selectForNestedGroup(networkType *dialer.NetworkType, policy consts.DialerSelectionPolicy, excluded *dialer.Dialer, fixed bool, activateLazy bool) (*dialer.Dialer, time.Duration, *dialer.NetworkType, error) {
	if m.group != nil {
		return m.group.selectWithExclusionResult(networkType, true, excluded, activateLazy)
	}
	if m.dialer == nil {
		return nil, 0, nil, fmt.Errorf("nested group member has no selectable dialer")
	}
	selectedNetworkType := preferAlternateSelectionNetworkType(m.dialer, networkType)
	if fixed {
		return m.dialer, 0, selectedNetworkType, nil
	}
	if m.dialer == excluded || !m.dialer.MustGetAlive(networkType) {
		return nil, time.Hour, nil, ErrNoAliveDialer
	}
	if policy == consts.DialerSelectionPolicy_Random {
		return m.dialer, 0, selectedNetworkType, nil
	}
	if policy == consts.DialerSelectionPolicy_FirstAlive {
		return m.dialer, 0, selectedNetworkType, nil
	}
	latency, ok := m.dialer.SelectionLatency(networkType, policy)
	if !ok {
		latency = time.Hour
	}
	if m.annotation != nil {
		latency += m.annotation.AddLatency
	}
	return m.dialer, latency, selectedNetworkType, nil
}

func (g *DialerGroup) _select(networkType *dialer.NetworkType, state *dialerGroupSelectionState, policy DialerSelectionPolicy, excluded *dialer.Dialer) (d *dialer.Dialer, latency time.Duration, selectedNetworkType *dialer.NetworkType, err error) {
	if len(g.Dialers) == 0 {
		if policy.Policy == consts.DialerSelectionPolicy_FirstAlive {
			return nil, 0, nil, ErrNoAliveDialer
		}
		return nil, 0, nil, fmt.Errorf("no dialer in this group")
	}
	switch policy.Policy {
	case consts.DialerSelectionPolicy_Random:
		networkTypes, count := g.selectionNetworkTypes(networkType, policy)
		for i := range count {
			a := state.aliveDialerSets[networkTypes[i].Index()]
			d := a.GetRandExcluded(excluded)
			if d != nil {
				selected := preferAlternateSelectionNetworkType(d, &networkTypes[i])
				return d, 0, selected, nil
			}
		}
		return nil, time.Hour, nil, ErrNoAliveDialer

	case consts.DialerSelectionPolicy_FirstAlive:
		networkTypes, count := g.selectionNetworkTypes(networkType, policy)
		for i := range count {
			a := state.aliveDialerSets[networkTypes[i].Index()]
			if a == nil {
				continue
			}
			for _, d := range g.Dialers {
				if d == nil || d == excluded || !a.IsAlive(d) {
					continue
				}
				selected := preferAlternateSelectionNetworkType(d, &networkTypes[i])
				return d, 0, selected, nil
			}
		}
		return nil, time.Hour, nil, ErrNoAliveDialer

	case consts.DialerSelectionPolicy_Fixed:
		// Fixed policy represents explicit user intent to use a specific dialer.
		// It ignores the 'excluded' parameter because user configuration takes
		// precedence over automatic exclusion. Even if the dialer is marked as
		// excluded, Fixed policy returns it as configured.
		if policy.FixedIndex < 0 || policy.FixedIndex >= len(g.Dialers) {
			return nil, 0, nil, fmt.Errorf("selected dialer index is out of range")
		}
		selected := preferAlternateSelectionNetworkType(g.Dialers[policy.FixedIndex], networkType)
		return g.Dialers[policy.FixedIndex], 0, selected, nil

	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		networkTypes, count := g.selectionNetworkTypes(networkType, policy)
		for i := range count {
			a := state.aliveDialerSets[networkTypes[i].Index()]
			d, latency := a.GetMinLatency(excluded)
			if d != nil {
				selected := preferAlternateSelectionNetworkType(d, &networkTypes[i])
				return d, latency, selected, nil
			}
		}
		return nil, time.Hour, nil, ErrNoAliveDialer

	default:
		return nil, 0, nil, fmt.Errorf("unsupported DialerSelectionPolicy: %v", policy)
	}
}

func (g *DialerGroup) selectionNetworkTypes(networkType *dialer.NetworkType, policy DialerSelectionPolicy) (networkTypes [3]dialer.NetworkType, count int) {
	networkTypes[0] = *networkType
	count = 1

	if policy.Policy == consts.DialerSelectionPolicy_Fixed ||
		networkType.L4Proto != consts.L4ProtoStr_UDP ||
		networkType.EffectiveUdpHealthDomain() != dialer.UdpHealthDomainData {
		return networkTypes, count
	}

	// If data-plane UDP has no alive dialer, retry selection against DNS UDP
	// first, then shared TCP health for the same IP family. A successful real
	// UDP flow will revive the data-UDP domain via ReportAvailableTraffic.
	networkTypes[count] = dialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       networkType.IpVersion,
		IsDns:           true,
		UdpHealthDomain: dialer.UdpHealthDomainDns,
	}
	count++
	networkTypes[count] = dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: networkType.IpVersion,
	}
	count++
	return networkTypes, count
}

func (g *DialerGroup) currentSelectionState() *dialerGroupSelectionState {
	state := g.selectionState.Load()
	if state == nil {
		return &dialerGroupSelectionState{}
	}
	return state
}

func (g *DialerGroup) buildSelectionState(policy DialerSelectionPolicy, setAlive bool) *dialerGroupSelectionState {
	state := &dialerGroupSelectionState{
		policy: policy,
	}
	if !g.needsAliveState(policy.Policy) {
		return state
	}

	specs := standardSelectionNetworkTypes()
	keys := dialer.StandardHealthKeys()

	for i, nt := range specs {
		networkType := *nt
		set := dialer.NewAliveDialerSet(
			g.log, g.Name, &networkType, g.checkTolerance, policy.Policy,
			g.Dialers, g.dialersAnnotations,
			func(networkType *dialer.NetworkType) func(alive bool) {
				return func(alive bool) { g.aliveChangeCallback(alive, networkType, false) }
			}(&networkType),
			false,
		)
		if setAlive {
			for _, d := range g.Dialers {
				set.NotifyLatencyChange(d, d.MustGetAlive(&networkType))
			}
		}
		state.aliveDialerSets[keys[i].CollectionIndex()] = set
		if networkType.L4Proto == consts.L4ProtoStr_TCP {
			if networkType.IpVersion == consts.IpVersionStr_4 {
				state.aliveDialerSets[dialer.IdxDnsTcp4] = set
			} else {
				state.aliveDialerSets[dialer.IdxDnsTcp6] = set
			}
		}
	}
	return state
}

func (g *DialerGroup) needsAliveState(policy consts.DialerSelectionPolicy) bool {
	return g.healthCheckEnabled || policyNeedsAliveState(policy)
}

func (g *DialerGroup) registerAliveDialerSets(aliveDialerSets [8]*dialer.AliveDialerSet) {
	for _, d := range g.Dialers {
		for _, a := range aliveDialerSets {
			d.RegisterAliveDialerSet(a)
		}
	}
}

func (g *DialerGroup) unregisterAliveDialerSets(aliveDialerSets [8]*dialer.AliveDialerSet) {
	for _, d := range g.Dialers {
		for _, a := range aliveDialerSets {
			d.UnregisterAliveDialerSet(a)
		}
	}
}

func policyNeedsAliveState(policy consts.DialerSelectionPolicy) bool {
	switch policy {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_FirstAlive,
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return true
	case consts.DialerSelectionPolicy_Fixed:
		return false
	default:
		panic(fmt.Sprintf("unexpected dialer selection policy: %v", policy))
	}
}

func uniqueAliveDialerSets(aliveDialerSets [8]*dialer.AliveDialerSet) []*dialer.AliveDialerSet {
	unique := make(map[*dialer.AliveDialerSet]struct{}, len(aliveDialerSets))
	var sets []*dialer.AliveDialerSet
	for _, set := range aliveDialerSets {
		if set == nil {
			continue
		}
		if _, ok := unique[set]; ok {
			continue
		}
		unique[set] = struct{}{}
		sets = append(sets, set)
	}
	return sets
}

func standardSelectionNetworkTypes() [6]*dialer.NetworkType {
	keys := dialer.StandardHealthKeys()
	var networkTypes [6]*dialer.NetworkType
	for i, key := range keys {
		networkTypes[i] = key.NetworkType()
	}
	return networkTypes
}

func preferAlternateSelectionNetworkType(d *dialer.Dialer, networkType *dialer.NetworkType) *dialer.NetworkType {
	if d == nil || networkType == nil {
		return networkType
	}
	if d.MustGetAlive(networkType) {
		return networkType
	}
	altType := alternateNetworkType(networkType)
	if altType == nil {
		return networkType
	}
	if d.MustGetAlive(altType) {
		return altType
	}
	return networkType
}

func alternateNetworkType(networkType *dialer.NetworkType) *dialer.NetworkType {
	if networkType == nil {
		return nil
	}
	switch networkType.IpVersion {
	case consts.IpVersionStr_4:
		alt := *networkType
		alt.IpVersion = consts.IpVersionStr_6
		return &alt
	case consts.IpVersionStr_6:
		alt := *networkType
		alt.IpVersion = consts.IpVersionStr_4
		return &alt
	default:
		return nil
	}
}
