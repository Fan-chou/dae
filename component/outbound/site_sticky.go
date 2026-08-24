/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

const (
	siteStickyTTL             = time.Hour
	siteStickyMaxEntries      = 4096
	siteStickyMinDwell        = 30 * time.Second
	siteStickyHoldDown        = 60 * time.Second
	siteStickyReclaimAfter    = 2 * time.Minute
	siteStickySlowBeforeProbe = 2
	siteStickyMaxAltTries     = 2
)

// siteStickyEntry remembers one site→leaf pin plus the anti-flap bookkeeping
// that stops a recovered or slightly-better node from yanking the site back
// within seconds.
type siteStickyEntry struct {
	leaf            *dialer.Dialer
	pinnedAt        time.Time
	lastSuccess     time.Time
	consecutiveSlow int
	triedAlts       int
	probeNext       bool
	probeArmed      bool
	converged       bool
	holdDownUntil   map[*dialer.Dialer]time.Time
	touchedAt       time.Time
}

type siteStickyTable struct {
	mu       sync.Mutex
	detached bool
	entries  map[string]*siteStickyEntry
}

func newSiteStickyTable() *siteStickyTable {
	return &siteStickyTable{entries: make(map[string]*siteStickyEntry)}
}

func (t *siteStickyTable) detach() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.detached = true
	t.entries = nil
}

func usesSiteStickyPolicy(policy consts.DialerSelectionPolicy) bool {
	return policy == consts.DialerSelectionPolicy_Fallback || policy == consts.DialerSelectionPolicy_UrlTest
}

func (g *DialerGroup) usesSiteSticky() bool {
	return g != nil && usesSiteStickyPolicy(g.GetSelectionPolicy())
}

// HasSiteStickyFor reports whether the exclusive selected path to d keeps a
// per-site pin table. Membership is not enough: a first_alive parent can pick
// a fixed DIRECT child while an unused fallback sibling also lists that same
// leaf. Slow-handshake retry must ignore the unused sticky sibling, or it
// would close a successful DIRECT dial and redial a proxy the next connection
// cannot remember.
func (g *DialerGroup) HasSiteStickyFor(d *dialer.Dialer, networkType *dialer.NetworkType) bool {
	return len(g.collectStickyTablesOnSelectedPath(d, networkType)) > 0
}

// internedSelectPath is the unique recorded nested member and sticky tables
// for one Select. DialerGroup interns these so flow bindings can store a
// comparable token without copying the table list onto every connection.
type internedSelectPath struct {
	nestedMember string
	tables       []*siteStickyTable
}

// SelectPath is an interned token for the nested member and sticky tables
// actually used by one Select. Slow-handshake, PinSite snapshots, and admin
// identity must use this recorded path. The token is comparable (a pointer
// plus NestedMember) so snapshot caches can key on it; the table slice lives
// once per unique path on the group, not per flow, and is not truncated.
type SelectPath struct {
	NestedMember string
	p            *internedSelectPath
}

// selectPathInlineCap is the number of sticky tables kept on the Select
// stack. It is not a path limit: deeper chains overflow to extra, and
// internSelectPath still stores the full table list on the interned token.
const selectPathInlineCap = 8

// selectPathBuilder records tables during one Select. Typical paths stay in
// inline so nested Select does not heap-allocate a slice per layer; extra
// holds tables beyond the inline cap without truncating.
type selectPathBuilder struct {
	NestedMember string
	n            int
	inline       [selectPathInlineCap]*siteStickyTable
	extra        []*siteStickyTable
}

func (p SelectPath) HasSiteSticky() bool {
	return p.p != nil && len(p.p.tables) > 0
}

func (p SelectPath) stickyTables() []*siteStickyTable {
	if p.p == nil {
		return nil
	}
	return p.p.tables
}

func internSelectPath(g *DialerGroup, b selectPathBuilder) SelectPath {
	if b.NestedMember == "" && b.n == 0 {
		return SelectPath{}
	}
	if g == nil {
		return SelectPath{
			NestedMember: b.NestedMember,
			p:            &internedSelectPath{nestedMember: b.NestedMember, tables: b.copyTables()},
		}
	}
	if existing := g.lookupInternedSelectPath(b); existing != nil {
		return SelectPath{NestedMember: existing.nestedMember, p: existing}
	}
	g.internMu.Lock()
	defer g.internMu.Unlock()
	if existing := g.findInternedSelectPathLocked(b); existing != nil {
		return SelectPath{NestedMember: existing.nestedMember, p: existing}
	}
	tok := &internedSelectPath{
		nestedMember: b.NestedMember,
		tables:       b.copyTables(),
	}
	g.internedSelectPaths = append(g.internedSelectPaths, tok)
	return SelectPath{NestedMember: tok.nestedMember, p: tok}
}

func (g *DialerGroup) lookupInternedSelectPath(b selectPathBuilder) *internedSelectPath {
	g.internMu.RLock()
	defer g.internMu.RUnlock()
	return g.findInternedSelectPathLocked(b)
}

func (g *DialerGroup) findInternedSelectPathLocked(b selectPathBuilder) *internedSelectPath {
	for _, existing := range g.internedSelectPaths {
		if existing.nestedMember == b.NestedMember && b.sameStickyTables(existing.tables) {
			return existing
		}
	}
	return nil
}

func (p *selectPathBuilder) tableAt(i int) *siteStickyTable {
	if i < selectPathInlineCap {
		return p.inline[i]
	}
	return p.extra[i-selectPathInlineCap]
}

func (p *selectPathBuilder) sameStickyTables(tables []*siteStickyTable) bool {
	if p.n != len(tables) {
		return false
	}
	for i, table := range tables {
		if p.tableAt(i) != table {
			return false
		}
	}
	return true
}

func (p *selectPathBuilder) copyTables() []*siteStickyTable {
	if p.n == 0 {
		return nil
	}
	out := make([]*siteStickyTable, p.n)
	for i := 0; i < p.n; i++ {
		out[i] = p.tableAt(i)
	}
	return out
}

func (p *selectPathBuilder) addTable(t *siteStickyTable) {
	if p == nil || t == nil {
		return
	}
	for i := 0; i < p.n; i++ {
		if p.tableAt(i) == t {
			return
		}
	}
	if p.n < selectPathInlineCap {
		p.inline[p.n] = t
		p.n++
		return
	}
	p.extra = append(p.extra, t)
	p.n++
}

func (p *selectPathBuilder) addSticky(g *DialerGroup) {
	if p == nil || g == nil || !g.usesSiteSticky() || g.siteSticky == nil {
		return
	}
	p.addTable(g.siteSticky)
}

func (p *selectPathBuilder) adopt(member dialerGroupMember, sub *selectPathBuilder) {
	if p == nil {
		return
	}
	if p.NestedMember == "" {
		if member.group != nil {
			p.NestedMember = member.group.Name
		} else {
			p.NestedMember = dialerName(member.dialer)
		}
	}
	if sub == nil {
		return
	}
	for i := 0; i < sub.n; i++ {
		p.addTable(sub.tableAt(i))
	}
}

func (p *selectPathBuilder) take(src *selectPathBuilder) {
	if p == nil {
		return
	}
	if src == nil {
		*p = selectPathBuilder{}
		return
	}
	*p = *src
}

func (g *DialerGroup) now() time.Time {
	if g != nil && g.nowFn != nil {
		return g.nowFn()
	}
	return time.Now()
}

func (g *DialerGroup) hasConcreteMember(d *dialer.Dialer) bool {
	if g == nil || d == nil {
		return false
	}
	for _, member := range g.nestedConcreteDialers() {
		if member == d {
			return true
		}
	}
	return false
}

func uniqueStickyTables(tables []*siteStickyTable) []*siteStickyTable {
	if len(tables) < 2 {
		return tables
	}
	seen := make(map[*siteStickyTable]struct{}, len(tables))
	out := make([]*siteStickyTable, 0, len(tables))
	for _, table := range tables {
		if table == nil {
			continue
		}
		if _, ok := seen[table]; ok {
			continue
		}
		seen[table] = struct{}{}
		out = append(out, table)
	}
	return out
}

func (g *DialerGroup) collectStickyTablesContaining(d *dialer.Dialer) []*siteStickyTable {
	return uniqueStickyTables(g.collectStickyTablesContainingSeen(d, make(map[*siteStickyTable]struct{})))
}

func (g *DialerGroup) collectStickyTablesOnSelectedPath(d *dialer.Dialer, networkType *dialer.NetworkType) []*siteStickyTable {
	if g == nil {
		return nil
	}
	if g.establishedSnapshot {
		return uniqueStickyTables(g.siteStickyTree)
	}
	var out []*siteStickyTable
	if g.usesSiteSticky() && g.siteSticky != nil && (d == nil || g.hasConcreteMember(d)) {
		out = append(out, g.siteSticky)
	}
	if len(g.nestedMembers) == 0 {
		return uniqueStickyTables(out)
	}
	for _, member := range g.nestedMembersOnExclusivePath(d, networkType) {
		if member.group != nil {
			out = append(out, member.group.collectStickyTablesOnSelectedPath(d, networkType)...)
		}
	}
	return uniqueStickyTables(out)
}

func (g *DialerGroup) collectStickyTablesContainingSeen(d *dialer.Dialer, seen map[*siteStickyTable]struct{}) []*siteStickyTable {
	if g == nil {
		return nil
	}
	if g.establishedSnapshot {
		return uniqueStickyTables(g.siteStickyTree)
	}
	var out []*siteStickyTable
	if g.usesSiteSticky() && g.siteSticky != nil && (d == nil || g.hasConcreteMember(d)) {
		if _, ok := seen[g.siteSticky]; !ok {
			seen[g.siteSticky] = struct{}{}
			out = append(out, g.siteSticky)
		}
	}
	for _, member := range g.nestedMembers {
		if member.group != nil {
			out = append(out, member.group.collectStickyTablesContainingSeen(d, seen)...)
		}
	}
	return out
}

// PinSite records a confirmed first-byte success for this site. Degraded does
// not unpin; a later connection reuses the same leaf until Dead, this-site
// failure, or a bounded site-unfriendly probe.
func (g *DialerGroup) PinSite(site string, d *dialer.Dialer, slow bool) {
	if g == nil || d == nil {
		return
	}
	now := g.now()
	stillMember := g.pinStillMember()
	for _, table := range g.collectStickyTablesContaining(d) {
		table.pin(site, d, now, slow, stillMember)
	}
}

// pinStillMember is nil on established-flow snapshots so dwell stays locked
// without retaining every sibling dialer on the compact view.
func (g *DialerGroup) pinStillMember() func(*dialer.Dialer) bool {
	if g == nil || g.establishedSnapshot {
		return nil
	}
	return g.hasConcreteMember
}

// FailSite forgets the pin when this connection failed and hold-downs that
// leaf so the next few requests cannot bounce straight back to it.
func (g *DialerGroup) FailSite(site string, d *dialer.Dialer) {
	if g == nil || d == nil {
		return
	}
	now := g.now()
	for _, table := range g.collectStickyTablesContaining(d) {
		table.fail(site, d, now)
	}
}

// FailSitePath is FailSite using the tables recorded by the original Select.
// An empty path is a no-op: membership collection would hold-down unused
// sticky siblings that share the failed leaf.
func (g *DialerGroup) FailSitePath(site string, d *dialer.Dialer, path SelectPath) {
	if g == nil || d == nil || !path.HasSiteSticky() {
		return
	}
	now := g.now()
	for _, table := range path.stickyTables() {
		table.fail(site, d, now)
	}
}

func (t *siteStickyTable) pin(site string, d *dialer.Dialer, now time.Time, slow bool, stillMember func(*dialer.Dialer) bool) {
	if t == nil {
		return
	}
	key := SiteKey(site)
	if key == "" || d == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.detached {
		return
	}
	entry := t.lookupLocked(key, now)
	if entry == nil {
		t.evictLocked(now)
		entry = &siteStickyEntry{holdDownUntil: make(map[*dialer.Dialer]time.Time), touchedAt: now}
		t.entries[key] = entry
	}
	entry.touchedAt = now
	if until, ok := entry.holdDownUntil[d]; ok && now.Before(until) && entry.leaf != nil && entry.leaf != d && !entry.probeArmed {
		return
	}
	if entry.leaf != nil && entry.leaf != d {
		dwellLocked := (stillMember == nil || stillMember(entry.leaf)) && now.Before(entry.pinnedAt.Add(siteStickyMinDwell))
		if dwellLocked && !entry.probeArmed {
			return
		}
		entry.holdDown(entry.leaf, now)
	}
	same := entry.leaf == d
	entry.leaf = d
	entry.lastSuccess = now
	entry.probeArmed = false
	entry.probeNext = false
	if !same {
		entry.pinnedAt = now
		entry.consecutiveSlow = 0
		if entry.triedAlts >= siteStickyMaxAltTries {
			entry.converged = true
		}
	}
	if slow {
		entry.consecutiveSlow++
	} else {
		entry.consecutiveSlow = 0
	}
	if !entry.converged &&
		entry.consecutiveSlow >= siteStickySlowBeforeProbe &&
		entry.triedAlts < siteStickyMaxAltTries &&
		!now.Before(entry.pinnedAt.Add(siteStickyMinDwell)) {
		entry.probeNext = true
	}
}

func (t *siteStickyTable) fail(site string, d *dialer.Dialer, now time.Time) {
	if t == nil {
		return
	}
	key := SiteKey(site)
	if key == "" || d == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.detached {
		return
	}
	entry := t.lookupLocked(key, now)
	if entry == nil {
		t.evictLocked(now)
		entry = &siteStickyEntry{holdDownUntil: make(map[*dialer.Dialer]time.Time), touchedAt: now}
		t.entries[key] = entry
	}
	entry.touchedAt = now
	entry.holdDown(d, now)
	if entry.leaf == d {
		entry.leaf = nil
		entry.consecutiveSlow = 0
		entry.probeNext = false
		entry.probeArmed = false
	}
	if entry.triedAlts >= siteStickyMaxAltTries {
		entry.converged = true
	}
}

func (e *siteStickyEntry) holdDown(d *dialer.Dialer, now time.Time) {
	if e == nil || d == nil {
		return
	}
	if e.holdDownUntil == nil {
		e.holdDownUntil = make(map[*dialer.Dialer]time.Time)
	}
	e.holdDownUntil[d] = now.Add(siteStickyHoldDown)
}

func (e *siteStickyEntry) activityStamp() time.Time {
	if e == nil {
		return time.Time{}
	}
	stamp := e.lastSuccess
	if e.pinnedAt.After(stamp) {
		stamp = e.pinnedAt
	}
	if e.touchedAt.After(stamp) {
		stamp = e.touchedAt
	}
	return stamp
}

func (e *siteStickyEntry) hasActiveHoldDown(now time.Time) bool {
	if e == nil {
		return false
	}
	for _, until := range e.holdDownUntil {
		if now.Before(until) {
			return true
		}
	}
	return false
}

func (t *siteStickyTable) lookupLocked(key string, now time.Time) *siteStickyEntry {
	if t == nil || t.detached || t.entries == nil || key == "" {
		return nil
	}
	entry := t.entries[key]
	if entry == nil {
		return nil
	}
	stamp := entry.activityStamp()
	if !stamp.IsZero() && now.Sub(stamp) > siteStickyTTL && !entry.hasActiveHoldDown(now) {
		delete(t.entries, key)
		return nil
	}
	for d, until := range entry.holdDownUntil {
		if !now.Before(until) {
			delete(entry.holdDownUntil, d)
		}
	}
	if entry.leaf == nil && len(entry.holdDownUntil) == 0 {
		delete(t.entries, key)
		return nil
	}
	return entry
}

func (t *siteStickyTable) evictLocked(now time.Time) {
	if t == nil || len(t.entries) < siteStickyMaxEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for key, entry := range t.entries {
		stamp := entry.activityStamp()
		if stamp.IsZero() {
			stamp = now
		}
		if first || stamp.Before(oldest) {
			oldestKey = key
			oldest = stamp
			first = false
		}
	}
	if oldestKey != "" {
		delete(t.entries, oldestKey)
	}
}

func (t *siteStickyTable) pinMeta(site string, now time.Time) (pinnedAt time.Time, triedAlts int, converged bool, ok bool) {
	if t == nil {
		return time.Time{}, 0, false, false
	}
	key := SiteKey(site)
	if key == "" {
		return time.Time{}, 0, false, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.lookupLocked(key, now)
	if entry == nil || entry.leaf == nil {
		return time.Time{}, 0, false, false
	}
	return entry.pinnedAt, entry.triedAlts, entry.converged, true
}

func (t *siteStickyTable) reclaim(site string, d *dialer.Dialer, now time.Time) {
	if t == nil || d == nil {
		return
	}
	key := SiteKey(site)
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.detached {
		return
	}
	entry := t.lookupLocked(key, now)
	if entry == nil {
		return
	}
	entry.touchedAt = now
	if entry.leaf == d {
		return
	}
	entry.leaf = d
	entry.pinnedAt = now
	entry.lastSuccess = now
	entry.consecutiveSlow = 0
	entry.probeNext = false
	entry.probeArmed = false
}

func (t *siteStickyTable) hit(site string, excluded *dialer.Dialer, now time.Time, admit func(*dialer.Dialer) bool, member func(*dialer.Dialer) bool) (d *dialer.Dialer, extraExclude *dialer.Dialer, hit bool) {
	if t == nil {
		return nil, nil, false
	}
	key := SiteKey(site)
	if key == "" {
		return nil, nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.lookupLocked(key, now)
	if entry == nil || entry.leaf == nil {
		return nil, t.holdDownExcludeLocked(entry, excluded, now), false
	}
	if member != nil && !member(entry.leaf) {
		entry.leaf = nil
		return nil, nil, false
	}
	if entry.leaf == excluded {
		return nil, nil, false
	}
	if admit != nil && !admit(entry.leaf) {
		entry.holdDown(entry.leaf, now)
		failed := entry.leaf
		entry.leaf = nil
		entry.consecutiveSlow = 0
		entry.probeNext = false
		return nil, failed, false
	}
	if entry.probeNext {
		entry.probeNext = false
		entry.probeArmed = true
		entry.triedAlts++
		return nil, entry.leaf, false
	}
	return entry.leaf, nil, true
}

func (t *siteStickyTable) holdDownActive(site string, d *dialer.Dialer, now time.Time) bool {
	if t == nil || d == nil {
		return false
	}
	key := SiteKey(site)
	if key == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.lookupLocked(key, now)
	if entry == nil {
		return false
	}
	until, ok := entry.holdDownUntil[d]
	return ok && now.Before(until)
}

func (t *siteStickyTable) holdDownSet(site string, now time.Time) map[*dialer.Dialer]struct{} {
	if t == nil {
		return nil
	}
	key := SiteKey(site)
	if key == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.lookupLocked(key, now)
	if entry == nil || len(entry.holdDownUntil) == 0 {
		return nil
	}
	out := make(map[*dialer.Dialer]struct{}, len(entry.holdDownUntil))
	for d, until := range entry.holdDownUntil {
		if d != nil && now.Before(until) {
			out[d] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (t *siteStickyTable) holdDownExcludeLocked(entry *siteStickyEntry, excluded *dialer.Dialer, now time.Time) *dialer.Dialer {
	if entry == nil {
		return nil
	}
	var newest *dialer.Dialer
	var newestUntil time.Time
	for d, until := range entry.holdDownUntil {
		if d == nil || d == excluded || !now.Before(until) {
			continue
		}
		if newest == nil || until.After(newestUntil) {
			newest = d
			newestUntil = until
		}
	}
	return newest
}

func (g *DialerGroup) stickyOverride(site string, networkType *dialer.NetworkType, excluded *dialer.Dialer) (d *dialer.Dialer, extraExclude *dialer.Dialer, hit bool) {
	if g == nil || !g.usesSiteSticky() || g.siteSticky == nil {
		return nil, nil, false
	}
	now := g.now()
	admit := func(leaf *dialer.Dialer) bool {
		return g.leafSelectable(leaf, networkType)
	}
	d, extraExclude, hit = g.siteSticky.hit(site, excluded, now, admit, g.hasConcreteMember)
	if !hit {
		return d, extraExclude, false
	}
	if better := g.fallbackStickyReclaim(site, d, networkType, excluded); better != nil {
		g.siteSticky.reclaim(site, better, g.now())
		return better, extraExclude, true
	}
	return d, extraExclude, true
}

// fallbackStickyReclaim returns an earlier fallback member that new connections
// may move to after the pin has aged. It does not migrate established flows.
// Sites that already probed away from a slow first member are left on the pin.
func (g *DialerGroup) fallbackStickyReclaim(site string, pin *dialer.Dialer, networkType *dialer.NetworkType, excluded *dialer.Dialer) *dialer.Dialer {
	if g == nil || pin == nil || g.GetSelectionPolicy() != consts.DialerSelectionPolicy_Fallback {
		return nil
	}
	now := g.now()
	started, triedAlts, converged, ok := g.siteSticky.pinMeta(site, now)
	if !ok || triedAlts > 0 || converged || now.Sub(started) < siteStickyReclaimAfter {
		return nil
	}
	skip := mergeDialerSkip(excluded, g.siteHoldDownSet(site))
	preferred, _, _, _, err := g.selectFirstAdmitted(networkType, g.currentSelectionState(), skip, true)
	if err != nil || preferred == nil || preferred == pin {
		return nil
	}
	if g.fallbackRank(preferred) >= g.fallbackRank(pin) {
		return nil
	}
	return preferred
}

func (g *DialerGroup) fallbackRank(d *dialer.Dialer) int {
	if g == nil || d == nil {
		return 1 << 30
	}
	for i, member := range g.nestedConcreteDialers() {
		if member == d {
			return i
		}
	}
	return 1 << 30
}

func (g *DialerGroup) leafSelectable(d *dialer.Dialer, networkType *dialer.NetworkType) bool {
	if g == nil || d == nil || networkType == nil {
		return false
	}
	if d.AdmissionState(networkType) == dialer.AdmissionDead {
		return false
	}
	set := g.MustGetAliveDialerSet(networkType)
	admitted := d
	if view := g.parentHealthViewForConcrete(d); view != nil {
		admitted = view
	}
	if set != nil {
		return set.IsAlive(admitted)
	}
	return admitted.MustGetAlive(networkType)
}

func (g *DialerGroup) siteHoldDownActive(site string, d *dialer.Dialer) bool {
	if g == nil || g.siteSticky == nil || !g.usesSiteSticky() {
		return false
	}
	return g.siteSticky.holdDownActive(site, d, g.now())
}

func (g *DialerGroup) siteHoldDownSet(site string) map[*dialer.Dialer]struct{} {
	if g == nil || g.siteSticky == nil || !g.usesSiteSticky() {
		return nil
	}
	return g.siteSticky.holdDownSet(site, g.now())
}
