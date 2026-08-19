/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// HealthDialerCache reuses one Dialer per (node identity, probe parameters).
// Overlapping Mihomo url-test groups otherwise Clone the same node N times and
// run N independent TCP/UDP probe loops.
type HealthDialerCache struct {
	mu    sync.Mutex
	byKey map[string]*dialer.Dialer
}

func healthDialerIdentity(d *dialer.Dialer) string {
	if d == nil {
		return ""
	}
	p := d.Property()
	if p != nil && p.Link != "" {
		return "link:" + p.Link
	}
	if p != nil && p.Name != "" {
		return "name:" + p.Name
	}
	return fmt.Sprintf("ptr:%p", d)
}

func healthOptionFingerprint(opt *dialer.GlobalOption) string {
	if opt == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "iv=%d;tol=%d;dns_tcp=%t;method=%s;tcp=%s;udp=%s",
		opt.CheckInterval,
		opt.CheckTolerance,
		opt.CheckDnsTcp,
		opt.TcpCheckOptionRaw.Method,
		strings.Join(opt.TcpCheckOptionRaw.Raw, ","),
		strings.Join(opt.CheckDnsOptionRaw.Raw, ","),
	)
	return b.String()
}

func healthDialerCacheKey(src *dialer.Dialer, option *dialer.GlobalOption) string {
	return healthDialerIdentity(src) + "\x00" + healthOptionFingerprint(option)
}

func (c *HealthDialerCache) ensureMapLocked() {
	if c.byKey == nil {
		c.byKey = make(map[string]*dialer.Dialer)
	}
}

// Remember records an existing dialer so a later ReuseOrClone with the same
// node identity and probe parameters can return it instead of cloning.
func (c *HealthDialerCache) Remember(d *dialer.Dialer) {
	if c == nil || d == nil {
		return
	}
	key := healthDialerCacheKey(d, d.GlobalOption)
	if key == "\x00" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureMapLocked()
	if _, exists := c.byKey[key]; !exists {
		c.byKey[key] = d
	}
}

// ReuseOrClone returns src when it already has the requested probe parameters,
// otherwise a shared clone. created is true only for a newly allocated clone.
func (c *HealthDialerCache) ReuseOrClone(src *dialer.Dialer, option *dialer.GlobalOption) (d *dialer.Dialer, created bool) {
	if src == nil {
		return nil, false
	}
	if option == nil {
		option = src.GlobalOption
	}
	if healthOptionFingerprint(src.GlobalOption) == healthOptionFingerprint(option) {
		return src, false
	}
	if c == nil {
		return src.CloneWithGlobalOptionContext(context.Background(), option), true
	}
	key := healthDialerCacheKey(src, option)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureMapLocked()
	if existing, ok := c.byKey[key]; ok {
		return existing, false
	}
	cloned := src.CloneWithGlobalOptionContext(context.Background(), option)
	c.byKey[key] = cloned
	return cloned, true
}

// CloneShared always returns a clone (never src) so a parent health view can
// keep independent alive state even when probe parameters match the leaf.
// Equivalent clones are still shared across groups.
func (c *HealthDialerCache) CloneShared(src *dialer.Dialer, option *dialer.GlobalOption) (d *dialer.Dialer, created bool) {
	if src == nil {
		return nil, false
	}
	if option == nil {
		option = src.GlobalOption
	}
	if c == nil {
		return src.CloneWithGlobalOptionContext(context.Background(), option), true
	}
	key := healthDialerCacheKey(src, option) + "\x00view"
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureMapLocked()
	if existing, ok := c.byKey[key]; ok {
		return existing, false
	}
	cloned := src.CloneWithGlobalOptionContext(context.Background(), option)
	c.byKey[key] = cloned
	return cloned, true
}
