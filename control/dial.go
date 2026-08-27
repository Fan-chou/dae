/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type proxyDialParam struct {
	Outbound    consts.OutboundIndex
	Must        bool
	Domain      string
	Mac         [6]uint8
	Dscp        uint8
	ProcessName [16]uint8
	Src         netip.AddrPort
	Dest        netip.AddrPort
	Mark        uint32
	Network     string         // e.g. "tcp", "udp"
	Excluded    *dialer.Dialer // Dialer to exclude in selection
	// IdentifiedQuic is set by the UDP GetDialOption path. TCP leaves it false.
	IdentifiedQuic bool
}

type proxyDialResult struct {
	OutboundIndex consts.OutboundIndex
	Outbound      *ob.DialerGroup
	Dialer        *dialer.Dialer
	DialTarget    string
	Network       string
	Mark          uint32
	Must          bool
	SniffedDomain string
	// StickySite is the fallback/url_test pin key. It may be a dest IP when
	// the flow has no sniffed name; it must not replace SniffedDomain.
	StickySite string
	IsDialIp   bool
	// PinnedFakeIPRealDest is set when FakeIP rematch replaced the dest with
	// a resolved real IP for direct (or a direct leaf). UDP must keep that
	// IP; rewriting it to domain:port would let the system resolver bounce
	// back into the FakeIP pool.
	PinnedFakeIPRealDest    bool
	OrigNetworkType         string
	SelectionNetworkType    string
	OrigNetworkTypeObj      *dialer.NetworkType
	SelectionNetworkTypeObj *dialer.NetworkType
	AdmissionNetworkTypeObj *dialer.NetworkType
	// SelectPath is the nested member and sticky tables used by this Select.
	// Slow-handshake and established-flow snapshots must keep this token.
	SelectPath ob.SelectPath
}

func shouldForceMarkUnavailableOnProxyDialError(err error) bool {
	if err == nil {
		return false
	}
	return commonerrors.IsNetworkUnreachable(err) || commonerrors.IsAddressNotSuitable(err)
}

func notifyProxyDialerHealthCheck(d *dialer.Dialer, l4proto consts.L4ProtoStr, err error) {
	if d == nil || err == nil {
		return
	}
	if commonerrors.IsCanceledOrClosed(err) || !isProxyBackedDialer(d) {
		return
	}
	if l4proto == consts.L4ProtoStr_UDP {
		d.NotifyCheckDnsUdp()
		return
	}
	d.NotifyCheckTcp()
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

func endpointNetworkTypeForSelection(requestedNetworkType *dialer.NetworkType, admissionNetworkType *dialer.NetworkType) *dialer.NetworkType {
	if requestedNetworkType == nil {
		return nil
	}
	endpointType := *requestedNetworkType
	if admissionNetworkType != nil && admissionNetworkType.IpVersion != "" {
		endpointType.IpVersion = admissionNetworkType.IpVersion
	}
	if endpointType.L4Proto == consts.L4ProtoStr_UDP {
		endpointType.IsDns = false
		endpointType.UdpHealthDomain = dialer.UdpHealthDomainData
	}
	return &endpointType
}

func (c *ControlPlane) chooseProxyDialer(ctx context.Context, p *proxyDialParam) (*proxyDialResult, error) {
	outboundIndex := p.Outbound
	domain := p.Domain
	src := p.Src
	dst := p.Dest
	mark := p.Mark
	must := p.Must

	domain, err := c.resolveFakeIPDomain(domain, dst.Addr())
	if err != nil {
		return nil, err
	}

	fakeDest := c.destIsFakeIP(dst.Addr())
	stickySite := stickySelectHost(domain, dst.Addr(), fakeDest)
	if fakeDest {
		// Kernel tproxy always marks FakeIP as 0xFD, but a stale conn_state
		// DIRECT/group result must not skip name-based reroute.
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	dialTarget, shouldReroute, dialIp := c.ChooseDialTarget(outboundIndex, dst, domain)
	if shouldReroute {
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	pinnedFakeIPRealDest := false
	if outboundIndex == consts.OutboundControlPlaneRouting {
		routingResult := &bpfRoutingResult{
			Mark:     mark,
			Mac:      p.Mac,
			Outbound: uint8(p.Outbound),
			Pname:    p.ProcessName,
			Dscp:     p.Dscp,
		}
		var newMark uint32
		var realIP netip.Addr
		proto := consts.L4ProtoType_TCP
		if p.Network == "udp" {
			proto = consts.L4ProtoType_UDP
		}
		if fakeDest {
			outboundIndex, newMark, must, realIP, err = c.routeFakeIP(ctx, src, dst, domain, proto, routingResult)
			if err != nil {
				return nil, err
			}
		} else if outboundIndex, newMark, must, err = c.Route(
			src,
			dst,
			domain,
			proto,
			routingResult,
		); err != nil {
			return nil, err
		}
		mark = newMark
		// Reset dialTarget.
		dialTarget, _, dialIp = c.ChooseDialTarget(outboundIndex, dst, domain)
		if fakeDest && realIP.IsValid() && c.fakeIPShouldPinRealDest(outboundIndex) {
			dst = netip.AddrPortFrom(realIP, dst.Port())
			dialTarget = dst.String()
			dialIp = true
			pinnedFakeIPRealDest = true
		}
		c.log.Tracef("outbound rerouted: %v => %v",
			consts.OutboundControlPlaneRouting.String(),
			outboundIndex.String(),
		)
	}

	if err := c.guardFakeIPOutbound(outboundIndex, dst.Addr()); err != nil {
		return nil, err
	}
	dialTarget, dialIp, err = c.rewriteFakeIPDialTarget(domain, dst, dialTarget, dialIp)
	if err != nil {
		return nil, err
	}

	if mark == 0 {
		mark = c.soMarkFromDae
	}

	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			return nil, fmt.Errorf("traffic was dropped due to no-load configuration")
		}
		return nil, fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}

	outbound := c.outbounds[outboundIndex]
	networkType := &dialer.NetworkType{
		L4Proto:         consts.L4ProtoStr(p.Network),
		IpVersion:       consts.IpVersionFromAddr(dst.Addr()),
		IsDns:           false,
		UdpHealthDomain: dialer.UdpHealthDomainData,
	}

	// For UDP, ensure dialer's address family matches client's to prevent
	// "non-IPv4/IPv6 address" errors when writing responses.
	// FakeIP direct pin uses the resolved real family so ipversion() and the
	// WAN dest follow the real A/AAAA, not the client's FakeIP v4 socket.
	selectionNetworkType := networkType
	if p.Network == "udp" && !pinnedFakeIPRealDest {
		if clientIpVersion := consts.IpVersionFromAddr(src.Addr()); clientIpVersion != networkType.IpVersion {
			selectionNetworkType = &dialer.NetworkType{
				L4Proto:         networkType.L4Proto,
				IpVersion:       clientIpVersion,
				IsDns:           false,
				UdpHealthDomain: dialer.UdpHealthDomainData,
			}
		}
	}

	strictIpVersion := dialIp
	d, _, admissionNetworkType, selectPath, err := outbound.SelectWithPath(selectionNetworkType, strictIpVersion, p.Excluded, stickySite)
	if err == ob.ErrNoAliveDialer {
		// Fallback for UDP/TCP: if selection failed (probably due to health check fail),
		// try the other IP version if strictIpVersion is not absolutely required by domain routing.
		altType := alternateNetworkType(selectionNetworkType)
		d, _, admissionNetworkType, selectPath, err = outbound.SelectWithPath(altType, false, p.Excluded, stickySite)
		if err == nil {
			selectionNetworkType = altType
		}
	}

	if err != nil {
		return &proxyDialResult{
			OutboundIndex:           outboundIndex,
			Outbound:                outbound,
			Must:                    must,
			IsDialIp:                strictIpVersion,
			OrigNetworkType:         networkType.StringWithoutDns(),
			SelectionNetworkType:    selectionNetworkType.StringWithoutDns(),
			OrigNetworkTypeObj:      networkType,
			SelectionNetworkTypeObj: selectionNetworkType,
			AdmissionNetworkTypeObj: admissionNetworkType,
		}, fmt.Errorf("select dialer from group %v (orig:%v sel:%v src:%v): %w",
			outbound.Name,
			networkType.StringWithoutDns(),
			selectionNetworkType.StringWithoutDns(),
			p.Src.String(),
			err,
		)
	}

	selectionNetworkType = endpointNetworkTypeForSelection(selectionNetworkType, admissionNetworkType)

	res := &proxyDialResult{
		OutboundIndex: outboundIndex,
		Outbound:      outbound,
		Dialer:        d,
		DialTarget:    dialTarget,
		Network: func() string {
			if p.Network == "udp" {
				return common.MagicNetworkWithIPVersion(p.Network, mark, c.mptcp, string(selectionNetworkType.IpVersion))
			}
			return common.MagicNetwork(p.Network, mark, c.mptcp)
		}(),
		SniffedDomain:           domain,
		StickySite:              stickySite,
		Mark:                    mark,
		Must:                    must,
		IsDialIp:                strictIpVersion,
		PinnedFakeIPRealDest:    pinnedFakeIPRealDest,
		OrigNetworkType:         networkType.StringWithoutDns(),
		SelectionNetworkType:    selectionNetworkType.StringWithoutDns(),
		OrigNetworkTypeObj:      networkType,
		SelectionNetworkTypeObj: selectionNetworkType,
		AdmissionNetworkTypeObj: admissionNetworkType,
		SelectPath:              selectPath,
	}
	// Reject identified QUIC before resolve_dns. A failing lookup must not
	// hide REJECT-NO-DROP behind a DNS error (no ICMP, client waits out the
	// handshake instead of falling back to HTTP/2).
	if p.IdentifiedQuic && c.shouldRejectProxiedQuic(d, true) {
		return res, ErrQuicAdministrativelyProhibited
	}
	if err := c.applyProxyResolveDNS(ctx, p, res); err != nil {
		return res, err
	}
	if p.Network == "tcp" && res.Dialer != nil && res.Dialer.ResolveDNS().IsValid() {
		preferV6 := p.Dest.Addr().Is6() && !p.Dest.Addr().Is4In6()
		c.prefetchProxyResolveDNS(domain, preferV6, p.Src, p.Mac, mark, p.ProcessName)
	}
	if err := c.ensureUdpDialTargetIP(ctx, p, res); err != nil {
		return res, err
	}
	return res, nil
}

func (c *ControlPlane) routeDial(ctx context.Context, p *proxyDialParam) (netproxy.Conn, *proxyDialResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastRes *proxyDialResult
	var lastErr error
	for attempt := range 2 {
		res, err := c.chooseProxyDialer(ctx, p)
		if err != nil {
			return nil, res, err
		}
		lastRes = res

		dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		start := time.Now()
		conn, err := res.Dialer.DialContext(dialCtx, res.Network, res.DialTarget)
		handshake := time.Since(start)
		cancel()
		if err == nil {
			slow := res.Dialer.ObserveHandshake(res.SelectionNetworkTypeObj, handshake)
			if attempt == 0 && slow && c.canExcludeSlowHandshake(res) {
				_ = conn.Close()
				res.Outbound.FailSitePath(siteFailDomain(res, p.Domain), res.Dialer, res.SelectPath)
				p.Excluded = res.Dialer
				lastErr = fmt.Errorf("slow handshake %s", handshake.Truncate(time.Millisecond))
				lastRes = res
				continue
			}
			return conn, res, nil
		}
		lastErr = err
		if res.Outbound != nil && !commonerrors.IsCanceledOrClosed(err) {
			res.Outbound.FailSitePath(siteFailDomain(res, p.Domain), res.Dialer, res.SelectPath)
		}
		if attempt > 0 || !shouldForceMarkUnavailableOnProxyDialError(err) {
			l4proto := consts.L4ProtoStr(p.Network)
			if res.SelectionNetworkTypeObj != nil {
				l4proto = res.SelectionNetworkTypeObj.L4Proto
			}
			notifyProxyDialerHealthCheck(res.Dialer, l4proto, err)
			return nil, res, err
		}
		if res.SelectionNetworkTypeObj != nil {
			res.Dialer.ReportUnavailableForced(
				res.SelectionNetworkTypeObj,
				fmt.Errorf("proxy dial failed: %w", err),
			)
		}
	}
	return nil, lastRes, lastErr
}

// stickySelectHost prefers a sniffed domain. When the flow is IP-only (no
// SNI / FakeIP name), the destination unicast IP becomes the sticky subject so
// fallback/url_test can pin the same node for that address.
func stickySelectHost(domain string, dst netip.Addr, fakeIP bool) string {
	if ob.SiteKey(domain) != "" {
		return domain
	}
	if fakeIP || !dst.IsValid() {
		return domain
	}
	if key := ob.SiteKey(dst.Unmap().String()); key != "" {
		return key
	}
	return domain
}

func siteFailDomain(res *proxyDialResult, domain string) string {
	if res != nil {
		if res.StickySite != "" {
			return res.StickySite
		}
		if res.SniffedDomain != "" {
			return res.SniffedDomain
		}
	}
	return domain
}

func pinSiteSubject(sticky, sniffed string) string {
	if sticky != "" {
		return sticky
	}
	return sniffed
}

func (c *ControlPlane) canExcludeSlowHandshake(res *proxyDialResult) bool {
	if res == nil || res.Outbound == nil || res.Dialer == nil || res.SelectionNetworkTypeObj == nil {
		return false
	}
	if !res.SelectPath.HasSiteSticky() {
		return false
	}
	d, _, _, err := res.Outbound.SelectWithExclusionResultForSite(res.SelectionNetworkTypeObj, res.IsDialIp, res.Dialer, res.StickySite)
	return err == nil && d != nil && d != res.Dialer
}
