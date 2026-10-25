/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// InboundProtocolSocks5 is the only inbound protocol so far.
const InboundProtocolSocks5 = "socks5"

// inboundNamePattern keeps names usable as a bare routing parameter, i.e.
// inbound(name), without quoting.
var inboundNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$`)

// Inbound is one user-space proxy listener. Flows accepted by it are routed by
// the ordinary routing section and can be told apart with inbound(name).
type Inbound struct {
	Name     string `mapstructure:"_"`
	Protocol string `mapstructure:"protocol" default:"socks5"`
	// Listen is host:port with an IP literal host, e.g. 127.0.0.1:1080 or
	// [::]:1080.
	Listen string `mapstructure:"listen" required:""`
	// Username and Password enable RFC 1929 authentication; both or neither.
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	// UDP enables UDP ASSOCIATE.
	UDP bool `mapstructure:"udp" default:"true"`
	// UDPAdvertise is the IP address told to clients as the UDP relay
	// address. Empty uses the local address of the client's TCP connection,
	// which is right unless dae sits behind NAT or port forwarding.
	UDPAdvertise string `mapstructure:"udp_advertise"`
	// Sniff is "auto" (default) or "off". With auto, a CONNECT to an IP
	// address is answered before dialing so the first client bytes can be
	// sniffed for a TLS SNI / HTTP Host; "off" keeps the reply after the dial
	// so failures reach the client as precise SOCKS5 error codes.
	Sniff string `mapstructure:"sniff" default:"auto"`
	// Resolve is "local" (default) or "deferred". With local, a domain target
	// is resolved first and routed with its real IP. With deferred it is
	// routed by name and only resolved when a rule or a direct dial needs the
	// address, so a proxied name is never looked up by dae.
	Resolve string `mapstructure:"resolve" default:"local"`
}

// Values of Inbound.Sniff.
const (
	InboundSniffAuto = "auto"
	InboundSniffOff  = "off"
)

// Values of Inbound.Resolve.
const (
	InboundResolveLocal    = "local"
	InboundResolveDeferred = "deferred"
)

// DeferResolve reports whether domain targets are routed before resolving.
func (in Inbound) DeferResolve() bool {
	return strings.EqualFold(in.Resolve, InboundResolveDeferred)
}

// SniffEnabled reports whether TCP sniffing is allowed for this inbound.
func (in Inbound) SniffEnabled() bool {
	return !strings.EqualFold(in.Sniff, InboundSniffOff)
}

// HasAuth reports whether clients must authenticate.
func (in Inbound) HasAuth() bool {
	return in.Username != "" || in.Password != ""
}

// ListenAddrPort parses Listen.
func (in Inbound) ListenAddrPort() (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(in.Listen))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("listen must be host:port: %w", err)
	}
	if host == "" {
		return netip.AddrPort{}, fmt.Errorf("listen must include an IP address (use 0.0.0.0 or [::] for all addresses)")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("listen host %q is not an IP address", host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("listen port %q is invalid", portStr)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// ValidateInboundName reports whether name can be used as an inbound name.
func ValidateInboundName(name string) error {
	if !inboundNamePattern.MatchString(name) {
		return fmt.Errorf("invalid inbound name %q: use 1-32 letters, digits, '_' or '-'", name)
	}
	return nil
}

func inboundListenConflict(a, b netip.AddrPort) bool {
	if a.Port() != b.Port() {
		return false
	}
	x, y := a.Addr().Unmap(), b.Addr().Unmap()
	return x == y || inboundWildcardCovers(x, y) || inboundWildcardCovers(y, x)
}

// inboundWildcardCovers reports whether binding w also takes other's port.
// [::] is dual-stack and covers every address; 0.0.0.0 covers IPv4 only, so it
// does not clash with a specific IPv6 address such as [::1].
func inboundWildcardCovers(w, other netip.Addr) bool {
	switch {
	case !w.IsUnspecified():
		return false
	case w.Is6():
		return true
	default:
		return other.Is4()
	}
}

// ValidateInbounds checks every inbound on its own and against the others.
// tproxyPort is the transparent proxy port, which an inbound must not shadow.
func ValidateInbounds(inbounds []Inbound, tproxyPort uint16) error {
	names := make(map[string]struct{}, len(inbounds))
	ids := make(map[uint32]string, len(inbounds))
	listens := make([]netip.AddrPort, 0, len(inbounds))
	for _, in := range inbounds {
		if err := ValidateInboundName(in.Name); err != nil {
			return err
		}
		if _, dup := names[in.Name]; dup {
			return fmt.Errorf("inbound %q is defined more than once", in.Name)
		}
		names[in.Name] = struct{}{}
		id := consts.InboundID(in.Name)
		if other, clash := ids[id]; clash {
			return fmt.Errorf("inbound %q and %q have colliding identities; rename one of them", in.Name, other)
		}
		ids[id] = in.Name

		if !strings.EqualFold(in.Protocol, InboundProtocolSocks5) {
			return fmt.Errorf("inbound %q: unsupported protocol %q (want %s)", in.Name, in.Protocol, InboundProtocolSocks5)
		}
		listen, err := in.ListenAddrPort()
		if err != nil {
			return fmt.Errorf("inbound %q: %w", in.Name, err)
		}
		if tproxyPort != 0 && listen.Port() == tproxyPort {
			return fmt.Errorf("inbound %q: listen port %d is the tproxy_port", in.Name, listen.Port())
		}
		for _, other := range listens {
			if inboundListenConflict(listen, other) {
				return fmt.Errorf("inbound %q: listen %v conflicts with another inbound (%v)", in.Name, listen, other)
			}
		}
		listens = append(listens, listen)

		if (in.Username == "") != (in.Password == "") {
			return fmt.Errorf("inbound %q: username and password must be set together", in.Name)
		}
		if len(in.Username) > 255 || len(in.Password) > 255 {
			return fmt.Errorf("inbound %q: username and password must be at most 255 bytes", in.Name)
		}
		if !in.HasAuth() {
			addr := listen.Addr()
			switch {
			case addr.IsUnspecified():
				return fmt.Errorf("inbound %q: binding %v without username/password would expose an open proxy", in.Name, addr)
			case !(addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()):
				return fmt.Errorf("inbound %q: binding the public address %v without username/password would expose an open proxy", in.Name, addr)
			}
		}
		if sniff := strings.ToLower(in.Sniff); sniff != "" && sniff != InboundSniffAuto && sniff != InboundSniffOff {
			return fmt.Errorf("inbound %q: sniff %q is invalid (want %s or %s)", in.Name, in.Sniff, InboundSniffAuto, InboundSniffOff)
		}
		if resolve := strings.ToLower(in.Resolve); resolve != "" && resolve != InboundResolveLocal && resolve != InboundResolveDeferred {
			return fmt.Errorf("inbound %q: resolve %q is invalid (want %s or %s)", in.Name, in.Resolve, InboundResolveLocal, InboundResolveDeferred)
		}
		if in.UDPAdvertise != "" {
			if _, err := netip.ParseAddr(in.UDPAdvertise); err != nil {
				return fmt.Errorf("inbound %q: udp_advertise %q is not an IP address", in.Name, in.UDPAdvertise)
			}
		}
	}
	return nil
}

// ValidateInboundReferences rejects inbound(name) predicates that name an
// inbound the configuration does not define. A typo would otherwise silently
// make the rule dead.
func ValidateInboundReferences(rules []*config_parser.RoutingRule, inbounds []Inbound) error {
	defined := make(map[string]struct{}, len(inbounds))
	for _, in := range inbounds {
		defined[in.Name] = struct{}{}
	}
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		for _, f := range rule.AndFunctions {
			if f == nil || f.Name != consts.Function_Inbound {
				continue
			}
			if len(f.Params) == 0 {
				return fmt.Errorf("routing: %v() requires at least one inbound name", consts.Function_Inbound)
			}
			for _, p := range f.Params {
				if p.Key != "" {
					return fmt.Errorf("routing: %v() does not accept the key %q", consts.Function_Inbound, p.Key)
				}
				if err := ValidateInboundName(p.Val); err != nil {
					return fmt.Errorf("routing: %w", err)
				}
				if _, ok := defined[p.Val]; !ok {
					return fmt.Errorf("routing: %v(%v) refers to an inbound that is not defined in section \"inbound\"", consts.Function_Inbound, p.Val)
				}
			}
		}
	}
	return nil
}

func patchInbound(params *Config) error {
	if err := ValidateInbounds(params.Inbound, params.Global.TproxyPort); err != nil {
		return err
	}
	return ValidateInboundReferences(params.Routing.Rules, params.Inbound)
}
