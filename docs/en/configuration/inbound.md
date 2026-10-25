# Inbound (SOCKS5 listeners)

Besides transparent proxying, dae can open ordinary SOCKS5 listeners. Flows accepted by a listener are routed by the
same `routing` section as transparent traffic, and the `inbound()` routing function tells them apart.

```shell
inbound {
    # One sub-section per listener. The name is what inbound() matches.
    s1 {
        listen: '127.0.0.1:1080'
    }
    lan {
        listen: '192.168.1.1:1081'
        username: 'alice'
        password: 'change-me'
    }
}

routing {
    inbound(s1) -> my_group
    inbound(lan) && domain(geosite:cn) -> direct
    !inbound(lan) && dport(25) -> block
    fallback: direct
}
```

## Options

| Key | Default | Meaning |
| --- | --- | --- |
| `protocol` | `socks5` | Only `socks5` is supported. |
| `listen` | required | `ip:port`, IPv6 as `[::1]:1080`. A host name is not accepted. See [IPv6](#ipv6). |
| `username`, `password` | none | RFC 1929 authentication; set both or neither (at most 255 bytes each). |
| `udp` | `true` | Allow `UDP ASSOCIATE`. |
| `resolve` | `local` | `local` or `deferred`. See [Deferred resolution](#deferred-resolution). |
| `sniff` | `auto` | `auto` or `off`. See [Sniffing and FakeIP](#sniffing-and-fakeip). |
| `udp_advertise` | none | IP announced to clients as the UDP relay address. Empty uses the local address of the client's TCP connection. Set it when dae sits behind NAT or port forwarding. |

Names are 1-32 letters, digits, `_` or `-`.

## Safety rules

- Binding an unspecified address (`0.0.0.0`, `[::]`) or a public address **requires** `username` and `password`; the
  configuration is rejected otherwise, so a typo cannot create an open proxy.
- Loopback, private (RFC 1918 / ULA) and link-local addresses may be unauthenticated.
- A listener may not use `tproxy_port` or the same port as another listener.
- `inbound(name)` must refer to a defined inbound; a typo is a configuration error.

## Behavior

- **TCP**: `CONNECT` is supported. `BIND` is not. dae normally dials the outbound first and only then answers the
  client, so a failure is reported with the matching SOCKS5 reply code (`block` rules answer "not allowed by ruleset").
  The exception is a sniffed flow, see below.
- **Domain targets** keep their name for `domain()` rules and domain dialing. dae resolves the IP through its own DNS
  controller (so the `dns` section and its routing apply) because `dip()` rules and the IP version need it. If that
  lookup fails, the connection fails with "host unreachable".
- **UDP**: each `UDP ASSOCIATE` opens a relay socket on the address the client connected to. Every distinct target of the
  association is routed on its own (so `inbound()`, `domain()`, `dip()` apply per destination) and gets its own outbound
  session; replies are only accepted from that target (symmetric NAT). Fragmented datagrams are dropped. The association
  ends with the TCP control connection. Idle sessions expire (17 s for port 53, 5 min for 443/8443, otherwise 30 s) and
  an association holds at most 256 sessions.
- **Reload**: listeners live outside the control plane generations. An unchanged inbound keeps its socket across
  reloads. A removed or changed inbound is closed together with its connections. A listener that cannot bind is
  logged and retried on the next reload; it never stops dae or the other inbounds.
- **Kernel offload**: the eBPF TCP relay offload is not used for these flows.
- `inbound()` is evaluated in user space only. The kernel never sees these flows, so for it `inbound(x)` is constantly
  false (and `!inbound(x)` constantly true); no eBPF program change is involved.

## Deferred resolution

By default (`resolve: local`) a domain target is resolved through dae's DNS first, then routed with the real IP and the
name. That costs a lookup before every new connection, and a name dae's DNS cannot resolve fails with "host
unreachable" even if the rules send it to a proxy that could resolve it.

With `resolve: deferred` the name is routed first, the way a FakeIP flow is:

- Rules that do not read the destination address are evaluated on the name alone. If the verdict is a proxy, the
  proxy is dialed with `host:port` and dae looks nothing up. If it is `block`, the client is refused without a lookup.
- If a rule needs the address (`dip`, `geoip`, `ipversion`), the name is resolved at that point and the rules continue
  with the real IP, exactly as in `local` mode.
- If the verdict is `direct` (or a group whose selected member is direct), the name is resolved and the real address is
  dialed.
- The same applies to every UDP target of an association.

Consequences to weigh before enabling it:

- dae's `dns` section is bypassed for names that go to a proxy: its routing, rewrites and reject rules do not see them.
  The proxy resolves the name with its own DNS.
- A name that dae cannot resolve but the proxy can now works.
- A rule that needs the address and cannot get one still fails the connection.
- `sniff` does not matter for domain targets in either mode; they are never sniffed.

## Sniffing and FakeIP

**Domain targets** (SOCKS5h / remote DNS) already carry the name, so they are never sniffed.

**IP targets** (the client resolved the name itself) hide the name from `domain()` rules and from `dial_mode: domain`.
With `sniff: auto` (the default) dae recovers it from the TLS SNI or HTTP `Host` of the first bytes, exactly like
transparent traffic, and it follows the same policy: `sniffing_timeout`, `dial_mode` and the list of ports that are
never sniffed (SSH, SMTP, databases, ...). Because the client sends nothing until its `CONNECT` is answered, dae
answers **first** and dials afterwards. A dial failure or a `block` verdict on such a flow therefore ends as a closed
connection and not as a SOCKS5 error code. A server-first protocol on a port that is not excluded makes dae wait up to
`sniffing_timeout` before it dials, as for transparent traffic. Set `sniff: off` on an inbound to keep the dial-then-reply behavior and
the precise error codes; domain rules then only see names the client sends. Changing `sniff` restarts that listener
like any other option.

**FakeIP**:

- A domain target never receives a FakeIP: dae resolves the real address through the DNS controller and routes with the
  real IP and the name (or by the name alone with `resolve: deferred`).
- An IP target inside the FakeIP range (the client got it from dae's DNS) is mapped back to its name, so `domain()`
  rules and domain dialing work without sniffing. The name is looked up when the connection is set up, as for
  transparent traffic. If the mapping has expired the connection fails with "host unreachable" unless the flow can be
  sniffed.
- UDP is routed per target in the same way; UDP is never sniffed.

## IPv6

- `listen` takes IPv6 literals: `[::1]:1080`, a ULA such as `[fd00::1]:1080`, or a link-local address with its zone,
  `[fe80::1%eth0]:1080`. `[::]:1080` is dual-stack and serves IPv4 and IPv6 clients on one socket; like `0.0.0.0` it
  needs `username` and `password`.
- Port conflicts follow what the operating system would do: `[::]` conflicts with every address on that port, `0.0.0.0`
  only with IPv4 addresses, so `0.0.0.0:1080` and `[::1]:1080` can coexist.
- The client's control connection and the target are independent. IPv6 clients can reach IPv4 targets and the reverse,
  for `CONNECT` and for `UDP ASSOCIATE` (address type 4 is accepted in requests and datagram headers).
- The UDP relay is opened on the address the client connected to and announced in that family. `udp_advertise` replaces
  it, so give an address of the family your clients use.
- A name that has only AAAA records resolves to its IPv6 address. FakeIP works for IPv6 when `dns.fakeip.inet6_range`
  is set: an IPv6 FakeIP target is mapped back to its name like an IPv4 one.
- In `routing`, write IPv6 literals in quotes, e.g. `dip('fd00::/8')`.

## Admin API, panel and LuCI

- `GET /v1/inbounds` lists every inbound dae knows, wherever it is defined, with its state (`listening`, `pending` when
  the saved definition is not running yet, or `failed` with the bind error), open connections, UDP sessions, and its
  `origin`: `config` (the `inbound` section of `config.dae`), `routing` (`routing.dae`) or `managed` (any other
  included file, e.g. the `local.dae` that the OpenWrt LuCI page generates). Passwords are never returned.
- `PUT /v1/inbounds` replaces the `inbound` section of `config.dae` with the list it is given; inbounds defined
  elsewhere are not touched and cannot be edited this way. A password left out keeps the saved one for that name, an
  empty one removes it. The whole configuration is checked before anything is kept (a name that clashes with an inbound
  in another file, a removed inbound that a rule still uses, an open proxy, a port that is taken by the transparent
  proxy), and the old file is put back when the check fails. Comments inside the replaced section are not kept.
  On success a reload is queued; a port that cannot be bound then shows as `failed` without affecting the others.
- `GET /v1/connections?inbound=NAME` lists only the flows of one inbound; every flow of an inbound carries
  `"inbound": "NAME"`, UDP sessions included.
- `routing.dae` is still served as text. An `inbound` section there has its `password` lines redacted, and saving the
  text back keeps the passwords of inbounds that already existed; a redacted password for a new or renamed inbound is
  refused.
- `dae inbound status -c config.dae` prints `GET /v1/inbounds` as JSON.
- The panel has an **Inbounds** page (state, connections, add / edit / delete for the `config.dae` ones) and an inbound
  column and filter on the connections page.
- On OpenWrt, Services → fdae → Settings has an **Inbounds** table that is rendered into `local.dae`, and shows the
  state of all inbounds. The panel shows those read-only, and the LuCI page does not touch the ones in `config.dae`, so
  the two never overwrite each other. Do not use the same name in both.
