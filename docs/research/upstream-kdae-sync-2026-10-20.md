# Upstream sync, 2026-10-20 (follow-up to the 2026-10-10 sync)

Previous review point: olicesx/dae `kdae` `2064c47a` (see
`upstream-kdae-sync-2026-10-10.md`). New upstream head: `e52e96f1` (2026-10-18),
five commits ahead. `kdae` has no other new activity; the other upstream
branches are all older than the last review (newest: `fix/netns-1109-auto-recovery`,
2026-09-20) and were not re-audited one by one.

Dependency forks: olicesx/quic-go pin is still `44a1f9eb` (no change). olicesx/outbound
moved `131419a` -> `1cf3439` (16 commits, none present in the fdae pin `909593ea`).

## dae: the five new commits

| Commit | What | Disposition |
|---|---|---|
| `3a001447` | learn sniffed TLS SNI into a new kernel LRU map `sni_routing_map` | not carried |
| `4893a72f` | bind `sni_routing_map` in the mandatory load pass (the first commit left it nil at runtime) | not carried |
| `eb510872` | skip TCP sniffing via an SNI consult with 30 s sampled verification | not carried |
| `79ade167`, `e52e96f1` | outbound pins | not carried as pins; the outbound content is handled below |

Why the SNI trio is held back:

- A trial cherry-pick of the three onto `fdae` (throwaway worktree) conflicts in 9
  files: `component/sniffing/{sniffer.go,benchmark_test.go,http_test.go}`,
  `config/config.go`, `control/control_plane.go`, `control/routing_matcher_builder.go`,
  both `routing.md` files and `example.dae`.
- It adds a BPF map, a hand-mirrored `bpfDataplaneMaps` field and about 600 lines in
  `control/sni_learning.go`. The second commit exists only because the first shipped
  a map that stayed nil at runtime, which upstream found live.
- The gain is kernel routing for connections DNS never saw. 223 runs fakeip, so most
  traffic is DNS-visible. This is an inference; the share of connections that fall to
  a userspace re-sniff on 223 was not measured.
- If it is ever taken, take all three together, including the `bpfDataplaneMaps` /
  `assignDataplaneToBpf` binding.

## outbound: carried

Branch `sync/upstream-20261020-vision` on `Fan-chou/outbound` (pushed), commit
`2f4699a` and `821f690` on top of `909593ea`, both pushed. dae pin: `c3d97c5c` then the bump to `821f690` on `fdae` (local, fdae not pushed).

- Vision TLS 1.3 framing and DirectCopy transition aligned with Xray-core:
  net of olicesx `2cec762` + `3732570` (`ed6e705`, `0fb28f7`); `protocol/vless/**`,
  applied 3-way, no conflicts. This also makes the dialer accept
  `xtls-rprx-vision-udp443`.
- `FilterTLS` bound on `session_id_len` (hunk of `b2a8211`). The fdae pin panicked
  on a malformed ServerHello (`slice bounds out of range [299:79]`; a length of 33
  also forged a cipher suite). Missed in the 2026-10-10 sync.
- simpleobfs: `http.NewRequest` error returned instead of dereferencing a nil
  request, bare IPv6 host bracketed (hunk of `b2a8211`). The
  `WriteDeadlineClosesSession` forwarder from the same commit is NOT carried: the
  fork has no `netproxy.WriteDeadlineClosesSession`.

- hysteria2 + UDP port hopping through a proxy chain (port of `b54af9a`, commit
  `821f690` on the same outbound branch, pushed and pinned in dae). `udpHopPacketConn` always advertised the OOB/batch/`SyscallConn`
  surface; when each hop's underlay is a `netproxy.FakeNetPacketConn` (any proxied
  `nextDialer`), `SyscallConn` returns an error and quic-go's `newConn`
  (`sys_conn_oob.go`) aborts the dial, so such a node could never connect. The hop
  conn is now wrapped so only `net.PacketConn` is exposed when the underlay has no
  `syscall.Conn`; direct dials keep GSO/ECN/batch reads. Evidence: the new
  `oob_surface_test.go` fails on the old source (advertises
  `OOBCapablePacketConn`, `SyscallConn`, `ReadBatch`) and passes after; the
  raw-UDP case is unchanged. The existing
  `TestUDPHopPacketConnFreezesResolvedIPForSubsequentHops` asserted the concrete
  type and was adjusted to unwrap. `go test -short -race ./protocol/hysteria2/...`
  passes. Not exercised end to end against a real hysteria2 server, and whether
  any node in use is hy2 + port hopping + chain was not checked.

Not carried (same reasoning as 2026-10-10):

- UDP batch writers across vless, vmess, trojan, juicity, shadowsocks, ss2022, ssr,
  hysteria2/tuic (`272bada`, `bbc886e`, `02273f5`, `3f30f91`, `df843af`, `7dc6884`,
  `2a35d62`, `ac584f8`, `d0a0e74`): default-on batching adds up to 1 ms tail latency
  and upstream's measured gain was on the anytls UoT path.
- anytls session-writer pipeline (`75a7195`): upstream's own pin message says its r11
  measurement rejected it.

## Validation

- Unit, before/after (old pin `909593ea` vs `2f4699a`):
  - `FilterTLS` hostile-length tests: panic before, pass after.
  - simpleobfs bare-IPv6 first-request test: nil-deref panic before, pass after.
  - `TestE2EVlessVisionInnerTLS13DirectCopy`: hangs (30 s timeout) on the old code,
    passes on the new. Its server is the in-test server written to the post-fix
    semantics, not Xray itself.
  - `TestNewDialerAcceptsVisionUDP443Flow`: fails before, passes after.
  - the new `padding_test.go` does not compile against the old code (different
    function signature); recorded, not a result.
- outbound: `go build ./...`, `go vet`, `go test -short ./...`, and `-race -short` on
  `protocol/vless/...` and `transport/simpleobfs`.
- dae built against the new pin (`go build ./...`, `go vet`, `go test -short` on
  `control cmd component common`, `make dae`); `go mod verify` clean.
- Live interop on 220, loopback only (nothing in `/etc`, no routes, no services):
  - Servers: sing-box 1.14.3 and Xray-core 26.3.27 (sha256 checked against the
    release `.dgst`), outer TLS.
  - Inner traffic: TLS 1.3, TLS 1.2, plain HTTP, and VLESS without `flow`.
  - Per cell: 4 x 8 MB download with sha256, 4 MB upload with sha256, 200 short
    connections (10 of them concurrent), 10 UDP echoes.
  - 128 checks (2 servers x 2 pins x 4 cells x 4 tests): all passed, 0 failures,
    for both pins. The old pin also passes everything, so this run is a regression
    check only and does NOT confirm the Vision fix.
  - Not verified: that the loopback runs actually reached the DirectCopy switch.
- `dae --version` and `dae validate -c example.dae` ran on 220 with the new binary
  (exit 0). No `dae run`.

## NOT done

- dae datapath (tproxy, BPF load, `dae reload`) was not exercised on the new pin.
  220 is a personal workstation; the field path used before is 220 -> 223, and
  223 is the production gateway, so installing the binary there is the user's call.
- simpleobfs has no live test: sing-box has no simple-obfs server and 220 has no
  `obfs-server`.
- No `-race` run of the whole dae tree on the new pin.

## Still open from earlier syncs

- `netproxy.WriteDeadlineClosesSession` (and the forwarders that use it, e.g. the
  simpleobfs one in `b2a8211`): still absent from the fork; only worth porting with
  the other wrappers that need it.
- Stop writing the write-only `routing_epoch_map` (small part of `06451485`).
- DNS truncation / datapath family and `42b70886`: unchanged from 2026-10-10.
