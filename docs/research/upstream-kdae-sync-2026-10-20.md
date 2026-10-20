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

## Addendum: second pass over olicesx/outbound fixes not in the pin

`git cherry` between the fdae pin and `1cf3439` lists 141 patches without a match.
Most are the perf stack, bbr3, batching or refactors (not carried, see above) or were
already picked under a different patch id. The standalone correctness fixes were
triaged by dropping each commit's own `_test.go` files onto the pin and running them,
and by trial cherry-picks where a commit has no tests. The result is on the branch
`sync/upstream-20261020-fixes`, 4 commits on top of `821f690`, pushed to `Fan-chou/outbound` and pinned in dae
(`17ab089`).

Carried on that branch (all builds, `go vet`, `go test -short ./...` pass; the touched
packages also under `-race`):

- `fe8ca1b` SS2022 UDP replay window: the bit-level shift went the wrong way, so the
  filter accepted replays and rejected fresh packets (minimal case:
  `CheckAndUpdate(100)`, `(107)`, `(100)` must reject the last). Also validates before
  committing the window and stops count-based eviction of sessions still inside
  `SaltStorageDuration`. Upstream's tests fail on the pin and pass after; applies clean.
- `887df86` hysteria2 FastOpen: caller deadlines are preserved across the deferred
  response read (its two tests fail on the pin). It needed the FastOpen half of
  `55518b1` first (dial deadline re-armed around `readFastOpenResponse`); the other
  halves of `55518b1` do not apply (the fork's `udpConn` already uses deadline
  objects and already returns the datagram-dropped contract on a short buffer).
- `8f8f64f` (conflicts in `header.go` and `reality.go` resolved by hand; upstream's
  `CongestionOverride` is not carried):
  - vmess `ReqInstructionDataFromPool` left the request padding region untouched, and
    the pool does not zero, so up to 15 bytes of a previous user's buffer were sent to
    the server on every connection. Found by reading the diff; no test exercises it.
  - REALITY `spiderX` was parsed with `url.Parse`/`http.NewRequest` and the errors were
    discarded, so a value such as `/\x00` panicked at load (upstream's spiderX test
    fails on the pin; spiderX comes from the node link).
  - the vmess `InitContext` length check is server-side only and does not matter for
    dae as a client.

Looked at and deliberately not carried:

- `d4ee68e` (short `ss:` / `ssr:` links) and `d605198` (UDP underlay closed when the
  cipher is rejected late). The parsers do panic when called directly with `ss:x`
  (checked before and after), but the link dispatcher only hands them links that
  already start with `ss://` / `ssr://`, and a probe through
  `NewNetproxyDialerFromLink` did not panic on the pin. So the "reachable from a
  subscription" claim does not hold; they were taken back out as unproven.
- `ab18b74` vmess sticky write-init error: server-side response path only.
- `143113c` grpc canceller, `b4a12a4` mux idempotent Close, `1a21f16` ssr http_simple
  reassembly, `2400eca` naive GOAWAY retry, `87f3d8a` SS2022 expired-timestamp error:
  apply clean and are small, but have no test and no evidence of impact here.
- `aba8749`, `92845447`, `d960282`, `87f3d8a`-adjacent wrappers: need
  `netproxy.WriteDeadlineClosesSession` and the coalesce/wrapper stack the fork lacks.
- `aa033b7` (tuic deadline timers), `6742469` (tuic datagram queue), `c90a148`
  (anytls UDP framing), `0f24c13`, `8396fb0` (REALITY retries): conflict with fork code
  that is already restructured; not reviewed further.

`2735b84` (direct UDP receiver) needs no port; the earlier note here that it was "open
and worth a careful manual port" was wrong. The cherry-pick conflicted because the fork
already fixed both problems in its own way:

- fd reuse between `recvfrom` and close: `directPacketReceiverEntry.receive` runs the
  peek and the recv inside `raw.Control`, which holds the socket reference, so close is
  deferred until the callback returns. `TestDirectPacketReceiverCloseProtectsInFlightRead`
  pauses a read in flight, closes the socket and checks it (100 runs under `-race`: pass).
- fatal `EpollWait` error: `packetReceiverRegistry.fail` delivers an error to registered
  endpoints and leaves the registry unusable, so `register` returns false and dae
  (`control/udp_endpoint_pool.go`, `startTransportReceiver() == false` -> `go
  ue.startReadLoop()`) falls back to a blocking `ReadFrom` loop per endpoint; new sockets
  are not blackholed. Covered by `TestDirectPacketReceiverFailureRetiresRegistry`.
- upstream's version holds the registry read lock across the syscalls and adds a
  per-entry pending queue; porting it would add locking to the hot path for no gain.
- `git diff 909593ea 17ab089 -- protocol/direct netproxy pool` is empty: the direct UDP
  receive code is identical before and after this session's pin changes.

## Addendum: unified test on 220 (functional matrix and performance A/B)

Old = outbound `909593ea` (pin before this session), new = `17ab089` (current pin). dae
itself is unchanged between the two (`git diff 2d0419ec 83d76571 -- . ':!go.mod'
':!go.sum' ':!docs'` is empty), so an outbound-level A/B is the whole comparison.
`protocol/direct`, `netproxy` and `pool` are identical in both pins, i.e. the direct UDP
receive path is untouched.

Method: loopback only on 220 (16 cores, otherwise idle), one directory (`/root/ab2`),
test binaries compiled once per pin (same toolchain, no `-race`), client pinned to cores
0-1 with `GOMAXPROCS=2`, sing-box on 4-7, inner origin on 8-9, old/new interleaved with
alternating order, 6 reps of which rep 0 is discarded, pass criteria written before the
run (`ab-2026-10-20/CRITERIA.txt`). Raw data, scripts and harness are in
`docs/research/ab-2026-10-20/`. Servers: sing-box 1.14.3 (vless+Vision, vless without
flow, VMess, SS2022 `2022-blake3-aes-128-gcm`, hysteria2, vless+REALITY, socks5) and
Xray-core 26.3.27 (Vision). Numbers are relative; 220 is not 223.

### Functional (each cell: 4x8 MB download with sha256, 4 MB upload with sha256, 200
short connections, 10 UDP echoes)

| Case | old | new |
|---|---|---|
| Vision on sing-box and Xray; inner TLS 1.3 / 1.2 / plain; VLESS without flow | pass | pass |
| VMess TCP + UDP | pass | pass |
| SS2022 TCP + UDP (every UDP reply accepted, i.e. validate-then-commit is sound) | pass | pass |
| hysteria2 TCP + UDP (FastOpen deadline path) | pass | pass |
| VLESS + REALITY + Vision (hand-resolved `reality.go`) | pass | pass |
| **hysteria2 port hopping chained through a socks5 proxy** | **fail (0/4, 0/1, 0/200, 0/1)** | **pass** |

The hop row is the one live A/B that discriminates: on the old pin the dial never
succeeds, which is the `b54af9a` bug. The Vision, SS2022 replay-window, FastOpen and
VMess-padding fixes are NOT distinguishable live (the old pin passes too: in-order loopback
UDP never exercises the wrong shift, and the padding leak is not visible to a normal
server); their evidence is the before/after unit tests and diffs listed above.
simpleobfs still has no live test (no server available).

### Performance (6 protocols x 22 metrics; median of reps 1-5)

`FLAGS: 0`. No metric was worse than the criteria allowed. Highlights (old -> new):

| | single-stream down | 8-stream down | client CPU s/GB (down) | new-conn total p50 / p99 | RTT p50 / p99 | UDP 64B RTT p50 / p99 |
|---|---|---|---|---|---|---|
| direct (noise floor) | 229 -> 225 MB/s | 433 -> 429 | 1.56 -> 1.51 | 0.589 -> 0.599 / 0.850 -> 0.878 ms | 0.051 -> 0.052 / 0.098 -> 0.105 | 0.018 -> 0.018 / 0.031 -> 0.036 |
| Vision | 243 -> 241 | 440 -> 438 | 1.38 -> 1.40 | 1.37 -> 1.40 / 1.82 -> 1.90 ms | 0.082 -> 0.084 / 0.138 -> 0.153 | 0.061 -> 0.060 / 0.110 -> 0.111 |
| REALITY | 228 -> 242 | 443 -> 440 | 1.51 -> 1.42 | 1.63 -> 1.62 / 2.14 -> 2.11 | 0.083 -> 0.086 / 0.146 -> 0.145 | 0.061 -> 0.061 / 0.106 -> 0.112 |
| VMess | 225 -> 238 | 439 -> 432 | 1.78 -> 1.67 | 0.77 -> 0.78 / 1.15 -> 1.15 | 0.089 -> 0.091 / 0.145 -> 0.162 | 0.047 -> 0.048 / 0.084 -> 0.079 |
| SS2022 | 245 -> 245 | 433 -> 429 | 1.64 -> 1.63 | 0.82 -> 0.83 / 1.15 -> 1.24 | 0.088 -> 0.087 / 0.142 -> 0.152 | 0.054 -> 0.055 / 0.130 -> 0.138 |
| hysteria2 | 237 -> 242 | 433 -> 441 | 3.94 -> 3.83 | 0.87 -> 0.86 / 1.23 -> 1.22 | 0.128 -> 0.132 / 0.213 -> 0.210 | 0.092 -> 0.093 / 0.163 -> 0.157 |

- Vision's new handshake flush timer (100 ms, same value as the existing
  `vless.NewConn` server-speaks-first flush) only fires when the client has not written
  within 100 ms; the new-connection time did not move (1.37 -> 1.40 ms), no 100 ms step.
- The `direct` row runs identical code in both pins and moves by up to +-16% on p99
  and a few percent on throughput, so differences of that size are noise on this box.
- No failed dial or request and no UDP loss increase in any cell. UDP burst receive
  ratios are low for direct, SS2022 and hysteria2 at a 20k-datagram flood on loopback,
  but identical between old and new.

Microbenchmarks (`benchstat`, 10 runs, interleaved, one pinned core):

| Benchmark | old | new | |
|---|---|---|---|
| SS2022 replay window, in order | 74.4 ns | 74.2 ns | ~ |
| SS2022 replay window, reordered | 22.3 ns | 22.7 ns | +1.7% (p=0.002), 0.4 ns per packet |
| SS2022 replay window, large jumps | 92.1 ns | 92.2 ns | ~ |
| VMess request header build | 211 ns | 304 ns | +44% (p<0.001), +93 ns per new connection |

The VMess cost is the random fill of the up-to-15-byte padding (previously uninitialized
pool bytes were sent). It is once per connection and is not visible end to end
(VMess dial p50 0.084 -> 0.085 ms).

### Not covered by this run

- dae's tproxy/BPF datapath, `dae reload`, and the 223 gateway.
- FastOpen and the SS2022 replay window under packet reordering/loss on a real path.
- REALITY `spiderX` malformed values (unit test only).
- HTTP/2 over the tunnel, large numbers of idle connections, long soaks.
- Any hardware other than 220.
