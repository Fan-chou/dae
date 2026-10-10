# Upstream sync, 2026-10-10 (batch 1: correctness fixes)

Previous sync point: olicesx/dae `kdae` `fb840869` (2026-09-05). `kdae` was
force-updated since, so commits are selected by subject/patch, not merged.
New upstream head at review time: `2064c47a` (about 270 commits since 09-05).
Dependency forks compared: olicesx/outbound `131419a`, olicesx/quic-go `44a1f9eb`.

Branches (unpushed): dae `sync/kdae-20261010`; outbound `sync/upstream-20261010`
(on `0db0543`); quic-go `sync/upstream-20261010` (on `42916a97`).

## Validation

- dae: `go build ./...`, `go vet`, `go test -short` on control/cmd/component/common,
  `go test -race -short ./control ./cmd ./component/...`, `make dae` (clang, trace tag).
  `control/kern` and `trace/kern` are untouched, so no BPF object change.
- outbound and quic-go: build, vet, `-short`, and `-race -short`.
- dae built against both fork branches through a temporary `-modfile`
  (go.mod unchanged).
- NOT done: a live `dae reload` / suspend / abort cycle with the built binary
  (needs a host that may load BPF; see the result of the discussion with the user).

## dae: picked

c6771037 reload resources released deterministically; d197e600 resolver read
buffer; 56ce7ba6 server_name length; 6eba2af8 fixed_domain_ttl range;
14b98b82 BPF maintenance rollback scope; e3dfc392 abort-marker / /proc races;
dbf4129c DNS upstream index range; 2266d9a2 upstream-ready callback optional;
e5310bc8 abort marker cleanup on failed suspend; fb14021b question-less terminal
DNS replies; 3207800c `must_rules` in both fast paths (plus 501a739a field
assignment); ca97821b CRYPTO length/offset in uint64 (relocation.go half, hand
applied); 9ea4fd28 clean-FIN sniff end (sniffer.go half, hand applied, the
carried test hangs without it). A small follow-up restores the `consts` import.

## dae: already in fdae (verified)

39c764f7, f07f81c9, 1e4e47cf (cherry-pick came out empty); d437282d (bootstrap
resolver is already family-agnostic); d8b3fe28 (`ActiveDnsController`); 69ac2234
(`sortedSubscriptionTags`); 6f80502f (fdae copies the DoQ query buffer);
731c446b (the source-mismatch check does not exist in fdae). Sniffing
0ab7b6e0 / ab934f9b: fdae's sniffer was rewritten and already compares QUIC
lengths in uint64 and returns ErrNeedMore on a missing LF (read by hand; not
proven by transplanted tests).

## dae: not carried

- Depend on features fdae lacks: 1d5102e3, e58aab58, 007cdbd8 (system-DNS leg for
  node addresses); 1134a9ba (needs da7f7da6).
- Behavior change that rejects configs that load today: 42b70886 (named parameter
  on bare-value functions). Needs a `dae validate` run on the real config first.
- `dae validate` dry-run of DNS routing blocks: 096a3d5d (fdae validate stays offline-lenient).
- DNS truncation / datapath family, to be ported as a whole with BPF regeneration:
  da7f7da6, 8a008c9f, 24234c45, ff59b81c, bfe23f4b, 1b7aeb70, 83da8a0e, 4e00d2ff,
  b7aa81fd, d3dc8dc1, c5bf5a84, plus dac92aa5 and 096a3d5d.
- Performance (batch 3): UDP write batching 0f50b3ac and friends, eBPF map
  right-sizing c71c20d6, hot-path map work 06451485, PGO profile f7c1cb6b,
  GOMAXPROCS default 968893cb, DNS evidence eviction 57729b4d / 9b7cc7d9 / 875a4b23
  (collides with fdae's own evidence design).

## outbound: picked

588330f stickyip all-IPs failure at debug; e9bc8bb SS2022 header-only datagram;
76cd4d5 datagram-dropped contract on write side / socks5; e9a1160 direct
LocalAddr; 672c765 vless server domain length; b661624 stickyip debug gating;
4df7171 tuic auth FIN best effort.

Already in the fork (empty picks): 165d039, cbc7ff2, f0fdbaa, 70dfd0b, 37417ec,
4163e01.

Not carried: everything that needs the upstream perf stack (coalesce,
pooled buffered reader, UDP batch writers, GSO trim, TCPDialControl):
131419a, 973ccc3, 09af900, aa7bb5f, 6504594, d0a4aa6, 9c6c1b9, 04be789,
0b282e1, f8b68c8, 3cf24dc, 75b7e03, d960282, c90a148, c8e883c.
b54af9a (hide OOB/batch surface of the hop conn) needs
`netproxy.WriteDeadlineClosesSession`, which the fork does not have; it may be a
real fix for the fork's udphop recvmmsg path and is worth porting together with
that function. REALITY (05bf275, 2f4eba2, 0f24c13, d7afa40, 29060b6, cc86ced):
the fork has its own equivalent implementation (`realityHelloAttempts` etc.).
Bounded caches 915236f / 4df57ac / d52677d / b3c5caa conflict with fork changes.

## quic-go: picked

3fac325b pool ownership on PutBack; 498d4544 qlog drain-on-close; c8480ac3 and
df8f5b81 http3 GOAWAY under in-flight open; ecc7a411 nil-tracer paths and close
causes; 677d0c3a atomic control-frame flag; dda1f726 and 765d53fe receive-path
allocations (scratch kept per call); 18f87d1c frames after a remote reset
returned to the pool (hand ported; the `ReadBuffered` hint is not carried).
Already present: ba274cf4, 271dd429, 1c9ad297, 5c51f15d (peerParams atomic).

Already present (checked piece by piece, nothing to port): edf4a231 (dial
cleanup, CapabilityCallback, waiter handoff, receive ring buffer and its
bounded-storage test, `abortAfterStartupFailure`, unpooled send-side datagram
frames). The carry's 11 conflicts were because the fork already had each piece.

Already present: a3269acd (http3 control stream kept open, GOAWAY handling,
PUSH_PROMISE per-stream handling, replay gated on H3_REQUEST_REJECTED/GetBody).
A trial cherry-pick conflicted only because the fork already had every hunk;
the patch's frames/conn/server/integration hunks reverse-apply cleanly to our
tree, and our transport/control-stream tests are supersets.

Not carried: 8126b16b (atomic congestion pointer,
collides with the fork's application-limited logic).
