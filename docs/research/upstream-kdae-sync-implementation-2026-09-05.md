# fdae 上游同步实施记录（2026-09-05）

本轮在 `tmp/upstream-sync/{dae,outbound,quic-go}` 三个独立仓库的 `sync/kdae-20260905` 分支完成本地集成。没有推送，没有访问 192.168.124.223。原工作目录中的用户改动不纳入、不覆盖。

## 固定版本及历史处理

- dae 从 fdae `4002f708` 开始；上游目标 `fb840869`。历史 squash 对照基准 `cda30d78`，不是 Git 共同祖先。
- outbound 从 `082691d` 合并 `5e4f658`，真实 merge commit `e17238b`；本地依赖后续提交 `6526ea2`。
- quic-go 从实际依赖 pin `8cfce08b` 快进到 `fbf90cb0`。不以旁边仓库检出的 main 为基线；不纳入较新的纯 CI 提交 `d3c999a5`。
- QPACK 为 `github.com/olicesx/qpack@0844ed36f1cd`；ebpf 为 `v0.22.0`。保留本地较新的 x/net、x/crypto、x/sys。
- 开发阶段曾使用独立 modfile；最终正式 `go.mod` 采用显式相对路径 `../outbound`、`../quic-go`，正常 `make dae` 即可构建。旧 modfile 已移除，避免依赖入口混淆。远端 pin 待获推送同意后另行发布。
- 集成仓库已 repack 并删除 alternates，不依赖 `/tmp` 对象库。

## 路线执行与重要适配

A：两个 fork 先独立闭合。outbound 的 12 个文本冲突按资源所有权解决，保留 `ContextWithUDPReplyAddr`、HY2 多 PacketID 有界交错重组、TUIC 域名分片及 HY2/TUIC/AnyTLS 原始目的回包。同步上游 buffer 释放、push receiver、读写边界和关闭生命周期。

B：健康与路由修复拆成独立提交 `e875ec9a`、`7afc5a81`、`2c00e10f`、`29fe8e8f`、`99896320`、`c938de6a`，并由 `6afbf33c` 保留本地集中发布复活事件的语义。无对应地址族不判节点死亡；保留本地选择器、站点粘滞和解析依赖。

C/D/E：generation、DNS、UDP、TC HookSet 的结构变化相互依赖，按目标快照做一次联合语义适配与验证，而非制造无共同祖先的 merge commit。`merge-tree --merge-base=cda30d78` 仅用于补丁构造；每处冲突及自动合并后的本地调用链继续核查，不宣称获得上游 ancestry。

保留的具体差异：

| 范围 | 最终行为 |
|---|---|
| FakeIP / resolve_dns | 新 generation DNS transport 承载本地解析依赖；缓存真实响应后才给客户端改写 FakeIP；保留 direct 实际地址、UDP 原始目的回包及共享工作预算 |
| 管理与规则 | 保留 Mihomo、规则源、原子同步、管理 API；连接快照适配 SessionManager 的 sync.Map |
| 分组及内核身份 | 保留 nested DAG、质量状态、site sticky、kernel-DIRECT bit、must_direct、sip(match_mac) 与 MAC map |
| UDP 查找 | 合入 prefetch 和重复查询复用，仍执行目标隔离探测，确保非 443 QUIC 不被已有 FullCone 映射吸走；因此两种场景比纯上游多一次必要查询 |
| UDP 失败策略 | 保留连续软错误阈值 3、datagram queue timeout 立即退役、仅原始游戏 UDP 的短静默重建；QUIC/H3 不新增 30 秒重建策略。接入上游非 QUIC 写 deadline 到期退役 |
| UDP 排队 | 保留本地 32 项 overflow、256 KiB 字节预算及丢旧包语义，合入关闭通知与直接分发上限；拒收与消费已丢弃任务区分，防止重复释放 |
| relay | 合入取消通知、半关闭活动刷新及可配置超时；默认保持 fdae 的零值（不额外开启闲置/半关闭定时限制） |
| auto_sniff_punt | 按用户已确认方案加入，默认 false；显式 true 才启用内核 fallback 域名嗅探分流 |
| routing-epoch | 保持当前 fdae 默认启用，同时保留显式 `DAE_SEMANTIC_REFACTOR_FEATURES=none` 的非重叠单槽发布、DNS 重放和 LPM 所有权回退；适配上游 TC HookSet 事务 |
| 文档与脚本 | 不跟随上游删除本地历史报告、现有 smoke/profile 脚本及 corpus 数据；保留仍有调用者的构造 API |

对比 `4002f708` 和 `cda30d78` 的本地新增生产函数，再对照集成树全局定义：唯一消失的名称 `retireFromReplySender` 已由上游 mode-specific receiver retirement 接替，避免 push 回调栈内自等待。此检查用于辅助发现遗漏，不能替代测试或证明所有行为完全等价。

## routing-epoch 历史纠正

此前交流误把 `control/semantic_refactor_gate.go` 的过期注释当成当前默认。实际启动代码 `cmd/semantic_refactor_features.go` 默认返回 routing-epoch；`none` 才关闭。

2026-07-27（北京时间）的提交链：

1. 09:02 `7b64a2aa`：明确记录嗅探 TCP 误进入 gather-write continuation，绕过 `Sniffer.Read`，丢失仍由 Sniffer 持有的缓冲字节和 dataError；curl 报 connection reset。通过不再满足 continuation 接口恢复正确路径。
2. 09:33 `9bb42373`：回退 routing-epoch 为可选，称 prepared-slot 不适合全部重载形态；没有定位到具体 map/切换的最终根因。
3. 10:35 `33a958b2`：回退三处内核修改以继续排查 WAN TCP reset。说明不能将所有现象归因于一个已完全定位的问题。
4. 17:14 `22450992`：加入同端口重载 TCP flow 迁移。
5. 21:23 `0b043d84`：重新默认启用 routing-epoch，保留 none opt-out；当前 fdae 已含这一行为。
6. 08-22 `ff83adfe`：上游删除 opt-out 和 legacy 路径，成为本轮需兼容的实际差异。

历史足以解释当时采取回退，但不足以认定 routing-epoch 自身是唯一根因。旧注释已纠正；嗅探转发修复保留。

## 验证结果

- quic-go：`go test -short ./...` 通过。
- outbound：最终相对路径依赖下 `go test -short -timeout 3m ./...` 通过；HY2 client/frag、TUIC、AnyTLS 定向 race 通过。
- dae：全仓 `go test -short -timeout 3m ./...` 通过；保留 none 回退的后续改动另跑 cmd/control 短测试通过。
- BPF：重新生成生产绑定，`make dae OUTPUT=build/dae` 构建成功；`make ebpf-test` 在本机真实 program test-run 通过，包括 FakeIP、MAC、kernel-DIRECT、槽切换和新增 AB 用例。
- 上游 TCX 将放行返回改为 `DAE_TC_CONTINUE`，本地新增三个用例相应更新期望；MAC 关联学习器直接返回的 `TC_ACT_OK` 保持原样。
- dae 控制层：会话迁移/中止、PacketSniffer reset、DNS cache clone/packed、UdpTaskPool 关闭/异常的定向 race 通过。
- 核查了合并标记、diff whitespace、实际模块图及本地扩展调用链。
- 没有执行 223 上的测试，也没有将本机 program test-run 等同于完整 OpenWrt 现网/内核矩阵验证。

## 上游提交覆盖索引

以下为固定目标相对 `cda30d78` 的提交索引。状态描述的是本轮接入方式，不表示每个原提交都能直接 cherry-pick：后续覆盖/撤销的变化以 `fb840869` 最终树为准；上述本地保留差异优先。

| 提交 | 接入方式 | 上游标题 |
|---|---|---|
| `6a93421` | 目标最终快照适配 | fix(cmd): tear down dae netns on fast exit |
| `f30109d` | 目标最终快照适配 | perf(control): drop redundant UDP last_seen_ns writes in tproxy |
| `d94d10e` | 目标最终快照适配 | fix(control): log panic stack in UDP dispatcher report |
| `471b11a` | 目标最终快照适配 | feat(control): honest UDP session rebuild and death detection |
| `89d2b07` | 目标最终快照适配 | test(control): fuzz the TCP DNS frame parser |
| `0ba80aa` | 目标最终快照适配 | fix(test): expect fast-exit netns teardown in live smoke |
| `81f72f2` | 由最终本地 fork / 依赖图覆盖 | fix(deps): pin quic-go/outbound lifecycle fixes and typed StreamError |
| `a752b37` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin quic-go/outbound to skip-addr chain (110ca0ac / a4521b4) |
| `7e1deb6` | 目标最终快照适配 | fix(control): unmount named netns synchronously before removing it |
| `8650fe4` | 目标最终快照适配 | test(control): add goleak goroutine-leak fence to test suite |
| `a1849a2` | 目标最终快照适配 | fix(subscription): validate subscription before overwriting persisted cache |
| `ff83adf` | 目标最终快照适配 | refactor(control): remove semantic-refactor feature gate and gated UDP dispatchers |
| `22fca28` | 目标最终快照适配 | chore: prune sprint/QA docs and consolidate live smoke scripts |
| `e602316` | 目标最终快照适配 | refactor: drop dead wrappers and deprecated control-plane APIs |
| `9eea6e8` | 目标最终快照适配 | docs: record subtraction campaign state in PROJECT_BRIEF and CHANGELOGS |
| `5d0dc1f` | 目标最终快照适配 | refactor(cmd): extract inline reload state machine from Run |
| `96e1195` | 目标最终快照适配 | refactor(cmd): deduplicate reload failure cleanup into failReloadAttempt |
| `cd14a6a` | 目标最终快照适配 | test(cmd): restore state-machine unit tests pruned with run_shutdown_test.go |
| `e4e0aee` | 目标最终快照适配 | fix(control): break push-mode self-waits and close the conn off the sender stack |
| `50b8a93` | 目标最终快照适配 | fix(cmd): notify reload failure on malformed-handoff and publish-error paths |
| `d16b572` | 目标最终快照适配 | fix(control): close push-mode teardown races around register and queue shutdown |
| `cdc1cf3` | 目标最终快照适配 | docs: record push-mode lifecycle fixes in PROJECT_BRIEF |
| `442efb0` | 目标最终快照适配 | fix(control): drain netlink subscriptions after the link watcher exits |
| `6f639b4` | 目标最终快照适配 | test(control): ignore the direct-dial epoll singleton in the goleak fence |
| `51fb677` | 目标最终快照适配 | fix(component): only drain a successful netlink subscription |
| `afb2932` | 目标最终快照适配 | fix(control): satisfy errcheck on the async endpoint Close |
| `cabd833` | 目标最终快照适配 | fix(ci): set the execute bit on semantic-refactor-smoke.sh |
| `849a0e8` | 目标最终快照适配 | chore(control): drop helpers left unused by the dispatcher pruning |
| `38d88be` | 目标最终快照适配 | perf(control): default GOMAXPROCS to 1 with environment override |
| `80244b1` | 由最终本地 fork / 依赖图覆盖 | chore(deps): repin quic-go to perf/client-skipaddr-and-gro |
| `f1318b0` | 目标最终快照适配 | fix(ci): satisfy errcheck on GOMAXPROCS test env handling |
| `224721c` | 目标最终快照适配 | fix(bpf): make tcp relay offload load fault-tolerant |
| `d602c4b` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump cilium/ebpf v0.20.0 -> v0.22.0 |
| `e55980d` | 目标最终快照适配 | perf(trace): batch kprobe attach via kprobe_multi when available |
| `958c8ac` | 目标最终快照适配 | fix(outbound): preserve HY2 multi-target reply addresses |
| `6ebae89` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin quic-go/outbound to skip-addr close-queue fix |
| `1aef3da` | 由最终本地 fork / 依赖图覆盖 | chore(deps): repin nil-safe quic-go close writes |
| `ec95734` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin QUIC and HY2 correctness fixes |
| `f225d0c` | 目标最终快照适配 | fix(dns): close QUIC client lifecycle gaps |
| `2f1caf2` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin outbound 22c9cd5 and quic-go b5c87c96 |
| `235f07c` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin outbound 6450dd17 and quic-go 8048a30 |
| `2607067` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin outbound b6051c8 WriteBatch/TransportDone/cwnd |
| `bba4dca` | 目标最终快照适配 | fix(control): keep netkit in L2 so IPv6 NDP works |
| `502d976` | 目标最终快照适配 | perf(control): cut relay log noise and reclaim stuck copies |
| `9dce36c` | 目标最终快照适配 | fix(control): forward reload stale threshold into retirement cleanup |
| `caa4074` | 目标最终快照适配 | refactor(dns): remove the production-idle async cache evictor |
| `f97e256` | 目标最终快照适配 | refactor(control): drop dead helpers, wrappers and stale comments |
| `33ed164` | 目标最终快照适配 | refactor(component,common,config): drop dead exported helpers |
| `e3c3398` | 目标最终快照适配 | chore(scripts): drop unreferenced profiling script and ignore session artifacts |
| `a23fd2c` | 目标最终快照适配 | refactor(dialer): drop helpers orphaned by the dead-export pruning |
| `0f25b3e` | 目标最终快照适配 | refactor(cmd): collapse constructor matrix and dedupe reload recovery paths |
| `4238e1b` | 目标最终快照适配 | refactor(cmd): dedupe reload worker supervisor failure tails |
| `60af0aa` | 目标最终快照适配 | refactor(control): fold duplicated DNS/UDP policy code and drop the flow-binding override mechanism |
| `cc467a6` | 目标最终快照适配 | refactor(dns): sink shared transport plumbing into component/dnstransport |
| `26c76f0` | 目标最终快照适配 | refactor(control): share the ingress routing-cache lookup pair |
| `58127ce` | 目标最终快照适配 | refactor(cmd,control): finish leftover attach and flow-binding cleanup |
| `f1a63c5` | 目标最终快照适配 | perf(control): fuse same-packet UDP pool Gets; measure WriteTo string roundtrip |
| `0413736` | 目标最终快照适配 | fix(control): drop unused cachedRoutingBinding wrapper |
| `6a335b8` | 目标最终快照适配 | perf(control): gate the retained-endpoint scan on the epoch tally |
| `1ce90de` | 目标最终快照适配 | refactor(control): drop the dead DNS fast path, account ingress queries |
| `a6b2e5b` | 目标最终快照适配 | refactor(control): drop the vestigial routing-cache TTL machinery |
| `e49a013` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to 2fe5c86 |
| `f019cfb` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to 75dfca6 |
| `c856dbd` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to 0702558 |
| `5f0bc36` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to 89233df |
| `75cfea6` | 由最终本地 fork / 依赖图覆盖 | fix(go.sum): pin correct outbound module hash for 89233dfc (#27) |
| `29fe076` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to dd3816d |
| `9677bb3` | 目标最终快照适配 | fix(control): thread onActive through relay continuations |
| `6dabeaa` | 目标最终快照适配 | chore(dialer): trim health-check waste |
| `29dcabe` | 目标最终快照适配 | fix(dns): keep shutdown cancellation across forwarded attempts |
| `b83c1b1` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to d8a4433 |
| `a7c461b` | 目标最终快照适配 | perf(control,dns,routing): gate per-flow work behind build-time facts |
| `bc8b335` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to 63b6477 |
| `779559b` | 目标最终快照适配 | fix(dns,relay): de-serialize the hot paths added this week |
| `1a040eb` | 目标最终快照适配 | fix(control): retire the poisoning-family caches found in audit |
| `7cfeb91` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to e030f04 |
| `d6eede2` | 目标最终快照适配 | fix(control): pass onActive through remainder and make FIFO real |
| `57deb31` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to 5063ca8 |
| `43407e9` | 目标最终快照适配 | docs: record the 2026-08-25..27 outbound/dae remediation plan |
| `20399ef` | 目标最终快照适配 | fix(control): keep onActive flowing when record is nil |
| `100566c` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to 9e1febf |
| `0784a99` | 目标最终快照适配 | feat(cmd): attribute startup slowness with per-phase timers |
| `e3980c5` | 目标最终快照适配 | fix(control): discard stranded UDP tasks before reusing queue channels |
| `1a3ef15` | 目标最终快照适配 | feat(control): make relay idle and half-close timeouts tunable |
| `56298d6` | 目标最终快照适配 | fix(control): propagate relay ctx into continuation copy sources |
| `336a47a` | 目标最终快照适配 | fix(control): meter retained-endpoint UDP egress to the owning plane |
| `d0b0445` | 目标最终快照适配 | perf(control): shard session-manager bookkeeping off one global lock |
| `622faea` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork to 6b6531e and quic-go fork to 71b82de6 |
| `161ef72` | 目标最终快照适配 | fix(control): reuse the UDP write-batch items backing array |
| `5642b28` | 目标最终快照适配 | perf(control): drop the vestigial generationsMu pairing on UDP tuple pinning |
| `8e8b5d9` | 目标最终快照适配 | perf(control): downgrade incoming-connection ownership to an RWMutex |
| `8458a97` | 目标最终快照适配 | docs(control): record why the write-batch mutex spans the transport write |
| `c8011b9` | 目标最终快照适配 | perf(control): make the incoming-connection admission path lock-free |
| `e1e96fc` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin quic-go fork to c6184578 (all-green CI head) |
| `0c168a6` | 目标最终快照适配 | fix(control): harden UDP and TC lifecycle |
| `207670c` | 由最终本地 fork / 依赖图覆盖 | chore(deps): update verified fork revisions |
| `ead0c56` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin race-verified fork revisions |
| `3703170` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin stable fork test revisions |
| `a3d3145` | 目标最终快照适配 | ci(forks): serialize race package execution |
| `ea50cdf` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin protocol-hardening fork revisions |
| `0f23952` | 目标最终快照适配 | fix(control): isolate reload runtime dependencies |
| `8f6860c` | 目标最终快照适配 | fix(control): harden DNS and connection lifecycle |
| `93a9957` | 目标最终快照适配 | fix(lint): check deferred Close errors and simplify ref increment |
| `261df7a` | 目标最终快照适配 | fix(control): initialize store-path DNS cache deadline watermark |
| `5aa481d` | 目标最终快照适配 | fix(control): synchronize LPM index install and dae netns state |
| `0fb18c5` | 目标最终快照适配 | fix(control): harden DNS exchange against spoofed and cross-delivered replies |
| `ef999ba` | 目标最终快照适配 | fix(control): narrow DNS dispatch lock domain behind a handle gate |
| `0669e29` | 目标最终快照适配 | fix(control): bound UDP direct dispatch and reclaim failed-build LPM slots |
| `1d95fc0` | 目标最终快照适配 | fix(component): sniffing pool-buffer race and upstream init stampede |
| `3ffde84` | 目标最终快照适配 | fix(cmd,trace): close reload races and bound trace skb tracking |
| `674a4a6` | 目标最终快照适配 | fix(control): close reload rollback ownership gaps |
| `ba7a6c7` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork for anti-pattern remediation round |
| `dada851` | 由最终本地 fork / 依赖图覆盖 | fix(deps): update outbound fork fixes |
| `1067a8c` | 目标最终快照适配 | refactor: remove dead code and rewire tests to live APIs |
| `3c5dfb5` | 目标最终快照适配 | fix(control,component,trace): preserve error chains on returned errors |
| `666de5f` | 目标最终快照适配 | docs(control,component): align comments with behavior and document lock ownership |
| `321c6e6` | 目标最终快照适配 | fix(control,component): tighten pool hygiene on hot-path object pools |
| `0e5c832` | 目标最终快照适配 | fix(netutils): wrap ctx.Err() into the DNS resolve timeout error |
| `08f34ea` | 由最终本地 fork / 依赖图覆盖 | chore(deps): bump outbound fork for the P2 hygiene round |
| `8c62dd6` | 目标最终快照适配 | fix(control): stop reassigning DnsController.log during reload |
| `7d70a3b` | 目标最终快照适配 | fix(routing): reject out-of-range domain rule indices instead of panicking |
| `b43d987` | 目标最终快照适配 | fix(dns): drop response-formed messages at the local DNS listener |
| `2b06584` | 目标最终快照适配 | fix(routing): normalize domain matcher case |
| `92898ad` | 由最终本地 fork / 依赖图覆盖 | fix(deps): update outbound reader fixes |
| `ce7e61e` | 目标最终快照适配 | feat(routing): auto sniff-punt for device-scoped domain whitelists |
| `886475f` | 目标最终快照适配 | refactor(control): harden eBPF lifecycle and reloads |
| `d4fe609` | 目标最终快照适配 | fix(control): restore verifier and TCX lifecycle CI |
| `5948f17` | 目标最终快照适配 | fix(control): stabilize constructor error cleanup |
| `dd57d5c` | 目标最终快照适配 | fix(control): load composite TC programs at runtime |
| `ebbec6b` | 目标最终快照适配 | fix(control): make generation publication coherent |
| `4cc4d2c` | 目标最终快照适配 | docs(control): record routing epoch risk contracts |
| `c80bc75` | 目标最终快照适配 | fix: harden config, lifecycle, and eBPF edge cases |
| `765783f` | 目标最终快照适配 | fix(outbound): classify probe errors before punishing dialer health |
| `022c519` | 目标最终快照适配 | fix(outbound): isolate sticky-IP caches per dialer |
| `f0ca4d7` | 目标最终快照适配 | fix(outbound): fire alive callback on data-UDP revival, keep lenient floor |
| `d18fdbf` | 目标最终快照适配 | fix(control): skip short-buffer UDP and idle-roll half-close drain |
| `fc29477` | 由最终本地 fork / 依赖图覆盖 | fix(deps): bump outbound fork for protocol lifecycle fixes |
| `ecdaf2e` | 目标最终快照适配 | fix(dns): preserve EDNS metadata, honor reload policy, bound UDP responses |
| `4d15276` | 目标最终快照适配 | fix(control): close push-mode UDP endpoints without deadlock and stop forwarding truncated datagrams |
| `6be9ddb` | 目标最终快照适配 | fix(outbound): close superseded dialers during registration and keep SIP008 plugin names |
| `6ad3ae3` | 目标最终快照适配 | fix(control): resume connectivity snapshots according to admission policy |
| `1c9ecee` | 目标最终快照适配 | fix(kern): correct TCP offload accounting keys and survive LTO send paths |
| `fb84086` | 由最终本地 fork / 依赖图覆盖 | chore(deps): pin repaired outbound fork and test owned forks from the module graph |
