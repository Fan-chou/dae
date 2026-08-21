# 上游 daeuniverse/dae 对照（2026-08-18）

> 对照对象：当前分支 `feat/mihomo-rule-provider-groups` HEAD `339c3b75`  
> 上游：[daeuniverse/dae](https://github.com/daeuniverse/dae/) `main` HEAD `caa6f5e9`（2026-07-31）  
> 共同祖先不可用：本仓库历史来自 olicesx/kdae 重写，与官方 `main` 无 merge-base。  
> 官方 `origin/main` 停在 `4baacefe`（[#931](https://github.com/daeuniverse/dae/pull/931)）。其后主线 18 个提交，按 **commit 主题** 对照。

**结论：不要 rebase / 不要整包 cherry-pick 官方 main 或 [#980](https://github.com/daeuniverse/dae/pull/980)。** 需要的话只对未进主线、且当前树仍存在的缺口做最小移植。

DNS / `dial_mode` / 一 IP 多域名 / [#763](https://github.com/daeuniverse/dae/pull/763) 设计结论：[dns-domain-routing-2026-08-18.md](./dns-domain-routing-2026-08-18.md)  
honk（Rust 实验，只当设计对照）：[honk-2026-08-19.md](./honk-2026-08-19.md)

---

## 1. 主线 `origin/main` 之后的 18 个提交

按主题，15 个这边已有；缺 3 个。

| 上游 | 改了什么 | 当前树 |
|---|---|---|
| [#939](https://github.com/daeuniverse/dae/pull/939) | LAN 非 SYN TCP 重写 `skb->mark` | 有 |
| [#962](https://github.com/daeuniverse/dae/pull/962) | utls 1.8.2 | 有 |
| [#968](https://github.com/daeuniverse/dae/pull/968) | runtime 流量 / 节点延迟 | 有 |
| [#970](https://github.com/daeuniverse/dae/pull/970) | olicesx 大包（conn_state、DNS、reload、CI） | 有（本树主体） |
| [#976](https://github.com/daeuniverse/dae/pull/976) [#978](https://github.com/daeuniverse/dae/pull/978) [#1036](https://github.com/daeuniverse/dae/pull/1036) | 发 v1.1.0 / v2.0.0rc1 / v2.0.0 | 有（ci 主题） |
| [#981](https://github.com/daeuniverse/dae/pull/981) [#1002](https://github.com/daeuniverse/dae/pull/1002) | Arch / 贡献文档 | 有 |
| [#986](https://github.com/daeuniverse/dae/pull/986) | `BPF_NO_PRESERVE_ACCESS_INDEX` 躲 CO-RE | 有 |
| [#989](https://github.com/daeuniverse/dae/pull/989) | Dockerfile Go 1.26 | 有 |
| [#991](https://github.com/daeuniverse/dae/pull/991) | cmdline 解析进程名 | 有 |
| [#994](https://github.com/daeuniverse/dae/pull/994) | CI GORISCV64 | 有 |
| [#995](https://github.com/daeuniverse/dae/pull/995) | 无 `bpf_get_current_task` 时退回 comm | 有 |
| [#1065](https://github.com/daeuniverse/dae/pull/1065) | group override 继承 DaeDNS | 有 |
| [#1056](https://github.com/daeuniverse/dae/pull/1056) | 只改 [#986](https://github.com/daeuniverse/dae/pull/986) 注释 | **无**，可忽略 |
| [#1010](https://github.com/daeuniverse/dae/pull/1010) | 日志时间戳 `ForceFormatting` | **无**，3 行，可选 |
| [#980](https://github.com/daeuniverse/dae/pull/980) | 见下一节 | **不要整包合** |

---

## 2. [#980](https://github.com/daeuniverse/dae/pull/980)（`d93e5a7b`）不必合

官方 squash：284 文件。起点是 IPv4 UDP 回包，评审期间叠了 outbound / trace / conn-state / shutdown。大量 diff 只是版权年份。

实质行为：

1. **IPv4 raw UDP 回包**：anyfrom 绑端口失败（DNS 应答）时走 raw socket；须在 `ErrAnyfromBindFailed` 负缓存之前兜底。
2. **主机 sysctl**：`dae0`/`all` 的 `rp_filter`/`arp_filter`、`dae0.accept_local`（主机 netns，不是 daens 里的 dae0peer）。
3. **conn_state 合成一张表**：`tcp`+`udp` → `conn_state_map`，`bpf_conn_state_map_size`，batch delete，`not`/`must` 改 `__u8`。
4. outbound 健康检查不写假延迟；DNS UDP 池复用前清 deadline。
5. 修 `dae trace`；drain 超时 abort；删 `prefix_compressor` / `pkg/ebpf_internal`。
6. `example.dae`：`bpf_conn_state_map_size: 262144`、`disable_thp: true`。

本地已有更早的 `be0103f6`，且后续还有 TCP conn_state 过期、H3/DNS UDP janitor。当前树已具备：

- `shouldTryRawUDPFallback` → `sendUDPv4RawInDaeNetns`（限源端口 53）
- 主机侧 rp_filter / arp_filter / accept_local
- `conn_state_map`、`bpf_conn_state_map_size`、`BpfMapBatchDeleteAll`、`disable_thp`

patch-id 与上游 squash 不同。整包 cherry-pick 会冲掉后续 janitor。

---

## 3. 未进主线的开放 PR：对照当前树是否属实

2026-08-18 对代码核对。4 月那批长期未动的 PR 不列入。

| PR | 声称 | 当前树 | 223 是否打得中 |
|---|---|---|---|
| [#1070](https://github.com/daeuniverse/dae/pull/1070) | DNS fast path 不看 `Must`，`must_rules` 失效 | **属实**。`control/udp.go`、`udp_ingress_task.go`、`tcp.go` 三条 53 端口 fast path 确认 DNS 后直接进 `DnsController` | 未必。fast path 只拦目的端口 53；mosdns 在 `:5335`。没有 `must_rules`、且进程不打 53 时看不到 PR 复现 |
| [#1081](https://github.com/daeuniverse/dae/pull/1081) | `ChooseDialTarget` 用旧 `dnsController` 而非 handoff | **属实，且这边更狠**。UDP/TCP DNS 已走 `ActiveDnsController()`，选拨号目标仍 `c.dnsController.HasDnsKnowledge`。reuse 会把旧平面 `dnsController` **置 nil**，知识在共享 store，官方「知识只在 handoff」不完全对；风险是 hot_reload 窗口里旧连接再 `ChooseDialTarget` **空指针**。`dial_mode: domain` 才进这段 | reload + domain 拨号时值得补 |
| [#1079](https://github.com/daeuniverse/dae/pull/1079) / [#1078](https://github.com/daeuniverse/dae/issues/1078) | `daens` 未关 `dae0peer`/`all` 的 `rp_filter` | **代码缺口属实**。主机 `dae0`/`all` 已关；切进 daens 后只设 `dae0peer.accept_local` | 本机 IPv4 再被 dae 代理才可能中；网关代理 LAN 一般不走 |
| [#1051](https://github.com/daeuniverse/dae/pull/1051) | 进行中的 reload 丢掉后续信号 | **属实、轻**。`tryQueueReloadRequest` CAS 失败只打日志，无 `reloadMissed` | 连点两次 `hot_reload` 可能丢第二次 |

不必整 PR 合入。若动手：优先 **#1081** 最小改（`ChooseDialTarget` 改 `ActiveDnsController()` 并处理 nil）；有 `must_rules` 再补 #1070；本机走代理再补 #1079。

已有近似、不必跟：[#1016](https://github.com/daeuniverse/dae/pull/1016) 分层 reload（本地 `90a49840`）、[#1050](https://github.com/daeuniverse/dae/pull/1050) 订阅归零（本地是拒绝 reload）。[#1048](https://github.com/daeuniverse/dae/pull/1048)/[#1047](https://github.com/daeuniverse/dae/pull/1047) TC 自愈树里没有，未在 223 上复现，不盲合。

---

## 4. LostAttractor/dae（`next`，2026-08-18 拉到 `4cba9a78`）

对照：[LostAttractor/dae](https://github.com/LostAttractor/dae) 默认分支 **`next`** `4cba9a78`（2026-08-17）。他的 `main` 与官方同一提交 `caa6f5e9`。相对官方 `main`：**ahead 191 / behind 27**，约 176 文件、+26578 / −6064。2026-08-14 有一大段同一时间戳的历史重放，不能按日期判断「最近才写」。

**结论：不要 rebase / 不要整包合这个 fork。** 这是另一套 control / DNS / outbound 平面（`DomainRegistry`、`DnsManager`、`dae status`、Prometheus、`skip_while_noalive`、路由 `ifname`/`ifindex`），与本仓库 olicesx 重写后的树没有干净 merge-base。硬合会冲掉 conn_state janitor、hot_reload、raw UDP fallback。

### 已进官方、这边也有的，不必再跟

LAN UDP conntrack、ppp/tun、网卡通配、Hysteria2 udphop、IPv6 扩展头、`must_rules` 污染 match_set、fallback DNS。

### 还开着的上游 PR（草稿 / 长期未合）

| PR | 内容 | 当前树 |
|---|---|---|
| [#783](https://github.com/daeuniverse/dae/pull/783)（draft） | 路由按 `ifname`/`ifindex` 分流 | **无** 这条用户态规则。kdae 的 ifindex 是 `dae0` 热更新，不是 LAN 口过滤器 |
| [#763](https://github.com/daeuniverse/dae/pull/763)（`do-not-merge`） | 同一 IP 对应多个域名：路由一致则内核直判，否则强制用户态 sniff | **思路合理，不要整包合。** 当前树是 bitmap OR，歧义时更容易错成内核 `direct`。收窄判定与落地约束见 [dns-domain-routing-2026-08-18.md](./dns-domain-routing-2026-08-18.md) |
| [#859](https://github.com/daeuniverse/dae/pull/859)（draft） | 全局 logger 替代传来传去 | 重构噪音大，不跟 |

### `next` 上近期独特提交 vs 当前树

| 提交 | 改了什么 | 当前树 / 建议 |
|---|---|---|
| `b392c820` | daens 里关 `all` + `dae0peer` 的 `rp_filter` | **就是 [#1079](https://github.com/daeuniverse/dae/pull/1079)**。主机 `dae0`/`all` 已关；daens 切进去后仍只设 `dae0peer.accept_local`。网关代理 LAN 一般打不中；本机 IPv4 再被代理才可能中。最小移植约 10 行 |
| `12154854` | 分片 QUIC ClientHello sniff | 小、独立，与这边 QUIC v2 sniff 不冲突。223 上有 QUIC 域名识别失败再补 |
| `7fdd3a43` `0d9679b3` `ad47bb7a` `172bc804` | reload：关 in-flight、UDP task 绑平面、拆已建立 TCP relay、重建 LPM | 主题与本地分层 reload（`90a49840`）重叠，patch 对不上，**不要整段 cherry-pick** |
| `e8491b0b` 及一串 `fix(dns)` | DNS flight / cache / 源端口隔离 | 绑在他的 DnsManager 上，移植成本高 |
| `feat(status)` + Prometheus | `dae status`、节点降级、域名历史 | 观测能力，不是数据面必须 |

### 若要从这个 fork 拿东西

只考虑最小移植：

1. **daens `rp_filter`**（`b392c820` / #1079）——本机也走代理时再补。
2. **分片 QUIC sniff**（`12154854`）——有失败证据再补。

reload / DNS 大重构不要跟。[#1081](https://github.com/daeuniverse/dae/pull/1081) 的 `ChooseDialTarget` 空指针仍比这个 fork 更值得先补。

---

## 5. 复核对法

```bash
git fetch https://github.com/daeuniverse/dae.git main:refs/remotes/daeuniverse/main
git log --oneline origin/main..daeuniverse/main
# 主题对照：git log --format=%s origin/main..HEAD  vs  上表

git fetch https://github.com/LostAttractor/dae.git next:refs/remotes/lost/next
git log --oneline daeuniverse/main..lost/next
git diff --stat daeuniverse/main...lost/next
```

开放 PR：`https://github.com/daeuniverse/dae/pulls?q=is%3Apr+is%3Aopen`  
LostAttractor 的 PR：`https://github.com/daeuniverse/dae/pulls?q=is%3Apr+author%3ALostAttractor`
