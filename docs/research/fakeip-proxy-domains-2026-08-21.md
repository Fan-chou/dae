# 选择性 FakeIP（仅代理域名）（2026-08-21）

> 对照代码：当前分支 DNS 应答 → `DnsCache` → `BatchUpdateDomainRouting`；TCP `dial_mode: domain++`；UDP 钉客户端 dst IP（`control/udp.go`）。  
> 223：`openwrt/kdae/files/config.nikki-replace.dae`（`dial_mode: domain++`，无 FakeIP，homedns `192.168.124.222:5354`）。  
> 一 IP 多域名的**内核分流**（OR bitmap / 冲突上楼）见 [dns-domain-routing-2026-08-18.md](./dns-domain-routing-2026-08-18.md)。本文只解决**客户端 HTTP/2 把不同 Host 焊到一条 TLS**。  
> 触发：chatgpt.com / ab.chatgpt.com / ios.chat.openai.com / api.openai.com 经 223 homedns 落到同一 VIP，API 复用 chatgpt 的 SNI，Cloudflare 421/403。根因可以是 1stream 焊 IP，也可以是 CDN 合法共用地址。kdae 四层拆不开已焊好的 HTTP/2。

**结论（未实现，只定设计）：**

1. **全局 FakeIP 仍然不上**（假地址不能内核直连，吃掉 dae 本钱）。本文是 **只对「`domain()` 已能确定走代理组」的 qname 回 FakeIP**。
2. 这些流今天本来就要 tproxy 进用户态，假地址不牺牲国内直连。
3. Eligibility 是 **Kleene 三值、first-match**。没有 `domain()` 的规则（组播 `dip`、`sip`、`dscp`、白名单 `!sip`）当 FALSE 继续；`l4proto`/`dport`/`sport` 当 FALSE 继续；`domain() && ip()` / `sip`/`mac` 才是 UNKNOWN 且不能跳过。命中用户组后看 **当前选中叶子**（不 `Select()`）：`direct`/`block` 不假，节点才假。不要 `destDontCare`，不要扩 `conflictFingerprint`。
4. TCP：SNI 优先，否则 LookBack。Dial 前目标在假地址池 → **拒绝**。Route 成 `direct`/`must_direct` 也拒绝，等客户端 TTL。
5. UDP/H3：key 用 FakeIP，`DialTarget` 钉真实 IP。无名 FakeIP → 拒绝。
6. `DnsCache` 只存真实 RR + real packed。Fake packed 在 **generation-local FakeIPPolicy**。**FakeIP 不进 `domain_routing_map`。**
7. 前缀不要用 `28.0.0.0/8`。IPv6 分配池 `/96`。默认关。
8. **FakeIPStore 进程级**。首次应答前 WAL `durableSeq >= mySeq`。range 变更 / disable 进 **retired**（仍 LookBack + 内核 trap），tombstone 地址禁止复用。
9. 内核前缀特判只绕过 outbound 决定，不跳过 metadata / conn-state。不要把 `ip(池)->0xFD` 插进 matcher。
10. ICMP echo：本地 reply 并 drop 原包。
11. 热路径 LookBack/Lookup P99 <1µs、0 syscall。首次 WAL 另测，不要和 µs 指标绑在一起。
12. **`filter`**：默认 skip + 内置 LAN/STUN/NTP/节点主机名。`only` ∩ PROXY。`asis` 不是 FakeIP skip。

---

## 1. 要修的和修不了的

kdae 一条客户端 TCP = 一次 SNI = 一次拨号。HTTP/2 在进 tproxy **之前**把 `chatgpt.com` 和 `api.openai.com` 并到同一条 TLS 上时，用户态看不到第二个 Host，也没有「域名不同就禁止复用」的开关。

能做的只有让客户端**不要合连接**：每个会进代理的 FQDN 一个地址。

| 客户端 | FakeIP 有没有用 |
|---|---|
| 白名单 MAC，目的 53 被劫持 | 有 |
| 非白名单 `must_direct`（53 不进 DnsController） | 不要改写 |
| DoH/DoQ / 硬编码 IP | 无，靠嗅探 + 真 IP 投影 |

这和「同 IP 不同 outbound 被 OR 成内核 direct」是两件事。四个 OpenAI 名字都进 `AI` 时内核选路是对的，坏在 TLS 身份。不要用 #763 来修 421。

---

## 2. 和现网路径怎么接

1. 内核：dst 53 且非 `must` → `OutboundControlPlaneRouting` → `DnsController`。223 非白名单先 `must_direct`，DNS 不劫持。
2. `DnsController` 只用 `dns.routing` 选上游，**不跑** traffic `routing {}`。FakeIP eligibility 在应答投影前额外跑。
3. **两层视图，不要改 `DnsCache.Answer`：**

```text
upstream → NormalizeAndCacheDnsResp_
         → DnsCache.Answer / NS / Extra = 真实 RR（immutable，reload 可跨 generation 共享）
         → prepackResponseBeforeStore() = real packed
         → cacheAccessCallback → domain_routing_map（真 IP）
         → 写出：FakeIPPolicy.eligible ? FakeIPPolicy.packed(qname,qtype) : real packed
```

cache hit 走 `GetPackedResponseWithApproximateTTL()` 的是 **real packed**。Fake 应答由当前 generation 的 FakeIPPolicy 合成/侧缓存，epoch 变了就重建。禁止把 FakeIP 写进 `DnsCache.Answer`。

`shouldFake` 每请求算；`fakeAddress(qname)` 在 FakeIPStore（含 retired LookBack）。白名单 A 假、非白名单 B 真，仍是同一条 real `DnsCache`。

4. TCP `domain++`：嗅探 SNI 优先，失败才 LookBack。`shouldTryTcpSniff` 对 `direct`/`block` 不嗅探。
5. UDP：现网 `DialOption.Target` **故意钉 `realDst`**（`udp.go`：「Keep fixed-IP target even if chooseProxyDialer selected a domain target」）。真 CDN IP 时这是对的；`realDst=198.18` 时必须改 `DialTarget` 为解析出的真 IP，**key 仍用 FakeIP**（见第 7 节）。

同 IP 不同 outbound 上楼（`domain_routing_tracker` / `Ambiguous` / `identitySensitive`）这个分支已经有，和 FakeIP 正交。不要用 #763 修 421。

---

## 3. 谁才准 FakeIP

判定只发生在 **DNS 写出层**。`shouldFake` 与 `fakeAddress` 分开。filter 短路之后跑 **独立的三值求值**，不要扩 `conflictFingerprint`（那是真 IP + domain bitmap 的 shared-IP ambiguity）。

### 3.0 Kleene + first-match

每个 predicate：TRUE / FALSE / UNKNOWN。

DNS **已知**：`domain()`、`ipversion()`（由本次 A/AAAA 问句）。  
DNS **当 FALSE（继续下一条）**：`l4proto()` / `dport()` / `sport()`。FakeIP 拆的是 TCP HTTP/2；这些不是「符合」。当成 TRUE 会命中 223 的 `domain && udp && 443 -> block`，google/chatgpt 仍然不假。  
DNS **UNKNOWN**（不当 true，有 `domain()` 则停表）：`ip()`/`dip()`、`mac()`、`sip()`、`pname()`、`dscp()`。

AND：`TRUE && UNKNOWN = UNKNOWN`，`FALSE && _ = FALSE`。  
OR：`TRUE || _ = TRUE`，`FALSE || UNKNOWN = UNKNOWN`。  
NOT：`NOT UNKNOWN = UNKNOWN`。

按 **原始规则顺序** first-match。但 UNKNOWN 必须先区分 **是否与这个 qname 有关**：

- 规则里 **没有任何 `domain()`**（223 开头的 `dip(组播)` / `sip(222)` / `dscp(0x4)` / `!sip(match_mac:…)`）→ 对 FakeIP eligibility **当 FALSE，继续下一条**。这些规则约束的是未来那张包的 IP/MAC/DSCP，DNS 阶段既证不成 TRUE 也证不成「这个名字不该假」。包上路之后仍按 traffic routing 匹配。
- 有 `domain()` 且 Kleene 为 **TRUE**：outbound 是 `direct`/`block`/`must` → **DIRECT**。outbound 是用户组 → 看 **当前选中走到的叶子**（只读 `FixedIndex` / 嵌套成员，**禁止 `Select()`**）：叶子 `direct`/`block` → **DIRECT**；叶子是节点 → **PROXY**。`url-test` / `min` / `random` / `first_alive`：成员里有节点就是 **PROXY**。
- 有 `domain()` 且 Kleene 为 **UNKNOWN**（`domain(example) && ip(cidr)`、`domain && sip/mac`）→ **UNKNOWN**，**不能看下一条**。
- Kleene **FALSE**（`domain()` 没命中，或 `domain() && udp` 因传输层当 FALSE）→ 继续。
- 落到 fallback：同样走叶子；`direct`/`block`/`must` → **DIRECT**。223 的 `fallback: Apple_Proxy` 叶子是节点 → 假。`CN_CN` 当前选中 `direct` → 不假。

反例（原文不修会废掉 223）：`dip(224.0.0.0/3) -> must_direct` 若当 UNKNOWN 停表，chatgpt.com 也假不了。它没有 `domain()`，应跳过。

反例（`destDontCare` 把 `ip()` 约成真）：

```text
domain(suffix: example.com) && ip(203.0.113.0/24) -> AI
fallback: direct
```

`example.com → 8.8.8.8`：`TRUE && UNKNOWN = UNKNOWN` → 真 IP。约掉 `ip()` 会错成 PROXY。

223 的 QUIC 拦截（传输层当 FALSE，看下一条）：

```text
domain(openai.com) && udp && dport(443) -> block
domain(openai.com) -> AI
fallback: direct
```

第一条 `TRUE && FALSE && FALSE = FALSE` → 继续 → `domain -> AI` → 假。包上路 UDP/443 仍按 traffic routing block。不要把 udp 当成「符合」。

实现：`RoutingMatcher.FakeIPEligibility(domain, ipVersion)`，按 compiled matches 三值求值；用户组经 `DialerGroup.FakeIPLeafIsProxy`。不要 `matchFacts + destDontCare`。

| 态 | 发给客户端 |
|---|---|
| **PROXY** | FakeIP |
| **DIRECT** / **UNKNOWN** | 真 IP |

MAC 分流（同一名字 A 代理、B 直连）**不做**：UNKNOWN → 真 IP。

`match: domain-rule` = 求值结果为 PROXY。禁止 `Route(dst=198.18)` 探测。`filter_mode: only` 仍要 PROXY。

---

### 3.1 `filter`（fake-ip-filter）

Clash/mihomo 的 `fake-ip-filter` 是全局 FakeIP 的逃生口；kdae 主闸已经是「只代理域名」，filter 解决的是：**routing 里 `domain()` 进了代理组，但这条 DNS 不能假**。典型：STUN/NTP/推送/连通性检测走 UDP、无 SNI，假地址会按第 7 节钉 `198.18.x` 出口。

**不是** `dns.routing`。`dns.routing` 只选上游；FakeIP eligibility 是 traffic 三值求值。**不要**把 `asis` 定义成 FakeIP skip：`asis` 只表示问句仍交给原来的 DNS 目的。局域网名交给 builtin/user `filter`。某 public qname `-> asis` 且 traffic 上 `domain() -> AI`（且三值为 PROXY）仍可假。

#### 模式

| `filter_mode` | 含义 | 对应 Clash |
|---|---|---|
| **`skip`（默认）** | 命中 filter → 真 IP。未命中再走 `domain-rule` | `fake-ip-filter-mode: blacklist` |
| **`only`** | 必须命中 filter **并且** `domain-rule` 是代理组 | `whitelist`，但 **∩ 代理组**，空表 = 全真 IP |

不要 Clash 的 `filter-mode: rule`（`GEOSITE,gfw,fake-ip` / `MATCH,fake-ip`）：和 `match: domain-rule` 重复，一写成 `MATCH` 就变相全局 FakeIP。

不要 Clash 通配符（`+.lan`、`*.lan`、`stun.+`）。mihomo 里非法 `stun.+` 会**静默关掉全部 FakeIP**。这里只用现有 **`qname()` 参数**：`full` / `suffix` / `keyword` / `regex` / `geosite:`。编不过就是配置错误，起不来。

`dns.fakeip.filter` **不是** `KeyableString`。dae 解析器对 `filter: qname(...)` 这种「冒号后跟函数」没有现成类型，要做成 **子段里的函数列表**（和 `dns.routing.request` 同类，但没有 `-> outbound`）：

```text
filter {
    qname(suffix: lan, suffix: local, keyword: stun)
    qname(full: localhost.ptlogin2.qq.com)
    qname(geosite:private)
}
```

多行合并进**同一张** `DomainMatcher`，DNS 路径匹配一次。不要每条正则现场跑。用户表编译失败 → 拒绝加载配置。`cmd.dnsConfigFingerprint` / `TestDNSConfigFingerprintCoversAllDnsFields` 必须把 `fakeip` 整段算进 fingerprint，改 filter 要换 DNS 平面。

#### 内置 skip（`filter_builtin: true`，默认开）

用户 `filter` **不能放行**内置项（没有 `unskip`）。关闭内置必须显式 `filter_builtin: false`，并在日志打 warn。

| 类 | 默认模式（dae 语义） | 为什么 |
|---|---|---|
| 局域网 / 特殊 TLD | `suffix: lan, local, localhost, home, internal, arpa, localdomain` | mDNS、PTR、家用名；假了没有可拨的真目标 |
| 私网分类 | `geosite:private`（DAT 没有则跳过并 warn） | 同左 |
| STUN/TURN | `keyword: stun`；另加 `full: stun.l.google.com, stun.cloudflare.com, turn.cloudflare.com` | WebRTC UDP 无 SNI。不要写 `suffix: l.google.com`（会误伤一串 `*.l.google.com`） |
| NTP / 校时 | `full/suffix: time.apple.com, time.windows.com, time.google.com, ntp.org` | UDP 无 SNI；223 `domain(geosite:apple)` 会误伤 `time.apple.com` |
| 连通性检测 | `suffix: msftconnecttest.com, msftncsi.com, captive.apple.com` | 假地址探活结果无意义，部分系统会当成「无网」 |
| QQ 登录坑 | `full: localhost.ptlogin2.qq.com` | Clash 经典例外，真解析才是 127.0.0.1 |
| **节点 / 订阅主机名** | 启动时从 `tagToNodeList` 抽 hostname，`full:` 进内置表 | FakeIP 后再去拨节点 = DNS/拨号环。Clash 用 `proxy-server-nameserver` 绕；我们直接不假 |

`keyword: turn` 不要进内置（误伤太多）。`keyword: stun` 可接受。xiaomi market 等留给用户 `filter`。

223 建议：**builtin 开**，用户再加游戏 UDP 主机、推送（`suffix: push.apple.com`）等无名 UDP。不要为了「少写几行」关 builtin。

#### 和映射 / 热路径

- filter 只影响 **新 DNS 要不要分配/改写**。LookBack 仍是 O(1) map，不跑 DomainMatcher。
- 名字先假后进 skip：客户端缓存里的 198.18 仍要能还原。持久化 **反向表保留**；正向（qname→ip）不再用于新应答。reload 改 filter 同理，不要扫盘删条目。
- 内置 + 用户 skip 编译进独立 matcher（1～2 bit），**不要**和 traffic `domain()` 那张 65536 bitmap 混在一个 set 里。

---

## 4. 地址、映射、内核兜底

- IPv4：`198.18.0.0/15`（不要 `28.0.0.0/8`）。
- IPv6：配置里写实际**分配池**，建议 `fd00:daee::/96`（或 `/112`），不要把 `/48` 当线性池。对外声明可以仍是 ULA，哈希/序号必须落在池内。`/48` 与第 6 节「不要扫 /48」冲突。
- 分配：FQDN 哈希进**池**（不是整个 /15 再靠运气），碰撞用内存表探测。同一名字固定同一地址。
- 给客户端的 DNS TTL 宜 30–60s（[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)）。**分配本身不跟 TTL 过期**。不要 TTL=1。
- **缓存**：`DnsCache` 只有真实 RR 和 real packed。Fake 应答由 **FakeIPPolicy 侧缓存**（带 policyEpoch / mappingEpoch），不作为 DnsCache 的 authoritative payload。epoch 不一致则重建。
- **A/AAAA**：eligible 时合成 **最小应答**：Question 名一条 Fake A 或 AAAA。CNAME、末端真 A/AAAA **不给客户端**，只留在 real cache。不要 `CNAME + Fake A` 混在一个 Answer 里。
- **AAAA** 同类 qname 也要假；不做 FakeIP 的 qtype 用 NODATA（NOERROR 空 Answer），不要 NXDOMAIN。
- **HTTPS/SVCB**（type 64/65）：eligible qname → **NOERROR / NODATA**。不要保留 SVCB 只剥 hint（还有 target / ECH）。逼客户端回 A/AAAA。
- 合成应答清 AD 位。
- [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343)：qname 入库前小写。
- [RFC 2544](https://www.rfc-editor.org/rfc/rfc2544) / [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890)：假地址禁止出 WAN。IPv6 [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) ULA 同样不外泄。
- **假地址不进 `domain_routing_map`。**

### 4.1 要不要 `control`

要的是两件事，**不是**多一个用户 outbound。

1. **假地址不能被内核当普通 IP 转发。** `domain_routing_map` 没有 198.18，`geoip:cn` / `geoip:private` 也对不上这段（RFC 6890 不是 RFC1918）。规则表走完只剩 fallback。223 的 fallback 是 `Apple_Proxy`，白名单客户端会 tproxy，**碰巧**不会出 WAN。官方示例 `fallback: direct` 则会把 198.18 直出，违反 RFC 6890。非白名单 `must_direct` 同样会出 WAN。所以 enable 时内核要像目的 53 那样：**LAN 上目的在池内 → 强制 tproxy**（内部可以仍标 `OUTBOUND_CONTROL_PLANE_ROUTING` / 0xFD），WAN 入站 drop。这是前缀特判，**不是** `routing {}` 里的一条 `dip`。

2. **上楼之后必须按名字重匹配。** 内核看见的 dest 是 198.18，选出来的 outbound 没有意义（223 上会是 fallback `Apple_Proxy`，不是 `AI`）。`dial_mode: domain++` 在 **嗅探到 SNI** 时会 `shouldReroute` 再 `Route(domain=sni)`，HTTPS 往往能纠正。嗅探失败、UDP 无 SNI、ECH：不会 reroute，会按内核给的组去 **拨 198.18**。所以 `chooseProxyDialer`：`dst` 在池内 → LookBack → 有名则 `Route(domain=名)`，无名则拒绝。有 SNI 时 SNI 优先。

**不要**增加名为 `control` 的配置 outbound，也 **不要** 自动往 matcher 插 `ip(池) -> 0xFD` / `dip(池) -> control`：

- 用户配置语言里 `dip` 是 `ip` 的别名（`AliasOptimizer`），但 **没有** `control` 这个 outbound。`outboundToId` 只认 OR/AND/must 和 group 名。
- 把 `ip(池)->0xFD` 当 INTERNAL RULE #0 插进 match_set：内核上楼没问题，用户态 `Route(dst=198.18, domain=sni)` **会再命中这条**，返回 0xFD，`0xFD >= len(outbounds)` 拨号失败。除非 matcher 对「已经在用户态、且 dst 在假地址池」跳过这条——等于特判，不如一开始就不要进表。
- `dip(池) -> AI` 更糟：所有假地址焊死一个组。

内核前缀特判：**FakeIP prefix bypasses outbound decision, not metadata collection / conn-state publication。** 仍要记下 MAC、pname、pid、DSCP、sport、routing epoch，后面 `LookBack → Route(domain=qname)` 要用。WAN 入站目的在（active∪retired）池内 drop。LAN 上这些前缀强制 tproxy（内部可标 0xFD），优先于 `must`。

用户态 LookBack 后 `Route(domain=名)`。Dial 前 invariant：**target ∈ fake pool → 禁止进入任何 Dialer**（含 `direct`）。Route 结果：

- 用户组 → 用域名 / 解析出的真 IP 拨。
- `block` → block。
- `direct` / `must_direct` → **拒绝**（等客户端 FakeIP TTL）。有意为之：reload/`enable:false` 后最多一个 TTL 短暂断流。禁止 resolve 后 `direct` 真 IP（会绕过当时「丢掉假地址」的安全选择），更禁止 `direct.Dial(198.18)`。

现网 `tproxy.c` 对 ICMP `return 1`；要本地 reply **并 drop**，见第 8 节。内核 trap 的前缀 = **active ∪ retired**。

---

## 5. 持久化（进程级 FakeIPStore）

映射是 **已经发给 LAN 的地址契约**，不是某个 ControlPlane generation 的资产。现网 reload 是 generation/epoch handoff：`DnsCache` RR immutable 跨代共享，`RestoreReloadCacheAndProject` 在 cutover 前同步 BPF；TCP/UDP endpoint 带着创建时的 routing epoch。不要做成「旧平面 flush → 新平面读盘」。

```text
Runner
 └── FakeIPStore          # process-owned：map + WAL + snapshot
      ├── ControlPlane gen N     FakeIPPolicy（filter / matcher / enable / range）
      └── ControlPlane gen N+1   新 policy，同一份 Store
```

reload 只换 **policy**。mapping 契约还在。

### Store 代际

```text
FakeIPStore
 ├── ACTIVE     Lookup / LookBack / 新分配；内核 trap
 └── RETIRED…   只 LookBack；内核仍 trap；禁止把这些地址分给新 qname
```

- **range 变更**：新 ACTIVE 用新池分配；旧 generation → RETIRED，文件备份。不要「备份后空表、立刻撤旧 prefix」。
- **`enable: false`**：停止 **新的** FakeIP DNS；ACTIVE 转 RETIRED。不是立刻停止识别历史 FakeIP。
- **grace**：`max(fake DNS TTL + 安全裕量, tombstone 默认 24h)` 之后才真正删除 RETIRED，并从内核 trap 拿掉该前缀。
- **invariant**：地址只要还在 ACTIVE 或 RETIRED/tombstone reverse 里，**不得**再分给另一个 qname（否则旧客户端 LookBack 会拨错名，比丢包更糟）。

内核 trap = 所有未过期 generation 的前缀并集。

### 路径

必须放在 **`persist.d/fakeip/` 子目录**。`cmd/run_controlplane.go` 会把 `persist.d/` **根下**陌生普通文件当订阅 tag 删掉；子目录 `continue`。

组选择现网是 `persist.d/group-selections/state.json`（0600、目录 0700、flock、tmp、fsync、rename、dir fsync），不是旧的 `mihomo-group-selection.json`。FakeIP 落盘纪律可以抄它；更新更勤，所以仍用 snapshot+WAL，不要每次 JSON 整文件重写。

默认运行时文件（**二进制**，不是 JSON）：

```text
<configDir>/persist.d/fakeip/mapping.bin
<configDir>/persist.d/fakeip/mapping.wal
```

`<configDir>` = 主配置所在目录（223 上即 `/etc/dae`）。可用 `dns.fakeip.path` 覆盖目录，但仍应落在 `persist.d/fakeip/` 下。排障可另 dump 一份 `mapping.json`，**不要当热路径或启动主格式**。

### 文件格式

`mapping.bin`：magic `KDAEFAK1` + version + inet4/inet6 前缀 + `count` + 定长/长度前缀记录。每条：intern 后的 qname、IPv4、IPv6、`updated_unix`。反向索引启动时从记录重建，不另存一份。

`mapping.wal`：只追加「新分配 / 覆盖」；启动 = 读 snapshot 再 replay WAL。WAL 过大（例如超过 snapshot 一半或 64KiB）时折进新 snapshot。

- qname 规范化（小写、有尾点，RFC 4343）。
- 不持久化真实解析 IP、bitmap、TTL；重启后真 IP 再问上游，**真 IP** 的 bitmap 按当时 `routing {}` 重投影。

### 读写

- **进程启动**：读 snapshot+WAL。体积上限 `max(2MiB, 64+max_entries×256)`。流式解码、预分配。range 与当前 ACTIVE 不一致：旧表进 RETIRED（仍加载 reverse），新 ACTIVE 空表起步。损坏则 ACTIVE 空、RETIRED 无，dae 必须能起来。Store 起来之前不要对外发新 FakeIP。
- **新分配**：内存占槽 → 记 seq → WAL append → **fdatasync / group commit** → 仅当 `durableSeq >= mySeq` 才写 FakeIP DNS。后续同名 Lookup 不写盘。group commit 可以一次 sync 多条，但 waiter 必须等自己的 seq durable，不能「先回 DNS 再异步 fsync」。
- graceful reload：Store 仍在；disable/range 变走 RETIRED，不是整表扔掉。进程退出前 flush snapshot。
- **原子 snapshot**：`mapping.bin.tmp` + fsync + rename；目录 fsync。抄 `GroupSelectionStore`。
- 热路径只读内存；单 writer 落盘。

### 淘汰

`max_entries`（默认 32768，硬顶同值）只计 **ACTIVE 活条目**。表满：oldest ACTIVE → RETIRED/tombstone（仍 LookBack、地址不重用）→ 再给新 qname 分配 **新地址**。不要「打满就停止发 FakeIP」。tombstone 另计，上限同量级。不要在每个 TCP/UDP 包上更新 LRU。grace 过完才释放地址回池。

---

## 6. 性能预算、RFC、他山经验

热路径（LookBack / 已分配 Lookup / ICMP 查映射）**O(1) 内存读**。首次分配含 WAL，不在这条路上。

### 测试（实现时必须有）

| 路径 | 目标 |
|---|---|
| LookBack / Lookup 命中 | P99 < 1µs，**0 syscall** |
| 纯内存占槽（尚未 WAL） | P99 < 20µs |
| 首次 durable publish（含 fdatasync） | 单独测，P99 < 10ms |
| 8k snapshot 启动 | P99 < 20ms |

不要把 WAL 和「零 syscall」写在同一条 bench 里。并发 LookBack 正确；热路径无盘。

### 热路径允许 / 禁止

| 允许 | 禁止（Clash/sing-box 踩过） |
|---|---|
| `uint32` 偏移 → intern id 的 map / swiss table；IPv4 用前缀内 offset 当 key | 把 `net.IP` / `string(ip)` 当 key |
| `RLock` 或无锁读；命中返回 intern 的 `string`（零分配） | 全局 `Mutex` 包住 LookBack（mihomo `Pool.LookBack`） |
| 前缀判断用 `netip.Prefix.Contains` 或已经在内核 `dip()` 做完 | 热路径读 bbolt / 任何 `fsync` |
| DNS 分配路径才写 Store + WAL | LRU `Get` 把节点搬到链表头（读变写，mihomo `memoryStore.GetByIP`） |
| | `encoding/json`、正则、域名 bitmap 重算 |

ICMP 假 reply：有映射才回 = 一次 LookBack，同样 µs。不要为 ping 另建结构。

### 内存与启动

选择性 FakeIP 正常是百～千条，不是 `/15` 的 13 万。**用 `max_entries` 锁死**，CIDR 只决定地址空间。

| `max_entries` | 内存（intern + 双向表，量级） | `mapping.bin` | 启动解码（量级） |
|---|---|---|---|
| 1 024 | ~0.3 MiB | ~50 KiB | <1 ms |
| 8 192 | ~2 MiB | ~0.4 MiB | 1–3 ms |
| **32 768（默认 / 硬顶）** | **~8 MiB** | **~1.5 MiB** | **~10 ms** |

预算：启动加载 **P99 < 20 ms**；体积上限见第 5 节，不要和 `max_entries` 各说各话。加载时峰值 ≤ 稳态的 1.2 倍。223 上再加 8 MiB 可以；再大会挤 eBPF/订阅。

IPv6 池用 `/96` 或 `/112`，不要 dense `/48`。IPv4 `/15` 也不要做 13 万槽数组，表里只存已分配。

### 不要抄的实现

概念祖先是 [RFC 3089](https://www.rfc-editor.org/rfc/rfc3089)（SOCKS 网关用假地址当 FQDN 的 key）。现网实现：

- **mihomo 内存模式**：双向 LRU。`Get` 提升链表 = 每条连接写。`store-fake-ip` 后 store 换成 **bbolt，Lookup/LookBack 同步读盘**，OpenWrt flash 上是 **百 µs～ms**，而且 Persistence 时 **Size 上限失效、全量堆积**。
- **sing-box**：脏数据在内存 map，未命中 **fallback `bbolt.View`**。启动可以很快（不预加载），但重启后 **第一条 SYN 的 LookBack 走盘**。我们要的是重启后立刻 µs，所以必须 **启动时把有界表全部装进内存，盘只做 WAL/snapshot**。
- **v2ray FakeDNS**：一般纯内存 LRU（常见 65535），重启丢失。kdae 网关不能这么干，但热路径形态可以学：map、不上盘。
- Clash 默认 **TTL=1**、常丢掉 AAAA：53 QPS 高、Happy Eyeballs（[RFC 8305](https://www.rfc-editor.org/rfc/rfc8305)）行为怪。我们 TTL 30–60s，AAAA 也假或明确空。

落盘学 `GroupSelectionStore` 的 fsync/rename，**`durableSeq >= mySeq` 才应答**；不要学 sing-box 热路径读盘。

---

## 7. 拨号

### TCP

1. 嗅探成功 → 用 SNI。
2. 否则 LookBack 映射名。
3. `Route(domain)`。**Dial 前**若目标 ∈ fake pool（active∪retired）→ 拒绝。
4. Route 到用户组 → 按域名/真 IP 拨。到 `block` → block。到 `direct`/`must_direct` → 拒绝，等客户端 TTL。禁止 `direct.Dial(198.18)`。

`shouldTryTcpSniff`：内核 0xFD 不是 direct/block，会嗅探。sniff 失败靠 LookBack。

### UDP / H3

现网会在 `chooseProxyDialer` 之后把 `DialOption.Target` **覆盖回 `realDst`**。真 CDN IP 时为了 QUIC 会话；FakeIP 时绝对不能沿用。

```text
packet dst = FakeIP
  → LookBack qname（无名则拒绝）
  → userspace Route(qname) 选 outbound
  → resolve qname 一次
  → UdpEndpoint {
        key        = client Src + 原来的 FakeIP dst   // flow / 回包 / BPF conn
        domain     = qname
        DialTarget = 真实 IP:port                     // 才发给节点
    }
  → 后续包同一 endpoint、同一 DialTarget
```

两个地址都要留着：客户端观察的仍是 FakeIP；`WriteTo` 用 `DialTarget`。现成字段：`SniffedDomain`、`DialTarget`、flowBinding。有 QUIC SNI 时 SNI 优先于 LookBack。

无名普通 UDP（真地址）保持现状钉 `realDst`。有名字的 H3/QUIC FakeIP：resolve once，钉 `DialTarget`。Packet Addr / 全锥载荷带目的 IP：改成钉死的真 IP，或这类协议不要 FakeIP。

---

## 8. ICMP：假回应，不转发

LAN `ping` 假地址必须有回应，否则探活类 App 当死。本地 echo-reply 并 drop 原包，不经代理转 ICMP。

现网 `tproxy.c` 对非 TCP/UDP `return 1`，内核当转发；段内无 FIB 则超时，有默认路由则可能把 198.18 送 WAN。

**做：本地 echo-reply，然后 drop 原包。** 目的在池内、ICMP echo-request（以及 ICMPv6 echo）→ 立刻回 echo-reply，源地址 = 那个 FakeIP，id/seq 原样；**原包不得进入转发**。只 reply 不 drop 时，内核仍可能把 198.18 送 WAN（RFC 6890 泄漏）。RTT 是局域网量级，只表示网关认这个假地址。

不要用 `ip route add local 198.18.0.0/15 dev lo`：整段变成本机投递后，TCP/UDP 也会进本机栈，**tproxy 失效**。假 ping 必须只拦 ICMP，例如：

- LAN 入口 eBPF：echo 且 dip 在池内则改包成 reply 并 `bpf_redirect` 回入接口，原方向 drop；或
- nft 把这类 ICMP 送到用户态 raw socket 回包，并 `drop` 原包。

无映射的 FakeIP（客户端乱 ping 段内空洞）也可以回 reply（Clash 常这么干），或静默丢。**有映射才回，没有就丢**，避免把整段扫活。

**不做：经代理转发 ICMP。** SS / Hysteria2 带不了 ICMP。从 223 WAN 直连 ping 真 IP 等于绕过分流、还常被墙。traceroute 同理，假 reply 也救不了 TTL 探测。

---

## 9. 配置草案

默认关。

```text
dns {
    fakeip {
        enable: true
        inet4_range: '198.18.0.0/15'
        inet6_range: 'fd00:daee::/96'   # 分配池；不要 /48
        match: domain-rule
        ttl: 60
        max_entries: 32768
        path: 'persist.d/fakeip/'
        filter_mode: skip
        filter_builtin: true
        filter {
            qname(suffix: push.apple.com)
            # filter_mode: only 时举例：
            # qname(suffix: openai.com, suffix: chatgpt.com, suffix: cursor.sh)
        }
    }
}
routing {
    # 不要写 dip(池) -> control / AI。enable 时内核前缀特判 tproxy。
    # 现有 must_direct / domain() ...
}
```

默认关。223 打开前确认与 222 Clash TUN 前缀错开；222 本机不吃 kdae FakeIP。

---

## 10. 实现清单

一次做完，不拆发布档。

- 解析 `dns.fakeip`。Store 挂 Runner（ACTIVE+RETIRED）。enable 时 eBPF trap **active∪retired** 前缀；只改 outbound 决定。不注册 `control`。fingerprint 覆盖 fakeip 整段。
- 三值 `FakeIPEligibility`（`predicateGroups`）。real DnsCache + Policy 侧 fake packed。首次 FakeIP：`durableSeq >= mySeq` 再应答。
- TCP/UDP 拨号 invariant：假地址不进 Dialer。ICMP reply+drop。
- 测试另加：`domain && ip(cidr)` 不得 FakeIP；`domain && udp -> block` 再 `domain -> AI` 不得 FakeIP；range/`enable` 变更后旧 198.18 仍 tproxy 且 LookBack 对；tombstone 地址不重用；满表淘汰后新名字仍能假。

---

## 11. 收益 / 弊端 / 代价

**收益**

- 走 223 的 53 的客户端：每个代理 FQDN 独立 IP，HTTP/2 不会把 api 焊到 chatgpt 的 TLS 上（不依赖拿掉 1stream，也不依赖 App 处理 421）。
- 问过 53 时 ECH/嗅探失败仍能按名字拨号。
- 国内直连、非白名单、无 `domain()` 的 fallback 仍真 IP，内核直连还在。
- FakeIP 不占 `domain_routing_map`；内核靠前缀特判 tproxy，用户态按映射名 `Route()`。
- `ping` 假地址有本地 reply，探活类 App 不超时。

**弊端和代价**

- 只覆盖 kdae 53。DoH、硬编码 IP、非白名单污染 DNS 照旧。
- 实现面：DNS 改写（含缓存分叉）、真 IP 投影、落盘、内核前缀特判、TCP/UDP 拨号、ICMP reply+drop、reload、双栈、fingerprint。完整特性，不是补丁。
- 落盘：首次 FakeIP 等 WAL durable；range/disable 走 RETIRED，不立刻撤 trap。
- 默认 32768 条 ACTIVE；满则 oldest → tombstone 后再分配新地址（tombstone 不重用）。
- ping RTT 是局域网，不能当国际延迟。traceroute 仍无意义。
- Packet Addr、无名 UDP + FakeIP 仍废；用 `filter` 把 STUN/NTP/游戏 UDP 主机留下来，不要把 FakeIP 铺上去。

**不要做的**

- 全局 FakeIP、`28.0.0.0/8`、`match: fallback`、用户或编译器把 `ip/dip(池) -> control/0xFD/某个组` 写进 matcher。
- 靠 223 `fallback: Apple_Proxy` 代替内核前缀特判。
- 用 `destDontCare` / 跳过 `ip()` 当 TRUE；有 `domain()` 的 UNKNOWN 规则跳过看下一条。
- 把没有 `domain()` 的 `dip`/`sip`/`dscp` 当 UNKNOWN 停表（223 会全真 IP）。
- range/`enable:false` 立刻清 reverse map 或撤内核 trap。
- tombstone / RETIRED 地址立刻分给新 qname。
- Fake packed 当 DnsCache 权威字段且不带 epoch。
- 内核 FakeIP 短路时丢掉 MAC/pname/DSCP/conn-state。
- `direct.Dial(198.18)`；把 `asis` 当 FakeIP skip。
- 把 WAL 和「P99 < 20µs / 0 syscall」写成同一条 bench。
- FakeIP 无名 UDP 回退拨 dst IP；ICMP reply 后仍转发原包。
- 把 FakeIP 写进 `DnsCache.Answer` / optimistic cache。
- `filter: qname(...)` 当 KeyableString；IPv6 用 `/48` 当分配池。
- Clash `filter-mode: rule` / `MATCH,fake-ip`，或 `only` 白名单不与 `domain-rule` 求交。
- Clash 通配符 `+.lan` / `stun.+`（非法模式静默全关）。filter 语法错误必须拒绝启动。
- 用户 filter 覆盖内置 skip（没有 unskip）；热路径跑 DomainMatcher。
- 在 kdae 里做 HTTP/2 拆流 / MITM / 「域名不同禁止复用」开关（四层做不到）。
- 把 FakeIP 写入 `domain_routing_map`，或 `ip route local` 整段（会把 TCP/UDP 变成本机投递）。
- 经 SS/Hysteria 转发 ICMP，或从 WAN 直连 ping 真 IP 冒充。
- 把 mapping 放在 `persist.d/` 根下当普通文件（会被订阅清理删掉）。
- 只把映射放在内存/reload store 而不写盘（重启必丢）。
- 热路径读 bbolt/JSON、读时更新 LRU、无 `max_entries` 全量加载、Clash 式 TTL=1。
- 把 mapping 主格式做成 `mapping.json` 当启动输入（dump 可以）。
