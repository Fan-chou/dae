# DNS、dial_mode 与一 IP 多域名（2026-08-18）

> 对照代码：当前分支 `feat/mihomo-rule-provider-groups`  
> 223 配置：`openwrt/kdae/files/config.nikki-replace.dae`（`dial_mode: domain++`，无 FakeIP，LAN 53 劫持后走真实解析）  
> 相关上游：[LostAttractor/dae#763](https://github.com/daeuniverse/dae/pull/763)（`do-not-merge`）  
> 上游对照见 [daeuniverse-main-2026-08-18.md](./daeuniverse-main-2026-08-18.md)  
> honk 对照（Rust 实验，OR bitmap 未做冲突抬楼；generation fence / 内核 direct 卸载条件可参考）：[honk-2026-08-19.md](./honk-2026-08-19.md)

**结论（未实现，只定设计）：**

1. 内核和用户态是**同一份** `routing {}` 的两套匹配器，不是每包双跑。
2. 当前 `domain_routing_map` 对同一 IP **无条件 OR bitmap**，CDN 共用 IP 且分流结果不同时，容易错成内核 `direct`，嗅探救不回来。
3. [#763](https://github.com/daeuniverse/dae/pull/763) 的主体合理：**同一 IP 上多个域名，最终 outbound/`must`/`mark` 一致则留内核，不一致则整 IP 抬到用户态嗅探再 `Route()`。不要整包合那个 PR。**
4. **全局 FakeIP 不上**（假地址不能内核真直连，解不了 DoH）。仅对 `domain()` 已能确定走代理组的 qname 回 FakeIP，见 [fakeip-proxy-domains-2026-08-21.md](./fakeip-proxy-domains-2026-08-21.md)。那是修客户端 HTTP/2 跨 Host 复用，不是修内核 OR bitmap。
5. 嗅探结果**不写** map。SNI 回填只能当弱 owner，且不得写入会导向 `direct` 的 bitmap。
6. 无解析的 80/443：只对「内核本要 `direct`」的连接抬用户态才有新收益，代价是 DoH 国内 HTTPS 变成用户态直连。

---

## 1. 两套系统不要混

| | 作用 | `dial_mode` 改不改它 |
|---|---|---|
| **DNS 控制面** | 拦目的端口 **53**；请求/应答分流；把 A/AAAA 投影进 `domain_routing_map`（epoch slot + 目的 IP → `DomainBitmap`） | 不改 |
| **dial_mode** | 已经 tproxy 上来的流：用什么地址拨号、要不要用嗅探域名再跑用户态 `Route()` | 只作用于用户态 |

内核匹配 `domain(...)` 时查的是 **目的 IP 的 bitmap**，不是现场 SNI。DNS 不过 dae → bitmap 空 → 域名规则 miss。

dae 只把 **UDP/TCP 53** 当 DNS。DoH/DoQ（443/853 加密）是普通流量，问句看不见，map 不会多记录。mosdns `:5335` 也打不中 53 fast path。

---

## 2. 内核 vs 用户态：不是双挂载抢包

一个 `RoutingMatcherBuilder` 吃同一份 `routing {}`：

- **内核**：`BuildKernspaceForSlot` → `routing_map` + LPM。域名没有 AC 自动机，只有 DNS 投影。
- **用户态**：`BuildUserspace` → 同一序列 `compiledMatches` + 真正的 `domainMatcher`（可吃 SNI 字符串）。`Match is modified from kern/tproxy.c; please keep sync`。

包路径串行：tc 先判 → 真直连不再进用户态 → 代理组 tproxy 上来后**默认不重跑整表**，只用内核给的 outbound 拨号。

用户态再跑 `Route()` 的情况：

- 内核标了 `OutboundControlPlaneRouting`（典型：非 `must` 的 53）
- `dial_mode` 的 `shouldReroute`（见下）
- DNS 上游自己选路、`domain_routing_map` 满、routing tuple 丢失

域名能力不对等：内核只能靠「这个 IP 曾经属于哪些规则」，用户态才能用真实域名。这是 `domain++` 存在的原因。

---

## 3. `dial_mode` 对转发 / 再分流的影响

`ChooseDialTarget`（`control/control_plane_dialtarget.go`）→ `chooseProxyDialer`（`control/dial.go`）。`shouldReroute` 把 outbound 改成用户态再匹配。直连/block 不嗅探。`dial_mode: ip` 把 `sniffing_timeout` 置 0。

| 模式 | 嗅探 | 用户态是否用嗅探域名重分流 | TCP 拨给节点 | UDP/H3 拨给节点 |
|---|---|---|---|---|
| **ip** | 关 | 否 | 目的 IP | 目的 IP |
| **domain** | 开 | **有 `HasDnsKnowledge`（或 real-domain 探测命中）就会** | 确认真域名则 `host:port`，否则 IP | 钉死目的 IP，outbound 仍可能变 |
| **domain+** | 开 | 否，沿用内核 outbound | 一律嗅探域名 | 钉 IP |
| **domain++** | 开 | **强制** | 一律嗅探域名 | 钉 IP，可按 SNI 换组 |

官方 `example.dae` / `config/desc.go` 写：`domain` 只改拨号、不重路由。**当前实现不是这样**：`domain` 只要有 DNS knowledge 就 `shouldReroute = true`。223 配的是 `domain++`，与文档一致。

UDP 故意和 TCP 不同（`udp.go`：`Keep fixed-IP target even if chooseProxyDialer selected a domain target`），避免 QUIC 被远端换 IP 打散。

`HasDnsKnowledge` 仍走平面上的 `c.dnsController`，reload reuse 会置 nil（[#1081](https://github.com/daeuniverse/dae/pull/1081)）。`domain++` 不走这段，坑小。DNS 收包已用 `ActiveDnsController()`。

---

## 4. 一 IP 多域名（CDN）

文档（`docs/zh/how-it-works.md`）已写误判：国内/国外站共用 IP。

当前 `domain_routing_tracker`（`control/domain_routing_tracker.go`）按 IP 把多个 DNS owner 的 bitmap **OR** 进内核。不是官方那种后一次 DNS 整表覆盖。

- 两域名命中**同一条**分流结果 → OR 后内核仍对。
- 分流结果**不同** → 内核按 `routing {}` **第一条命中的 `domain()`** 定胜负。

危险的是判成 **`direct`/`must_direct`**：真直连不进用户态，`domain++` 救不回来。判成代理则 223 的 `domain++` 能用 SNI 再分流。

TCP 拨号用 SNI 与这张 IP 表无关；UDP/H3 仍连客户端解析出的 IP。

---

## 5. DoH / DoQ / 不发 53

对 dae 不是 DNS。解析完成后客户端连真实 IP，内核没有该 IP 的域名 bit。

223：白名单外 MAC 整机 `must_direct`，DoH 和后续请求都不会被嗅探。白名单且 fallback 进代理时，靠 `domain++` 补域名。ECH / 非 TLS 嗅探失败则一直按 IP。

`dial_mode: domain` 在这种路径上几乎退回按 IP 拨号（没有 knowledge）。

---

## 6. FakeIP：全局不上；选择性见另文

Nikki 曾用 `28.0.0.0/8`。全局 FakeIP 能分清 CDN 共用 IP，但假地址不能内核真直连，`dip(geoip:cn)` 无意义，假 IP 段必须全部 tproxy，且解不了 DoH/DoQ。官方不用，223 注释也曾定：53 真实解析 + 嗅探。

**全局 FakeIP 仍然不上。** 若只对 traffic `domain()` 已能确定走代理组的名字回假地址（这些流本来就要上楼），则不吃直连本钱，可拆开客户端 HTTP/2 跨 Host 复用。设计见 [fakeip-proxy-domains-2026-08-21.md](./fakeip-proxy-domains-2026-08-21.md)。

---

## 7. 嗅探写不写 map

**现在不写。** `domain_routing_map` 的唯一入口是 DNS 应答 → `BatchUpdateDomainRouting`。SNI/Host/QUIC SNI 只在：

- TCP：本次 `handleConn` 的局部 `domain`
- UDP：`UdpEndpoint.SniffedDomain`（endpoint 回收即没）

所以 DoH 即使这次嗅到 `netflix.com`，内核下次看到同一 IP 仍无域名 bit。

### 若按「一 IP 一域名」把 SNI 写进 map

原则可以共用，但 SNI **观察窗口不等于 DNS**：

- DNS：两次解析都会进 `DnsController`，即使流量已被 `direct`，tracker 仍能发现第二 owner。
- SNI：只有已经 tproxy 的连接才看得到。若第一次嗅探写入的 bitmap 让内核命中 `direct`，后续包不再上楼，**冲突检测失效**（先到者焊死）。

安全约束：

- 仅当用户态 `Route()` 结果是**代理组**时，SNI 才可以占这个 IP（给 DoH 的第二次连接用）。
- 已有 owner 且结果相同：保持。
- 已有 owner 且结果不同：整 IP 标歧义上楼，**不覆盖**。
- **禁止**写入会导向 `direct`/`must_direct` 的 SNI。
- 嗅探无 TTL，必须有空闲超时；ECH 写不了。

SNI 只是「补 DNS 空白的弱 owner」，不能和 DNS 平权先到先得。

---

## 8. 采纳的方案：#763 收窄版（未实现）

[#763](https://github.com/daeuniverse/dae/pull/763) 原文：两域名匹配同一条 domain 规则则内核走该 IP，否则强制用户态 sniff。标 `do-not-merge`，实现粗糙，**不要整包合**。

可落地判定：

1. 比 **最终 outbound + `must` + `mark`**，不是 bitmap 是否相等，也不是「是否同一条 `domain()`」。不同域名规则可以指向同一组，仍应留内核。
2. 抬的是 **该目的 IP 的所有后续包**。内核分不出连接属于哪个域名，做不到「只抬后来的那个域名」。
3. 目标必须是 **`OutboundControlPlaneRouting`（强制上楼）**，不能从 map 删除后去撞 `fallback`/`direct`。
4. 检测靠 **过 dae 的 DNS**。DoH 没记录，763 帮不上。
5. Owner 过期只剩一个域名时，可降回内核（现有 per-owner tracker 适合做）。

当前树是无条件 OR，比「冲突才上楼」更容易错成内核直连。若实现：改 tracker 合并策略 + 内核认歧义标记，不必跟 LostAttractor 的 DNS 大重构。

「先到先得、后来全上楼」更差：两个国内站也会无谓上楼；先到 `direct`、后来 Netflix，Netflix 会被内核放走。

---

## 9. 无解析的 80/443 抬用户态（未实现，与 763 正交）

已经进代理的 80/443，`domain++` 本来就会嗅探，再标「无解析就上楼」没有新收益。

补的是：**无 `domain_routing` + 内核要 `direct`**。DoH 真实 IP 被 `geoip:cn` 放走时，SNI 没机会。

代价：抬上去后即使用户态仍判直连，也是用户态再拨真实 IP，不是内核真直连。DoH 客户端的国内 HTTPS 会变成每条连接进 dae。

不要「凡是 80/443 无解析就抬」，若做：

**无 `domain_routing` 且当前匹配是 `direct` 的 80/443 → `OutboundControlPlaneRouting`。**

`must_direct`（223 非白名单 MAC）仍应先于这条。UDP 443（H3）同理；853 不是网页。不能接受国内 HTTPS 进用户态就别靠这条，去拦 DoH / 强迫 53。

与 SNI 回填正交：先上楼嗅探；只有结果是代理才考虑占坑。

---

## 10. 对 223 的含义

当前：`dial_mode: domain++`、`sniffing_timeout: 100ms`、无 FakeIP、53 真实解析、白名单 MAC 才进代理。

- 过 53 的解析：内核 `domain()`/`dip()` 可用；CDN 撞车仍可能被 OR 错成 direct（763 收窄版要补的洞）。
- DoH：内核无名字；进代理的 80/443 靠嗅探；已被 `direct` 的救不了（除非做第 9 节，并接受用户态直连）。
- 非白名单：整机 `must_direct`，上述用户态路径都不走。

优先顺序若动手：**#1081 空指针（小）→ 763 收窄版（正确性）→ 无解析 80/443 直连抬楼（可选，有性能代价）。** 不要全局 FakeIP，不要整包 #763 / LostAttractor `next`。客户端跨 Host HTTP/2 复用走选择性 FakeIP 文档，与 763 正交。
