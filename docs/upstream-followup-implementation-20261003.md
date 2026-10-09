# 上游跟进实施记录

日期：2026 年 10 月 3 日。对应[设计与历史复核](upstream-followup-plan-20261002.md)。

阶段一至四的 20 个单元已落地并提交；正确性批次已部署到 223。Astra 复核修正及版本见「Astra 审查修正与再次部署」。后续补充共享节点 splice、较长自然流量窗口、U1 的 off／observe 和 P1、P2 的默认关闭候选，结果见末尾。P3 完成生产调用审计，未接入的 GRO／arena 暂不移植。P1、P2 已有两种真实代理的 WAN 初测，仍不足以批准启用。修复后的 CS2 官方匹配本轮成功，用户报告没有卡顿或掉线；U2 已完成受控 SS AEAD 请求／应答现场验收，完整游戏阶段观测及实际业务执行资格仍待验证，不能将本记录理解为全部 25 个单元已经验收。

## 固定版本与历史约束

| 项目 | 首批部署版本 |
| --- | --- |
| 223 dae | `6e0d075c468a179034b558381f13ab0ff759ed91`，版本名 `upstream-followup-20261003` |
| outbound | `github.com/Fan-chou/outbound v0.0.0-sticky-ip.0.20261003043055-b642f95f5383` |
| quic-go | `github.com/Fan-chou/quic-go v0.0.0-20261003042709-d2a724750f5d` |
| qpack | 保留 `0844ed36f1cd` |
| 二进制 SHA256 | `44d134ba423629cff9c4cc6ccdb8afcbaa42b073002211c828da8daaa48906a7` |

两个依赖已分别发布到 [outbound 分支](https://github.com/Fan-chou/outbound/tree/codex/upstream-followup-20261002)与 [quic-go 分支](https://github.com/Fan-chou/quic-go/tree/codex/upstream-followup-20261002)，主仓库固定 immutable pseudo-version。正式验证及产物使用 `GOWORK=off`；构建信息确认 `vcs.modified=false`。主仓库本轮提交仍在本地 `fdae` 分支。

保留原有 DATAGRAM 取消、合包、发送诊断和应用供给判断，以及作用域 resolver、gRPC worker 引用计数、FD／netpoll 所有权和半关闭路径。接收 buffer 仍池化；发送 DATAGRAM 帧及 payload 改为独立持有，以修正回收后引用错误。

主动慢探测连续三次才降级；普通主动失败一次、QUIC TCP 槽失败三次、真实 alive 检查不通立即 dead 的口径保持。busy 阈值、TCP／UDP 钉选隔离、成功恢复预算、Laya HTTPS 和质量默认 off 保持。223 延用主要 fallback／url_test 组的 observe 范围，采集抽样仍为 25‰。

未引入静默 UDP 重建、整个 `/run/netns` 的 tmpfs 覆盖、固定 MSS 或新的性能默认值。显式规则与成员顺序保持；订阅标签消除 map 随机性后，原先依赖随机顺序的 fixed 索引可能选中不同节点。

## 已实施的修复

| 单元 | 修改与主仓库提交 |
| --- | --- |
| G0 | `c79329ea`：验证有效模块图中的三个依赖，支持 Fan-chou replace、隔离 checkout、缺失／重复目标失败 |
| Q1–Q5 | quic-go：有界接收环、发送所有权、截断关闭、HTTP3 GOAWAY 与有界重放、qlog 非阻塞及 audit 用例 |
| O1–O4 | outbound：REALITY AES-GCM／hello 兼容、typed dropped-datagram 契约、Vision／VMess／SS2022 边界、五项协议修复、独立 loopback 端到端测试和 wrapper 半关闭适配 |
| D1–D3 | `d7156f97`、`6e0d075c`：共享错误分类、DNS 有界跳过丢包及 TCP fallback、DoQ 调用者 ID 不变、内部 DNS 全范围 buffer；最终 TCP 故障不会被前序丢包掩盖 |
| C1 | `583b6441`：非法 ext 返回错误，QUIC 长度先用 uint64 核对再转换 |
| C2–C3 | `8c8faad4`：菱形 include 合并一次、稳定订阅标签、超限保留旧缓存、TTL／配置校验与 Marshaller.Bytes |
| D4–D5 | `3fc3361e`：IPv4 interface／all redirect 均检查，bootstrap 服务器拨号与查询结果地址族分离 |
| N1 | `d6a02ee6`：同步／lazy 卸载顺序保持，准确报告 errno；清理失败停止 NewNamed，日志移到锁外 |
| C4 | `288b4df1`：资产路径错误说明与可选 systemd 环境文件，保持 GOMAXPROCS 覆盖约定 |

协议端到端测试还发现现有 TLSObfs 把 105 字节 hello 丢弃请求放入三字节数组，导致 panic。额外移植[上游修复 12e2c24](https://github.com/olicesx/outbound/commit/12e2c24068e13f4da6a72a675e559efcf076cd53)，按实际大小丢弃并跳过空记录；outbound 提交为 `9a7be97`。

上游 coalescer 未整体移入；只适配当前已有 wrapper 的能力透传和半关闭，保留当前 fork 能力边界。

## 开发验证

| 验证 | 结果与范围 |
| --- | --- |
| strict 跨仓库 race | 发布版本下 3／3 通过，包含 outbound、quic-go、qpack；使用 `--short -- -race -p=1` |
| 主仓库 | 正式模块图下 `make test`、`make test-race` 及相关 vet 通过；正常 `make dae` 构建通过 |
| outbound | 正式发布 QUIC 下完整 race 套件通过 |
| QUIC | 根包、HTTP3、qlog 等 race 通过；最终完整 `integrationtests/self -race -count=1` 通过，耗时 72.7 秒 |
| 386 | QUIC 超大 token／protected payload 与 Naive padding 用例实际执行通过 |
| ARM64 | control 测试交叉编译通过，未在 ARM64 机器执行 |
| 队列与分配 | 保留两个接收包运行 20,000 次，存储容量保持 512；接收约 60–63 ns/op、0 alloc；1200 字节独立发送约 215–219 ns/op、1328 B/op、2 alloc |

QUIC 完整套件前两轮分别遇到 `TestStreamWriteCancellation/immediate` 超时及 `Test0RTTRetransmitOnRetry` 包数断言失败。取消定向重复五次通过，旧版本 Retry 重复十次通过，最终新版本完整集成套件通过。没有削弱断言；失败日志保留，后续仍需关注这些时序敏感用例。原依赖基线的 strict 运行也遇到 transport 启动状态断言失败，不能把基线描述为全绿。

发送退出池化的分配成本已量化；本批次没有以此宣称 p95／p99 或 GC 收益，也没有完成性能 A/B。

## 223 实测

### 服务与访问路径

使用与原产物一致的 Go 1.27.0、CGO=0、trace 与 `heapminimum512kib` 构建。原子替换 daemon，部署脚本包含 EXIT／信号失败回退，服务就绪后再解除回退。配置和 init 脚本 SHA256 均未变化；运行中 executable SHA256 与上述产物一致。IPv4 `all`、`br-lan`、`Home` 的 `send_redirects` 均为 0。

按用户指定从 **220** 验证：默认路由指向 223，Google 和 Cloudflare 的 HTTPS 请求均返回 **204**。223 日志确认源地址 `192.168.124.220`：Google 使用 `US_Dmit_LAX_Hysteria`，Cloudflare 使用 `HK_GG_IPLC_Dmit_HK`，均经过代理选路。

222 配置有 `sip(192.168.124.222) -> must_direct`，其 Google 超时／TLS 提前关闭不作为代理路径验收结果；222 的本地 Mihomo TUN 检查也不用于证明 223 正常。

### 五分钟自然流量

窗口为 2026-10-03 **04:46:48 至 04:51:48 UTC**，六个一分钟快照。该时间内服务持续运行，无采集 generation 变化或游标缺口。

| 指标 | 区间结果与分母 |
| --- | --- |
| capture considered／sampled | 新增 443／7；完成记录还包含窗口前已开始的流 |
| offload_unmeasured | 新增 2；区间导出的 9 个完成流中 2 个未测量，占 22.2% |
| invalid_window | 新增 0；15 个节点／本流可比较窗口，0／15 |
| queue_dropped | 新增 0；32 条导出记录加 dropped／oversize 的分母，0／32；API 不暴露待处理队列长度 |
| 计数关系 | 15 个可比较窗口中，节点字节少于本流字节的次数为 0 |
| evidence | 新导出 73 条；capture 和 evidence 记录均通过现有 Python validator |
| observe 事件 | below_sampling_threshold 149、offload_or_unmeasured 7、insufficient_activity 4；严重速度信号 0 |
| 站点恢复 | probe_started 1、slow_first_byte 1、成功提交 0；未记录成功提交预算消耗 |
| observe 组选中成员 | 六个快照未见变化；一分钟分辨率可能遗漏短暂变化 |
| RSS | 121.8–127.4 MiB，末尾 121.8 MiB；五分钟不足以证明长期稳定或归因收益 |
| 日志 | error／fatal／panic 为 0；warning 38 条，含既有 FakeIP、拨号超时与 peer reset，不称为无告警 |

observe 本身不预留候选试探或提交质量切换，因此质量切换预算消耗为 0。首选站点恢复是另一条机制，不能从 observe 模式推导其消耗为 0；本窗口仅按恢复日志确认成功提交为 0。恢复日志 suppressed 字段为 0，结果仍限于留存日志，不能当作完整内部预算账本。

末尾主要 observe 组有 67 个质量条目，仅 2 个有速度样本，0 个有速度参考。质量 API 的 invalid_windows 包含短流／未测量样本，与 capture 的 invalid_window 不同。没有严重触发尚不足以批准 enforce，继续 observe。

自然流量的节点计数包含未采样的并发流，节点减本流不能直接解释为计数漂移；userspace_accounting 也不区分 buffered relay 与 splice。未测量记录保留缺失原因，没有按零字节处理。

### 真实 splice

扩展 `control/tcp_splice_capture_live_test.go`，加入两上传、两下载的并行矩阵。223 显式使用 `-test.parallel=4`，四流同时运行约 21 秒，每流 20 MiB，总计 80 MiB，调用生产 `relayFastCopy` 及 FlowRuntime 计数回调。

四流的实际发送、接收、splice、本流、节点和归档字节均各为 20,971,520；各有一个完整窗口和一个尾部窗口。完整窗口最大快照差为 0，阈值 262,144；invalid_window／queue_dropped 均为 0。原单流实测也通过；新增矩阵在开发机上使用发布依赖、四路并行执行 race 检查通过。

这是 223 内核上的 loopback 核对，各流独立节点计数器与 collector。它覆盖上传／下载并发计数路径，不等同于共享节点聚合误差测试或真实 WAN 吞吐测试。临时上传的测试二进制已删除。

## 保留证据与后续

本地构建信息、测试失败及成功日志、快照、采集归档、健康报告位于忽略目录 `build/upstream-followup/`。包含业务标识的原始日志不进入提交。

223 的备份目录：`/root/upstream-followup-20261003-6e0d075c/before`。整批 daemon 回退入口：`/root/upstream-followup-20261003-6e0d075c/rollback.sh`。保留证据与回滚产物，不抹除归档历史。

后续先补阶段五：长时间业务覆盖、H3／WG 暂停和重载源端口身份、共享节点计数、新旧 REALITY 服务端互通、线上大 DNS 应答及 IPv6 bootstrap 定向核对。ARM64 状态发布／预算／重载还需在实际机器执行。上述缺项登记为未验证，不能用短期健康检查替代。

之后交付 U1 的 off／observe，并按证据决定 U2 执行范围；P1 至 P3 分别完成相同配置与工具链下的 A/B 后再决定启用。当前不启用 UDP 无回复重建或 quality enforce。

## Astra 审查修正与再次部署

Astra 独立审查发现一项 P1、三项 P2 和一项既有 REALITY 生命周期问题。本轮逐项修复，Astra 再次检查代码并运行独立用例，确认五项问题已关闭，未发现需要阻止合入的确定缺陷。

| 问题 | 修复与提交 |
| --- | --- |
| HTTP3 client 所有权 | quic-go `42916a97`：流局部错误保留可用连接；退役 client 持续受 Transport 管理，等待活动响应体结束后关闭；Transport.Close 也能关闭退役连接。拨号失败归还引用，重放失败关闭重建的请求体 |
| DNS 丢包后 deadline | 主仓库 `4a78221a`：首个 typed drop 后最多等待 100 ms 的替代应答，保留丢包分类；可升级 UDP 的请求预留一半 TCP 时间。真实 closed／QUIC timeout 仍按硬故障处理并丢弃连接，最终 TCP 失败保留自身原因 |
| REALITY 退避 | outbound `a3085ab`：失败期限固定，普通失败不持续延期；两种缓存 hello 都遵守退避，到期只允许一个并发试探 |
| VMess packetaddr 边界 | outbound `8b92848`：用完整帧 buffer 接收并解析地址，再检查 payload 是否适合调用者 buffer；IPv4／IPv6 的 128 字节 payload 配 128 字节 buffer 均可成功 |
| REALITY 本地 hello 重建 | outbound `a3085ab`：nil ECDHE 的本地重建保留尚未使用的连接；切换 hello 的重新拨号失败立即返回，避免继续使用已关闭连接 |

outbound `5cb6280` 固定修复后的 QUIC。两个依赖已发布到原跟进分支；主仓库 `4a78221a` 固定正式 pseudo-version。

| 项目 | 当前部署版本 |
| --- | --- |
| 223 dae | `4a78221aa26ccd5026840da1b2ff66317d75912f`，`upstream-review-fixes-20261003` |
| outbound | `github.com/Fan-chou/outbound v0.0.0-sticky-ip.0.20261003052141-5cb62805177d` |
| quic-go | `github.com/Fan-chou/quic-go v0.0.0-20261003051923-42916a975611` |
| qpack | 保留 `0844ed36f1cd` |
| 二进制 SHA256 | `7736eaeb12a606cc5a2d1e607b84a4ef20463c68c3f34587017cd42390c368f7` |

正式模块图下 `make test`、`make test-race`、相关 vet 及生产构建通过。strict 跨仓库 race 为 3／3 通过；QUIC 完整 self 集成套件在该次检查中耗时 68.2 秒。outbound 完整 race、HTTP3 完整 race 及 HTTP 集成 race 也通过。首次主仓库测试曾因 222 磁盘满中断，清理后重跑通过，失败日志保留。

构建沿用 Go 1.27.0、CGO=0、trace、`heapminimum512kib`，构建信息确认 `vcs.modified=false`。223 原子部署成功，PID 为 19686，配置与 init 脚本校验值保持。220 默认路由经 223，Google／Cloudflare 均返回 204；223 日志分别确认 `US_Dmit_LAX_Hysteria`／`HK_GG_IPLC_Dmit_HK` 承载请求。IPv4 all、br-lan、Home 的 send_redirects 均为 0。

当前保持原有 observe 范围及 25‰ 采集。新批次备份为 `/root/upstream-review-fixes-20261003-4a78221a/before`，回退入口为同目录的 `rollback.sh`；前一批备份也保留。修正、复审、部署与观测证据位于忽略目录 `build/astra-remediation/`。

### 修复版五分钟观测

窗口为 2026-10-03 **05:37:45 至 05:42:45 UTC**，六个快照。服务持续运行，采集无 generation 变化和游标缺口，capture／evidence 记录均经现有 validator 校验。

| 指标 | 区间结果与分母 |
| --- | --- |
| capture considered／sampled | 新增 275／12，导出 20 条记录 |
| offload_unmeasured | 新增 6；12 个完成流中 6 个未测量，占 50%，缺失原因是 offload_or_relay_not_started |
| invalid_window | 新增 0；4 个可比较窗口，0／4 |
| queue_dropped | 新增 0；20 条导出记录加 dropped／oversize，0／20 |
| 计数关系 | 4 个可比较窗口中，节点字节少于本流字节的次数为 0；另有 6 个短流结束时没有节点快照 |
| evidence | 新导出 84 条 |
| observe | below_sampling_threshold 56、insufficient_activity 2；严重速度信号与质量切换提交均为 0 |
| 站点恢复 | 留存日志没有恢复事件或成功提交；质量预算消耗为 0，恢复事件口径不代表完整内部账本 |
| observe 组选中成员 | 四个组在一分钟快照中均未见变化 |
| RSS／日志 | RSS 110.0–120.1 MiB，末尾 117.0 MiB；error／fatal／panic 为 0，warning 20 条（peer reset 14、FakeIP 3、拨号超时 3） |

四个 observe 组末尾共 43 个质量条目，没有可用速度样本或参考。本窗口可以确认服务与采集持续运行；未测量比例及质量触发频率仍需更大业务样本。继续 observe，尚未满足 enforce 的证据要求。节点计数与本流计数可比较窗口较少，也不能据此推断长期 splice 偏差。

### 222 磁盘整理

222 根盘从可用空间 0 恢复至约 5.8 GiB。清理了未在用的旧 Cursor 服务端／worker 版本、可重建的 web／web-next 前端依赖、旧 Go 编译对象和旧生成器缓存。前端源码、pnpm 锁文件及 dist 均保留；后续前端构建先按锁文件安装依赖。

保留当前生产构建及主仓库／依赖测试使用的 3,143 个 Go export 对象，持久 Go 缓存约 2.7 GiB，模块缓存约 1.5 GiB。当前 Cursor worker、SmartDNS、Nginx、Docker、SSH 复核正常；业务数据、归档及部署回滚副本保留。

独立用例覆盖固定退避、并发试探、随机 hello 的连接生命周期、H3 活动响应体、重放关闭和 UDP drop 后真实 timeout。新旧 REALITY 服务端互通以及全部 H3 并发交错仍需后续业务覆盖；当前短期上线验收不替代前文列出的阶段五及 A/B 项目。

## U1：UDP 回复观测

新增独立的 off／observe 配置，默认 off。该 ledger 没有 endpoint retire、节点健康或切换预算接口；enforce 配置报错。与历史提交 `6d167837` 的静默期间保留会话决策一致。

`/v1/status` 在开启时返回 `udp_reply_drought`：generation、成功写／有效回复计数、资格排除原因、peer 快照、association 级未归属计数及最多 32 条候选事件。全局最多 256 个 peer，每 association 最多 8 个；60 秒空闲淘汰，候选事件每分钟最多保留 20 条。扫描只在短锁内复制 association 列表，逐流计算在锁外完成。off 不创建 ledger 或 worker，不执行每包解析和计时。

实际发送前先登记有界意图，让快速回复能找到对应 peer；单写完成后才计成功发送，批量仅计实际完成的成功前缀，读取在 backing buffer 复用前完成。Append、短写和未完成队列不能冒充发送完成。接收先经过错误分类和首回复保护，再按实际应用 peer 归因；NAT 回复地址另行保留，来源未知时记录未归属。固定目标的 canonical 映射不会把陌生 peer 计为有效回复。跨地址族别名在收发两端都归一到真实 peer。

候选要求明确的 request_reply 契约和 IP:port 范围、至少 3 次有效回复历史、六个完整 5 秒桶各至少 10 次非空成功写，以及至少 30 秒无回复。队列接受型 transport 排除候选。读写错误、partial flush、回压及异常回拨均使旧证据失效；时间窗口使用单调时间。重载时停止 worker 并清空旧表，保留的 endpoint 继续持有已关闭 observer，不转入新代，因此新代对这些已有会话存在预期覆盖缺口。

用户明确重点为 **CS2 官方匹配 SDR**。当前没有经验证的游戏阶段解析器，所以保持 `unknown`，只记录收发与排除原因。[SDR 的中继机制](https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay?l=english)和端口范围不证明当前应有回复。真实对局中应独立记录开始／结束、加载／暂停、掉线及恢复时间，再与 peer 记录对照；不能把普通无回复标为节点故障。

示例配置中的 client IP 需要换成实际游戏电脑。client 和 group 仅限制观测，保持现有选路：

```dae
global {
    udp_reply_drought_mode: observe
    udp_reply_drought_client: '192.0.2.10'
    udp_reply_drought_contract: unknown
}
```

223 的 Game_Game 目前只匹配 9339／9449；SDR 未命中专用规则的流量依照原有规则和 Apple_Proxy 默认出口处理，不把 Game_Game 直接当作 CS2 样本。客户端已确认为 201；当前 UDP 观测 off，待新的 CS2 实测再按客户端限定范围开启。已有质量 observe 和 25‰ TCP 采集延续。

Astra 独立静态审查指出并已修正：当前桶错误仍可复用历史满桶、退休代保留 peer 表、adoptUDP 发布之前 observer 未初始化，以及墙钟回拨后旧证据误报。新增测试覆盖 unknown／队列接受排除、暂停／keepalive／单向流、当前及旧桶错误、回拨、peer 隔离、真实 Append／flush、typed drop／陌生回复、跨族收发、并发容量、事件限流和重载晚回调。审查与运行测试分别记录，不把静态审查称为 race 验证。

## 阶段五补充验证

### 共享节点 splice

`TestSpliceCaptureLiveSharedNodeAccounting` 将四条真实 loopback TCP splice 流放在同一节点和 collector 中，两上传、两下载，各 20 MiB。223 与开发机 race 均通过：节点和归档上传／下载分别为 41,943,040 字节；四个完整窗口按同一截止时刻比较，最大快照差为 0，容差为四个 splice step 合计 1 MiB。invalid_window、queue_dropped 均为 0。

原始试验把不同截止时刻的节点窗口直接比较，失败日志已保留。总字节当时已经一致；修正了验收口径后才通过，没有改动计数实现。共享节点窗口重叠，不能将它们求和当成独立流量。该核对覆盖 223 内核的 splice 计数，不代表 WAN 吞吐收益。

### 三十分钟自然流量

固定 `upstream-review-fixes-20261003`，2026-10-03 **05:47:30 至 06:17:30 UTC**，31 个一分钟快照；整个窗口没有部署、重载、generation 变化或游标缺口。

| 指标 | 区间结果与分母 |
| --- | --- |
| capture considered／sampled | 新增 1,284／34，导出 89 条 capture、437 条 evidence |
| offload_unmeasured | 新增 25；34 个完成流中 25 个未测量，73.5%；均为 direct 路径 |
| invalid_window | 新增 0；23 个可比较节点／本流窗口，0／23；节点少于本流字节的次数为 0 |
| queue_dropped | 新增 0；89 条导出记录加 dropped／oversize，0／89 |
| 缺失原因 | 25 个窗口 flow_window_not_measured，9 个短流 flow_ended_before_node_snapshot；不能将缺失当零流量 |
| observe 事件 | below_sampling_threshold 176、offload_or_unmeasured 5；严重速度触发和质量切换提交均为 0 |
| 首选恢复 | probe_started 7、slow_first_byte 5、stable_changed 1、recovered 1；成功提交属于 Heart_Proxy |
| 预算 | 质量 observe 不预留试探／切换预算；按留存恢复日志计，本窗口成功恢复消耗 1 次；日志没有 suppressed，不等同完整内部账本 |
| 组选中成员 | 四个 observe 组一分钟快照均未见变化；不能排除短暂变化 |
| RSS／日志 | 120.2–129.9 MiB，末尾 127.7 MiB；error／fatal／panic 0，warning 246 条 |

末尾四个 observe 组共 98 个质量条目，没有可用速度样本或参考。直连未测量占比反映本窗口路径构成；capture 的缺失原因不能进一步区分正常 offload 与 relay 未开始。保持已有采集和 observe，不据此开启 enforce。

### UDP 暂停身份：发现未闭合项

从 220 经 223，复用同一 UDP socket，向同一 Google STUN peer 查询远端看到的 IP／端口。[RFC 8489 的 XOR-MAPPED-ADDRESS](https://www.rfc-editor.org/rfc/rfc8489#section-14.2)用于解析结果。223 日志确认使用 US_Dmit_LAX_Hysteria；222 未参与代理测试。

两次试验中，客户端 socket、目标 peer 和外部 IP 均保持；立即、5 秒、15 秒暂停后的远端源端口保持一致，35 秒后端口改变。日志和失败断言保留。当前证据不足以判断变化来自 dae endpoint、Hysteria UDP 会话还是远端空闲／NAT 策略；需使用 generation＋association 对照，并补足真实 H3／WG 暂停及重载验证。没有调整超时、改端口或引入静默重建，也不把 STUN 当作 CS2 对局验收。

本批主仓库 `make test`、`make test-race` 通过；最终 UDP 增量使用正式 experiment 做定向 race 与 vet 通过。没有改 outbound／quic-go pin。U2、真实 ARM64 重载以及 P1 至 P3 的 A/B 继续保留验收门槛。

### U1 部署与 association 对照

| 项目 | 结果 |
| --- | --- |
| 提交 | 共享节点测试 `ba732f18`；U1 `5b8ca273e96205a35c5152a858ce966d2e7e9f08` |
| 223 版本 | `upstream-udp-observe-20261003`，运行 PID 29794 |
| executable SHA256 | `3be34ff3ebe267966479799001198713f50fab710c292dfcb844bd0c7a4ab273` |
| 构建 | Go 1.27.0、CGO=0、trace、heapminimum512kib／randomizedheapbase64；固定正式依赖，vcs.modified=false |
| 配置 | config.dae、local.dae 与 init 哈希恢复为部署前值；质量 observe 及 25‰ 采集保持，UDP 观测最终 off |
| 访问与内核 | 220 默认路由经过 223；Google／Cloudflare 204；all／br-lan／Home 的 send_redirects 均为 0 |
| 回退 | `/root/upstream-u1-20261003-5b8ca273/rollback.sh` 校验备份，成套恢复二进制和 config.dae／local.dae；旧版本不支持新 UDP 字段 |

部署后临时仅为 220 开启 unknown／observe，并创建新 UDP socket。29 个快照始终记录同一进程内的 generation=1、association=1、Google 组、US_Dmit_LAX_Hysteria 节点及 STUN peer；本地写完成／接受和有效回复各计 5 次。该 transport 标为 transport_acceptance_only，unknown_reply_semantics 始终排除候选；候选事件为 0。

这轮外部端口在 15 秒及 35 秒暂停后改变，但 association 未变化，因此现象不能归因为 dae endpoint 对象重建。仍需检查底层代理会话及远端策略；没有把固定空闲秒数当成可靠阈值。启用／关闭观测的两次配置重载完成，PID 保持；脚本用 EXIT／信号收尾恢复配置，local.dae 哈希核对通过，状态 API 已不再返回 UDP observer。真实 CS2 客户端 IP 尚待补充，本轮没有对局验收。

222 本批构建后的可用空间约 5.2 GiB。删掉了本轮误用非正式 experiment 生成的重复缓存和已完成实测的测试二进制；65 份重复观测日志经校验后无损压缩，保留最后一份原格式供分析。正式 Go 缓存、业务证据及回滚产物保留。

## P1 候选与 splice 交互停顿修复

### 实现和历史决策

P1 引入两个进程级环境开关：`DAE_TCP_DIAL_MSS` 和 `DAE_TCP_LISTEN_MSS`。默认均为 `0`，保留内核的 MSS 选择；显式值接受 `88–32767`。范围来自 [Linux TCP 定义](https://github.com/torvalds/linux/blob/master/include/net/tcp.h)。`1380` 用于实验，没有成为新的默认值。

主动连接的选项保存在 generation-scoped direct dialer pair 中。mark、MPTCP dialer clone、本地绑定、取消和 resolver 重试沿用现有实现；内部 resolver 和 UDP socket 不应用 TCP MSS。这个开关会影响经过该 pair 的 TCP 直连及代理底层拨号，也包含探测、订阅下载等调用。非 Linux 的 `0` 保持原有行为，显式非零值报 unsupported，不撤掉 BSD 的 mark 支持。

监听和主动连接分开设置。只在创建新的 TCP listener 时应用 MSS；IPv4 UDP fallback 使用独立 control。listener clone 继续共享原内核 socket，因此环境开关和错误按进程缓存，修改开关必须重启，配置重载不会在准备阶段修改正在运行的 listener。没有增加 TFO 或 NODELAY syscall。

outbound 发布为 `github.com/Fan-chou/outbound v0.0.0-sticky-ip.0.20261003064605-1651a64a78ac`，主仓库固定正式版本；quic-go／qpack 保持原 pin。

矩阵另复现已有 exact splice 的小包停顿：`SPLICE_F_MORE` 在排空 pipe 后仍承诺后续写入，但 relay 此时可能等待新的请求。旧代码中，保持源连接打开的一字节请求超过 **150 ms** 的读取截止时间；220 的两腿 splice 样本 ping p50 约 **416 ms**。去掉 MORE，保留 MOVE／NONBLOCK、netpoll、部分写处理、pipe 池、exact accounting 和半关闭流程。该修复单独提交为 `012f2cdd`，符合此前保留 splice 与及时发送尾部数据的决策。Go 标准库的 [splice 实现](https://github.com/golang/go/blob/master/src/internal/poll/splice_linux.go)也没有使用 MORE。

### 220 隔离内核矩阵

最终测试有 **96 个条件，每个三轮，共 288 项**：MTU 1280／1500、IPv4／IPv6、timestamps 关／开、dial／listen MSS 的四种组合、direct／生产 splice／生产 buffered 两腿 relay。交替运行候选顺序；每项传输 16 MiB 并核对 CRC，两腿 relay 同时核对复制量和计数回调，总计核对 **4.5 GiB**。

MTU 和 sysctl 只在 `unshare -n` 的子 namespace 修改，修改前核对真实父进程 namespace；父子相同、声明不匹配或读取失败均退出。最终矩阵全部通过，协商 MSS 均满足 MTU 和显式上限，timestamps 状态符合设置。

| 路径 | 每项 ping p50 的范围 | 两个 MSS 均为 1380 相对默认的吞吐变化范围 |
| --- | --- | --- |
| direct | 7.7–24.5 µs | −7.7% 至 +14.9% |
| exact splice relay | 16.9–47.1 µs | −10.6% 至 +17.8% |
| buffered relay | 15.5–31.8 µs | −7.1% 至 +28.9% |

吞吐变化按各 MTU／timestamps／地址族条件的三轮中位数比较；样本短、范围有正有负，没有据此批准启用 MSS。重传分别记录 client 和 sender，direct 时二者是同一 socket，不能相加；不少条件出现非零重传，不能称无重传或证明重传改善。这是 loopback 实验，尚未覆盖加密代理、WAN、真实 MPTCP 子流与 ARM64 内核。

旧矩阵在 60 秒父超时后退出，仅部分数据留存，用于定位 splice 延迟，不能当作完整吞吐基线。修复后的定向 race 三轮通过；Astra 静态复核通过，并独立解析最终矩阵数量。原始日志和逐条件报告位于忽略目录 `build/upstream-p1-20261003/`。

### 正式验证

发布的 outbound 完整 race 与相关 vet 通过；FreeBSD 的 netproxy 测试包交叉编译和 direct 包构建通过，未在 FreeBSD 执行。主仓库使用 `GOWORK=off` 的正式模块图，`make test`、`make test-race`、相关 vet 及 `make ebpf-test` 通过。223 实际内核上的 listener clone、IPv4 UDP fallback 和小包 splice 回归连续三轮通过。

`make ebpf-lint` 未通过：现有 C 文件有缩进、空行及其他 checkpatch 提示。三个被检查的 C 文件与本轮开始前的 `0ea026d2` 完全一致，这不是新增的 lint 失败；本轮没有混入 C 格式修改。失败日志保留，不能将本批所有检查写成全绿。

222 的旧构建产物无损压缩；APT 的二进制索引缓存已移除，可由现存包列表重建。闲置 pnpm store 经 tar 比较后保存为 `build/cache-archives/pnpm-store-20261003.tar.gz`，可用 `tar -xzf build/cache-archives/pnpm-store-20261003.tar.gz -C /root/.local/share/pnpm` 还原。

### P1 默认关闭部署

| 项目 | 结果 |
| --- | --- |
| 主仓库 | splice 修复 `012f2cdd`；MSS 候选和依赖 pin `d4325f9096bd8db01a81f146f3a25e331388b86d` |
| 223 版本 | `upstream-mss-candidate-20261003`，部署后 PID 4691 |
| executable SHA256 | `1ed3e8bd5639c6433eb1ff051129afffa56b403076203fff7c04c5145add116a` |
| 构建 | Go 1.27.0、CGO=0、trace、heapminimum512kib／randomizedheapbase64，`GOWORK=off`、`vcs.modified=false` |
| 模式 | 两个 MSS 环境开关均未设置；UDP observer off；主要质量组 observe、采集 25‰ |
| 访问和内核 | 220 默认路由经过 223；Google／Cloudflare 204；all／br-lan／Home 的 send_redirects 均为 0 |
| 配置 | config.dae、local.dae、init.d/dae 哈希与部署前一致 |
| 回退 | `/root/upstream-p1-20261003-d4325f90/rollback.sh`；备份的 daemon／配置／init 已核对部署前哈希；本批无新增配置字段，回退脚本恢复二进制并重启 |

部署采用原子替换、EXIT／信号失败回退和就绪检查。MSS 的 loopback 数据不足以批准生产启用；后续继续验证 P2／P3 与 P1 的真实代理路径。CS2 SDR 仍待客户端 IP 和真实对局，U2 保持待验收。

部署后三分钟为 **06:54:26 至 06:57:26 UTC**，七个 30 秒快照。capture generation 保持一致，游标缺口为 0；窗口新增 24 条 capture、46 条 evidence，均通过现有 validator。三个完成流中两个 offload_unmeasured，比例 **2／3**，样本很少；17 个节点／本流可比较窗口中 invalid_window **0／17**、节点少于本流 **0／17**；queue_dropped **0／24**。本批没有把未测量流算成零流量，也没有为了改善该比例关闭 offload。

质量日志只有 below_sampling_threshold 7 次，严重速度信号和质量切换提交均为 0；没有成功恢复日志。主要 observe 组选中成员在快照中未变化，质量切换预算不消耗；恢复统计限于保留日志，不能当作完整预算账本。没有速度参考，三分钟也没有覆盖真实 CS2，继续保持 observe。RSS 114.5–123.1 MiB，error／fatal／panic 为 0，既有 warning 18 条。

222 收尾可用空间约 **5.2 GiB**。临时测试程序从 220／223 移除、本地测试产物压缩；本轮完成交叉验证的 FreeBSD 专用编译缓存按平台头和时间筛选后移除，保留正式 Linux Go 缓存。原始观测和最终报告保存在 `build/upstream-p1-20261003/`。

## P2 小段合并候选与前缀保护

Linux 增加进程级 `DAE_TCP_WRAPPED_GATHER`，默认 `false`，非法值记录 warning 并回落到 `false`；修改必须重启。仅在 gather 已拿到数据时，对包装连接的相邻小段尝试合并：单段不超过 4 KiB、每次合并不超过 8 KiB，临时数组池化，调用结束归还。大段直接交给原连接；没有等新数据的延迟或后台聚合队列。裸 TCP 始终走原有 writev，其他平台保持原路径。

没有整体移植上游 32 KiB coalescer，也没有删除读端 onActive。现有 250 ms 活动刷新、exact splice、半关闭和取消仍由原 relay 负责。回压测试确认：读取成功、写端尚未完成时先刷新活动，流量计数仍为零；取消并唤醒写端后，只计实际写出的字节。删除读端刷新会改变这一语义，当前没有足够收益证据支持修改。

新增测试同时复现既有前缀覆盖：bufio 的 prefix 借用 reader 缓冲区，而 gather 会在写前试读内核中已经到达的正文；当 reader 为 64 KiB、复制缓冲为 32 KiB 时，bufio 会重填内部缓冲，覆盖 prefix。旧路径传输量和计数均为 1,152，但内容校验失败。现在仅在 bufio 读可以直接使用复制缓冲时追加读；否则先写 prefix，再沿用 continuation。4 KiB／64 KiB reader 的半关闭测试都核对完整内容和精确计数。

候选测试覆盖顺序、8 KiB 上限、大段原切片、部分写和错误、取消前不消费前缀、continuation、EINTR／EAGAIN 与 partial writev、裸 TCP 优先，以及采集回调只计成功写入。TLS 基准使用可信临时证书和真实 loopback socket，按生产常见的“一段前缀＋一段正文”比较；接收端逐帧核对内容和总量。

该基准计时只覆盖持续 TLS 写入，握手、接收端最后排空和核对在计时外。`socket-writes/op` 是底层 `net.Conn.Write` 调用数，不是 syscall 跟踪。基准重复使用一条 TLS 连接，而业务前缀通常每连接仅处理一次；不能据此推断 WAN、真实代理协议的交付时延或尾延迟收益。

220 上使用原路由和真实 Linux 7.2.7 内核运行，CGO=0，三轮顺序为 off／on、on／off、off／on，GOMAXPROCS=2，各子项 250 ms；12 个 workload／round 对照均完成内容与总量校验。表内为三轮中位数：

| 前缀＋正文 | off 持续写入 ns/op | on 持续写入 ns/op | 写入时间变化 | 底层 Write 调用 off → on |
| --- | --- | --- | --- | --- |
| 1 KiB＋1 KiB | 10,673 | 5,974 | −44.0% | 2 → 1 |
| 4 KiB＋4 KiB | 13,406 | 7,782 | −42.0% | 2 → 1 |
| 1 KiB＋32 KiB | 23,010 | 22,764 | −1.1% | 3 → 3 |
| 单段 1 KiB | 5,444 | 5,558 | +2.1% | 1 → 1 |

小段有局部收益；大段和单段的差异不足以认定稳定收益。继续默认关闭，后续真实包装协议和每连接前缀验收仍需补充。220 的 gather 正确性测试三轮通过。主仓库正式模块图下 `make test`、`make test-race`、control vet 通过；完整 relay 取消、continuation 和前缀增量 race 五轮通过。Astra 两次只读复核没有发现阻断，新增完整 relay 取消测试补齐其指出的直接覆盖缺口。

原始测试、A/B 和负向回归保存在 `build/upstream-p2-20261003/`。一次 vet 命令漏设正式 experiment，生成了重复对象；已统一工具链后重跑 vet，非正式对象按本次时间窗口和 archive header 筛选，无损归档到 `build/cache-archives/nonformal-vet-cache-20261003.tar.gz`，核对后移除原对象。正式 Go 缓存保持。

### P2 默认关闭部署

| 项目 | 结果 |
| --- | --- |
| 主仓库 | `f1867e787a0e6b66c0cced54872c36f500d3c8c6`；无依赖 pin 变更 |
| 223 版本 | `upstream-gather-candidate-20261003`，部署后 PID 24157 |
| executable SHA256 | `05ed9034cbfd57fd95dabffe821f3ee298510b559193ef4191de4be273fb42ca` |
| 构建 | Go 1.27.0、CGO=0、trace、heapminimum512kib／randomizedheapbase64，正式模块图，vcs.modified=false |
| 模式 | MSS 和 wrapped gather 环境开关均未设置；UDP observer off；主要质量组 observe、采集 25‰ |
| 配置与内核 | config.dae、local.dae、init 哈希不变；all／br-lan／Home send_redirects 均为 0 |
| 访问与测试 | 220 经 223 的 Google／Cloudflare 均为 204；本机 DNS 正常；223 实际内核 gather 正确性三轮通过 |
| 回退 | `/root/upstream-p2-20261003-f1867e78/rollback.sh`；恢复前核对备份哈希，原子恢复 daemon 并重启 |

部署脚本包含 EXIT／信号失败回退和 API 就绪检查。本批没有新增配置字段。最初的诊断测试程序启用了 CGO，在 musl 的 223 上因缺少 glibc loader 未启动；改为 CGO=0 后重新完成 220 的 A/B 和 223 的正确性测试。正式 daemon 始终是静态产物，未受这个测试工具错误影响。失败日志保留，临时测试程序已从两台机器移除。

部署后三分钟为 **08:29:22 至 08:32:22 UTC**，七个 30 秒快照，capture generation 保持一致，游标缺口为 0。新增 159 个 considered、3 个 sampled，导出 6 条 capture、48 条 evidence，全部通过 validator。两个完成流均为 proxy userspace_accounting，offload_unmeasured **0／2**；queue_dropped **0／6**。invalid_window 计数增量为 0，但两个 relay 窗口均为 flow_ended_before_node_snapshot，没有可比较窗口，因此其比例和节点／本流偏差本轮不可评估。

质量日志只有 below_sampling_threshold 37 次，没有严重速度信号、质量切换提交或成功恢复日志；主要 observe 组在快照中未见成员变化。observe 不消耗质量切换预算，站点恢复统计仍限于留存日志。没有可用速度样本／参考，也没有真实 CS2 对局，继续保持 observe。RSS 112.3–123.4 MiB，error／fatal／panic 为 0，既有 warning 13 条。

222 收尾可用空间约 **5.3 GiB**。另外筛出旧缓存中 1,292 个未使用 heapminimum512kib 的对象，818,745,374 字节；先归档并逐文件核对，再移除原对象，归档为 `build/cache-archives/older-nonformal-go-cache-20261003.tar.gz`。正式编译、race、trimpath 缓存以及模块缓存、业务证据和回退产物保留。两份非正式 Go 对象归档均可用 `tar -xzf <归档路径> -C /root/go-cache` 恢复。旧 Cursor 会话缓存位于 tmpfs，压缩档留在 `/tmp/kdae-cursor-cache-c72f6d0a-20261003.tar.gz`；没有将它计作持久盘释放。

## P3 最终生产调用复核

复核固定版本 dae `fce18b201308d7f7a2ed8edc68da69ed5c834caa` 和 outbound `04be789bbeebff55c2eac3fcc50873398ae7ea07`，并对照当前 fork：

| 能力 | 最终调用情况与处理 |
| --- | --- |
| PacketGSOWriter／WriteGSO | 新接口只有库实现和测试，没有业务入口。当前 QUIC 已通过 WriteMsgUDP 传递 UDP_SEGMENT；保留 connected socket 的 control message 修复 |
| EnableUDPGRO／ProbeUDPGSO | 新 helper 没有生产调用。当前 direct 接收契约是一条 datagram；没有 GRO ancillary 拆分路径，单独开启会破坏边界，因此不启用 |
| JumboBufferArena／ReleasePhysicalPages | arena 没有生产创建点，页回收仅由未接入的 arena 调用。Close 在 inUse 大于零时仍能 Munmap，不满足设计中的借出所有权要求，暂不移植 |
| TrimProcessMemory | 无生产调用；没有增加强制 GC／FreeOSMemory，不能声称 RSS 或 GC 改善 |
| dae 中间 helper | 已被最终上游提交删除，不恢复删除代码 |

Astra 独立确认了上述调用范围和 arena 的关闭问题。P3 的本轮结论是保留现有 GSO 生产能力、暂不接入上游未使用的 GRO 和内存管理 API；这符合方案“只评估最终仍在生产调用的实现”。将来若接入，需先设计 datagram 拆分和借出／归还／关闭所有权，再执行内核与 RSS／GC 对照。当前没有修改 outbound／quic-go pin。

## P1／P2 真实代理 WAN 初测与 H3 暂停

测试客户端仍为 **220**。新增默认跳过的 `TestTCPProxyWANLive` 和 `hack/test-tcp-proxy-wan.py`：独立进程在 223 原地读取选定节点，使用生产 relay，只允许 220 向两个固定 HTTPS 测试域名发起 CONNECT。生产 daemon、选路和配置没有修改。计数 wrapper 要求 upstream 为不透明协议连接，拒绝会被包装器改变裸 TCP 复制路径的节点。节点 URI 留在 223；解析和拨号错误只输出类型，关闭错误仅输出分类。

每轮必须同时通过 fixture 的实际写入计数核对，以及 220 的证书验证、HTTP 200、精确 1 MiB 和完整 SHA256 核对。下载端点为 `speed.cloudflare.com/__down?bytes=1048576`，每批先验证两次完整响应；本次内容为 1 MiB ASCII `0`。fixture PASS 单独不代表下载成功，计数是代理逻辑流字节，没有核对加密后的 wire 字节或 syscall 数量。

### 自然前缀与 MSS

固定 Shadowsocks 节点 `HK_GG_IPLC_Dmit_HK` 和 Hysteria2 节点 `US_Dmit_LAX_Hysteria`，各比较 dial／listen MSS 的四种组合及 gather off／on，三轮交替顺序，共 **48 轮、48 MiB**，全部通过联合验收。

| 路径 | 220→223 的协商 send MSS | 223→节点的协商 send MSS | 各条件三轮下载中位数 |
| --- | --- | --- | --- |
| Shadowsocks | listen 默认为 1448，1380 候选为 1368 | dial 默认和 1380 均为 1268 | 0.244–0.286 秒 |
| Hysteria2 | 同上 | UDP 底层，TCP dial MSS 不适用 | 1.567–1.677 秒 |

实际 MSS 受时间戳、peer 和路径上限影响。这条 Shadowsocks 路径原本已低于 1380，候选没有进一步约束 WAN 分段。被观测的 TCP socket 重传均为 0，不能据此证明其他路径的重传改善；没有测 QUIC 包丢失。样本少、单个测试站点，继续关闭 MSS，尚缺真实 WAN 的 MTU／地址族组合、MPTCP 子流和 ARM64 内核验证。

自然 TLS 前缀每轮都是 **1577 字节单段，追加正文为 0**，没有实际触发 P2 合并。首批 runner 执行期间补齐了禁用 curl 默认配置和异常留证；220 已独立检查，无 curlrc 文件、无代理环境变量，因此该批没有继承覆盖。初始脚本按记录补丁重建保留，并明确标为重建版本；后续批次保留执行前的最终脚本副本。

自然矩阵中 21／24 个 Hysteria2 relay 返回 joinError，完整内容仍通过验证。另用最终验收工具追加八轮错误分类，八轮均完整交付，随后收到远端 QUIC stream reset，错误码为 0，无 deadline／timeout；没有把它改写成 EOF，不能称所有 relay 都正常关闭。

### 受控分段的 P2 对照

另将已经读到的 1577 字节前缀拆成 788＋789 两段，不改变顺序、内容或读取时机。此模式只存在于 opt-in fixture，通过 `--split-prefix --mss 0` 明确启用；自然流量保留原段分布。两个节点各 off／on 三轮，共 **12 轮**，全部通过内容和计数核对，并额外核对实际两段与首次 Write 大小。

| 节点 | 前缀 Write 调用 off→on | 整个逻辑流 Write 调用 off→on | 1 MiB 下载中位数 off→on |
| --- | --- | --- | --- |
| Shadowsocks | 2→1 | 5→4 | 0.253→0.252 秒 |
| Hysteria2 | 2→1 | 5→4 | 1.571→1.587 秒 |

确认候选在真实加密代理上合并了前缀，未取得稳定交付收益。这是测试构造的段分布，不能替代自然流量中多段出现频率或长时间性能证据。P2 继续默认关闭。

Astra 独立静态复核指出并确认修正了联合验收、wrapper 路径、关闭前 TCP_INFO、curl 配置继承和异常留证问题；最终受控分段复核通过。正式模块图下 control vet、相关 relay／gather race 回归通过；远端 live 工具使用 CGO=0。原始结果、工具副本、失败日志和报告位于 `build/upstream-wan-20261003/`。

### H3 请求间隔与关联复用

收到临时仅覆盖 220 的授权后，223 开启 unknown／observe，220 经生产 daemon 向 Cloudflare H3 发出三对请求，启动间隔为 5／15／35 秒。六次均 HTTP 200、HTTP/3，每对 conn_id 和本地端口相同，第二次 num_connects 为 0。间隔中仍可能有传输层包，不能称为 UDP 静默暂停；curl 显示的 28.0.87.4 是 FakeIP。

54 个状态快照中，三对请求分别保持同一 observer generation／association／group／node／真实 peer：generation 1、association 1／2／3，`Cherry_Proxy` → `HK_GG_IPLC_Dmit_HK` → `104.16.123.96:443`。累计本地写完成 26 次、归属回复 77 次，未归属回复、登记丢弃和无效窗口均为 0。确认这些工作负载的 dae 关联复用，未观测远端 NAT 端口。

Astra 独立复核后将结束客户端快照与最后观测快照分开：最后的 `status-50.json` 中 peer_evicted 为 2，存活 unknown peer 为 1；结束客户端时分别为 1 和 2。60 秒空闲 TTL、每 5 秒扫描只回收观测元数据，累计统计保留，不改变 endpoint 的 NAT 租约。所有流均因 unknown_reply_semantics 排除，不进入 U2。

观测结束已恢复 local.dae 原哈希，observer off，PID 24157 未变，binary／主配置／init 哈希不变。PID 由主代理 SSH 核对，离线状态快照没有 PID 字段，不能将其称为 Astra 独立确认。证据及修正后的报告位于 `build/upstream-wan-20261003/h3-*`。

### CS2 官方匹配排查（201）

用户确认客户端为 192.168.124.201，开始搜索后报“遇到未知的网络错误”。客户端日志显示大陆 12 个 SDR 中继可用、香港与新加坡没有有效直接测量，同时报告 No official datacenters pingable。中继可用与完成官方匹配是不同的证据；尚未取得成功对局。

12:19 UTC 起仅覆盖 201 开启 unknown／observe，5 秒快照，20 分钟后自动恢复。大陆中继 conntrack 有双向包；被代理的海外 SDR IP 流进入 `Cherry_Proxy` 的香港 Shadowsocks 节点。Google H3 同时贡献大量写入，global unattributed_replies 不能算到 Steam。扫描许多中继也触及 256 peer 的登记上限；不因此扩大上限或触发节点降级。

Astra 核对出两个观测缺口：Hysteria2／TUIC 等 NAT-preserving transport 可返回原 FakeIP，而 write 记真实 peer；首次回复也可能先于 WriteTo 返回和 peer 登记。现有精确 peer 匹配可能计为未归属。这些是 U1 正确性问题，不能据此认定生产转发失败。U2 继续关闭，后续需加入 transport 的实际 peer 元数据和早到回复回归，并保留跨 peer 隔离。

按 [Valve 的 CS2 SDR 配置](https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid=730)，revision 1790374330，12:30 UTC 临时仅对 201 到 hkg／sgp 共 16 个 IPv4 的 UDP 27015–27060 加 must_direct 对照。规则位于 local.dae，按 merger 顺序排在 generation 分流前，由本轮外层 EXIT 回退恢复。首轮预验证候选文件没有 .dae 后缀，merger 跳过了它；已修正脚本后缀，并验证实际加载配置通过，PID 不变。此次按重开后的新五元组、conntrack 回包和客户端匹配结果联合判断。

12:36:59 UTC 的 conntrack 出现新五元组 `192.168.124.201:53975` → `103.10.124.119:27039`，双向均 12 包、OFFLOAD，回复经 WAN NAT 返回。当时确认该指定新加坡中继的直连流有回包；仅这条流不能证明成功对局或定位代理协议缺陷，后续客户端确认见下文。

12:33:48–12:35:48 UTC 的五个只读快照，capture generation 不变，considered 新增 134、sampled 新增 2、capture 新增 6 条；新增完成 relay 两条、offload_unmeasured 0／2，queue_dropped 0／6。该代全部留存的四条完成 relay 中有一条 offload_or_unmeasured，不应拿窗口增量 0 掩盖已有缺失。invalid_window 没有新增，但可比较 node／flow 窗口为 0，splice 偏差仍不可评估。质量日志 below_sampling_threshold 14、insufficient_activity 1，未见恢复事件；RSS 187.5–188.7 MiB。短窗口不证明长期预算和内存行为。

reload 会保留部分 UDP 路由与 endpoint；observer 新代不接管旧账本，direct 流本身也不进 proxy-only observer。因此统计消失或归零不能证明改善，恢复配置也不能保证已有 UDP socket 立即改回原路线。试验后需新建客户端连接以验证正常路由。

12:39 UTC 测试到期，外层 EXIT 已恢复 baseline local.dae，observer off，临时规则撤销。主代理再次核对 PID 24157、binary／主配置／local／init 四个 SHA256，全部符合基线；已有活跃 direct UDP 缓存仍按上述限制解释。220 的常规 Google／Cloudflare 检查均为 204，222 可用空间约 4.9 GiB。状态快照单独归档，未导出配置备份、节点凭据或密钥。后续客户端确认匹配恢复，见下文。

#### 用户确认匹配恢复

约 12:47 UTC 收到用户确认“匹配已经恢复”，未提供确切恢复时间。12:47:37 UTC 的 conntrack 仍保留直连 SDR 流 `192.168.124.201:53967` → `103.28.54.180:27047`，发送 47,214 包／27,809,287 字节、回复 57,197 包／50,684,647 字节，OFFLOAD、经 WAN NAT；baseline local.dae 哈希和 PID 24157 未变。同时日志中的新源端口已重新经 `Cherry_Proxy` → `HK_GG_IPLC_Dmit_HK` 访问香港／新加坡中继。

客户端结果与直连双向数据支持海外 SDR 路径选择与此次故障有关；仍不能区分代理节点／链路限制、代理协议缺陷或重开客户端的影响。当前活跃直连缓存延续并不代表后续匹配会使用同一路线。CS2 的应用回复语义仍为 unknown，UDP observer off、U2 不启用，quality 保持 observe。

长期候选 `build/upstream-wan-20261003/cs2-sdr-201.dae` 仅包含 201 到 hkg／sgp 的 16 个精确 IPv4、UDP 27015–27060 的 must_direct 规则，计划单独 include 在 `routing.dae` 前。223 使用以 .dae 结尾的暂存 root／fragment 联合验证通过；暂存文件由 EXIT 清理，生产配置哈希不变，未 reload 或加载候选。此前是限时试验，长期保留规则的选择待用户确认。

#### 再次复现与第一跳分片

用户同意只记录包头、不改路由后，13:31–13:34 UTC 在 br-lan 与 IEPL 同期记录有限 IP／UDP 头部文本，未保存 PCAP 或游戏载荷。用户再次搜索后确认相同网络错误；控制台仍是大陆 12 个中继有效、hkg／sgp 没有有效直接测量、No official datacenters pingable，匹配延迟上限 50 ms。

LAN 窗口共 848 包，其中发送 656、回复 192。hkg／sgp 的 **18 条捕获流发送 34 个 1300 字节 UDP 载荷，未见对应回复**；不能用 34÷2 推流数，末尾两条流各只捕获到一个请求。其余捕获流包括大陆中继的双向包。路由日志确认这些 hkg／sgp 流仍是 `Cherry_Proxy` → `HK_GG_IPLC_Dmit_HK`，并通过连接关闭日志中的地址关联到独立 SS carrier 端口。

对应 34 个请求在 IEPL 上均形成 **34 首片＋34 尾片**：SS UDP 载荷 1366 字节，原始外层 IPv4 包 1394 字节，超过接口及 socket 路径 MTU 1320；首片 IPv4 长度 1316、尾片 98、偏移 1296，IP ID 和时序匹配。捕获窗口内未见这些 carrier 的入向首片。LAN／IEPL tcpdump 的 kernel dropped 均为 0；接口抓取仍不能代替远端接收证据。

这确认了实际游戏包长、生产节点选择和本机出向分片，**没有证明远端收到、重组、解密或转发，也没有定位确切丢包跳数**。小包 DNS 健康探测与 SDR 的工作负载不同；分片存在本身不能证明分片导致匹配失败。

#### 独立 UDP 诊断工具与限制

新增 opt-in `TestUDPProxyWANLive` 与 `hack/test-udp-proxy-wan.py`，客户端使用 220；223 原地读取节点凭据，仅允许固定 DNS 目标、固定问题及零填充私有 EDNS 选项 65001。每请求上限 1800 字节、最多 48 次、单次 4 秒，整个 fixture 有期限和内存限制，不创建控制平面、不改路由或接口 MTU。gateway 与 client 独立校验 DNS 事务／问题，并联合比较结果及长度；公网目标仍不可控，结果不能单独证明游戏路径 MTU。

首批使用 EDNS Padding，后发现 [RFC 7830 §6](https://www.rfc-editor.org/rfc/rfc7830.html#section-6) 限定其用于加密 DNS；代理出口仍是普通 UDP DNS，因此这些结果保留为带协议干扰的探索记录，不用于判定 MTU。修正为 [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.2) 要求忽略的未知私有选项后，另做两个节点各 12 次的小批量复核。

| 修正后探针（1.1.1.1、ReadFrom） | 有效 DNS 回复 | 读取超时 | 能力／校验失败 |
| --- | --- | --- | --- |
| 香港 SS | 6／12 | 6 | 0 |
| 美国 Hysteria2 | 7／12 | 5 | 0 |

香港 SS 的 1200 字节查询也两次超时，其观察到的封装外层约 1294 字节，小于 MTU；结果不支持“仅超过 1320 才失败”。TXT 回复全为 43 字节且 TC=1，未验证大回包。修正批次未覆盖 direct、第二 DNS 目标或 PacketReceiver；探索批中 SS receiver 不支持，已单列 capability failure，不能算网络丢包。

Astra 独立离线复核确认上述计数、双端校验与结论边界。诊断日志直接写文件，错误用不含凭据的阶段／原因枚举，避免日志阻塞或把接口不支持混入超时。相关回包校验、查询策略 race 测试及 control vet 通过。生产二进制与依赖 pin 不因诊断工具改变。

#### 香港 Hysteria2 限域对照

用户明确批准五分钟对照后，13:41:28 UTC 仅将 **201 → hkg／sgp 的同一 16 个 IPv4、UDP 27015–27060** 导向新建 `CS2_SDR_Trial`，固定选择 `HK_DMIT_HK_Hysteria`，该临时组 quality off。其他组仍按已有配置工作。候选先用原地配置 validate；试验脚本在 EXIT／信号或五分钟期限结束时原子恢复 local.dae 并 reload，未重启进程。

**13:42:30–13:43:38 UTC** 的 LAN 包头样本中，四条 hkg／sgp 流全部由同期路由日志确认走临时 Hysteria2 组，发送 2438 包、回复 2110 包，其中 1300 字节载荷上下行各 6 包。两个短测量流各为 8／8 包，一个为 17／17 包，另一个为 2405／2077 包。前两个流的 50411／50412 端口曾用于旧 SS 关联，13:41:50 已关闭，捕获中的 13:43:20 流量对应 Hysteria2 重建；不能仅按相同五元组混入旧日志。捕获在 5000 包额度处停止，filter received 为 5078、kernel dropped 为 0；这是截断样本，不能外推整局丢包率。

用户随后确认 **“匹配成功”**，没有提供新的完整 RTT 表，因此不宣称测得特定延迟或更改了 50 ms 门槛。原 SS 路径再次报错、Hysteria2 新流有双向大包且匹配成功，加上此前直连恢复，支持将失败范围收窄到原 SS 节点的链路、服务端策略或协议处理路径。节点、传输和 SDR 五元组同时有所变化，仍不能单独证明 SS 协议、MTU 或某一跳是根因。确切定位需要原 SS 远端的接收／重组、解密后转发、SDR 回包和加密回送证据。

五分钟后自动回滚完成。主代理 SSH 核对 PID 24157，binary／主配置／local／init 四个 SHA256 全符合基线；临时组、候选和配置备份均移除，UDP observer off，主要组继续 observe。已有 UDP 缓存可能延续试验路径，新流回到原规则；此次结果不代表长期规则已经生效。永久 direct 候选仍未加载。

收尾 220 的 Google／Cloudflare 常规请求均为 204。223 status RSS 为 221.7 MiB，可用内存约 234 MiB；短时数据不能证明长期内存稳定。222 可用约 **4.5 GiB**，两个诊断构建均经解压 SHA256 验证后压缩归档，远端诊断二进制及本次临时目录清理，正式 Go／模块缓存保留。证据位于 `build/upstream-wan-20261003/cs2-{retest,hy2}-*`，没有导出配置、密钥或节点 URI。

#### 原 SS 服务端回送失败定位

用户允许检查服务器后，14:00–14:10 UTC 通过 223 跳转，只读检查原 SS 服务器 `10.8.1.4` 及中间网关 `10.8.1.11`。服务器运行 shadowsocks-rust **1.22.0**，服务 PID 1426，自 7 月 8 日持续运行。未修改 socket、路由、MTU、配置或重启服务。

**已定位本次复测的直接失败点：服务端收到 SDR 的 1300 字节回复后，通过 SS 监听 socket 回送客户端失败，返回 `EMSGSIZE`（errno 90）。** 13:31–13:34 的目标日志中有 66 条此类错误，其中 **34 条与此前捕获的 18 条流逐条对应**：carrier 端口、SDR 地址／端口和顺序一致，无重复或缺项。错误时间晚于对应出向首片 12–60 ms；这是跨机日志时间差，不能作为 RTT。

服务端看到的客户端为 `[::ffff:10.8.1.11]:<carrier-port>`，223 抓到的出向源为 `10.8.1.10`。中间网关 `wg-ixp0` 的地址为 `10.8.1.11`，存在该出口的 masquerade 规则，支持地址转换解释；历史 conntrack 映射未留存，关联仍以端口、目标与时间联合核对。

| 证据 | 结果 |
| --- | --- |
| 34 条对应错误 | 全部为 1300 字节目标回复，回送 errno 90 |
| 实际监听 socket | `[::]:34564`；IPv4／IPv6 `MTU_DISCOVER=2`，即 `PMTUDISC_DO` |
| socket 路由标记 | `SO_MARK=0`，未绑定接口；按此标记查询回程走 `wg11` |
| 回程接口 | `wg11` MTU **1320**，目标为网关 `10.8.1.11` |
| 最小包长 | 1300 字节载荷＋IPv4／UDP 头部已为 **1328**，SS 封装继续增加长度 |

回程加密报文没有成功发出，也未捕获其封装长度，不能沿用请求的 1366 字节 UDP 长度。监听选项快照采于 14:06，晚于 13:32 事件；持续运行的同一服务、版本源码和当前选项共同支持禁分片解释。这一证据已足以解释对应 34 次回送失败，不能外推为所有历史匹配失败的唯一原因。

[v1.22 listener 源码](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.22.0/crates/shadowsocks/src/net/sys/unix/mod.rs)无条件禁止 IP 分片；`server/udprelay.rs` 中这些错误仅在收到目标回复、调用 inbound 回送失败后记录。该版本 `outbound_udp_allow_fragmentation` 只作用于服务器到目标的另一组 socket，无法修复此 listener。[上游修复 #2161](https://github.com/shadowsocks/shadowsocks-rust/pull/2161)及 [v1.25.0 发布说明](https://github.com/shadowsocks/shadowsocks-rust/releases/tag/v1.25.0)新增 `inbound_udp_allow_fragmentation`；默认仍为 false，只升级版本不会自动启用。

当时拟定的修复方案如下；实际部署结果见下一节：

1. 准备支持该修复的官方 v1.25.0 服务端候选，验证产物及现有 JSON5 配置兼容性。该版本包含其他变更，当前未进行候选运行验收。
2. 在 `servers` 中只给端口 **34564** 的实例增加 `"inbound_udp_allow_fragmentation": true`；保留现有 SS2022 配置、outbound 选项和接口 MTU。已核对 v1.25 配置解析、per-server 覆盖及 listener 创建调用链。
3. 备份二进制和配置后重建监听 socket；重启同一 service 会影响其全部监听实例及现有连接，须安排验证窗口。失败时恢复备份并重启旧服务。
4. 核对新 socket 不再强制 `PMTUDISC_DO`，在原 SS 路径复测 1300 字节回复和 CS2 匹配，确认对应 `EMSGSIZE` 消失且客户端收到回复。允许分片后的完整回程仍待验证。

Astra 独立只读复核确认日志关联、错误触发路径、两版本选项范围和上述结论边界。服务端日志仅保存时间、回复长度、客户端、目标、错误和 errno 六个白名单字段，丢弃可能含用户密钥的整个 control 字段；未导出原始日志、配置或凭据。相关材料为 `cs2-ss-server-{send-errors,socket,socket-routing}.json`、`cs2-ss-gateway-return-nat.json`、更新后的 `cs2-retest-fragments.json` 及 `cs2-ss-server-check-manifest.json`，均在上述 build 证据目录。

14:08 UTC 收尾确认 223 PID **24157** 及 binary／主配置／local／init 四个 SHA256 均符合基线，可用内存约 218 MiB；222 可用空间 **4.52 GiB**。本轮只增加排查记录，生产配置保持回滚后的状态。

#### 三台 SS 服务端修复与受控回包验收

用户随后授权操作修复，并检查 `10.8.1.5`、`10.8.1.6`。三台的 SS **34564** 监听 socket 均为 `PMTUDISC_DO`，回程 WireGuard MTU 均为 **1320**。`.5` 与 `.4` 同为 shadowsocks-rust 1.22.0；`.6` 使用 sing-box 1.13.12。`.5`、`.6` 初查最近一小时没有“消息过大”记录，不能据此判断大回包正常。

从 **220** 经 223 的实际 SS 客户端，对每台服务器的固定 loopback 响应器做修复前后对照。响应器仅接受合成 DNS 问题、零填充的私有 EDNS 选项 65001、64–1800 字节载荷；绑定 `127.0.0.1:46663`，上限 48 请求／12 分钟，同尺寸返回并设置 DNS 回复标记。凭据继续由测试进程在 223 原地读取；测试绕过 daemon 的选路与采集，不能作为 quality／capture 的样本。此项不依赖公网 DNS 的大回包策略。

每台每轮 10 请求：6 个 64 字节回复，以及 1300、1700 字节各两次。gateway 与 220 独立核对来源、事务、问题及回复长度；三台响应器最终均接受并回复 20 请求，无非法请求，大小分布为 64 字节 12 次、1300 与 1700 各 4 次。

| 服务器／223 节点 | 修改 | 修复前有效回复 | 修复后有效回复 | 当前 PID |
| --- | --- | --- | --- | --- |
| `10.8.1.4`／`HK_GG_IPLC_Dmit_HK` | rust 1.22.0 → **1.25.0**；34564 的 inbound 分片 true | 6／10；4 个大回包均超时 | **10／10**，大回包 4／4 | 873979 |
| `10.8.1.5`／`SG_GG_IPLC_NNC_SG` | rust 1.22.0 → **1.25.0**；34564 的 inbound 分片 true | 6／10；4 个大回包均超时 | **10／10**，大回包 4／4 | 27247 |
| `10.8.1.6`／`US_GG_IPLC_Dmit_LAX` | 保持 sing-box **1.13.12**；34564 的 `udp_fragment: true` | 6／10；4 个大回包均超时 | **10／10**，大回包 4／4 | 1045349 |

修复前后目标、请求内容、测试客户端、223 诊断二进制和 WireGuard MTU 保持一致；正式服务重启，新建 SS 会话。两轮的全部小回包均正常；修复后共 **12／12** 个大回包通过双端验证。该结果验证了三台受控 IPv4 SS 大回包路径；真实 SDR、IPv6 外层和长期稳定性仍需另行验收。CS2 官方匹配复测已向用户提出，尚未收到结果。

rust 使用 [v1.25.0 官方发布产物](https://github.com/shadowsocks/shadowsocks-rust/releases/tag/v1.25.0)，发布 API digest 与 `.sha256` 双重核对。musl 压缩包 SHA256 为 `8439bf43c324b0fc273e663d0b1f8926fd8f666cbd1e0fd59b35096f0e778e92`，部署 ssserver 为 `d63836978a3d2534f0ea1206ca12502b77b965fcfed2958d327353071b6bbf91`。sing-box 使用其已有版本支持的 [Listen Fields／udp_fragment](https://sing-box.sagernet.org/configuration/shared/listen/#udp_fragment)，未替换程序。

JSON5 配置在服务器原地解析，候选序列化为 JSON；反向语义比对证明每台配置仅增加受影响 34564 实例的分片选项，密码、用户、路由及其他配置值不变。两个 rust 候选以完整配置在独立 `unshare --net` namespace 启动；sing-box 完整配置 `check` 通过，并在独立 namespace 验证目标 SS 入站。隔离修改前核对 namespace 与父进程不同。三台候选以及正式 socket 的主监听 IPv4 `MTU_DISCOVER` 均为 **1（WANT）**，rust 双栈 socket 的 IPv6 值也为 1。

部署依次进行，原子替换前留存二进制／配置备份，保留原文件所有者与权限；文件和目录均 fsync。部署或监听检查失败立即回退，并预先设置 240 秒未验收回退。修复执行器在生产切换前上传回退脚本及依赖，核对远端 SHA256；每台 10／10 回包、四个大回复均通过后才写 accepted 标记并取消 timer。Astra 独立只读审查指出的回退脚本上传缺项已修正。三台备份和回退脚本保留在 root 私有目录 `/var/lib/kdae-ss-repair/20261003T142415Z/`，timer 均 inactive。

修改限定于 SS 34564 实例；34565 的明文入口保持原策略，`.6` 的 Hysteria2 配置保持。重启 sing-box 会重建其 Hysteria2 监听；收尾实际监听检查包含该 UDP 58523 端口。未调整任何接口 MTU、系统分片设置、223 路由、quality 范围或依赖 pin。

14:31 UTC 的新进程日志中，三台“消息过大”及 fatal／panic 文本计数均为 0，统计范围仅为各自新 PID 的保留日志。220 默认路由仍经 223；Google／Cloudflare 均为 HTTP **204**、TLS 校验结果 **0**。223 仍为 PID **24157**，binary／主配置／local／init SHA256 均符合基线。

三个响应器已停止，223 临时诊断二进制已删除；删除后可用内存约 **240 MiB**。本次控制测试二进制压缩并验证解压 SHA256，正式 Go／模块缓存保留；222 收尾可用 **4.41 GiB**。运维记录、前后对照及非敏感哈希位于 `build/upstream-wan-20261003/ss-server-fix/`，汇总见 `repair-manifest.json`；新增可复用 `hack/udp-controlled-responder.py`，UDP 诊断目标仍限定为两台公网 DNS 或这个固定 loopback 端点，并拒绝 direct 使用该端点。相关 control race／vet、Python 请求边界检查通过。

#### WireGuard MTU 检测

用户随后要求检查 WireGuard 配置和实际链路，判断能否适当增大 MTU。**三条 SS 路径的 IPv4 MTU=1400 已通过双向整链路试验；建议只对这些路径协调提升，当前证据不支持使用 1420。** 检测阶段没有修改持久化配置或生产接口 MTU；后续已授权的修改和验收见下节。共享接口上的其他 peer 保留原来的路径限制。

223 的 SS 路径为 `10.8.1.10 → 10.8.1.11 → 10.8.1.2 → 10.8.1.4／.5／.6`。223 的 IEPL 对三台服务器和 `.11` 选择同一个 peer；`.11` 对三台服务器选择核心 peer。标准 DF ping 显示 `.2` 在转发到三台服务器时均返回 `Frag needed and DF set (mtu = 1320)`。223 直接访问 `.2` 则选择 `.1` peer，traceroute 首跳为 `.1`，与服务器路径不同。用户授权当前公钥后，最终从 222 成功登录核心，确认了配置来源。

| 节点 | 当前隧道 MTU | 外层接口 MTU／配置来源 |
| --- | --- | --- |
| 223／`IEPL` | 1320 | PPPoE 1492；UCI 明确设置 1320 |
| `.11`／`wg-ixp0` | 1420 | eth0 1500；配置明确设置 1420 |
| `.4`／`wg11`、`.5`／`wg0`、`.6`／`wg0` | 1320 | eth0 1500；配置均明确设置 1320 |
| `.1`／`wg-ixp0` | 1420 | 共享 IEPL 对端，配置明确设置 1420 |
| `.3`／`wg-ixp0` | 1320 | 共享 IEPL 对端，配置明确设置 1320 |
| `.2`／`wg-tcgz0` | 1320 | eth0 1500；`/etc/wireguard/wg-tcgz0.conf` 明确设置 1320，Table=off |

用静态 C 工具进行少量 DF ICMP 探测，记录原始 IPv4 总长度、有效回复、本地 EMSGSIZE 与网络 PTB，避免把本地接口限制误计为网络丢包。223 发往三个 IEPL 公网端点的 1492 字节 DF 请求均获得回复；`.11` 与三台服务器发往各自核心公网端点的 1500 字节 DF 请求也获得回复。**普通 echo reply 不保证带 DF，这些结果只能证明请求方向，不能证明回程无需分片。** 对家庭公网地址的反向 DF ICMP 没有 echo reply 或 PTB，不能由此推导可用 MTU。

真实 WireGuard 检验采用专用 `SO_MARK=0x4b444d54`、独立路由表 62132 和临时规则，仅诊断 socket 使用较大路由 MTU；生产接口、普通流量路由保持原值。三台服务器向 `.2` 发出的 1400／1420 字节 DF ICMP 各 5 次，合计 **30／30** 回复成功。包头证实请求经实际 WireGuard socket 发送，外层 IPv4 长度分别为 1468／1480；核心返回的内层 echo reply 被拆为 1316 字节首片和 104／124 字节尾片，因此不能把 ping 成功等同于双向无分片。

223 与 `.11` 的 1400／1420 字节 ICMP 也各 5 次成功，但 PPPoE 抓取显示回程 WireGuard UDP 的首片长度为 **1460** 且 MF=1。该批按 UDP 端口过滤，未包含尾片，结论限于已证实存在分片。这个回程分片边界解释了为何只依据 PPPoE 1492 或 ping 成功来选择 1420 会遗漏问题；尚未确定发生分片的具体路由器。

随后对 223 和 `.11` 的专用诊断 socket **同时使用路由 MTU=1400**，以受限 UDP 响应器复核。响应器绑定 `10.8.1.11:46664`，只接受 `10.8.1.10`、固定标记与零填充、1394／1400 字节 IPv4 总长度，最多 10 请求／25 秒；逐字节验证返回内容。两种尺寸各 **5／5** 成功，服务端接受并回复 10 请求，非法请求和发送错误均为 0。内层共捕获 **20** 个完整 UDP 包；包含潜在非首片的外层过滤共捕获 **20** 个 1460 字节 WireGuard 包，均无 MF、无非零偏移，两次抓取的 kernel dropped 均为 0。1400 在这一段已验证双向无需分片，并能容纳先前测得的 1394 字节 SS 包。

**10 月 4 日 00:03（北京时间）**，对整条三段 WireGuard 路径进行专用 UDP 试验。223 的诊断 socket 与三台服务器的响应 socket 使用独立 mark；`.11` 和 `.2` 仅对指定地址组合、UDP `46665 → 46664` 及反向组合安装路由 MTU=1400。接口 MTU、生产路由和配置保持原值。`.11` 的既有 WG 出口 masquerade 会将源地址改为 `.11`，核心规则及服务器响应器按此实际源地址限定；响应器只接受固定标记、零填充和两种尺寸，每台最多 10 请求。所有规则有正常退出清理和独立 45 秒回滚。

每台服务器的 1394／1400 字节 IPv4 包各 **5／5** 成功，总计 **30／30** 请求获得逐字节一致的回复，非法请求和发送错误均为 0。按观察点统计，223 内外层各 60 个包，`.11` 和 `.2` 各 120 个，每台服务器各 20 个，符合 30 请求和 30 应答经过三段链路的预期。对应的 **360 次外层观察**全部为 1460 字节，内外层均无 MF、无非零片偏移，全部抓取 captured 与 received by filter 一致、kernel dropped=0。首轮虽然往返成功，但一个抓取提前达到数量上限、部分服务器抓取未排空；结论使用补齐这些问题后的完整第二轮记录。

1400 已验证适用于这些 SS IPv4 路径的双向大 UDP 包。部署时仍需协调 `.11` 回 223 的路由限制，避免 WireGuard 填充把外层包推到 1460 以上；共享 IEPL 的其他对端维持原来的路径 MTU，另行验收。检测结束时正式路由尚未提升；该诊断不能替代 CS2 对局验证。SS 的按实例允许分片应继续保留，用于更大的应用报文。

最初本机 root 身份及已尝试的相邻节点身份未获 `.2` 授权。自动审批拒绝了继续使用 `.1` 现有 SSH 身份的尝试，理由是凭据尝试缺少明确授权；此后停止这类操作。后续成功检查使用用户明确授权的本机公钥。

用户追问 `.2` 是否有问题后，**23:42（北京时间）** 从 `.11` 复测：核心小包 20／20、1320 字节包 10／10，核心 RTT 平均约 **3.6 ms**；经核心到三台服务器的 1320 字节包各 10／10。上述短时有效回复共 **60／60**。每台服务器另发两个 1321 字节 DF 包，共六个，全部收到 `.2` 返回的 MTU=1320 错误，进一步定位到严格的转发边界。未观察到这些有效尺寸的短时丢包；不能由此判断核心长期负载或配置是否合理。使用本机已有身份经 `.11` 再次访问 `.2`，仍为 root 公钥认证失败，未尝试相邻节点身份；核心配置、资源和日志尚未检查。结果保存在 `wg-mtu/node2-recheck.json`。

用户随后确认当前公钥已授权，并说明已从 220 登录成功。经 223 的两条路径、经 220 跳转，以及在 220 上明确指定同一公钥身份直接连接，最初仍被拒绝。220 已知主机记录与目标 SSH 主机指纹一致，其 `id_ed25519.pub` 指纹也与本机当前公钥一致。用户再确认 222 已可用此公钥访问后，立即成功登录。自动审批曾拒绝向两个尚未获用户确认的公网地址尝试 SSH 认证，此后未继续这些地址的认证操作。

核心主机为 `pen.cnix`，内核 `6.1.0-50-amd64`，服务 active、无 failed unit。首次检查 load average 为 0.00／0.02／0.00，可用内存约 668 MiB、磁盘可用约 14 GiB；最近 24 小时查询未返回内核 warning 及以上日志。**23:55:31 至次日 00:08:24** 的快照中，eth0 错误／丢弃和 fq 队列丢弃均无新增，WG 接收错误／丢弃无新增；WG 发送丢弃新增 **13**，接口计数不能精确归属到某个 peer，不能把全网络描述成零丢包。主要 SS 路径的验收仍全部成功。

另外发现 `.2 ↔ .3` 的直接 peer 没有有效握手，两个公钥相互对应，双方都未设置 PSK。12 秒对照包头中，核心向 `.3` 发出 148 字节 UDP；`.3` 收到其中一次，并立即向核心的公网 NAT 地址、端口回发 92 字节 UDP；核心相同窗口未收到回包。报文长度与 WireGuard 握手一致，故障定位到两者的直连 UDP 回程或 NAT 映射，具体丢失位置尚未确定；小包总长仅 120 字节，与 1320 的 MTU 限制无关。

`.3` 的 `.11` peer 拥有更具体的 `10.8.1.0/24`，因此 `.3 → .2` 实际走 `.11` 并经其 masquerade，反向 ping 可成功；核心主动 ping `.3` 则失败。当前三条 SS 路径不依赖这个直接 peer。后续若恢复直接路径，需要同时处理公网 UDP 回程和 `.3` 的 `.2/32` peer 归属；若改为经 `.11` 中继，则需同步核心的 AllowedIPs，单改普通路由不能完成 peer 切换。检测阶段只检查；随后按用户授权补齐经 `.11` 的中继路径，详见下节。

独立诊断规则和路由均已清理，UDP 响应器已退出，远端诊断文件删除。各生产接口 MTU 和已读取的 WireGuard 配置 SHA256 保持原值，223 daemon 仍为 PID 24157，binary／主配置／local／init／network 哈希符合前述基线；220 仍经 223，Google／Cloudflare 返回 204、TLS 校验为 0。本轮非敏感测量、包头和工具保存在 `build/upstream-wan-20261003/wg-mtu/`，包括 `e2e1400-analysis.json` 和 `peer3-handshake-headers.json`；222 可用磁盘约 4.5 GiB。

#### WireGuard 定向修改与入口约束（10 月 4 日）

用户授权修改，并明确要求 `.1/.3/.11` 与核心 `.2` 建立 WireGuard 连接时，只能使用入口 **165.101.4.113:65008**，禁止使用出口 **43.250.104.133**。已安装专用 nftables 表 `inet kdae_wg_entry`：入站按出口源 IP 和本地 WG 端口丢弃，出站按出口目的 IP 和本地 WG 源端口丢弃，防止 endpoint roaming 回到出口。`.1/.3` 本地端口为 65008，`.11` 为 65012；其他流量维持原规则。三个运行时 endpoint 均固定到入口，配置中的入口值保持。核心对 `.3/.11` 的 PersistentKeepalive 改为 0；三个客户端保留 25 秒，由客户端发起并维护入口映射。

MTU 修改采用 **main 表的定向 `/32` 路由**，保留共享 WG 接口原来的 MTU；下列 15 条路由使用 MTU 1400、各自 WG 地址作为 src：

| 节点 | 接口 | MTU 1400 的目的地址 |
| --- | --- | --- |
| 223 | IEPL | `.4/.5/.6/.11` |
| `.11` | wg-ixp0 | `.4/.5/.6/.10` |
| `.2` | wg-tcgz0 | `.4/.5/.6/.11` |
| `.4` | wg11 | `.11` |
| `.5/.6` | wg0 | 各自到 `.11` |

Linux 节点通过 `/usr/local/sbin/kdae-wg-paths` 和 WireGuard 的 PostUp hook 持久化路由；入口限制另有 PreUp hook。`.3/.11` 的 nftables 配置语法检查通过，加入专用规则的 include。`.1` 的原 `/etc/nftables.conf` 已有语法错误、nftables 服务原先处于 failed；没有重载这个旧规则集。该节点的入口限制由 WG PreUp 独立加载，并增加 nftables 服务的 guard hook；旧文件保持原状，仍需单独整理。223 通过 `/etc/hotplug.d/iface/95-kdae-wg-paths` 在 IEPL ifup／ifupdate 后加载路由，实测重放 hook 后四条路由均保留。

**00:49（北京时间）**，使用普通 main 路由、SO_MARK=0 的 UDP socket 验收；没有安装专用诊断路由。三个响应器分别接受 1394／1400 字节 IPv4 包各五个，**30／30** 得到逐字节一致回复，非法请求、发送错误均为 0。完整第二轮抓取中，223 内层 60 条、`.11/.2` 各 120 条、三台服务器各 20 条，符合受控请求的双向计数；12 个抓取点 captured 与 received by filter 均一致，kernel dropped 均为 0。所选外层共 **528 条记录**，均为 1460 字节、无 MF 和非零片偏移；其中包含同期正常业务，不能将 528 条全部归属于受控请求。第一轮抓取结束时存在少量未排空记录，留作 initial 文件，验收以即时抓取模式补齐后的第二轮为准。

`.3` 的入口直连仍没有握手：它确实发出了到入口的 148 字节 UDP，但同一时间窗口核心 eth0 没有收到；出口发来的握手被 guard 丢弃。该问题发生在入口请求到达核心之前，与 MTU 无关。用户确认入口由 SSH 手动维护；直接连接其 22 端口在认证前关闭，经 223 的尝试则在 banner 阶段超时。10 月 4 日用户进一步确认，入口只向部分 AS 提供可达路由，限制覆盖全部端口，因此这些公网 SSH 结果不能作为服务故障证据。管理继续使用已可用的 `10.8.1.2` 隧道 SSH；`.3` 直连需核对入口对其来源 AS 的路由准入，未将某个 NAT 或防火墙规则认定为根因。

为了恢复核心主动访问 `.3`，已补齐现有 `.11` 中继：核心 `.11` peer 的 AllowedIPs 加入 `10.8.1.3/32`，并持久化 `.3/32` 的 MTU 1320 路由。`.3` 仍通过其已有 `.11` peer 到核心；该路径不使用核心出口建立连接。**00:52** 双向小包各 5／5、1320 字节 DF 包各 5／5，共 **20／20**，TTL=63、平均 RTT 约 13.4–13.7 ms。`.1/.11` 的入口握手已刷新，小包各 3／3；`.3` 经中继小包 3／3，出口 guard 已拦截八个 176 字节握手包，出站出口包计数为 0。保留原直接 peer，后续修好入口后需同步调整 `.2/32` 与 `.3/32` 的 peer 归属才能恢复直接业务路径。

MTU 路由和中继修改在应用前备份并设置独立 12 分钟自动回滚；通过相应验收后写 accepted 标记并取消计时器。入口限制直接持久化，回退其他修改时继续保留。Linux 备份位于 `/var/lib/kdae-wg-paths/20261004-v1/deployment/`，核心中继另有 `peer3-relay/`；223 备份位于 `/root/kdae-wg-paths-backup-20261004-v1/`。手动回退需先移除对应 accepted 标记，再执行所存 rollback 脚本；核心应先回退 peer3-relay，再回退 MTU 路由，入口限制继续保留。七台 WG 服务 active，全部接口 MTU 与修改前一致。

收尾 220 默认经 223，Google／Cloudflare 返回 **204**、TLS 校验 **0**。223 daemon 仍为 PID **24157**，binary／主配置／local／init／network 五项 SHA256 符合基线；受控 UDP 响应器和远端临时诊断文件均已清理。222 可用空间约 **4.5 GiB**。非敏感部署快照、入口包头、普通路由验收及脚本保存在 `build/upstream-wan-20261003/wg-mtu/`，汇总见 `deployment-manifest-20261004.json`、`unmarked1400-analysis.json`。

#### WireGuard 全网 peer 最大 MTU 复核（10 月 4 日）

按用户要求，从八台在线节点的运行时 peer 和磁盘配置清点 `10.8.1.0/24`，找到 `.1/.2/.3/.4/.5/.6/.7/.10/.11` 九个登记地址、16 对 peer。`.10` 为 223；`.7` 仅存在于 `.6` 配置，Endpoint 为空，用户表示应该已停用。以下公网端点采用测量后的运行时快照，NAT 端口按具体 peer 单独记录；`.2` 对 `.1/.3/.11` 使用入口 165.101.4.113，其余相关连接使用出口 43.250.104.133。未发现其他属于该网段的已登记 peer。

此处最大 MTU 是**内层 IPv4 总长度，在该方向的实际 WireGuard 公网传输中无需分片的上限**。通过专用 SO_MARK=0x4b445054、路由表 62140、优先级 90 及 UDP 46720／46721 测量，仅诊断 socket 命中。每个候选值使用对应路由 MTU，使填充也限制在候选值内；Linux WireGuard 会采用路由 MTU，并据此限制填充，依据见 [device.c](https://git.zx2c4.com/wireguard-linux/plain/drivers/net/wireguard/device.c)、[send.c](https://git.zx2c4.com/wireguard-linux/plain/drivers/net/wireguard/send.c)。接收端核对固定标记、长度和零填充，返回小 ACK，从而分别测出两个方向，避免大回复受回程 MTU 限制而混淆方向。

14 对直连全部完成双向边界验证：28 个方向各在最大值验证 **5／5**，合计 **140／140**；每个方向再增加一字节、各测三次，均观察到外层分片。56 个内外层抓取 captured 与 received by filter 全部一致、kernel dropped 全部为 0；完整 PCAP 用同一个解析器再次核对。测量流程先在 223／`.11` 验证，再测其余链路；`.5` 的 IPv6 路由实际走 eth1，抓取按该实际设备进行。表中数值不代表已经修改接口配置。

IPv4 公网承载；括号为隧道地址尾号：

| A 公网端点（节点） | B 公网端点（节点） | A → B | B → A | 双向上限 |
| --- | --- | ---: | ---: | ---: |
| `106.53.65.44:43257`（.1） | `165.101.4.113:65008`（.2） | 1440 | 1440 | **1440** |
| `106.53.65.44:65008`（.1） | `39.108.101.120:65008`（.3） | 1404 | 1440 | **1404** |
| `106.53.65.44:65008`（.1） | `120.229.59.143:1068`（.10） | 1404 | 1432 | **1404** |
| `106.53.65.44:65008`（.1） | `43.136.77.84:65012`（.11） | 1440 | 1440 | **1440** |
| `165.101.4.113:65008`（.2） | `39.108.101.120:65008`（.3） | — | — | **未握手** |
| `43.250.104.133:38863`（.2） | `154.3.39.21:65008`（.4） | 1440 | 1440 | **1440** |
| `43.250.104.133:65008`（.2） | `185.248.186.73:11825`（.5） | 1440 | 1440 | **1440** |
| `43.250.104.133:65008`（.2） | `154.17.29.199:37408`（.6） | 1440 | 1440 | **1440** |
| `165.101.4.113:65008`（.2） | `43.136.77.84:65012`（.11） | 1440 | 1440 | **1440** |
| `39.108.101.120:65008`（.3） | `120.229.59.143:1068`（.10） | 1432 | 1432 | **1432** |
| `39.108.101.120:65008`（.3） | `43.136.77.84:65012`（.11） | 1440 | 1404 | **1404** |
| `154.3.39.21:65008`（.4） | `154.17.29.199:65008`（.6） | 1440 | 1440 | **1440** |
| `154.17.29.199`（.6） | `未知`（.7） | — | — | **疑似停用** |
| `120.229.59.143:1068`（.10） | `43.136.77.84:65012`（.11） | 1432 | 1404 | **1404** |

IPv6 公网承载；内部诊断包仍为 IPv4：

| A 公网端点（节点） | B 公网端点（节点） | A → B | B → A | 双向上限 |
| --- | --- | ---: | ---: | ---: |
| `[2403:18c0:5:30d:dc38:4aff:fe21:ba6f]:65008`（.4） | `[2407:cdc0:d002::1961]:65008`（.5） | 1420 | 1420 | **1420** |
| `[2407:cdc0:d002::1961]:65008`（.5） | `[2605:52c0:2:13c0:dc9f:98ff:febf:9bd]:65008`（.6） | 1420 | 1420 | **1420** |

`.2 ↔ .3` 直连缺少握手，双方的当前业务 peer 归属经 `.11`；不能用中继成功代替直接链路的 MTU 测量。本轮最大 MTU 复核时，中继路由为 1320，此前双向验收成功；后续统一接口 MTU 时同步提升至 1400，见下一节。`.6 ↔ .7` 缺少 Endpoint，无法确认该边的实际公网对端和端口，也不提供 MTU 数字。

此前已验证的 1400 为部署值；本轮证明部分链路的精确边界为 1404。`.11 → 223` 的 1404 字节内层包对应 1464 字节外层完整包；1405 字节内层包对应的外层出现 1460 字节首片。IPv4 非最后一片的数据长度按八字节对齐，因此“首片长 1460”不等同于完整外层上限是 1460。外层实际分片位置仍未确定。另有 `.1 → .3`、`.11 → .3` 的单向上限为 1404，反向均能达到 1440；`.3 ↔ 223` 则双向达到 1432。

最大 MTU 复核时的接口默认 MTU：`.1/.11` 为 1420，其他七个登记地址中六台在线节点为 1320，`.7` 配置未知。223 的四条路由为 1400。该复核保持所有接口 MTU、WG 配置哈希和生产策略规则，诊断路由、响应器、抓取进程和八台节点的临时工具目录均已清理。测试触发了已有 peer 的握手：原来 latest-handshake=0 的 `.4/.5/.6` 直接 peer 现已具备有效握手；其磁盘配置保持。220 默认仍经 223，Google／Cloudflare 均为 204、TLS 校验为 0，223 daemon 仍为 PID 24157。

逐候选结果、PCAP、公开端点 CSV 和配置哈希保存在 `build/upstream-wan-20261003/wg-peer-mtu-20261004/`，汇总为 `manifest.json`、`verification-summary.json`、`peer-mtu-public-endpoints.csv`。222 可用空间约 4.4 GiB。

#### WireGuard 接口统一 MTU 1400（10 月 4 日）

用户明确授权将上述网络的 WireGuard MTU 统一为 1400。八台在线节点已同时更新运行接口和持久配置：

| 节点 | WireGuard 接口 | 修改前 | 当前运行值／持久值 |
| --- | --- | ---: | ---: |
| `.1` | wg-ixp0 | 1420 | 1400／1400 |
| `.2` | wg-tcgz0 | 1320 | 1400／1400 |
| `.3` | wg-ixp0 | 1320 | 1400／1400 |
| `.4` | wg11 | 1320 | 1400／1400 |
| `.5` | wg0 | 1320 | 1400／1400 |
| `.6` | wg0 | 1320 | 1400／1400 |
| `.10`（223） | IEPL | 1320 | 1400／1400 |
| `.11` | wg-ixp0 | 1420 | 1400／1400 |

Linux 节点原有 `wg-quick@接口` 已启用；对应 `/etc/wireguard/接口.conf` 的 MTU 字段原子修改，运行中用 `ip link set` 生效。223 执行 `uci set network.IEPL.mtu=1400`、`uci commit network`，再更新运行接口；核对其 WireGuard 初始化脚本会重新读取 UCI 并设置接口 MTU。未执行接口下线或服务重启，八个接口的 ifindex 均保持。核心 `.2 → .3/32` 的运行路由及 `/etc/kdae-wg-paths/routes.sh` 同步由 1320 改为 1400，既有 15 条 MTU 1400 路由继续保留。

**普通路由验收**使用 SO_MARK=0、UDP 46720／46721，没有安装诊断路由或修改策略规则。14 对已连通 peer 的 28 个方向各发五个内层 IPv4 总长 1400 的 UDP 包，接收端验证标记、长度和零填充，**140／140** 获得有效 ACK。每个接收器 accepted=5、invalid=0、ack_errors=0。发送和接收两端均观察到完整 WireGuard 包，无外层分片；包括两对使用 IPv6 公网承载的 peer。完整 PCAP 再次解析通过。

`.2 ↔ .3` 经 `.11` 的中继另用 1400 字节 IPv4 DF 包验收：两个方向各 **5／5**，平均 RTT 约 13.6／13.7 ms。两端内层各捕获 20 个 ICMP 包，外层所选 1400 字节承载包全部无分片；外层包含同期业务，因此其计数不全部归属于受控 ping。直连验收和中继验收合计 **60 个抓取点**，全部 captured=received by filter、kernel dropped=0。该验收验证的是中继路径；`.2 ↔ .3` 的入口直接握手问题仍保留。

修改前每台节点均备份，并设置独立 20 分钟自动回滚；全部验收通过后写入 accepted 标记并取消回滚，测试进程和临时工具目录已清理。Linux 备份为 `/var/lib/kdae-wg-mtu/20261004-unify1400-v1/`；223 为 `/root/kdae-wg-mtu-backup-20261004-unify1400-v1/`。手动回退需先移除对应 accepted 标记，再运行 Linux 备份中的 `python3 deploy.py rollback <节点隧道 IP>`，或 223 的 `sh deploy.sh rollback`。这一级回退恢复本次 MTU 字段、接口值及核心 `.3` 路由，保留此前入口限制和中继的 peer 归属。223 的首轮准备因缺少 stat 在修改前退出；原始配置哈希核对不变后，保留未完成备份，改用保留文件权限的复制方式完成安装。

收尾再次核对八台接口／配置均为 1400；物理口、PPPoE 和其他接口 MTU 与基线一致，WG peer 的 AllowedIPs、keepalive 及入口 guard 文件哈希保持。`.1/.3/.11` 到核心的 endpoint 均为入口 `165.101.4.113:65008`。220 默认仍经 223，Google／Cloudflare 均返回 **204**、TLS 校验为 **0**；223 daemon 仍为 PID **24157**，binary、主配置、local、init 哈希保持。持久化依据配置和初始化脚本核对，本次未执行整机重启。

非敏感脚本、部署／收尾快照、普通路由记录及 PCAP 保存在 `build/upstream-wan-20261003/wg-unify1400-20261004/`，汇总为 `manifest.json`、`configuration-verification.json`、`verification-summary.json`、`accepted.json`、`cleanup.json`。

### 223 再次观测

**09:13:37–09:16:37 UTC**，七个 30 秒快照：新增 considered 169、sampled 3，10 条 capture、25 条 evidence 均通过 validator；generation 不变、游标缺口 0。两个完成流都是 proxy userspace_accounting，offload_unmeasured **0／2**；queue_dropped **0／10**。invalid_window 增量为 0，但没有可比较窗口，两个 relay 都是 flow_ended_before_node_snapshot，因此 splice 计数偏差仍不可评估。独立 WAN fixture 流量不经过生产 daemon 的采集，不能拿它充当这批 capture 样本。

质量日志仅 below_sampling_threshold 16 次，没有严重触发、质量切换提交或恢复日志；主要 observe 组快照未见成员变化。质量切换预算不消耗，站点恢复结论限于留存日志。末尾 106 个质量条目均无速度参考；继续 observe。RSS 117.0–119.7 MiB，error／fatal／panic 为 0，既有 warning 52 条，不能称无告警。

收尾仍为 PID 24157、版本 `upstream-gather-candidate-20261003`；executable、三个配置／init 哈希与 P2 部署一致，send_redirects 均为 0，三个性能环境开关均未设置。本轮仅增加测试工具和记录，不需要重启 daemon 或改变依赖 pin。

220 收尾默认路由仍经 223，Google／Cloudflare 均返回 204；远端测试二进制和临时目录已清理。222 可用空间约 **5.0 GiB**：本地 P1／P2 发布产物压缩为各自目录下的 `dae.gz`，诊断工具为 `control.test.gz`，均先核对解压 SHA256 再移除未压缩副本；可用 `gzip -dc <文件.gz> > <还原路径>` 还原。正式 Go／模块缓存、业务证据和远端回退产物保留。

### 10 月 4 日收尾与 UDP 归因修复

此前 WireGuard 的入口限制、peer 最大 MTU 表、统一 1400 的部署及验收记录已提交为 `cc2bce35`。本节时间采用北京时间。

#### `.1` nftables 持久化修复

原 `/etc/nftables.conf` 的 NAT chain 位于 table 外，语法检查失败；nftables 服务 failed 且已启用开机加载。未生效的示例还包含 input／forward 默认 drop，直接补括号并加载会改变生产策略。运行中的 ip／ip6 filter、nat 表由 iptables、Tailscale 与 WireGuard hook 维护，因此将该文件替换为仅加载已有 `/etc/kdae-wg-paths/entry-guard.nft` 的入口配置。服务 drop-in 设置 RemainAfterExit，reload 同样只加载此配置。

已备份并原子替换，语法检查、start、reload 均通过，服务恢复 active。核对前后规则，排除运行计数和 handle 后，其他表完全一致。新的 SSH 连接成功，WG 服务 active，到核心入口的 1400 字节 DF 包 **3／3**；接口 MTU 1400，核心 endpoint 仍为入口。备份为 `/var/lib/kdae-wg-paths/20261004-nft-repair-v1/`，含旧配置、旧 drop-in、前后规则及 accepted 记录。

`.2 ↔ .3` 入口直连尚未握手；重试 `165.101.4.113:22` 在认证前关闭。用户后续确认入口存在 AS 路由准入限制，公网 SSH 失败不能说明 SSH 服务异常。已可通过 `10.8.1.2` 的隧道 SSH 管理核心；当前业务继续经 `.11` 中继，入口准入复核见末节。

#### UDP 观测的两个归因缺口

outbound 本地提交 `0bb08a457f98e9b0126fc041dd7e55bb1a6ab88b`：新增独立的实际应用 peer 元数据，Hysteria2／TUIC 的 push 和 ReadFrom 路径均保留客户端 NAT 回复地址，同时提供 NAT 改写前的真实 peer。未知域名来源保持未归属。SOCKS5、SS stream 和 SS2022 在解码后更新 peer，避免沿用下层代理地址；分片重组保留同一语义。

主仓库工作区在实际 WriteTo／WriteBatch 调用前登记有界的发送意图，快速回复可立即找到 association 中的 peer。意图不计成功发送，排队不填充观察窗口；返回后仅计成功包或批次的成功前缀，失败仍使窗口失效。未发送的意图同样受每 association 八个／全局 256 个 peer、60 秒 TTL 和代次关闭约束。快照增加 association 级未归属计数，便于区分同时运行的 Steam 与其他流量；不同 IP、端口及未知来源不会合并，mapped IPv4 与对应 IPv4 正常归一。

受影响的六个 outbound 包普通测试、race 和 vet 通过。主仓库 UDP 观测、端点生命周期、批量写、跨地址族回归通过 race；config、outbound、dialer、quality 四包 race 通过；DNS／bootstrap 相关回归和 control vet 通过。REALITY 的现有兼容、hello 和恢复测试通过，尚不能代替新旧实际服务端互通。

**发布状态：** 用户明确授权后，outbound `0bb08a457f98` 已推送至 `Fan-chou/outbound` 的 `codex/upstream-followup-20261002` 分支，正式 go.mod 固定 `v0.0.0-sticky-ip.0.20261004031250-0bb08a457f98`。主仓库提交为 `5a150027`，使用实际下载的发布模块重新通过上述 UDP／DNS 与受影响 outbound、质量配置包的 race 回归及 vet。QUIC 继续固定 `42916a975611`。223 已安装 `upstream-udp-attribution-20261004-5a150027`，部署验收记录见下节。质量继续 observe；UDP 观测及自动重建、MSS 和 gather 均保持关闭。

#### eBPF、DNS 与 IPv6 验证

历史 checkpatch 提示已整理为 `a78c788a`：调整缩进、空行、布尔指针判断及过长测试行，重写一处被误判为 switch fallthrough 的注释。`make ebpf-lint` 和 `make ebpf-test` 均通过。

**11:11**，220 默认仍经 223。向外部 DNS 地址发送 org DNSKEY 请求，4096 字节 EDNS 上限得到 **1337 字节完整应答**；512 上限、禁止自动重试时得到 **476 字节、TC=1**；允许重试时自动转 TCP，再得到 1337 字节完整应答；显式 TCP 同样成功。向路由器本地 53 查询的另一响应路径未遵循 512 上限，已单独保存，未用作 dae 截断验收。

220 经 223 的显式 IPv6 HTTPS 返回 **200、TLS 校验 0**。客户端 DNS 会被生产策略接管，因此不能用其 FakeIP／AAAA 结果证明 bootstrap。另在 223 运行固定目标、超时的探针，沿用生产 `BootstrapResolvers`、`ResolveIp46`、代次 direct dialer 和内部 socket mark，以 `[2400:3200::1]:53` 分别走 UDP／TCP，四项 A／AAAA 查询均获得真实地址、无错误。探针已从远端清理；生产 resolver 和配置未改。该验证覆盖 IPv6 resolver 链路，未覆盖服务端 IPv6-only 名称及所有订阅初始化场景。

#### 223 观测和后续条件

当前采集代次从 **10 月 3 日 21:47 至 10 月 4 日 11:13** 保持，分页读取无游标缺口，**4884 条记录全部通过 validator**。850 个完成流中，offload_unmeasured 为 **510／850＝60.0%**，全部是 direct，其中包含 90 个 offload_error 终态；不能把“未测量”计为代理失败。queue_dropped 为 **0／4884**；3163 个可比较 userspace 窗口中 invalid_window 为 **0／3163**，没有节点方向计数小于本流的窗口。直接 splice 流仍缺少本流计数，这些自然样本不能给出其精确偏差；此前受控 splice 验收继续作为依据。

**11:00:40–11:16:59** 的最近 4000 行日志没有 local_quality 或 site_recovery 事件，error／fatal／panic 为 0，warning 101 条。恢复预算结论限于所留日志，未声称已读取内部预算余额。daemon 仍为 PID 24157，原 binary／主配置／local／init 哈希保持；IEPL 运行和持久 MTU 均为 1400。222 可用空间约 **4.1 GiB**，正式 Go／模块缓存保留。

仍需后续条件：用户在 201 复测修复后的 CS2；确认入口是否计划向 `.3` 的来源 AS 提供直连路由；新旧 REALITY 实际服务端与 ARM64 机器验收。继续 observe；UDP 自动重建与性能默认值依照原方案的证据门槛推进。上述脚本、测试日志和非敏感汇总保存在忽略目录 `build/pending-followup-20261004/`。

#### 223 正式发布与验收

`5a150027865052f218290185b744da1076666a62` 从干净工作区构建，`GOWORK=off`，没有本地路径替换。产物记录 `vcs.modified=false`，使用 `trace`、CGO=0、linux/amd64 和 `heapminimum512kib`；outbound 固定上述新版本，QUIC 与 QPACK 版本保持。二进制 SHA256 为 `700ed72747ce08eb766f5407ac083708f126e0bcbf9ac8c5a89b33ecde798947`。

部署前验证旧版哈希和生产配置，先备份再原子替换二进制。脚本包含 EXIT／信号失败回滚、启动与 API 就绪检查，以及独立的 15 分钟验收超时回滚。主配置、local、init 和 network 文件的哈希均保持；新进程 PID **14819** 的运行哈希一致。**13:00:11** 完成验收并在锁内写入 accepted，解除超时回滚。旧版备份保留在 `/root/kdae-udp-attribution-20261004/before/`，手动回滚脚本为同目录上层的 `rollback.sh`。

**12:56–12:59**，220 默认经 223，Google／Cloudflare 的 HTTPS 各 **3／3** 返回 204；显式 IPv6 HTTPS 返回 200，TLS 校验均为 0。外部 DNS 的 org DNSKEY 得到 **1043 字节完整 UDP 应答**；512 字节上限得到 **476 字节、TC=1**，自动转 TCP 和显式 TCP 均得到 1043 字节完整应答。

180 秒、七次状态快照均运行正常，39 个组末尾都有可用节点，采集代次稳定，无游标缺口。导出 30 条采集记录，其中 23 个 relay 窗口、7 个完成流；offload_unmeasured 为 **5／7＝71.4%**，全部 direct。invalid_window 为 **0／16 个可比较窗口**，queue_dropped 为 **0／30 条记录**；节点方向计数小于本流的窗口为 0。该小样本不足以比较长期未测量比例；直接 splice 流没有本流字节计数，仍不能从自然样本计算精确偏差。

四个主要组继续 observe，末尾共 16 个质量条目，没有速度样本或参考。日志中的 9 次 local_quality 事件均为 `below_sampling_threshold`，质量切换和 site_recovery 提交为 0，30 秒快照没有观察到组成员变化。observe 不消耗质量切换预算；恢复结果限于所保留日志，未读取内部预算余额。error／fatal／panic 为 0；warning 包括 21 次对端 reset、3 次 unnamed FakeIP、3 次 FakeIP 拨号超时。部署前三分钟已有 26 次对端 reset 和 3 次 unnamed FakeIP。RSS 为 **113.6–123.3 MiB**。

IEPL 的 ifindex 未变，运行与 UCI MTU 都为 **1400**。质量 enforce、UDP 观测与自动重建、MSS 和 gather 继续关闭；本次真实 peer 归因修复已有协议和控制层回归，CS2 的新现场观测仍待 201 实测。发布证据位于忽略目录 `build/udp-attribution-release-20261004/`；本地候选压缩为 `dae.gz`，解压哈希已核对，222 根盘可用空间约 **3.7 GiB**，持久 Go／模块缓存及回滚副本保留。

#### 入口 AS 路由限制的补充复核

用户明确入口 `165.101.4.113` 对全部端口的可达性受 AS 路由范围限制。此前把公网 SSH 不可达列为缺少管理入口不够准确；核心 `10.8.1.2` 的隧道 SSH 可用，sshd 正在 IPv4／IPv6 的 22 端口监听。可见的 iptables INPUT 策略为 ACCEPT，hosts.allow／deny 没有生效条目，SSH 配置未发现用户／地址拒绝条件；这些检查不覆盖入口上游的路由策略。

**15:47（北京时间）**，沿隧道 SSH 只读复核：`.1/.11` 到核心入口的握手持续刷新，`.3` 的直接 peer 握手仍为 0。三个 endpoint 仍为 `165.101.4.113:65008`，`.3` 到入口使用物理口默认网关。RIPEstat 的公开 BGP 数据显示，[`.1` 的 `106.53.65.44`](https://stat.ripe.net/data/network-info/data.json?resource=106.53.65.44) 和 [`.11` 的 `43.136.77.84`](https://stat.ripe.net/data/network-info/data.json?resource=43.136.77.84) 都由 **AS45090** 宣告；[`.3` 的 `39.108.101.120`](https://stat.ripe.net/data/network-info/data.json?resource=39.108.101.120) 由 **AS37963** 宣告。RIPEstat 的[公共视角没有找到入口的路由前缀](https://stat.ripe.net/data/network-info/data.json?resource=165.101.4.113)，这不表示受限网络内部没有路由。

现象与入口只向部分 AS 可达相符，但尚不能证明 AS37963 是否被入口策略排除，也不能由普通 `ip route get` 推断上游 BGP 的回程。保留 `.3 → .11 → .2` 的已验收中继，以及入口／出口限制和 MTU 1400。没有开放端口、扩大来源范围或修改服务器配置。后续如需公网直连，应先核对入口是否向 AS37963 提供必要的双向路由；无需把任意公网来源的 SSH 成功作为前置条件。只读记录保存在 `build/wg-entry-acl-20261004/`。

### 上游跟进待办复核（10 月 4 日）

对照方案的 25 个单元和当前提交：20 个正确性单元及 U1 已实现；P1、P2 已实现默认关闭的候选；P3 已完成评估，决定暂不接入没有生产调用的 GRO／arena；U2 的自动重建、预算和 peer 拆分执行路径尚未实现。相关主仓库实现提交均为当前 HEAD 的祖先。

共享节点的双向并发 splice 字节核对、线上大 DNS 应答／截断升级、IPv6 resolver 的 UDP／TCP bootstrap、eBPF lint／测试及 NAT 真实 peer／早到回复修复已有通过记录，不再列为未完成。自然 splice 样本缺少本流计数，仍不能用它们取代受控字节核对。

| 待办 | 当前状态与剩余条件 |
| --- | --- |
| 最终 strict 验证 | 最新 pin 的完整三仓检查中，QUIC 的损坏包握手用例发生 1 秒期限超时；当前版和旧基线的定向重复均通过，整套失败原因仍需定位，详见下文 |
| CS2 修复后现场验收 | 201 本轮匹配成功，用户报告无卡顿、无掉线；原 SS 路径的 13 个新 SDR 目标有有效回复。仍需从游戏长流建立前覆盖观测并标注游戏阶段，详见下节 |
| UDP 暂停／重载身份 | H3 请求间隔及 association 复用已验证；真正静默的 H3／WG keepalive、暂停与重载组合尚未完整覆盖。STUN 的远端映射端口变化已排除 dae endpoint 对象重建，底层 transport／远端 NAT 原因未闭合 |
| U2 UDP 自动重建 | 10 月 5 日完成执行、预算、peer 拆分、生命周期及真实 SS／SOCKS5 隔离验收，Astra 复核通过。尚未部署及完成 220 → 223 现场验收；CS2 保持 unknown |
| REALITY／bootstrap 场景 | 本地兼容和生命周期测试通过；尚缺新旧真实 REALITY 服务端互通，以及代理节点使用 IPv6-only 名称的完整初始化验证 |
| ARM64 实机 | 已交叉编译；状态发布、预算竞争、重载和相关内核路径尚未在 ARM64 机器执行 |
| 质量 observe 的启用门槛 | 223 本次读取的 147 个质量条目均为 observe，仅 3 条有速度样本、1 条有速度参考；仍需有代表性的业务样本、触发频率和恢复提交记录，保持 enforce 关闭 |
| P1／P2 性能启用 | 两种真实代理的短期 A/B 已完成。MSS 尚缺完整 WAN MTU／IPv4／IPv6／MPTCP 矩阵，gather 尚缺自然多段出现频率和稳定交付收益；两者继续关闭 |
| 主仓库发布 | 代码及部署记录已提交本地；outbound／quic-go 已推送并固定，主仓库 fdae 尚未推送 GitHub |

**最终依赖验证：** 最新 `0bb08a457f98` 更新后，受影响包 race 和 vet 已通过。此前完整 strict 三仓日志对应旧 outbound `5cb62805177d`；本次指定 `build/upstream-followup/` 下三个实际 fork 工作区，确认最终 outbound／quic-go／qpack 的 dry-run 覆盖，并执行 `--strict --short -- -race -p=1`。outbound 和 qpack 通过；QUIC 的 `TestMITCorruptPackets/towards_the_client` 在客户端 Dial 成功后、服务端 Accept 处超过 1 秒 context 期限，严格检查返回失败。未发现 DATA RACE 报告，不能将本轮写为三仓全部通过。

保持工具链、GOMAXPROCS=2、原始断言及期限，对当前 QUIC `42916a975611` 和旧基线 `e64dc7a1252e` 各运行 20 轮该用例的 race，对照均通过；两版本的 `mitm_test.go` 内容和 SHA256 相同。测试会随机损坏握手及数据包，但目前没有证据把整套超时归因于随机性、调度或本次修改。定向通过不替代整套 strict 通过，失败原因与稳定性仍为待办。没有修改测试、重试至全绿或改变线上参数。

入口对 AS37963 的双向路由范围仍需确认，`.2 ↔ .3` 现有中继已验收；这是关联的网络接入事项。只读核对、最终验证日志与清单保存在 `build/upstream-completion-audit-20261004/`。

### CS2 修复后实测（10 月 4 日）

**本轮业务结果通过：** 用户在 201 进行 CS2 官方匹配，确认「匹配成功，没有出现卡顿或者掉线」。未提供具体进入／结束对局时间，因此不能把整个采集窗口标作同一游戏阶段。

**20:16:15–20:36:21（北京时间）**，223 仅对 `192.168.124.201` 临时启用 UDP unknown／observe，保留生产路由，质量继续 observe。240 个状态快照、40 个质量快照和有界包头记录完成；**20:36:21** 自动恢复 local.dae 原始哈希，UDP observer 关闭。daemon 始终为 PID **14819**，二进制、主配置、init 和 network 哈希与基线一致。没有启用自动重建、quality enforce 或性能候选。

新观测覆盖 **13 个 SDR 目标、144 个 association**，均经 `Cherry_Proxy → HK_GG_IPLC_Dmit_HK`；各 association 最后快照合计成功写 **481**、有效回复 **481**。同期全部 UDP 观测合计写 483、回复 482，另两条属于非 SDR 目标；未归属写／回复、登记丢失和失效窗口均为 0。这些是本地成功写与有效回复计数，不能按一包一应答推算网络丢包率。CS2 回复语义保持 unknown，候选为 0 不代表无回复故障检测已通过。

主要高流量连接 `201:59526 → 103.28.54.163:27035` 的日志确认其在观测开启前已经建立，走同一香港 SS 节点；reload 保留了该关联，新 observer 没有接管其账本。**20:16:15.980–20:17:01.371** 的包头样本有双向数据，包括 **1261 字节 UDP 回包**。`any` 上的 24,000 条记录含 dae0、bridge 和物理口的重复观察，按 br-lan 单独统计后为 8,000 条；达到上限后停止抓取，不能称已记录整局包头。该长流覆盖缺口保留，不通过关闭活跃关联补齐。

同期 TCP capture 共 71 条记录、24 个完成流，offload_unmeasured **16／24＝66.7%**，全部 direct；queue_dropped **0／71**，16 个可比较字节记录中 invalid_window 为 0，节点方向计数小于本流为 0。直接 splice 流仍缺少本流计数，不能据此计算其偏差。RSS 为 **156.3–171.0 MiB**。

留存日志中的 177 次 local_quality 事件均为 `below_sampling_threshold`，没有质量切换触发；质量快照均为 observe。其他站点的 stable leaf 有四次变化，原因尚未逐一归属，不能解释成质量模块切换。`Heart_Telegram_HK / telegram.org` 有三次首选恢复试探，均为 `slow_first_byte`，按约 2／5／10 分钟退避；没有成功恢复提交日志。未读取内部预算余额，这些恢复事件不属于 CS2 UDP 自动重建。

本轮支持原 SS 路径在修复后可以完成官方匹配并正常游戏，记录为一次业务验收通过。U2 仍未实现；回复义务、暂停保护、从建立起覆盖的游戏长流以及完整阶段标注仍为后续条件。配置备份仅留在 223 的私有诊断目录；无凭据的采集证据、汇总和用户结果保存在忽略目录 `build/cs2-live-20261004/`，汇总为 `summary.json`。

### U2 执行设计完成（10 月 4 日）

[执行设计](upstream-followup-plan-20261002.md#u2-执行设计10-月-4-日)已对照当前 UDP pool／prefetch／retained 查找、SessionManager、实际写入与 batch、replySender、BPF tuple 引用，以及固定 S12 原始补丁核查。通用机制先在可控请求／应答服务验证；CS2 实测通过记录保留，unknown 和启用条件保持。

设计确定先准备候选、再隔离故障 peer 写入、复核证据后发布新所有者；原节点与 binding 保留，健康 peer 继续原关联。预算与站点恢复分开，重建后的三个新回复限制随活跃 lineage 保留；预留、实际 dial 和发布分开计数。所有查找入口及普通 Close 需要复核相同 revision，解决只创建目标专用 key 仍会被 retained／prefetch 绕过的问题。旧接收队列保留排空，晚回复不更新新账本；tuple 与别名按引用交接。

按 U2-A 身份与预算、U2-B 单目标、U2-C peer／生命周期、U2-D 隔离验收交付；执行开关在验收完成后加入。候选限频／期限已明确写为未实测初值。本次只有设计与状态记录变更，执行代码尚未落地；223、依赖 pin 和业务配置保持，未启用 enforce 或 UDP 自动重建。

### U2 信息获取渠道（10 月 4 日）

这批实现后续验收所需的信息渠道，尚未实现执行账本、dial 准备、peer 屏障或提交。配置仍只接受 off／observe，CS2 仍为 unknown。未修改 223，也未改变 outbound／quic-go 的 pin。

#### 接口与证据

| 渠道 | 可确认的信息 | 边界 |
| --- | --- | --- |
| 认证只读 `GET /v1/udp-recovery?after=N&process=P` | 进程 ID、采集时刻、候选门槛、当前 peer、覆盖范围及事件游标 | `execution_implemented=false`；没有执行预算或恢复成功指标 |
| peer 的 `windows` | 六个完整桶与当前部分桶，非空成功写入次数、回复次数、失效标记、证据是否存在 | 资格条件不变；计数到 1,048,576 后标记下界，未记录桶不冒充有效空窗口 |
| `runtime_id`、`policy_epoch`、generation／association | 把新流、旧代长流、候选与结束记录关联起来 | 当前没有重建后代，尚不提供 lineage／revision 的执行承诺 |
| `coverage` | 开启观察前建立的流、实际 peer 归属不足、尚无 peer 证据 | 旧 source-only 流在指定 peer 范围内标为 `retained_peer_scope_unresolved`，不按记忆的首个目标推断全部 peer |
| 进程级事件账本 | `qualified`、`candidate_ended`、`observation_ended`、未归属 association、代际开关和覆盖缺失 | 256 条，分页 128 条；reload 保留，进程重启重置；明确返回丢失数量、最早／最新／下一条游标 |
| `/v1/quality` 的 `recovery_diagnostics` | 质量原因计数、独立验证窗口数、TCP／UDP 站点恢复的试探结果与 30 分钟切换预算用量 | 计数不依赖日志级别和限流；只读，不过期试探或裁剪预算；最多 256 个 fallback／url_test 组 |

结束记录保留最后一次 peer 计数和 association 的未归属计数。`candidate_ended: reply_resumed_on_original` 表示原关联自行恢复回复，不能算作 U2 重建成功。同一窗口同时触发相对与绝对劣化时，`verify_alternative_windows` 只计一次。站点恢复的 `probe_started` 与 `recovered` 分开计数，失败试探不冒充预算提交。

账本按事件到达顺序编号，回调可并发；用 process、generation、association、peer、`candidate_episode` 关联一次候选的开始和结束，结合 `at_ms` 对齐阶段。旧代关闭的是观察账本，`generation_closed` 不表示活跃 UDP socket 关闭。覆盖缺失事件每代按 runtime ID 去重，最多 256 项；快照注明输出截断和去重容量耗尽。

本轮仍使用 U1 既有的协议分类区分本地写完成和队列接受。这不是独立关联能力声明；后续执行资格还必须通过实际 PacketConn 的能力接口和隔离 fixture。无候选、无事件、没有字节参考或没有实际回复义务时，不能给出“自动恢复有效”的结论。

#### 现场采集

更新二进制及已审查的 `tools/laya-capture/read-observation.sh` 后，可用现有 SSH 认证采集；工具自身不修改配置或路由。应在创建游戏长流前启用限定客户端的 observe。先检查 `coverage`，不能用开启前保留的流补足无回复证据。

```sh
python3 tools/udp-recovery/collect.py collect \
  --router root@192.168.124.223 \
  --output build/udp-recovery-live/ --seconds 1200

python3 tools/udp-recovery/collect.py mark \
  --output build/udp-recovery-live/ --phase search
# 进入、暂停、结束或报错时分别记录 playing / paused / ended / error。
# 补报时间须包含时区：--at '2026-10-04T23:00:00+08:00'。

python3 tools/udp-recovery/analyze.py build/udp-recovery-live/ \
  > build/udp-recovery-live/summary.json
```

默认每 5 秒读取 UDP 诊断、capture 和 status，每 30 秒读取质量计数与组状态。单次最多 20 分钟，可设置到 1 小时；单轮最多分页四次；数据与 manifest 预算默认 100 MiB。SSH 使用已知主机、公钥认证和期限；token 只经现有读取脚本的 stdin 进入 curl。文件目录 0700，归档原子发布并 fsync，先发布 SHA256 manifest，再发布数据，两者完成后才一起保存游标。分析器忽略尚无数据的 manifest；采集或阶段标记发布前会校验旧版留下的完整孤儿数据并补写 manifest，不依赖下一轮内容相同。并发阶段标记与采集共用归档发布锁，不竞争采集游标。

每轮记录实际运行二进制 SHA256、PID／启动标识、配置目录内 `.dae` 文件摘要，以及请求前后时间。来源变化时保留原始数据并拒绝推进游标；过程重启、ring 丢失、分页预算耗尽、观察代在一轮内变化和采集失败均留存为缺口。服务器 `at_ms` 与本机请求时间给出时钟偏差区间，不假定跨主机时钟已同步。阶段标记区分操作人提供的时间与报到时间。

分析器先验证归档哈希，重算候选所需窗口与回复历史，按代整理质量触发频率与预算。capture 比例注明分母是归档下界；节点计数包括其他流，正差不能当成本流计数误差。自然 splice 流没有本流字节参考时不计算偏差，skew 后被排除的窗口另列。阶段标记只提供业务上下文，不把 unknown 自动改为 request_reply。

验收仍分两步：信息渠道证明证据完整、覆盖正确、开销受控；U2 执行 fixture 再证明预算／所有权顺序、健康 peer 不变及新关联收到三个有效回复。自动执行部分完成后，需要继续扩展 committed、awaiting_replies、recovered 等实际状态；当前接口不会填入虚构的零值或成功状态。

验证：control、cmd、outbound、config 的 UDP／SessionManager／质量／站点恢复／管理接口相关 race 用例和四包 vet；新增 Python 13 项归档与分析测试、原 laya-capture 29 项测试及读取脚本语法检查。整套三仓 strict 的既有 QUIC 超时待办保持，不将本批测试替代该门槛。

#### Astra 独立审查与修正

Astra 对冻结的 `61dce077..cd62f250` 独立审查，复现两项 P2 问题：发布数据后、写 manifest 前中断，真实重启产生的新 poll 不能修复旧孤儿文件；仅有未知 peer 的 association 未登记到 observer，重载遗漏累计结束记录。审查没有部署或访问生产服务器。

归档修正为 manifest 先于数据发布，并对旧孤儿数据验证文件名摘要与 schema 后补齐 manifest。回归覆盖重启后内容变化，以及 manifest 已完成但数据尚未发布时中断。观察代新增有界 association 登记，未知写入与未知回复均纳入代际收尾；peer 全部淘汰后仍保留未归属累计计数。登记上限为 256，容量不足计入 `admission_dropped`；关闭 observer 保留实际 UDP socket。回归覆盖这三种结束场景和容量上限。

Astra 再次独立复核 `cd62f250..a585f32e`，确认两项发现均已修复，未发现修正引入的新问题。原先失败的冻结回归在修正后通过；Astra 重跑 Python 13 项测试及相关新增／并发 race 用例均通过。复核未覆盖生产流量、长期内存或观测开销，也不代表 U2 执行与业务恢复验收完成。本轮实现、修正及审查记录均已提交本地，尚未推送或部署。

## U2 自动重建执行（10 月 5 日）

执行逻辑已接入生产代码，默认仍为 off。`enforce` 必须同时给出单个客户端 IP、精确组名、数字 IP:port peer 列表和 `request_reply`。配置缺项直接报错；质量模式不会隐式启用它。223 已部署并完成下述受控验收，生产配置恢复 off；CS2 官方 SDR 继续按 unknown 排除执行。

### 执行与隔离

- 六个完整 5 秒窗口、每窗至少 10 个非空成功发送、至少 3 个历史回复、30 秒回复干旱及最近 5 秒仍有发送继续作为资格。排队、准备和发布前重新核对证据、存活、实际所有者及活跃配置代；回复恢复或错误使候选取消。
- SessionManager 持有 256 项有界账本。peer／组／进程分别最多 1／2／8 次每分钟；实际 dial 计尝试，发布计提交。拨号前取消不消耗尝试，拨号后取消保留尝试。活跃所有者、票据和等待新回复的记录不能淘汰；所有所有者结束后保留 60 秒墓碑。
- 活跃执行器使用 2 个准备 worker、32 项队列、10 秒票据和 2 秒准备期限。使用原节点及已固定的 egress binding 准备独立关联，prepared 不能被查找或承载业务包。未知能力、队列接受型传输、batch、DNS、直连、旧代、跨地址族、resolve_dns、域名和不明确的目标别名均排除。
- 能力由实际 PacketConn 声明。direct 提供底层本地完成和独立 socket；SS AEAD 保留底层承诺；SOCKS5 还要求独立 UDP ASSOCIATE control。没有声明则不执行。SS2022、SS stream、Hysteria2／TUIC 没有被此批放行。新关联不保证远端端口一定改变。
- source-only 共享关联 S 中，只将故障 B 拆成目标专用 T，A 继续使用 S。查找、路由缓存、prefetch、retained 和实际写入均遵循 peer 所有者。每个 endpoint 生命周期最多保留 8 个 peer claim，容量满时拒绝新增，避免无限保留 detached 身份。
- claim 覆盖实际 I/O。仅 B 的发布屏障等待当前 I/O，最长 100 毫秒；提交锁忙、等待超时、所有者变化或证据变化均取消。准备及发布不复制或重放业务包。先增加 T 的 tuple 引用，再释放 S 的 B 引用，旧缓存和晚到 tuple 登记不能重新挂回 S。
- 原关联的晚回复照常排空并返回客户端，单独计数，不恢复新账本。新所有者收到非空业务发送后的 3 个实际 peer 回复，才解除再次执行限制。普通 hard error／NAT 后代保持 lineage、revision、专用 key 和回复门槛；关闭开关也保留这些所有权。
- reload 在发布新代前取消并等待未提交工作；已提交关联由进程持有。回滚重新启用仍存活的旧执行器，预算不重置。冷启动 off／observe 不分配执行 worker、账本或 claim map。

### 信息渠道

`/v1/udp-recovery` 保留原游标、覆盖和窗口证据，增加 `execution`：实际尝试／提交／恢复、各种取消和 defer、group/process 预算、live owner、runtime／lineage／revision／policy epoch、下一次 peer 预算时间以及执行上限。`retry_at_ms` 只表示 peer 预算最早时间，组预算、容量或回复门槛仍可继续阻止执行。

committed 事件保留原证据和 successor runtime ID；recovered 绑定实际后代及 peer。即使普通后代没有 observer，也写入已有进程 journal，以 `generation: 0` 表示无观察代，并保留它的实际 policy epoch。不会因关闭 observe 丢掉回复确认。热路径的 claim retry／late reply／handoff timeout 使用原子计数，不获取全局账本锁。

Python 分析工具显示进程执行快照及可与已归档 commit 对应的新回复确认。缺失 commit 不会被补造；应用验收继续要求操作人结果。档案中的恢复计数不等同于 CS2 匹配或对局通过。

### 本地验收与 Astra 审查

真实本地 SS AEAD／SOCKS5 fixture 使用一个客户端关联交替访问两个真实 UDP 请求／应答服务，只丢弃 B 原映射的应答。已核对 B 新映射及三个有效回复、A 原映射不变、唯一业务序号只出现一次、旧回复不进入新账本、普通后代及 off 后的门槛和事件、所有查找入口、tuple 引用及预算。只重排已经实际发送的 datagram 的观察时间，避免普通测试等待 30 秒；真实网络、内容、计数与映射没有合成。

准备失败、准备期间旧回复恢复、reload／rollback、B 的实际 I/O 卡住时 A 仍可收发、等待上限、未知能力／batch 排除、并发票据、容量满、活跃记录长期保留、墓碑和关闭竞争均有保护用例。

Astra 独立审查发现并修正三项问题：

1. Close 提前设置 dead 导致原 resolve_dns 的 discard 和禁止晚 save 分支失效；保留 `wasLive`，行政关闭和自然到期都覆盖。
2. 旧 S 指针转到 T 后的硬错误，可能使上层仍清理 S；实际 T 承担失败与原有退休处理，上层仅丢弃该包，健康 A 保留共享关联。
3. Close 与首次 reserve 竞争可能永久登记已结束 owner；生命周期锁排序登记／结束，拒绝 dead owner，取消时保留无 owner 墓碑。

Astra 修正后及收尾后分别独立复核，正式模块 pin 下四类相关回归 `-race -count=3` 通过，未发现新增问题。主 agent 完成 control／cmd 的 UDP、FIFO、batch、跨地址族、SessionManager、配置代、resolve_dns／FakeIP／QUIC 相关 race 回归，outbound／dialer／quality／config 四包全量 race，以及六包 vet。受影响 outbound netproxy／direct／SS／SOCKS5 的完整 short race 和 vet 通过；UDP 归档 Python 14 项、原归档 Python 29 项及读取脚本语法检查通过。

### 延迟对照

基线为 `f1ef34f1`。在同一 QEMU 主机、相同 Go 工具链、`heapminimum512kib`、GOMAXPROCS=2、固定 CPU 0／1 上预编译测试，按基线／当前交错 3 轮，表格为各轮中位数。两边真实 fixture 使用相同 outbound 源码，新增能力方法不改变数据收发实现。模拟路径每例取 100,000 次分布；真实 fixture 每例预热 100 次后取 2,000 次，回复等待在计时区间之外。原始日志与环境记录在忽略目录 `build/udp-rebuild-performance/`。

| 稳态写入 | 基线均值 ns/包 | 当前均值 ns/包 | 基线 p99 ns | 当前 p99 ns | 当前堆分配 |
| --- | ---: | ---: | ---: | ---: | ---: |
| off | 111.5 | 114.0 | 241 | 250 | 0 |
| observe | 268.9 | 273.8 | 401 | 410 | 0 |
| 限定范围 enforce | 尚未实现 | 329.4 | 尚未实现 | 461 | 0 |

off／observe 均值增量约 2.5／4.9 ns，分别为 2.2%／1.8%；enforce 相比当前 observe 增加约 56 ns，包含地址解析和 peer claim。

| 真实本地写入 | 基线 p50／p95／p99 μs | 当前 p50／p95／p99 μs |
| --- | ---: | ---: |
| SS off | 8.367／12.905／19.046 | 8.287／11.252／15.419 |
| SS observe | 8.746／14.057／16.812 | 8.666／12.064／15.239 |
| SS enforce | 尚未实现 | 8.836／14.126／18.726 |
| SOCKS5 off | 2.104／4.910／7.023 | 2.114／3.347／7.665 |
| SOCKS5 observe | 2.355／4.930／7.845 | 2.444／5.881／7.794 |
| SOCKS5 enforce | 尚未实现 | 2.535／5.240／7.434 |

既有完整 ingress → FIFO → 选路 → 建流 → 首包 benchmark：单 producer 16.550 → 16.424 μs；8 producer 15.713 → 16.006 μs（约 +1.9%）。分配次数分别维持 72／71，建流总分配增加约 100 B；稳态写入未新增每包堆分配。

这些对照未发现显著稳态延迟退化或新增阻塞。真实尾延迟受本机调度影响，不能证明公网或生产 p99；主动切换时 B 最长 100 毫秒等待是明确的执行上限，A 的隔离用例验证其不等待 B 的屏障。

### 版本与待办

outbound `8647a14b7f3691b596eaf37f3fb6bb86e9e45876` 已发布至 `Fan-chou/outbound` 的跟进分支；正式 pin 为 `v0.0.0-sticky-ip.0.20261004163218-8647a14b7f36`。QUIC 保持 `42916a975611`，无需新增提交。正式模块校验和验证、tidy 差异及模块图检查通过，无本地路径替换。

220 → 223 → 自管请求／应答服务的有界现场验收已完成，结果见下方。SS2022 能力声明与实际恢复验收、CS2 的回复义务及暂停保护仍待完成。CS2 SDR 不能据端口、一次成功对局或 UDP 静默自动获得执行资格。既有全套 QUIC strict 的 `TestMITCorruptPackets/towards_the_client` 超时待办仍保留，本批定向测试没有替代该门槛。

### 10 月 5 日首次现场验收与 native peer 修正

223 首先安装正式依赖构建 `unstable-20261005.r1277.90fe9b59`（SHA256 `a8bb63716ce3f9b8d1feb2daef046bd24fb2ffc6453de8182576cef8635aa19a`）。备份旧二进制和读取脚本，设置独立自动回滚；生产配置、init、网络配置保持。220 默认路由经 223，222 保持原直出规则。Google／Cloudflare HTTPS 均返回 204、TLS 校验为 0。

临时 `U2_Live` 组复制现有 SS 节点，凭据仅在 223 处理，去掉 `resolve_dns`；其实际数字 underlay 为 `10.8.1.6:34564`。仅 `192.168.124.220` 到自管 `.5` 公网 `185.248.186.73:46671/46672` 的 UDP 被导向该组。两端口运行带随机令牌、时间及包数上限的 256 字节请求／应答服务。客户端同一个 socket 每 peer 每秒发送五次；observe／enforce 中，B 从第 100 个请求后仅屏蔽首个代理映射，A 始终回复。off 阶段不注入故障，只是正常基线。测试配置有独立恢复 watchdog。

首轮结果：off A／B 各 175／175 回复；observe 和 enforce 均为 A 550／550、B 550／100，服务端逐包确认各屏蔽 B 的 450 个请求。所有请求到达，无重复、无每 peer 序号逆序。observe 产生一个经归档窗口校验的候选，执行器为空。enforce 同样产生候选，但有 12 次 `peer_alias_unsupported`，实际 attempt／commit 均为零，没有新映射；因此首轮没有验证恢复成功。各阶段归档无游标缺口或读取错误。配置已恢复 off，测试服务已停止并清理。

原因是全局启用跨地址族映射时，普通 native IP 的 endpoint 同样持有 writable store；直接用 `crossFamily != nil` 排除执行，误把映射能力当成了实际 alias。修正只允许源和 peer 同族、身份明确的 native peer；真实 foreign peer、映射池中的目标或 DialTarget、固定目标或原始 peer 不一致、未知／未打开的 store、域名和 resolve_dns 继续排除。prepare 继承旧 endpoint 的 store，保留其回复映射视图。未关闭全局跨族功能，也未修改每包写入路径。配置说明同步更新为实际支持的 scoped enforce。

真实 SS／SOCKS5 回归新增全局 mapping 启用场景，验证 B 获得新映射及三个新回复、A 映射保持、同一 store 保留、tuple 引用仍为一。native IPv4／IPv6／mapped IPv4 和已分配／未分配 alias、foreign、原始 peer 不一致及未 Ready 的正反用例通过。五类执行回归 `-race -count=3`、较宽 UDP 恢复／跨族／观测／诊断／resolve_dns race 回归及 control／config／cmd vet 通过。Astra 独立确认过宽排除的原因，修正的静态审查通过。下一轮继续相同范围的现场验收。

首轮脚本、逐包应用记录、服务端记录和可校验 API 归档位于忽略目录 `build/udp-rebuild-live-20261005/`。阶段顺序运行且使用不同客户端源端口，现场 RTT 只能描述样本，不能用来归因执行开销；延迟判断仍以此前交错本地对照为依据。

### 10 月 5 日受控现场验收完成

native peer 修正提交为 `f6b1e63d902d28fe1c3d85216934f0b54f8f1d1c`。正式依赖构建 `unstable-20261005.r1278.f6b1e63d` 已部署到 223，SHA256 为 `1eb68161de5744a19f2ad4060de829d437c2a59da23a6e559e81bb447e5868ec`；构建时源码干净，无本地依赖替换。安装前保留二进制及独立回滚脚本。Astra 静态复核通过，并独立重跑 native mapping 回归 `-race -count=3`。

第二轮仍使用原节点，native alias 排除消失，但出现 12 次 `transport_capability_missing`，attempt／commit 均为零。安全检查确认原节点使用 `2022-blake3-aes-256-gcm`，其实际 PacketConn 尚未声明恢复所需能力。服务端确认所有请求到达，失败按预期保守拒绝；没有按协议名称绕过检查。证据保存在 `build/udp-rebuild-live-20261005-r2/`。

第三轮在自管 `.5` 临时建立 `aes-128-gcm` relay，仅绑定 WireGuard `10.8.1.5:46680`，设置 900 秒期限；生产 shadowsocks-rust 服务保持。独立随机凭据仅通过 SSH 在两端私有文件中传递，没有进入本地证据、日志或提交。应用服务、220 客户端、精确路由范围及故障注入方式与前两轮相同；223 无须再次更换二进制。off 35 秒，observe 和 enforce 各 110 秒，阶段使用不同客户端源端口。

| 阶段 | 健康 A 回复／发送 | B 回复／发送 | B 服务端主动丢回复 | 映射与执行 |
| --- | ---: | ---: | ---: | --- |
| off 正常基线 | 175／175 | 175／175 | 0 | A、B 共用原映射，新增尝试 0 |
| observe 故障 | 550／550 | 100／550 | 450 | 记录候选，映射保持，新增尝试 0 |
| enforce 故障 | 550／550 | 379／550 | 171 | B 新映射收到 279 次回复；一次尝试、提交、恢复 |

enforce 中 A 始终使用 `185.248.186.73:7291`；B 序号 0–99 经原映射回复，100–270 被服务端规则丢弃，271–549 经新映射 `185.248.186.73:6696` 回复。服务端逐包核对所有 550 个请求均到达，每 peer 序号完整且有序，无重复、重放或无法解释的丢回复。A 无缺失，未被 B 的重建改变映射。

执行候选包含六个完整 5 秒窗口，每窗 25 次本地完成发送、零回复，历史回复 100 次，回复干旱 34.177 秒。同一 B peer 的 lineage 824 从旧 runtime 824／revision 1 转至新 runtime 862／revision 2；journal 序号 40 的 committed 与序号 41 的 recovered 对应，提交后 623 毫秒取得三个新关联回复。客户端最后一个旧回复到第一个新回复间隔 34.400 秒，包含策略要求的 30 秒干旱和扫描等待，不表示即时恢复。

本轮预算增量为 peer、组及进程各一次尝试，attempt／commit／recovered 各新增一；没有 claim retry、发布等待超时或晚回复。第二轮累计的 `transport_capability_missing: 12` 保持不变，不能算成本轮新排除。读取工具及分析器按进程、观察代、客户端源端口和事件序号核对；第三轮 57 份采样的 manifest、哈希及来源均通过，无归档缺口或读取错误。`live-summary.json` 将应用序号、映射、服务端故障与实际 commit／recovered 交叉核对，结果为通过。

#### 延迟与观测结果

| 阶段 | 健康 A RTT p50／p95／p99，ms | B 有效回复 RTT p50／p95／p99，ms |
| --- | ---: | ---: |
| off | 53.626／54.161／57.671 | 53.569／54.111／57.117 |
| observe | 53.638／54.346／55.999 | 53.633／54.589／55.293 |
| enforce | 53.634／54.267／55.028 | 53.596／54.204／54.996 |

这是顺序运行的公网 RTT 样本，不能隔离 dae 的处理开销或证明生产尾延迟；B 的统计只包含有效回复，不包含故障等待。处理开销判断继续依据上面的交错本地对照，未发现显著稳态退化；native peer 修正只改候选资格及准备路径，没有增加每包检查。健康 A 的收发和映射隔离获得本轮现场证据。

enforce 阶段归档 9 个 capture relay 窗口，`offload_unmeasured`、`invalid_window`、`queue_dropped` 均为零。恢复后采样再归档 5 个可比较窗口，节点计数没有小于本流；节点包含并发流，正差不能当成本流计数偏差。自然 splice 流没有独立本流字节参考，本轮仍不能计算其精确偏差。主质量组 Heart_Proxy、Cherry、Heart_YouTuBe 保持 observe；短窗口内质量切换和站点恢复预算均为零，Cherry 出现一次 `below_sampling_threshold`。reload 改变质量观察代，不能把本轮零计数外推为长期触发频率。

#### 恢复、审查与证据

测试结束已恢复 UDP 自动重建 off，移除 `U2_Live` 作用域；config、local 及 routing 文件哈希与安装作用域前基线相同，网络、init、生产节点和组保持。223 PID 9150、版本及正式二进制哈希一致，HTTPS 检查通过。`.5` 临时 relay／应用服务、监听及私有凭据均已清理，生产 shadowsocks-rust 仍运行。

恢复后采集任务运行 60 秒，获得 12 份有效采样，首末覆盖 55.541 秒；全部 mode off、observation null，历史 attempt／commit／recovered 始终各一，tombstone 的 live owners 为零。服务持续 running，FD 从 304 降至 288，UDP sessions 从 38 降至 33，RSS 约 223.64–223.69 MB。采集丢弃及窗口错误计数保持零。短样本未见新增执行或资源增长迹象，不能替代长期内存和负载验收。

Astra 独立读取第三轮逐包应用／服务端记录、57 份阶段归档、恢复文件及 12 份恢复后采样，确认健康 peer 隔离、三个新关联回复、事件与预算、清理及 off 恢复均成立，无待修发现。验收结论限定为受控 SS AEAD 请求／应答；SS2022 和 CS2 仍不具执行资格。

安全证据、脚本和分析位于忽略目录 `build/udp-rebuild-live-20261005-r3/`，主要文件为 `live-summary.json`、`restore-verification.json`、`server-cleanup-verification.json`、`relay-cleanup.json` 和 `after-restore/analysis.json`。发布 manifest 位于 `build/udp-rebuild-native-20261005/manifest.json`。223 二进制回退副本与脚本保留在 `/root/kdae-udp-rebuild-live-r2-20261005/`，测试配置恢复脚本保留在 `/root/kdae-udp-rebuild-live-r3-20261005/`。

222 当前磁盘约余 2.1 GiB。旧 benchmark／诊断二进制压缩后校验；四份旧缓存归档复制至 220 的 `/root/kdae-222-cache-archives-20261005/`，校验 SHA256 后删除本地重复副本。当前正式 Go／模块缓存、现场证据和回退副本保留；转存及压缩 manifest 分别在 `build/cache-archives/offloaded-20261005.json`、`build/udp-rebuild-20261005/compressed-artifacts.json`。

后续仍需按实际 SS2022 的独立关联和发送完成语义补齐能力声明、互操作及隔离验收；CS2 先补完整游戏阶段与暂停／keepalive 的回复义务证据，再决定是否可建立精确执行范围。保持生产 UDP 重建 off、主要质量组 observe；本轮受控通过不自动放行其他传输或业务。

### resolve_dns 自动重建扩展设计（10 月 5 日）

[扩展方案](upstream-followup-plan-20261002.md#resolve_dns-自动重建扩展设计10-月-5-日)已按现有实现与历史提交复核。核心是保留客户端 original key／回复地址，发送与证据使用已固定的实际 peer；重建不重新解析业务域名，外层代理 hop 的解析另计。首批限同族目标专用 numeric pin，QUIC 身份保护作为放行前置条件，DNS FakeIP 等映射引用保护完成后再加入。

当前需要同时修正 slot.original、prepared 的 pool key、detached／retained 查找、普通后代的 peer 安装及 DNS state 交接。准备取消必须不删旧恢复记录；成功提交后，旧 retire／save／discard 不能覆盖新 pin，旧 Close 也不能重新写入已撤销身份的 QUIC／domain memory。方案明确了身份快照、prepared／current／superseded 状态、store／Once 同步边界、最终预算校验及发布顺序、Initial 变化、普通错误／NAT／行政关闭／reload 规则、诊断、性能及真实 DNS 变化验收。

历史 `80e1f858` 的原地址回包、`9fabeeaf` 的固定目标及恢复边界、暂停保护、真实 peer 归属、进程预算及三次新回复规则继续保留。实施分 U2-R1 至 U2-R5，代码与对应回归一起交付；先取得 SS AEAD／SOCKS5 本地证据与 Astra 独立审查，再做 220→223 的有界现场验收。

Astra 独立设计审查要求明确三项边界：store 锁内不能调用或等待 Once.Do；旧 Close／retire 的 domain／QUIC memory 晚写需要身份同步保护；off／reload 不能释放仍收发或排空的 FakeIP owner 引用。修订后再次静态复核通过，未发现阻碍实施的残留歧义。业务 DNS 与代理 hop 解析分开计数，未知 Initial 不直接销毁活跃关联，新身份沿用有界墓碑预算。审查没有运行执行测试，不代表扩展已经实现或验收。

`113b045a` 记录上述设计。后续本地实施如下，223 配置及二进制仍保持原版本。SS2022 能力声明、CS2 回复义务、跨族 alias 和既有 QUIC strict 超时各自仍有独立门槛。

#### 本地实现与回归

U2-R1 至 R3 已实现，R4 的诊断及本地性能检查已加入：

- 原始目标 O 用于 pool、override、retained、BPF tuple 和客户端回包；实际固定目标 P 用于发送、证据、精确作用域及 peer claim。自动准备沿用 O→P、原节点及 egress 绑定，不重新解析业务域名；普通错误重试可以重选节点，仅在已有身份及路由条件满足时继承固定目标与 lineage。
- scoped enforce 的 DNS 流持有不可变目标快照和共享业务身份；DNS state 分别有 prepared、current、superseded、closed 状态。准备取消不删除旧记录，预算、token 和所有权按原发布临界区交接。store 锁内不调用或等待 Once。
- 新 QUIC Initial 的身份检查位于 routing cache、override、prefetch 和 retained 使用前。同 Initial 维持固定目标，未知 Initial 冻结自动执行，明确不同身份撤销旧目标及记忆，再进入当前策略。身份变化继续消耗有界墓碑预算。
- 普通 write-error 清理保留有界退休 pin，覆盖后续拨号失败及负缓存到期后的重试；行政 Close 和 NAT 到期结束 pin。scoped Close 在生命周期及身份锁内完成最后合法记忆、关闭 token，然后公布 dead；旧晚回调不能覆盖新流的 domain／QUIC memory。提前移出 pool 的 owner 通过非阻塞所有权检查拒绝写记忆。
- 诊断增加可选 `original_target`、`target_kind`、`dns_pin_owner_id`、`flow_identity_revision` 和 `pin_inherited`。归档分析器仅在 DNS 继承字段完整且一致时确认新恢复链；旧归档缺字段会明确记录缺失，不推断继承。

真实本地 SS AEAD、SOCKS5 fixture 验证 O≠P、固定目标与 DNS 变化、原地址回复、健康 peer 隔离、无 payload 重放、预算提交和三个新关联回复。IPv6 客户端／应用目标经 IPv4 代理的交接也通过；“同地址族”限制针对原始目标与固定应用目标，外层代理可使用另一地址族。QUIC 身份用例使用明确的 Initial 元数据，应用包为真实 UDP echo，不构成 CS2 或实际 H3 回复义务的证明。

保护回归覆盖 IPv4／IPv6／mapped IPv4、FakeIP／跨族／端口及 mapping store 排除，准备期新回复／reload／身份变化取消，store／Once 竞争、prepared Close 与发布交错、退休身份变更、行政关闭和移出 pool 后的晚记忆。正式环境为持久 Go 缓存、`GOWORK=off`、`GOEXPERIMENT=heapminimum512kib`、`GOMAXPROCS=2`、`GOFLAGS=-mod=readonly`、`-tags trace`。定向 control race 集通过（8.104 秒），control／cmd vet 通过，归档分析器 15 项 Python 测试通过；没有据此宣称 control 全量或既有 QUIC strict 测试通过。

#### 性能对照与审查

正式依赖不变，与 `113b045a` 比较。初测发现首次建连增加约 2–3 微秒，CPU 采样定位为 create frame 扩大导致深层选路多一次栈扩容。已将普通后代身份处理移到仅传指针的函数，create frame 恢复到基线 `0x4a0`；入口栈和已有 endpoint 热字段布局也保留。

固定 CPU 0、1，同工具链及配置进行 5 轮交替首包、3 轮稳态对照：

| 路径 | 基线中位 ns/op | 当前中位 ns/op | 变化 |
| --- | ---: | ---: | ---: |
| 完整 QUIC Initial，1 个生产者 | 16699 | 16251 | -2.68% |
| 完整 QUIC Initial，8 个生产者 | 14199 | 13928 | -1.91% |
| 稳态 off | 116.8 | 114.4 | -2.05% |
| 稳态 observe | 271.8 | 271.0 | -0.29% |
| 稳态 scoped enforce | 327.7 | 329.9 | +0.67% |
| 新增 pinned enforce | 无对应基线 | 340.3 | 0 B/op、0 allocs/op |

原有三条稳态路径均为 0 B/op、0 allocs/op；首包分配次数基线与当前相同。这批本地样本未再现首包平均回退，稳态均值未达到 5% 回退门槛。早期基线与当前 relay fixture 不同，相关真实代理 p99 对照存在混杂，已排除出放行依据。

随后使用相同 relay fixture 和相同临时测量代码，基线生产源码仍取 `113b045a`，固定 CPU、7 轮交替，每协议／模式／轮预热 2000 包、测量 20000 包。以下为各轮写入 p99 的中位数，回复等待在测量区间外：

| 真实代理路径 | 基线 p99，ns | 当前 p99，ns | 变化 |
| --- | ---: | ---: | ---: |
| SS AEAD off | 18646 | 18245 | -2.15% |
| SS AEAD observe | 19387 | 17864 | -7.86% |
| SS AEAD enforce | 17955 | 18565 | +3.40% |
| SOCKS5 off | 14919 | 14068 | -5.70% |
| SOCKS5 observe | 15339 | 15119 | -1.43% |
| SOCKS5 enforce | 14999 | 12004 | -19.97% |

这组统一 fixture 的 p50／p95／p99 中位数没有达到 5% 回退门槛，各轮仍有 syscall 尾延迟波动。只用于本地处理开销检查，不代表生产尾延迟或公网 RTT 保证。共同 fixture／测量源、基线 commit、候选生产文件、二进制校验值及交替顺序均记录在 `performance-summary.json`。

Astra 独立审查及复核了早于 routing cache 的身份边界、退休身份撤销、普通错误清理、prepared Close 发布交错，以及旧记忆的关闭同步。发现均已修复；独立定向 race 通过（3.269 秒），最后两项关闭记忆回归由主代理追加执行通过，Astra 静态复核通过。Astra 还独立重算首包、稳态及统一 fixture 的 7 轮真实代理日志，验证生产源码、fixture、测量源和二进制校验值及轮次顺序；与表中数值一致。审查和本地性能检查不替代现场 DNS 验收。

本地安全证据在忽略目录 `build/udp-resolve-rebuild-20261005/`，包括构建 overlay、基线／候选测试二进制、CPU profile、交替原始日志、`performance-summary.json` 及最终 race／vet／Python 结果。R4 的 220→223 有界 DNS 验收仍待完成，结束须恢复 off；R5 的 DNS FakeIP 映射引用保护尚未实施。当前仍不放行 SS2022、SS stream、Hysteria2、TUIC 或 CS2 unknown。

### 跨族固定目标自动重建（10 月 5 日讨论，10 月 9 日记录）

本节记录同族 `resolve_dns` 落地之后，关于不同地址族的全部交流和最终方案。此前同族设计、通俗说明和“同意实施”已写在上面；本地实现为 `c55bd62c`。这里的地址族指客户端原始目标与 DNS 固定应用目标，不是代理入口。

#### 交流

1. 10 月 5 日 09:55，问为什么自动重建排除 `resolve_dns`。答复：第一版还没有交接客户端原始地址、实际固定目标和连接身份；直接放行会让后续包找不到新关联、回包源改变或丢失固定目标。普通发送错误已有保留固定目标的恢复；缺的是持续发送但没有回复时的自动重建。节点仅仅配置了 `resolve_dns`，不会因此排除所有 UDP。
2. 10:03，要求设计。10:13 写出方案：原始目标 O 负责查找和回包，固定目标 P 负责发送和证据；重建不重新解析业务域名。准备失败保留旧关联，提交前复查身份、证据和预算。首批只做同地址族、目标专用的数字固定 IP。FakeIP 等映射引用保护完成后再加入。Astra 设计审查通过，记录为 `113b045a`，当时还没有改执行代码。
3. 10:18，要求用通俗说法对照原来和新方案。答复：原来这类连接会被跳过；新方案在无回复证据足够后新建 UDP 通道，仍走原节点和原来的服务器，收到新通道的有效回复才算恢复，准备失败则留下旧通道。DNS 后来推荐另一台服务器，也不改正在使用的目标。10:19 同意该方案。
4. 10:21，问为什么必须同地址族。11:22 答复：同地址族指 O 和 P 同为 IPv4 或同为 IPv6。自动重建要继承旧连接的回包映射；跨族还要移交地址转换和映射引用，当时尚未验收，所以第一版先收窄。代理节点可以用另一地址族，IPv6 业务经 IPv4 代理已经测过。此时同族实现、Astra 审查和本地延迟检查已经完成，223 的 DNS 现场验收仍待做。
5. 11:40，问不同地址族有没有方案。11:44 给出两步方案，并建议先做第一步。11:47 同意。
6. 同意后开始实现第一步。11:48 确认固定目标跨族可以复用现有原地址回包，不必分配虚拟地址；证据按真实目标归属，需要映射保护的流继续排除。11:51 报告两个方向的真实 Shadowsocks、SOCKS5 重建已初步通过，固定目标和客户端回包地址保持，健康流未受影响，没有分配虚拟地址；当时还在补重试、取消和延迟，诊断已加入原始地址族与实际目标地址族。
7. 11:54 这一轮因用量上限中断，没有完成延迟对照和 Astra 审查。19:11 要求继续，但指定模型不可用，没有新的代码或结论。
8. 10 月 9 日复核未提交工作区。定向测试通过，包括两个方向、无映射／可写／只读映射视图、DNS 变化、重试、重载和准备期取消。审查没有发现会错误恢复、把跨族地址交给客户端，或把不一致 pin 判成匹配的问题。回包先恢复成原始目标，客户端与该地址同族时不会分配 alias；干旱和三次新回复仍记在实际 peer 上。跨族用例里的映射计数原先没有直接调用生产回包函数；随后补了 `TestUDPRebuildResolveDNSCrossFamilyReplyKeepsOriginal`，按生产顺序先 `canonicalReplyFrom` 再 `forwardUdpEndpointReplyToClient`，两个方向、可写和只读视图都确认客户端看到 A、映射条数为 0、没有丢包；同一用例把未经恢复的 B 直接送入时，可写视图会分配替身、只读视图会丢包，证明该顺序是这条保证的前提。

#### 最终方案

第一步现在做，第二步以后单独做。

**第一步：固定目标的跨族 `resolve_dns`。** 客户端看到的原始目标是 A，`resolve_dns` 固定的实际目标是 B，A 和 B 可以一个是 IPv4、一个是 IPv6。自动重建继续连接原来的 B，DNS 后来给出别的地址也不换目标。回包对客户端仍显示 A，地址和端口保持不变。是否恢复，只看来自真实目标 B 的回复。两个方向都要支持。不分配虚拟地址。映射池检查留在建流和重建资格判断，不放进每包路径。无回复窗口、恢复预算和三次新关联回复继续沿用。验收要覆盖迟到的旧回复、重载、取消和 DNS 变化，并用此前 5% 的稳态延迟门槛做对照，完成后由 Astra 独立审查。

客户端和原始目标在去掉 IPv4-mapped 之后仍须同族，端口必须相同，实际目标必须等于已固定的 peer。映射 store 已打开时，原始地址或实际 peer 落在映射池里仍拒绝。DNS FakeIP、只有域名而没有数字固定目标、共享关联上的目标歧义、batch，以及非 DNS 的 native foreign peer，继续排除。

诊断在原有 pin 字段之外增加可选的 `original_family` 和 `actual_peer_family`。归档分析器在这些字段出现时核对标签与地址，并把 IPv4-mapped 视为 IPv4；旧归档两边都没有这些字段时，仍按原有 pin 字段确认，不把缺字段当成跨族失败。

**第二步：使用跨族虚拟地址的流。** 新旧连接沿用同一条虚拟地址到真实地址的映射；映射失效或身份变化就取消本次重建；迟到的旧回包仍用原映射。虚拟地址不回收，也不重新分配给其他目标。DNS FakeIP 仍是另一套映射，按原 R5 单独补引用保护，不并入第一步。

#### 当前进度

第一步的资格判断、两个方向的交接测试、重试与取消，以及两个地址族字段已经在未提交工作区。功能测试已通过。

10 月 9 日做了稳态写入延迟对照。基线是 `c55bd62c`，当前是未提交工作区。两边都用 Go 1.27.0、`GOWORK=off`、`GOEXPERIMENT=heapminimum512kib`、`GOMAXPROCS=2`、`-tags dae_stub_ebpf`，`taskset -c 0,1`。7 轮交错，奇数轮先基线，偶数轮先当前；每轮 `benchtime=1s`。这是 mock `WriteTo`，衡量已有 endpoint 的持续转发，不包含建流首包，也不代表真实代理或公网 RTT。原始输出在忽略目录 `build/udp-cross-family-latency/`。

| 路径 | 基线中位 ns/op | 当前中位 ns/op | 变化 |
| --- | ---: | ---: | ---: |
| 稳态 off | 114.9 | 115.8 | +0.78% |
| 稳态 observe | 275.8 | 276.6 | +0.29% |
| 限定范围 enforce | 328.9 | 333.1 | +1.28% |
| 同族 pinned enforce | 342.1 | 348.8 | +1.96% |

四条已有路径都是 0 B/op、0 allocs/op，没有达到 5% 回退门槛。

跨族路径没有对应基线，在当前二进制上与同族 pinned 比较，同样是 0 B/op、0 allocs/op：

| 路径 | 中位 ns/op | 相对同族对照 |
| --- | ---: | ---: |
| 跨族 v6→v4 | 350.0 | 比同族 IPv4 pinned 高 0.34% |
| 同族 IPv6 pinned | 380.7 | 另 7 轮，比同轮 IPv4 pinned 高 11.51% |
| 跨族 v4→v6 | 377.3 | 比同轮同族 IPv6 低 0.89% |

v4→v6 与同族 IPv6 的逐轮比值中位数是 1.002。多出来的时间来自既有写入路径处理 IPv6 目标地址，不是跨族资格判断。

第二步已在未提交工作区实现。已经存在的替身才重建：客户端可见地址 A，真实 peer P，`decode(A)==P`，不新分配。目标专用和 FullCone、两个方向、只读空缓存都测过。store 关闭或换成另一张表会取消，原因是 `alias_mapping_changed`；这步检查在 prepare 成功之后、fence 之前。FullCone 的旧 endpoint 不结束，其他 peer 继续用它。按 P 的表和按 A 的索引放在同一个指针后面，安装时一次发布，端点结构不为此增加字段。提交后按 A 查旧 endpoint 能找到同一条 slot：旧端点拒绝再登记 (Src, A) 的连接记录、路由缓存和重载保留流，后继自己仍接受 A。归档事件用 `target_kind=peer_alias`，并填写 `original_target`、`original_family`、`actual_peer_family`，不填 DNS pin 字段。分析器对这种事件单独核对 A 与 P，原有 pin 确认不变。

FullCone 新通道的 pool key 目的地址是 A，回包由 `canonicalReplyFrom` 显示 A。旧通道迟到回包仍经 store 的 `reply` 译回 A。

同日在第二步落地后测过一次延迟（原始输出在 `build/udp-alias-latency/`）。那次测的是按 A 的索引还单独占一个指针的版本；该版本让 `UdpEndpoint` 达到 1320 字节，触发内存布局守卫。随后把按 P 的表和按 A 的索引合到同一个 `rebuildPeers` 指针后面，一次 CAS 同时发布，每包查找仍是一次原子 load。下面是合并后重测的结果，取代前一次。

基线仍是 `c55bd62c`，在临时 worktree 中构建；当前是未提交工作区。条件与上表相同：Go 1.27.0、`GOWORK=off`、`GOEXPERIMENT=heapminimum512kib`、`GOMAXPROCS=2`、`-tags dae_stub_ebpf`、`taskset -c 0,1`，7 轮交错，奇数轮先基线，偶数轮先当前，每轮 `benchtime=1s`。每轮对照之后，再用当前二进制单独跑一次新增路径。原始输出、`summary.json` 和两个测试二进制在忽略目录 `build/udp-alias-latency-r2/`；二进制 SHA-256：基线 `3e70d414…5345fcd4`，当前 `4492dd00…caf3c57`。

| 路径 | 基线中位 ns/op | 当前中位 ns/op | 变化 |
| --- | ---: | ---: | ---: |
| 稳态 off | 115.2 | 115.9 | +0.61% |
| 稳态 observe | 272.6 | 276.9 | +1.58% |
| 限定范围 enforce | 331.5 | 332.6 | +0.33% |
| 同族 pinned enforce | 345.2 | 345.7 | +0.14% |

四条已有路径都是 0 B/op、0 allocs/op，没有达到 5% 回退门槛。

新增路径没有对应基线，在当前二进制上与同轮的同族 pinned 对照比较，都是 0 B/op、0 allocs/op：

| 路径 | 中位 ns/op | 逐轮比值中位（相对同族 IPv4 pinned） | 逐轮比值中位（相对同族 IPv6 pinned） |
| --- | ---: | ---: | ---: |
| 同族 IPv4 pinned | 346.0 | 1.000 | 0.916 |
| 同族 IPv6 pinned | 374.3 | 1.092 | 1.000 |
| 跨族 pinned v4→v6 | 377.4 | 1.096 | 1.004 |
| 跨族 pinned v6→v4 | 347.3 | 1.009 | 0.921 |
| FullCone 替身 | 514.3 | 1.483 | 1.358 |

跨族 pinned 与目的地址同族的 pinned 基本持平，和 10 月 9 日上一轮结论一致。FullCone 替身比 pinned 慢约 36%～48%，计时区间与前一次相同：已有 dial 字符串上的 `TrackUdpConnStateTuplePair` 加写入，写入里的 `droughtPeer` 会 decode 真实 peer，连接记录查找会读按 A 的索引；拨号字符串的格式化在计时之外。目前没有同族 FullCone 的对照基准，这部分差距不能全部归因于替身，也不构成对已有路径的回退。前一次（合并前）的中位为 525.8 ns/op。

这批已提交为 `92a44aff`。10 月 9 日决定取消 Astra 独立审查，本地验证以上述测试与延迟对照为准。DNS FakeIP 引用保护见下一节。现场验收见“10 月 9 日现场验收”。

### U2-R5 DNS FakeIP 引用保护实现（10 月 9 日）

跨族固定目标与替身重建先提交为 `92a44aff`，随后按[计划](upstream-followup-plan-20261002.md#u2-r5-dns-fakeip-引用保护10-月-9-日)实现 R5。引用上限取 `min(maxLive, 1024)`，只保护进入重建的流，两点均已确认。

#### 实现

- **store 侧**（`fakeip_lease.go`）：`AcquireLease(addr, name)` 在写锁下确认 X 仍属于 D（墓碑也算），计数加一并返回带纪元的句柄；`Release` 用原子交换保证只释放一次，纪元不符时不动新表。`expireTombstonesLocked` 跳过有引用的墓碑，这类墓碑既不到期释放，也不计入超上限的释放候选。`resetMemoryLocked` 递增纪元并清空引用表。引用不写 WAL、不进快照。
- **身份**：`DialOption` 增加 `FakeIPName`、`FakeIPStore`，在 `handlePktOwned` 由建流时的 `fakeDomain` 和当前 FakeIP store 填入。固定目标身份记录二者；不使用 `SniffedDomain`。
- **资格**：`pinnedDNSExclusion` 对 FakeIP 固定目标改为只读检查 `LookBack(X)==D`，失败记 `resolve_dns_mapping_changed`；没有名字或 store 未就绪仍记 `resolve_dns_fakeip_unleased`。
- **准备与提交**：拨号前取引用，失败按原因记 `resolve_dns_mapping_changed`、`resolve_dns_fakeip_lease_full` 或 `resolve_dns_fakeip_unleased`，不拨号。引用在后继创建后交给它的 `udpResolveDNSState`，之后任何失败都由后继关闭释放。fence 之前复核句柄仍有效（同一纪元、store 未关闭），失败记 `resolve_dns_mapping_changed`。
- **普通后代**：`inheritPinnedRebuildTarget` 允许 FakeIP 后代，前提是 store 与名字一致且自己取得引用；否则按新流处理。
- **释放**：`closePreservingFlowIdentity` 的一次性关闭里释放，覆盖行政关闭、NAT 到期、写入失败、prepared 取消和提交后旧端点结束。原始流不取引用。
- **诊断**：`/v1/udp-recovery` 增加 `fakeip_leases`（`active`、`retained_tombstones`、`limit`）。分析器沿用 DNS pin 确认规则，增加 FakeIP 用例；FakeIP 提交不能由 native 回复确认。

`UdpEndpoint` 不增加字段，每包路径不变。

#### 测试

store 单测覆盖：一条活跃记录、宽限期为零时连续分配 32 个名字，被引用的地址不被分出且仍映射回原名；池前缀移走再移回后同样不被改派；名字不符、地址未分配、引用上限、重复释放；内存重置后旧句柄失效且不影响新表计数；关闭后不发新引用。临时去掉墓碑保护后，前两项失败。

端到端（真实 SS AEAD 与 SOCKS5）复用固定目标的完整用例：DNS 变化、旧发送方跟随、三次新回复、关闭观察器、普通后代；另测引用生命周期（提交后计数为 1，连续分配不改派 X，回包源保持 X，关闭后计数归零、墓碑按期释放）、准备前映射已变、引用已满时不拨号、准备期取消三种原因后计数归零、准备后 store 重置时在 fence 前取消。以下四种临时破坏各至少被一项捕获：准备不取引用、关闭不释放、提交不复核、普通后代不持有引用。

整个 `./control/` 的 `-race` 通过，`control`／`cmd` vet 干净，内存布局守卫未改，分析器 18 项通过。

#### 延迟

基线 `92a44aff`，在临时 worktree 中构建；当前是未提交工作区。条件同前：Go 1.27.0、`GOWORK=off`、`GOEXPERIMENT=heapminimum512kib`、`GOMAXPROCS=2`、`-tags dae_stub_ebpf`、`taskset -c 0,1`，7 轮交错，奇数轮先基线。稳态每轮 `benchtime=1s`；首包沿用 R4 的 `BenchmarkQuicInitialEndToEnd`，每轮 `20000x`，覆盖入口分发、`handlePktOwned`、代理拨号、首包写入和端点创建。原始输出、`summary.json` 和测试二进制在忽略目录 `build/udp-fakeip-lease-latency/`；SHA-256：基线 `9732afb6…e52471b2`，当前 `40ed2931…ba225fc`。

**首包对照发现并修正了一处每包分配。** 第一次首包对照中，当前版本每次多 1 次分配（p=1 由 73 到 74，p=8 由 72 到 73）。原因是建流闭包直接引用了 `fakeDomain`，而它在 `handlePktOwned` 里被重新赋值过，Go 只能按引用捕获，逃逸分析显示 `udp.go: moved to heap: fakeDomain`。这个分配发生在每次进入 `handlePktOwned` 时，即每个入口包都会多一次，不只是首包；稳态基准直接调用 `WriteTo`，测不到。修正为在闭包前复制成不再赋值的 `fakeIPName`，按值捕获；之后 `udp.go` 的逃逸条数与基线相同（11 条）。修正前的二进制和输出移到 `superseded/`。下表是修正后的结果。

| 路径 | 基线中位 ns/op | 当前中位 ns/op | 变化 |
| --- | ---: | ---: | ---: |
| 首包 p=1 | 16936 | 17140 | +1.20% |
| 首包 p=8 | 14674 | 14500 | -1.19% |
| 稳态 off | 115.3 | 115.1 | -0.17% |
| 稳态 observe | 274.6 | 274.1 | -0.18% |
| 限定范围 enforce | 332.8 | 330.9 | -0.57% |
| 同族 pinned enforce | 342.1 | 354.6 | +3.65% |
| 跨族 pinned v4→v6 | 374.3 | 377.3 | +0.80% |
| 跨族 pinned v6→v4 | 343.2 | 343.2 | +0.00% |
| FullCone 替身 | 510.9 | 506.8 | -0.80% |

稳态全部 0 B/op、0 allocs/op。首包 p=8 各轮都是 72 次分配，与基线相同；p=1 个别轮显示 74，字节中位多约 90 B。用 `memprofilerate=1` 跑 100000 次比较分配 profile，两边都是每次 56 次分配，差异只在嗅探池的少量噪声（总量 0.44%，当前更少），入口和建流路径没有新的分配点。

同族 pinned 的 +3.65% 各轮一致（比值 1.02～1.07），但没有达到 5% 门槛，判断为代码布局效应：该基准经过的源码在修正前后完全相同；把基线、修正前、修正后三个二进制交替各跑 5 轮，修正前与基线持平（中位 345.7 对 344.1），修正后为 360.7。`objdump` 显示 `writeTo`、`writeToRebuildPeer`、`udpReplyDroughtFlow.write`、`observeDroughtWrite` 的指令完全一致，只是整体前移 32 字节，从 64 字节对齐变为 32 字节对齐。

#### 待办

已提交为 `442aa222`。10 月 9 日决定取消 Astra 独立审查，本地验证以上述测试与延迟对照为准。现场验收见下一节。

### 10 月 9 日现场验收

R4 的 220→223 现场验收，与 `92a44aff`（跨族固定目标、替身重建）和 `442aa222`（FakeIP 引用）的现场验收一并完成。Astra 独立审查已取消。

#### 部署与范围

223 由 `f6b1e63d`（`1eb68161…`）升级为 `4ec20f5d`（`unstable-20261009.r1284.4ec20f5d`，SHA-256 `a1e4563f…0154bb1`）。安装前用新二进制校验现有配置通过；`push223-dae.sh` 校验 SHA、留存 `/usr/bin/dae.bak.202610091825`，只重启一次。之后 220 访问正常，`/v1/udp-recovery` 出现 `fakeip_leases` 字段。

链路沿用 10 月 5 日的方式：220 → 223 → 10.8.1.5 上的临时 SS AEAD 中继 → 同机自管请求／回复服务（185.248.186.73，IPv6 2407:cdc0:d002::1961）。每个场景单独准备：223 上备份配置、20～25 分钟看门狗自动还原，只对 220 与测试端口生效，作用域为精确 client、group、实际 peer 与 `request_reply`。每个场景依次 off 35 秒、observe 110 秒、enforce 110 秒，结束还原 off。客户端每 0.2 秒向健康的 A 和受测的 B 各发一个请求；服务在 observe／enforce 阶段从 B 的第 100 个请求起丢弃来自旧中继映射的请求，新关联换了源端口后恢复回复。测试域名用 sslip.io 公共通配：`185-248-186-73.sslip.io` 只有 A，`2407-cdc0-d002--1961.sslip.io` 只有 AAAA。节点链接带 `resolve_dns=8.8.8.8`。

#### 场景与结果

| 场景 | 客户端原始地址 | 实际目标 | `target_kind` | enforce 阶段 B（发／收） | 回复中断 |
| --- | --- | --- | --- | ---: | ---: |
| FakeIP 同族固定目标（R4＋R5） | FakeIP `28.0.22.240:46672` | `185.248.186.73:46672` | `resolve_dns_fakeip` | 550／354 | 39.4 秒 |
| FullCone 替身 | 替身 `198.19.13.237:46674` | `[2407:cdc0:d002::1961]:46674` | `peer_alias` | 550／379 | 34.4 秒 |
| QUIC SNI native 固定目标（R4） | `185.248.186.73:8443` | `185.248.186.73:8443` | `resolve_dns_native` | 550／381 | 34.0 秒 |
| QUIC SNI 跨族固定目标 | `185.248.186.73:8443` | `[2407:cdc0:d002::1961]:8443` | `resolve_dns_native` | 550／357 | 38.8 秒 |

四个场景的共同结果：

- 健康的 A 在所有阶段 100% 回复，始终只有一个映射。
- observe 不重建：B 只收到前 100 个回复。
- enforce 恰好一次开始、提交和恢复（第三个新关联回复后才记 recovered）；B 的新映射源端口不同，客户端看到的回包源始终是原始地址（FakeIP、替身或原 IPv4）。
- 归档无缺口、无错误，候选证据校验通过；服务端核对无丢失、重放、重复或乱序。
- 提交记录的原始地址、实际目标与两个地址族均与上表一致；跨族场景记为 ipv4／ipv6。

场景说明：

- **FakeIP**：220 经 dae DNS 拿到 FakeIP，节点以 `resolve_dns` 固定 IPv4。提交后后继持有 1 个 FakeIP 引用；流结束后引用数回到 0。
- **FullCone 替身**：220 先向 A 的 IPv4 发介绍请求，服务从 IPv6 套接字向中继关联端口回包。中继出站套接字为双栈，回包经 dae 映射为 198.19.x 替身；220 之后向替身收发，A 与 B 共用同一个 FullCone 端点，只重建 B。
- **QUIC SNI**：dae 只嗅探 443／8443，B 用 8443。客户端在同一四元组上先发 quic-go 生成的真实 Initial（两包，ClientHello 带后量子密钥交换），生成器当场用 dae 的嗅探器核对 SNI；之后发普通请求／回复数据报。跨族场景中域名只有 AAAA，`resolve_dns` 在 A 查询无结果后用 AAAA 固定到 IPv6，客户端仍看到 IPv4 原始地址。

#### 还原

三个试验的 `config.dae`、`local.dae`、`routing.dae` 与试验前副本逐字节一致，临时 scope 文件已删除，模式为 off，dae 进程（pid 7547）全程未重启，只做重载。未触发的看门狗已停止；223 上的临时中继凭据文件已删除；10.8.1.5 上的临时中继和服务已停止、工作目录已删除，常驻 ssserver 未受影响。223 保留 `4ec20f5d`。

#### 局限

- 顺序运行的公网 RTT 样本不能隔离 dae 处理开销；QUIC 跨族场景的 enforce 阶段 A 与 B 的 p99 同时升到约 77～80 毫秒，其余阶段约 54 毫秒。
- 只验证了 ssserver 的 SS AEAD；SS2022、Hysteria2、TUIC 与 CS2 仍不在执行范围。
- QUIC 场景只用真实 Initial 提供 SNI，之后不是完整 QUIC 会话。
- FakeIP 跨族固定目标在本环境无法自然产生：对只有 AAAA 的域名，dae 不返回 A 类型的 FakeIP。该路径只有本地测试覆盖。

脚本、客户端／服务端程序、Initial 生成器源码、归档、汇总与 `manifest.json`（含二进制与产物校验值）在忽略目录 `build/udp-field-20261009/`。

#### 生产开启 observe（10 月 9 日 19:03）

验收后决定在 223 生产上开启 observe，不开 enforce：223 现有节点为 SS2022、AnyTLS 和 Hysteria2，均不在自动重建的执行范围内，enforce 只会记排除；enforce 还要求明确的客户端、分组、peer 列表与 `request_reply` 契约。

`udp_reply_drought_mode: observe` 写在手工维护的 `/etc/dae/config.dae` 的 `global` 块（`local.dae` 由 luci-app-kdae 生成，不改）。不设客户端、分组和 peer，即观察所有客户端在所有代理分组上的 UDP；只记录证据，不重建。修改前备份为 `/etc/dae/config.dae.bak.202610091903`，校验通过后重载，dae 进程未重启。

开启后从 220 发起一条经代理的 QUIC 测试流（www.google.com:443），快照记到 2 次写入、7 次回复，分组为 `Google`，覆盖状态为 `observed`。开启前已存在的流记为 `retained_owner_not_observed`。回滚：恢复上述备份并 `dae reload`，或把该行改为 `off`。

