# 上游跟进实施记录

日期：2026 年 10 月 3 日。对应[设计与历史复核](upstream-followup-plan-20261002.md)。

阶段一至四的 20 个单元已落地并提交；正确性批次已部署到 223。Astra 复核修正及版本见「Astra 审查修正与再次部署」。后续补充共享节点 splice、较长自然流量窗口、U1 的 off／observe 和 P1、P2 的默认关闭候选，结果见末尾。P3 完成生产调用审计，未接入的 GRO／arena 暂不移植。P1、P2 已有两种真实代理的 WAN 初测，仍不足以批准启用；真实 CS2 SDR 对局和 U2 执行待验收，不能将本记录理解为全部 25 个单元已经验收。

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

`/v1/status` 在开启时返回 `udp_reply_drought`：generation、成功写／有效回复计数、资格排除原因、peer 快照及最多 32 条候选事件。全局最多 256 个 peer，每 association 最多 8 个；60 秒空闲淘汰，候选事件每分钟最多保留 20 条。扫描只在短锁内复制 association 列表，逐流计算在锁外完成。off 不创建 ledger 或 worker，不执行每包解析和计时。

单写完成后计数；批量仅计实际完成的成功前缀，读取在 backing buffer 复用前完成。Append、短写和未完成队列不能冒充发送完成。接收先经过错误分类和首回复保护，再按原始 peer 归因；固定目标的 canonical 映射不会把陌生 peer 计为有效回复。跨地址族别名在收发两端都归一到真实 peer。

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

223 的 Game_Game 目前只匹配 9339／9449；SDR 未命中专用规则的流量依照原有规则和 Apple_Proxy 默认出口处理，不把 Game_Game 直接当作 CS2 样本。客户端未确定前保持 UDP 观测 off；已有质量 observe 和 25‰ TCP 采集延续。

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

### 223 再次观测

**09:13:37–09:16:37 UTC**，七个 30 秒快照：新增 considered 169、sampled 3，10 条 capture、25 条 evidence 均通过 validator；generation 不变、游标缺口 0。两个完成流都是 proxy userspace_accounting，offload_unmeasured **0／2**；queue_dropped **0／10**。invalid_window 增量为 0，但没有可比较窗口，两个 relay 都是 flow_ended_before_node_snapshot，因此 splice 计数偏差仍不可评估。独立 WAN fixture 流量不经过生产 daemon 的采集，不能拿它充当这批 capture 样本。

质量日志仅 below_sampling_threshold 16 次，没有严重触发、质量切换提交或恢复日志；主要 observe 组快照未见成员变化。质量切换预算不消耗，站点恢复结论限于留存日志。末尾 106 个质量条目均无速度参考；继续 observe。RSS 117.0–119.7 MiB，error／fatal／panic 为 0，既有 warning 52 条，不能称无告警。

收尾仍为 PID 24157、版本 `upstream-gather-candidate-20261003`；executable、三个配置／init 哈希与 P2 部署一致，send_redirects 均为 0，三个性能环境开关均未设置。本轮仅增加测试工具和记录，不需要重启 daemon 或改变依赖 pin。

220 收尾默认路由仍经 223，Google／Cloudflare 均返回 204；远端测试二进制和临时目录已清理。222 可用空间约 **5.0 GiB**：本地 P1／P2 发布产物压缩为各自目录下的 `dae.gz`，诊断工具为 `control.test.gz`，均先核对解压 SHA256 再移除未压缩副本；可用 `gzip -dc <文件.gz> > <还原路径>` 还原。正式 Go／模块缓存、业务证据和远端回退产物保留。
