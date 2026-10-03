# 上游跟进实施记录

日期：2026 年 10 月 3 日。对应[设计与历史复核](upstream-followup-plan-20261002.md)。

阶段一至四的 20 个单元已落地并提交；正确性批次已部署到 223。Astra 复核修正及版本见「Astra 审查修正与再次部署」。后续补充共享节点 splice、较长自然流量窗口和 U1 的 off／observe 实现，结果见末尾。真实 CS2 SDR 对局、U2 执行及 P1 至 P3 的 A/B 仍未验收，不能将本记录理解为全部 25 个单元已经验收。

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
