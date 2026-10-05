# 上游修改跟进方案与历史决策复核

日期：2026 年 10 月 2 日。状态：截至 2026 年 10 月 4 日，阶段一至四的正确性修复已提交；依赖已发布并固定，UDP 实际 peer 归因和快速回复修复也已提交并部署到 223。阶段五初步实测通过，长期及定向场景仍待验证，详见[实施记录](upstream-followup-implementation-20261003.md)。

本方案覆盖本轮上游审计列出的全部修复、配置改进、UDP 恢复和性能方向，并补充跟进过程中必需的依赖验证。结论是：正确性修复大多符合当前项目的历史目标，但需要在现有 Fan-chou 依赖分支上移植。整分支替换会丢失本项目已有的取消、地址族隔离、发送观测和 BBR 修复。

需要单独处理的行为变化有三项：UDP 无回复重建、netns 全目录覆盖恢复、固定 MSS。其中 UDP 无回复重建采用新的可选观测流程；netns 优先引入准确报错和启动失败退出；固定 MSS 先作为关闭状态的可选能力评估。

## 对照基线和范围

| 仓库 | 本次对照版本 |
| --- | --- |
| 当前 dae | fdae，8eadb9ed3139b2db97e551db3b8deffe501ce7bf |
| 当前 outbound 有效依赖 | Fan-chou/outbound，8a6bd0300c3f |
| 当前 quic-go 有效依赖 | Fan-chou/quic-go，e64dc7a1252e |
| 当前 qpack 有效依赖 | olicesx/qpack，0844ed36f1cd |
| olicesx/dae | kdae，eaf59e18b8dc519cf8f67cd6155b2d8055eca9de |
| daeuniverse/dae | main，e3fee8fbc68a65167af13b685ab0b958757e20ee |
| olicesx/outbound | feat/transport-optimizations，4163e01a20a9a78d00d2839a71444658f2c3dadd |
| olicesx/quic-go | fix/audit-20260907，f49fbeaefa99b9b5b0ba05d7b8372390b68ccc31 |

版本以有效模块图中的 replace 为准。outbound 和 quic-go 的名义 require 版本不能代表实际编译版本。olicesx/dae 的 main 不是本次跟进对象。

历史复核查看了当前分支提交索引，重点复核 29 个当前分支祖先提交和 11 个有效依赖历史提交，阅读说明、补丁及当前实现。早期 Sprint 的“只做语义保持优化”“不改 fork”是当次工作的范围限制，不能推导为项目永久禁止修复行为或维护依赖。当前任务对行为修复另列验证与开关。

## 历史决策与本轮取舍

下表区分提交中的明确取舍和本方案的工程判断。“需适配”表示修复目标一致，直接覆盖实现会破坏已有约定。

| 历史证据 | 已有决策或约定 | 本轮结论 |
| --- | --- | --- |
| e8ab1d1c → 6d167837 | 先豁免 H3、DNS、直连的静默重建，随后彻底删除静默重建；会话保持身份直到 NAT 租约到期或真实 I/O 失败 | 无回复重建是新的行为扩展。持续发送也不能普遍证明应用应当回复，采用独立开关和先观测流程 |
| 6d167837；outbound f2b7538；quic-go 的 SendDatagramContext | 单个 QUIC 数据报超时或取消不应关闭共享会话 | 移植 DATAGRAM 所有权修复时保留可取消入队和独立写 deadline；不能恢复上游按 deadline 关闭会话的实现 |
| outbound 77f4a93；quic-go c501a9e0、5032a165；dae 41f4fa2f | 应用供给不足必须由发送循环明确判断；拥塞窗口已满不等于应用没有数据 | 保留 OnApplicationLimited、pacing、RTT probe 窗口及相关测试；算法切换另做实验 |
| 2eebf705、76f2a24d、c0bc4e6c；outbound 8a6bd03 | 传输隔离按组和角色生效，peer DNS 属于关联；gRPC 发送 worker 可复用 | 协议修复只改相应路径，保留作用域键、resolver 生命周期和 worker 所有权 |
| 5f3a9314、1c6e9fcd、bc906e20；outbound 204c35e | 查询结果的地址族、代理服务器的地址族和内层目的地址族分别处理 | bootstrap 修复与历史一致；只取消 DNS 服务器拨号的错误地址族限制，保留结果过滤 |
| 935c4977、59ab099f、78dc609c、a91545a6、ade99731 | TCP 半关闭要送完尾部；offload 根据已接受字节判断队列，受能力和监听代际约束 | 性能移植保留 exact splice、尾部排空、netpoll、监听所有权及所有现有核对测试 |
| 672418c5、e6ae08fb；fae7c87a | UDP 保持 FIFO、跨族别名和重载身份；批量写入实际成功后才更新时间 | 无回复计量从实际发送完成读取，不用 Append 成功代替；peer 拆分不能打乱 FIFO 或迁移别名 |
| 7afc5a81、6afbf33c、682dd9d1、53669993 | 故障分类先于处罚，健康恢复统一发布；QUIC 内层 stream-open 不充当真实 TCP RTT | DNS 分类修复符合历史；保留探测设施故障豁免、真实故障识别和集中恢复发布 |
| 53669993；会话中已确认的主动探测策略 | 连续三次慢探测才按 RTT 劣化降级；普通主动失败一次、QUIC TCP 槽沿用三次，真实 alive 检查不通立即 dead | 本轮分类和协议修复不改这些阈值；失败不能因 busy 状态被豁免 |
| 53669993、8eadb9ed | quality 默认 off；先 observe；Laya 只做影子对照；恢复预算只计成功恢复提交；TCP 与 UDP 分表 | UDP 重建使用自己的预算和日志，不能改变 TCP 钉选、质量租约或消耗站点恢复预算 |
| 6f110ba4、17069c8a、cd435873 | Mihomo 成员按声明顺序，路由保持 no-resolve 和规则顺序；坏订阅不能覆盖好缓存 | 订阅标签排序只能消除 map 随机性，不能重排显式成员；include 只合并一次，保留规则相对顺序 |
| 65fc1058 | netns 先同步卸载，再尝试 lazy 卸载，解决后续启动被残留项阻断 | 准确报错与历史一致。没有找到允许自动隐藏整个 /run/netns 的历史决策；默认采用 fail fast 是本方案判断 |
| 0b7a855a、71e192c0 | GOMAXPROCS 缺省固定 1；显式值和显式空值由用户控制 | 环境文件可加入；保留这三种状态，不自动改为多 P |
| [8 月修复约定](remediation-aug25-27.md)；[分配与验证决策 D1、D4](brainstorm/brainstorm.md) | 保留实测优化；池化必须满足所有权；超限丢包需要明确契约；性能改动要测量 | QUIC 接收环符合有界内存目标。发送帧退出池化调整了性能实现，但纠正所有权错误；必须补分配和 race 验证 |
| [状态发布审计](weak-memory-publication-audit.md) | 多字段配置、身份和预算不能靠若干独立 atomic 冒充一致快照 | 新 budget、peer 状态和模式随代际发布；锁或不可变快照先完成状态，再允许 retire |
| [Sprint 7 验证约定](sprint-7/done.md) | 普通跨仓库验证可 advisory，依赖升级采用 strict | 先修 harness 对 Fan-chou 的漏检，再允许升级；strict 的成功必须覆盖真正被编译的三个依赖 |

### 直接替换分支会造成的回退

实际对照当前 Fan-chou 分支与上游最新分支，发现上游缺少当前的 PacketWriteDeadline、ForProxyHop、作用域 resolver 及 QUIC 发送诊断接口。QUIC 上游也缺少 SendDatagramContext、DATAGRAM 合包和明确的应用供给判断。direct 接收的 FD 所有权及 netpoll 实现不同；gRPC 两边都有复用 sender，但上游没有当前发送请求的双持有者引用计数，必须核对退出和回收时序。

因此每个修复提交需要同时回答两件事：新增的错误路径是否修好，原有能力是否仍由测试覆盖。不能用“上游版本日期更新”代替这个检查。

质量回归还要保留本轮已确认的负载口径：64 条活动连接，双向合计 2 MiB/s 或每秒 16 条新连接，峰值参考上行 1 MiB/s、下行 4 MiB/s。busy／预热只暂缓负向质量证据，成功钉选和候选正向恢复仍可提交。Laya 继续使用 HTTPS、自定义 CA 和关闭环境代理的客户端；DNS 新事件维持采样先于解包，capture 关闭时不增加每连接工作。

## 跟进单元

下表保留各单元的设计和验收要求。G0、Q1 至 Q5、O1 至 O4、D1 至 D5、C1 至 C4、N1、U1 已落地；P1、P2 的默认关闭候选已实现。P1 完成 220 的隔离内核矩阵及两种真实代理的 WAN 初测；P2 完成自然前缀与受控分段对照，尚无生产启用收益证据。P3 已复核最终生产调用：新增 GRO 与 arena 没有生产入口，保留既有 QUIC GSO，暂不移植未接入的 helper。U2 完成受控 SS AEAD 请求／应答现场验收，实际业务语义及其他传输资格仍待验证。线上验收缺项见实施记录。来源对应文末的上游提交表。修复与能复现问题的测试放在同一提交；跨仓库依赖以发布版本连接。

### 验证入口和 QUIC 修复

| 单元 | 设计 | 历史关系 | 验收 |
| --- | --- | --- | --- |
| G0 有效依赖验证 | harness 按模块图识别 outbound、quic-go、qpack 的逻辑模块及实际替换仓库，支持 Fan-chou。验证目标缺失即失败 | 延续 Sprint 7 的 strict；当前脚本只匹配 olicesx，会漏掉实际 outbound、quic-go，仍可能仅测试 qpack | dry run 必须列出三个有效版本；测试覆盖 replace、镜像仓库、缺失版本及参数转发，不能默默测试部分图 |
| Q1 接收队列 | 将 slice 加 head 转为预分配环；消费时清除槽位，容量受既有上限约束；保留接收 buffer 池和诊断计数 | 内存目标一致，来源 S1 | 持续保留两个包运行 20,000 次循环，存储不增长；FIFO、满队列和关闭排空测试通过 |
| Q2 发送帧所有权 | 发送 DATAGRAM 帧和 payload 由队列及包持有，按上游方案退出发送帧池；接收池保留。审计序列化、tracer、ACK 和关闭路径 | 调整池化实现以恢复正确所有权，来源 S1 | 并发发送、qlog、回调保留引用、取消、队列满、超大包和关闭的 race 测试；测量 alloc/op 与 GC |
| Q3 截断关闭 | 记录关闭时是否丢弃未读尾部；这种关闭返回真实错误，完整 FIN 仍返回 EOF | 符合半关闭目标，来源 S11 | 完整 FIN、部分读后关闭、CancelRead 及同时关闭的矩阵测试 |
| Q4 HTTP3 控制流 | SETTINGS 后继续处理控制流，校验 GOAWAY ID 和递减规则；仅在确定未处理请求或 body 可由 GetBody 重建时重试，最多一次 | 需适配 HTTP3 请求所有权，来源 S11 | 未发送请求、RequestRejected、不可重放 body、GetBody 失败、活动请求与 GOAWAY 并发 |
| Q5 qlog 和日志 | 满队列时不阻塞包路径，记录 trace 丢失；常规关闭及逐包缓存日志降级；故障日志保留 | 符合有界观测，来源 S11 | 慢 writer、满队列、关闭和 shared counter 测试；采集缺失不能伪装为网络故障 |

Q2 不修改 SendDatagramContext、队列超时、取消交接和合包规则。Q4 先保留当前 qpack 版本及错误作用域；如果修复确需更新 qpack，先补独立 API 和 header 大小错误回归，再把新 pin 纳入 G0。上游 qpack pin 的变化不能通过无关 tidy 隐式引入。

### outbound 协议和 REALITY

| 单元 | 设计 | 历史关系 | 验收 |
| --- | --- | --- | --- |
| O1 REALITY | 认证固定 AES-GCM；移植指纹别名、缺失 key share 的明确错误、有界随机 hello 重试，以及混合 key share 的替代尝试和退避 | 修复握手兼容性，来源 S2 | ChaCha-first 指纹认证、未知指纹、有界重试、旧与新服务端；取消及时退出；两个形态失败后的退避 |
| O2 数据报契约 | 引入 ErrDatagramDropped，含原因、完整消费一个包且会话可用的约定；修复 Vision 65,536 边界、VMess packetaddr 和 16 位写长度、SS2022 截断 | 延续不可静默截断的约定，来源 S3 | 1,500／65,535／65,536 缓冲；短缓冲后下一包仍对齐；带 AEAD／padding 的写长度边界；合法大包成功且内容完整 |
| O3 五项协议修复 | 分开修 HTTP2 typed nil、SS2022 响应 salt、simple-obfs 首包头部边界、VMess mapped IPv4 和 Naive 32 位随机索引 | 同一审计发现但协议各异，来源 S5 | HTTP2 拒绝 CONNECT 不 panic；错误 salt 拒绝；正文与头部同读；IPv4 编解码；386 执行 padding 测试 |
| O4 协议端到端测试 | 引入 S5 的独立服务端测试思路和相关用例，使用真实 loopback；同时覆盖当前 fork 私有能力 | 符合以实际路径验证的历史要求 | 断开、短读写、认证失败、半关闭、超限和复用；fixtures 不能调用被测客户端 codec 构造所有预期 |

O1 只对尚未建立的同一 REALITY 节点尝试另一 hello 形态，不切换站点 leaf，也不消耗站点恢复预算。保留现有 uTLS 1.8.2 KeyShareKeys 兼容辅助函数。缓存成功形态按实际节点或服务端身份隔离，并审计并发拨号与 clone 行为。

O2 的 legacy ErrShortBuffer／ErrDomainResolution 兼容仅适用于已确认完整消费数据报的读路径。帧头、长度或正文没有读完整时必须返回致命错误并关闭，不能“丢一个包后继续”。

### DNS 与网关

| 单元 | 设计 | 历史关系 | 验收 |
| --- | --- | --- | --- |
| D1 错误分类与策略 | 共享“发生了什么”的分类，DNS 和普通 UDP 各自决定重试、阈值、retire、健康报告和日志。生命周期取消要结合上下文判断 | 适配 7afc5a81 与 c0bc4e6c，来源 S4 | 完整消费的丢包不处罚节点；重载取消不处罚；活着的 mux 遇到 closed／reset 仍识别为真实故障；软认证门槛保留 |
| D2 DNS 重试和池 | udp 非 as-is upstream 的丢包可尝试一次 TCP；保持其他 scheme 契约。池读循环跳过坏包但受 deadline 和 stale cap 限制 | 符合已有 TC 恢复目标，来源 S4 | TCP 成功／失败、禁止升级的 scheme、连续坏包、取消、复用下一查询、健康状态与计数 |
| D3 完整缓冲与查询 ID | 内部 resolver 按完整合法 DNS 消息范围读取；DoQ 保持调用者查询 ID，错误路径也恢复 | 符合 DNS 完整性和复用身份，来源 S4 | 大应答、错误 ID、DoQ 后再走 UDP fallback、并发查询独立；不会复制或修改共享只读 cache wire |
| D4 IPv4 重定向 | 设置和检查 conf/interface 及 conf/all；只处理 IPv4；每个失败有明确路径 | 延续网关应停止 redirect 的目标，来源 S6 | all=1／interface=0 仍被检出；两个写入都尝试；权限失败报告；网关实际状态复核 |
| D5 bootstrap 地址族 | DNS 服务器拨号按固定地址决定，结果仍按调用者需求过滤 | 与地址族隔离历史一致，来源 S7 | udp6 来源配 IPv4 resolver；AAAA 结果过滤；SO_MARK、MPTCP 与取消继续生效 |

D1 不机械照抄“所有 canceled 或 closed 都是调用者终止”的分类。当前历史明确要求：上下文仍存活时的远端 mux 关闭仍可处罚。TCP fallback 失败同时保留 UDP 丢包与最终失败的信息，健康策略按失败阶段判断，避免一个 errors.Join 中的丢包原因掩盖真实 TCP 连接故障。

D3 的全范围 DNS buffer 只在 resolver／DNS 事务读取时按需借用并归还。不得顺带把 direct polling receiver 的每个常驻小 buffer 改为 64 KiB；历史已经对常驻内存和超大包契约做过取舍。Vision 边界修复在放大全范围 buffer 前到位。

### 配置 订阅和启动

| 单元 | 设计 | 历史关系 | 验收 |
| --- | --- | --- | --- |
| C1 ext 与 QUIC 长度 | ext 先检查 file:tag，再进入 worker；QUIC token 和 payload 长度先用 uint64 比较剩余空间，再转 int | 与 339c3b75 的配置不 panic 目标一致，来源 S8 | 错误 ext 返回定位信息；token 和 payload 两种路径分别测试；386 真正执行测试，不只编译 |
| C2 include 与顺序 | 分离 visiting、parsed、merged；共享文件仅合并一次。订阅标签排序，节点顺序与显式过滤器顺序保留 | 适配路由和 Mihomo 顺序约定，来源 S9 | 菱形、自环、多级环、重复文件；比较规则序列；多次构建 fixed(N) 稳定；声明成员选择不变化 |
| C3 下载与 API 校验 | 超过订阅上限明确报错且保留旧缓存；增强 digit-prefix 提示、fixed_domain_ttl 校验；恢复 Marshaller.Bytes | 与保留好缓存和明确配置错误目标一致，来源 S9、S14 | 超限／垃圾／空订阅不覆盖缓存；TTL 合法、缺字段、无效值矩阵；validate 与 run 共用解析检查 |
| C4 assets 与环境 | 清理资产搜索目录重复项，错误说明 DAE_LOCATION_ASSET；systemd 加可选 dae.env，文件由用户维护 | 与用户环境覆盖约定一致，来源 S9、S15 | 无环境文件也启动；资产路径搜索；GOMAXPROCS 未设置、显式值、显式空值；procd 保留已有流程 |
| N1 netns 残留 | 校验 namespace 名，保留同步／lazy 卸载顺序，返回各阶段 errno；清理失败时停止进入 NewNamed；Close 记录清理失败，在锁外输出日志 | 延续 65fc1058；默认策略为本方案选择，来源 S10 | mock 非挂载、正常卸载、EBUSY、kernel-locked；非法名拒绝；清理失败后 NewNamed 不被调用；重载共享 netns 所有权保持 |

N1 本轮先实现准确识别与 fail fast。上游“挂载 tmpfs 覆盖整个 /run/netns”的自动恢复会隐藏其他工具的命名空间；历史未提供允许这种范围扩张的依据。将其登记为需替代设计的上游行为：后续只在能证明 dae 独占目录时考虑覆盖，或给出明确的人工恢复说明。不能把普通 EBUSY、权限错误也归为 kernel-locked。

C2 对固定索引属于有意修正：消除原先随机选择后，升级时可能选中与上次随机顺序不同的节点。发布说明应写明；显式 Mihomo 声明顺序和持久化选择不得因此改变。

### UDP 无回复恢复

来源 S12。该单元先完成诊断和观测，再做受控执行。

独立的 global.udp_reply_drought_mode 默认 off；off／observe 已交付。10 月 5 日加入 enforce，严格限定单个客户端、精确组、数字 peer 和 request_reply，详见下方 U2 及实施记录。它不由 quality_mode 隐式启用。client IP、精确 outbound group 与可选 IP:port peer 限定观测范围；这些字段不建立业务回复语义。

| 单元 | 设计 | 历史关系 | 验收 |
| --- | --- | --- | --- |
| U1 证据与模式 | 有界记录代理 data session 的本地成功写与有效回复；DNS、直连退出。unknown 语义始终排除候选；明确服务可声明 request_reply，并限定 IP:port。六个完整 5 秒桶各至少 10 次非空成功写、至少 3 次回复历史、30 秒无回复，仅作为观察初值；队列接受不等于完成发送 | 新行为扩展，保留 6d167837 的静默保护 | H3 视频间歇、WG keepalive、长暂停后的单包、单向数据、回压、旧桶和错误后的当前桶不能触发；observe 不改源端口与 endpoint |
| U2 执行与 peer 隔离 | 独立 rebuild ledger，按稳定关联身份和 peer 隔离；最多 256 项，已无活跃所有者的记录保留 1 分钟；重建后再次尝试前要求至少 3 个新关联的有效回复；先登记预算再发布所有权变更，具体设计见下节 | 适配 FIFO、代际、身份与预算历史，来源 S12 的后续排序修复一同引入；活跃关联的回复限制不因 TTL 到期而清除 | 全锥中故障 peer 拆出，健康 peer 保持；绑定目标协议不 promotion；重载、别名、批量 flush、预算竞争和晚回调测试 |

用户选择 CS2 官方匹配的 SDR 作为业务覆盖目标。[Valve 的 SDR 文档](https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay?l=english)描述了中继与连接票据。本项目当前只能看到代理侧 UDP 的 peer 和收发结果，无法确认游戏阶段及此时应有的回复，因此 CS2 保持 unknown。端口、域名、SDR 地址范围和过去曾有回复，都不能替代当前回复资格；没有合格候选时保留排除统计，不放宽条件制造候选。通用执行机制先以可控请求／应答服务设计和验证；CS2 的自动执行范围仍需真实对局阶段标注、请求／回复义务与暂停保护证据。

2026-10-03 的 201 实测新增 U1 验收门槛：先修复 NAT-preserving transport 的实际 peer 归属和 WriteTo 返回前的早到回复，再解释无回复频率。保留向客户端返回原 NAT 地址的契约，通过独立的实际 peer 元数据关联；不能把所有 raw reply 强行归到固定目标。补 Hysteria2 FakeIP 的 push／ReadFrom、写内同步回复、Shadowsocks 不同 IP／端口与 mapped IPv4 隔离回归。未归属计数需要按 association 定位，混合 Google／Steam 流量的全局数不能直接归因给游戏。reload 保留的旧流与新 observer 账本要明确标为覆盖缺失。

2026-10-04 修复后复测，201 的官方匹配成功，用户报告无卡顿、无掉线；原 SS 节点的新 SDR 流获得有效回复。主要游戏长流在观测开启前已建立，未进入新 observer，且未取得精确游戏阶段时间；本轮业务结果通过，U2 的回复义务和暂停保护门槛保持。详见[CS2 实测记录](upstream-followup-implementation-20261003.md#cs2-修复后实测10-月-4-日)。

“客户端持续发送但没有回复”也可能是单向应用、对方策略或丢包，不能标注为节点已坏。在 observe 中先记录候选频率与协议／端口分布。enforce 初期仅覆盖有明确双向语义和已有回复历史的范围；只看端口或 SNI 不能认定 H3、游戏或 WG 的应用状态。

U2 的预算与站点首选恢复预算分开。UDP 重建不直接写 TCP 或 UDP 的站点 leaf，也不把稳定节点变更作为恢复成功；先保留当前身份和选路结果，经现有故障策略需要重新选路时再处理。旧代不能直接修改新代的关联／ledger，跨重载继承由明确的所有权交接完成。

#### U2 执行设计（10 月 4 日）

**状态（10 月 5 日）：执行及隔离验收已实现并部署到 223，Astra 独立复核通过。220 → 223 → 自管服务的受控 SS AEAD 现场验收通过：B 新映射恢复回复，A 原映射保持；结束后恢复 off。** 首轮发现的 native peer 过宽排除已修复。现有 SS2022 没有声明所需传输能力，仍不执行；CS2 SDR 继续按 unknown 排除。[现场结果及限制](upstream-followup-implementation-20261003.md#10-月-5-日受控现场验收完成)与[诊断接口及归档方法](upstream-followup-implementation-20261003.md#u2-信息获取渠道10-月-4-日)保留候选、实际提交、新关联回复及质量预算证据。正常 CS2 实测不解除 unknown 的执行限制。以下预算与执行时限是候选初值，尚无生产长期实测依据。

##### 执行资格与模式

- 保留 `off`／`observe` 的语义。U1 扫描器继续只产生证据和事件；执行器通过有界候选通道接收不可变快照。observe 不占真实执行预算，不准备连接。
- `enforce` 要在下面的执行与隔离用例通过后加入配置。必须同时指定单个客户端 IP、精确组名、明确的 IP:port 列表及 `request_reply`；配置错误直接报错。
- 执行沿用六个完整 5 秒桶、每桶至少 10 次本地成功发送、至少 3 次有效回复历史、30 秒无回复、最近 5 秒仍有发送的资格。未知回复语义、DNS、直连、未完成发送、窗口失效、身份不明确和暂停继续排除。
- 执行前按当前时间重新计算资格。回复恢复、发送错误、作用域变化或配置所有权变化都会取消候选。busy／warming 不作为阻断理由。
- V1 只执行当前代新建、具有本地发送完成和独立关联能力的代理流。Hysteria2／TUIC 的队列接受不能代替发送完成；其实际完成接口补齐前继续 observe。保留的旧代流只报告覆盖缺失，后续所有权交接单独交付。
- 创建关联不保证远端源端口改变，也不保证恢复有效。传输必须明确提供独立关联能力；真实 fixture 验证关联身份和远端映射的效果。

候选复查与事件日志分开：U1 的 transition 标记和每分钟事件限流只控制日志，不能让预算 defer 后的候选永久停止尝试。执行器到 retry_at 后重新读取完整证据，不能直接重用排队前的旧窗口。限频、票据期限和 TTL 都使用进程内单调时间；UTC 字段仅用于对齐外部记录。

##### 身份、账本和限频

`SessionManager` 是进程级所有者，执行账本归它管理并按需创建。`UDPFlowRuntime.id` 已有进程内稳定身份；U1 的 association 编号仍保留，与 observer generation 配对展示。执行候选额外携带 runtime ID、lineage ID 和 ownership revision，不使用 observer 的局部编号识别所有者。

| 身份 | 内容与用途 |
| --- | --- |
| endpoint 所有权 | runtime ID、endpoint 实例、policy epoch、egress lease 与所有权 revision；执行前逐项复核 |
| recovery lineage | 第一个 endpoint 的 runtime ID；经确认的重建后代沿用，正常新流不能仅按相同五元组被认作后代 |
| peer | 客户端原始目标、规范化的实际 IP:port、RouteScope 和已固定的 route／egress binding；观察证据不跨身份合并 |
| 限频键 | 客户端 IP:port、原始目标、实际 peer、稳定组名；不使用会随 reload 改变的 outbound 数字索引 |

同一 IP 的不同端口分别管理。FakeIP／跨地址族别名保留客户端地址，同时用实际 peer 判断证据；只接受明确的一对一对应。多目标歧义、别名过期或实际 peer 未归属时排除执行。mapped IPv4 只按既有规则归一，不改变客户端回复地址。

初始执行限制：每 peer **1 次／60 秒**、每组 **2 次／60 秒**、全进程 **8 次／60 秒**；全进程最多 **2 个并发准备任务**，待处理队列最多 **32 项**。这些限制独立于 TCP／UDP 站点恢复预算。重复候选按身份去重；预算不足只记 defer 和下次可尝试时间，不增加失败次数。

预算分两种计数：开始实际 dial 时占用一次尝试额度，成功发布新所有者时计一次重建提交。尚未开始 dial 的取消退回预留额度；dial 已开始后即使回复恢复而取消，也保留尝试额度，但不计重建失败。准备失败保留原关联，下一次至少等待该 peer 的 60 秒限频窗口。排队与有效预留最多保留 10 秒，过期后需重新取证。

账本总容量 **256 项**。有活跃 endpoint、正在执行或等待新回复的条目不能淘汰；容量满时拒绝新执行。全部所有者结束后，记录作为 tombstone 保留 **60 秒**，防止紧接着创建同目标关联绕过限频或回复限制。正常重建继承剩余限制，不继承旧观察桶和回复历史。进程重启时清空内存账本；配置重载不会清空尝试额度。

每次提交后进入 `awaiting_replies`，至少收到 **3 次新 endpoint、对应实际 peer 的有效回复**才恢复执行资格；期间仍需满足限频和新的完整观察窗口。活跃记录的这项限制不因 60 秒 TTL 到期而消失。旧 endpoint 的晚回复不能增加新 endpoint 的回复计数。

##### 状态与提交顺序

```text
qualified → reserved → preparing → fencing → committed → awaiting_replies
                            │          │                       │
                            └─ cancel ─┘                  3 次新回复
                                 ↓                            ↓
                        保留旧关联及限频                 新窗口可再评估
```

1. 候选包含原 endpoint、peer、binding 和回复／失效版本。执行器预留预算，准备时间受 **2 秒 dial 上限**及调用者剩余期限共同约束。准备不持有 pool、观察、预算或 SessionManager 的数据锁。
2. 使用原节点、原选路路径和网络参数创建候选 PacketConn。full-cone 拆分时将新 target 固定为该 peer；客户端回复地址仍为原始目标。准备路径不会运行质量重选、写站点 leaf 或将推测性 dial 失败记入节点健康。普通数据面错误保留现有处理。
3. 将候选封装为尚不可选中的 prepared endpoint，保存独立 egress lease 和所需别名引用；完成 receiver／read loop 的初始化，失败则取消。当前 `createEndpointLocked` 混合了 dial、adopt 和发布，需拆出准备／发布步骤，避免候选提前被 pool 或 retained 查找命中。prepared 接收不得向新账本贡献合法回复，第一包的发送意图仍先于实际 I/O 登记。
4. 只对故障 peer 进入写入屏障，停止发放旧所有者的新写入 claim，等待已在执行的写和 pending batch 完成。屏障最多等待 **100 ms**；超时则取消本次切换并继续旧路径。健康 peer 使用自己的 claim，不等待该屏障。
5. 在提交所需的配置所有权读租约下，再次检查模式、作用域、endpoint、binding、回复版本、窗口资格、预算票据，以及原所有者和目标专用 pool 槽。取得相关 create 锁失败时 defer；需同时检查两个 shard 时按索引排序，锁内只复核和发布。发现原槽已移除／更换或其他正常关联已占用目标槽时取消，不覆盖它。
6. 在短临界区完成新 endpoint 的注册、BPF tuple 引用准备和账本状态；**先记录新回复限制与预算提交，再发布 peer 的新所有者**。这个发布是切换的唯一生效点。pool 项、detached 标记和所有权 revision 必须与之保持一致，发送端不能使用半发布候选。发布前的失败可撤销预提交记录和新引用；发布后的取消只能保留已提交新所有者，并按正常生命周期退出，不能撤回已被发送端使用的关联。
7. 提交后释放旧 peer 的 tuple／别名引用；目标专用旧 endpoint 在锁外退出，共享旧 endpoint 继续服务其他 peer。候选取消时释放其 conn、observer、egress lease、别名 lease 和预留资源各一次。

切换只影响后续真实数据。准备过程不发送复制的业务包，不重放已成功发送或完成情况不明的包。选路之后、真正调用 WriteTo 前仍要验证 claim；过期 prefetch 需重新取得所有者，且只允许在确认尚未调用 I/O 时重试一次本地查找。

新写入遇到正在切换的 peer 时，利用原 ingress task 持有的有界 buffer 等待屏障结果，最长 100 ms。超时按已有 UDP 丢包契约处理并单独计数，不生成额外重放队列。该超时及 pending batch 未完成会令本次提交取消。所有等待都支持取消；不用每候选一个额外 goroutine 等锁。

##### full-cone、FIFO 与回复

假设共享 endpoint S 服务 A、B，只有 B 合格：候选 endpoint T 绑定 B，A 保留 S。提交后 B 的所有查找返回 T；S 对 B 拒绝新的写入 claim。T 结束时，B 在有界 tombstone 有效期间也不能悄悄回落到 S，必须由当前所有者明确释放或按既有错误路径处理。

目标专用 endpoint 可以整体替换。source-only endpoint 一律按可能共享处理，即使账本只登记了一个 peer；只有传输支持独立目标发送时才拆出 B。目标绑定协议不做 full-cone promotion，未登记的其他 peer 不因观测容量不足而被当作不存在。

需要接入的入口包括 `lookupCachedRoutingBinding`、普通／prefetch endpoint 查找、`handleRetainedUDPEndpoint`、`SessionManager.retainedUDPEndpoint` 和实际写入。现有目标专用 key 优先级可以复用，但单靠 key 不足以覆盖 retained 和缓存路径；它们都要核对同一 peer 所有权。retained 扫描在打分前排除已 detached 的 peer，避免选择旧共享 endpoint。

claim 在实际 I/O 完成后释放。batch 的 Append 只是接受，claim 要保留到实际 flush／取消；部分 flush 只给成功前缀记发送，其余使窗口失效。等待 batch 排空时不持有 batch mutex、pool 锁或观察锁。第一版不支持某类 batch／传输屏障时必须明确排除并通过保护用例，不能默认为安全。

每个流继续使用原有 `UdpTaskPool` 的 FIFO 和有界溢出处理。直接分发的流同样要经过 peer claim；不能只依靠 ordered queue 避免切换竞态。prepare 可以与旧写入并行，发布需要等该 peer 的实际写入完成，不能通过打断共享 conn 让等待结束。

接收端同时携带实际 peer 和接收时的所有者 revision。发布前已经入队的回复按原有规则排空、返回客户端，记在旧 endpoint；发布后的 detached peer 回复不能恢复新账本。共享 S 上 A 的回复照常处理。未知实际 peer 时不执行切换。Close 仍在接收回调／replySender 栈之外运行，保留已有防自等待和 buffer 回收规则。

BPF tuple 交接先增加新所有者引用，再释放旧 peer 的引用，不删除仍有人持有的 tuple。清除旧 endpoint 的该 peer tuple、lastPair 和路由缓存关联时使用身份复核，不能因旧 endpoint 日后关闭而删除新引用或恢复旧别名。客户端 NAT 地址、resolve_dns 固定 target 和 QUIC 身份继续由既有机制管理。

普通 retire、hard error、transport 结束、NAT expiry 与 U2 共用所有权 revision 的变更规则。关闭先使相应所有权失效并取消未提交任务，再在锁外运行现有 Close；执行器不能在检查存活之后覆盖一个已经正常退出或被替换的 endpoint。已启动实际 I/O 的包只走原有完成／错误路径，不能因切换再发送一次。

##### 重载与覆盖

V1 的执行 owner 只属于创建它的活跃代。reload 发布前冻结旧执行器的提交入口，取消并等待未提交任务；已提交 endpoint 继续由进程级 SessionManager 持有。所有权读租约不能跨 dial／屏障等待持有，提交完成后先释放租约，再进行 Close。预算与回复限制保留在进程级账本，旧执行器不能改新 owner。

observe 增加 `retained_owner_not_observed` 覆盖统计，使用 runtime ID 去重且仍有容量上限；不能把缺少观测显示成零回复。后续跨代观察采用明确交接：暂停该 peer 的 claim、取旧 owner 快照、发布新观察 owner、以空观察窗口重新积累。保留 binding／egress lease 和预算限制，旧回调只属于旧观察 owner。没有这套交接时继续排除旧代自动执行。

关闭开关停止候选、准备和新提交；已经提交的关联按正常生命周期保留，避免关开关再次改变远端映射。已有 detached 所有权在关闭期间仍需维持到关联结束。冷启动 off 和从未执行过的流不创建新 ledger／worker，也不增加地址解析、计时或写入锁；已参与恢复的流只保留必要的所有权检查。

##### 接口与文件职责

| 位置 | 实施内容 |
| --- | --- |
| `config/udp_reply_drought.go` | 保持 off／observe；执行验收后加入 enforce 的严格作用域校验 |
| `control/udp_reply_drought.go` | 只读候选快照、runtime／lineage／revision、覆盖缺失统计；不调用 retire |
| 新 `control/udp_rebuild.go` | 模式与资格复核、有界执行器、票据、状态和取消 |
| 新 `control/udp_rebuild_ledger.go` | 进程级限频、live pin、tombstone、新回复限制与一次性提交 |
| `control/session_manager.go` | 稳定 lineage、配置提交租约、prepared／active 区分、所有权索引 |
| `control/udp_endpoint_pool.go`、`udp_endpoint_lifecycle.go` | 准备／发布分离、peer claim、detached、目标专用切换、普通关闭的 revision 失效与 tuple 交接 |
| `control/udp.go`、`udp_ingress_task.go`、`udp_write_batch.go` | 查找与 prefetch 复核、FIFO、实际 I/O claim 与 batch 屏障 |
| `control/udp_endpoint_reply.go`、相关 read／push 路径 | 回复所属 revision、旧队列排空、晚回调和 buffer 所有权 |
| outbound `netproxy` 及已核实的实现 | 明确声明本地发送完成、独立关联、peer 归属及目标绑定能力；缺省能力为不支持 |

传输能力须由实际 PacketConn 与包装层显式声明，不能只按 protocol 名称放行；包装层不得把底层能力自动扩展成自己未证明的能力。V1 不需要修改 QUIC 协议实现；以后加入 QUIC 发送完成通知时再单独跟进 outbound／quic-go 固定版本。

锁顺序实施前逐处核对：提交租约 → peer 屏障状态 → 观察证据 → ledger → pool 发布。SessionManager 的注册／lease 准备在观察锁前完成。等待 I/O、batch 排空、Close、日志和 buffer 回收均在这些数据锁之外。正常 packet 路径不获取全局 ledger 锁；仅候选、实际尝试和发布使用它。

##### 验收与交付顺序

| 批次 | 交付与必须通过的用例 |
| --- | --- |
| U2-A 身份与预算 | runtime／lineage、能力与覆盖统计，账本接入真实准备路径；并发只获一个票据、跨 reload 限频不清零、live 记录不因 TTL 消失、容量满拒绝、未开始 dial 退款、迟到完成不重复提交 |
| U2-B 单目标执行 | 先准备再提交；dial 失败保留旧关联，回复在提交前到达则取消，预算先于所有权可见，发送未知／错误／暂停排除，prepared 不可命中，ctx 取消无泄漏 |
| U2-C peer 与生命周期 | A 健康／B 故障共用 source；只拆 B、A 身份与包序保持；所有缓存／retained／prefetch 入口、新旧代、直接分发、batch 部分 flush、晚回复与 tuple 引用均覆盖 |
| U2-D 隔离验收与开关 | 用真实 SS／SOCKS5 fixture 制造服务端旧映射失效，确认 B 恢复有效应答、A 无额外重建；off／observe 完全不准备或切换；随后加入 enforce 校验和状态计数 |

同一客户端 socket 交替发 A／B、各包带唯一序号；B 服务先正常回复，之后仅忽略旧映射的包，A 始终应答。检查实际目标端看到的映射、B 新关联至少 3 次有效回复、A 的映射／内容／顺序保持。测试对旧回复、复制业务包、遗漏预算登记和遗漏 claim 的实现必须能失败。没有完成的批次不能以只有测试引用的草稿生产文件提交。

计时单元使用可控时钟，不把真实等待 30 秒写进普通用例；真实传输 fixture 保留少量期限检查。测试范围包括 config、control 的 UDP 生命周期／FIFO／batch／跨地址族／session manager，以及涉及的 outbound 包 race、vet 和正式模块图检查。准备、发布和关闭的资源使用最终回收计数核对，热路径用 scoped／off 的分配和 p99 比较。

现场先用 **220 → 223 → 自管请求／应答服务**，每次只覆盖一个客户端、一个组和精确目标；222 的本机测试不替代该链路。实际 CS2 继续 unknown，下一轮在启动游戏长流前启用 observe，并取得搜索、进入、暂停、结束时间。整套 strict 的既有 QUIC 超时待办继续保留。

状态接口分开显示 qualified、reserved、attempt_started、committed、awaiting_replies、recovered 和各种 cancel／defer；独立计数 late_reply、claim_retry、handoff_wait_timeout、ledger_full 和 coverage_missing。`recovered` 只在新关联有足够有效回复时记录。日志在锁外、按事件限流；预算等待以 Debug 记录，不能用事件限流替代执行预算。

历史复核结论：保留 `6d167837` 的静默保护、`672418c5` 的 FIFO 修复、进程级保留关联与 egress 所有权、真实 peer 归属和早到回复修复。采用 S12 的独立目标拆分与预算发布顺序，继续使用本项目更严格的连续窗口证据。新增的先准备后提交、活跃账本保留和冷启动 off 是本项目执行边界；不恢复按端口／空闲时长判定游戏或预先销毁活跃关联的旧策略。

#### resolve_dns 自动重建扩展设计（10 月 5 日）

**状态：U2-R1 至 R3 已本地实现并通过定向回归；R4 的诊断、本地性能检查及独立审查已完成，现场 DNS 验收待做；R5 尚未实施。** 实施对照基线为 `113b045a`，223 继续使用 `f6b1e63d` 的默认关闭版本。本节扩展已有 U2 执行器；此前同族 native IP 的受控验收不能替代本节 DNS 扩展验收。生产开关、传输能力和实际业务回复资格分别验收。

##### 目标与首批范围

对已使用 `resolve_dns` 固定目标的 UDP 关联，自动重建沿用当前实际 IP、节点及 egress binding，保留客户端原始地址与连接身份。成功后仍经原始地址查找及返回数据，新关联的实际回复才解除再次重建限制。

首批支持同地址族、目标专用、身份明确的数字目标：客户端原始目的 IP 可以与固定 IP 不同。QUIC 身份保护须在放行带 QUIC 身份的 DNS 流之前完成；没有明确回复义务的 H3／CS2 保持 unknown。DNS FakeIP 另设一批，完成映射引用保护后放行。实际跨地址族 alias、只有域名但没有数字固定目标、共享关联上的 DNS 目标歧义及 batch 继续排除。

继续使用现有 off／observe／enforce 与精确 client、group、数字 peer、request_reply 作用域，不增加第二套模式。`udp_reply_drought_peers` 匹配实际固定 IP:port；域名解析到另一个 IP 时，必须重新符合作用域并积累证据。配置中的域名或 resolve_dns 参数本身不建立请求／回复义务。SS2022／SS stream／Hysteria2／TUIC 的能力缺项保持，各自支持不能由本节间接放行。

##### 现状与历史约束

| 依据 | 已有语义 | 本设计的要求 |
| --- | --- | --- |
| `80e1f858` | resolve_dns 固定发送目标，回复保持客户端原始目的地址，节点切换后仍遵守 block_quic | 保留原始地址和固定目标，复用当前 NAT 回复上下文与 QUIC 拒绝路径 |
| `9fabeeaf` | 活跃 endpoint 持有不可变目标；DNS 缓存刷新不改它；普通重试有界继承，路由／域名／Initial 不匹配则失效 | U2 从活跃 owner 取得固定目标，不重新查询 DNS；保留普通退休恢复的边界 |
| `3ff7022b`、`e8ab1d1c`、`6d167837` | 曾因静默或暂停换源端口导致业务中断；后续保留活跃身份，排除单凭空闲重建 | 原来的暂停、keepalive、unknown 及真实回复保护继续生效 |
| `5a150027` | 实际应用 peer 与客户端 NAT 回包地址分开；发送意图早于可能快速到达的回复 | 证据只使用真实 peer，原始地址不能冒充实际回复来源 |
| `90fe9b59`、`f6b1e63d` | 准备后提交、peer claim、revision、进程预算、三次新回复、真实 alias 排除 | 复用现有执行器及界限，native mapping store 存在仍可通过真实身份检查 |

当前代码有五个必须一起调整的点：`admitLocked` 将 `slot.original` 设为实际 peer；prepare 将 `poolKey.Dst` 设为实际 peer；`detachedRebuildPeer` 按原始地址直接查询以实际 peer 索引的表；普通后代也按 `key.Dst` 安装 peer；新 prepare 未继承 DNS 状态。仅删除 exclusion 会使查找、回复、普通退休和晚回调失去一致身份。

还需处理准备取消：新 DNS state 的 owner ID 大于旧 state 时，现有 `discard` 的 `<=` 判断可能让未发布候选的 Close 删除旧恢复记录。旧关联的晚 retire／save 也可能在成功交接后重新写入旧 pin。它们必须由明确的发布状态和 owner 交接保护。

##### 地址与身份

例：客户端向 `O=198.51.100.10:46672` 发送，resolve_dns 固定为 `P=203.0.113.20:46672`。旧关联和新关联均向 P 发包，客户端均收到源地址 O 的回包；更换的是代理关联，不改变业务服务器。

| 字段 | 用途 | 重建规则 |
| --- | --- | --- |
| original O、client、RouteScope | pool／override／retained 查找、BPF tuple、客户端回包 | 保留原始 key；固定目标重建的 `next.poolKey = old.poolKey` |
| actual peer P | 本地完成发送、回复证据、精确 peer 作用域、peer claim 索引 | 必须等于当前数字 DialTarget，port 和 family 符合首批范围 |
| 规范化 domain、初始身份、flow identity revision | DNS pin 与业务连接边界 | 创建时固定；准备及提交核对，身份变更取消候选 |
| runtime、lineage、ownership revision | 当前 transport 与已确认的恢复后代 | runtime 更新，lineage 保留，ownership revision 增加 |
| DNS state owner ID、一次性 save／关闭状态 | 防止旧回调覆盖或删除新恢复记录 | 新 state 分配新 ID 和新 sync.Once，保留 initial 内容，独立管理生命周期 |
| route／egress binding、mark、must、network、sticky site | 原节点、外层地址族与既有回包路由 | 原样继承；数字实际目标保持，内层 family 不改外层 MagicNetwork |

拟增加不可变的 `udpPinnedTargetIdentity`，保存 O、P、规范化域名、初始身份、是否已识别为 QUIC、DNS state owner 与身份 revision。原始地址种类在建流时确认，区分 native、DNS FakeIP 和跨族 alias；不能仅凭“地址能解析”认定 native。已有绑定可直接引用，避免复制整套可变状态；仅在 resolve_dns 流上需要这份快照。

`rebuildPeers` 继续按 P 索引，发送和真实回复复用现有查找。`slot.original` 从固定目标快照取 O。按 O 查 detached、普通后代及 retained 时，目标专用 DNS 流通过不可变 O→P 关系取得同一 slot；native 共享流沿用现有查找。避免建立两套独立可变 peer 表。非一对一或关系不一致时拒绝执行。

DNS 记录 TTL 与退休 recovery 的 30 秒 TTL 不作为活跃 pin 的期限。旧 owner 活着且身份相同，U2 可以继续沿用 P；自然 NAT 到期、行政删除或真实新连接结束这项继承。无法到达 P 时只报告未恢复，后续目标切换由普通建流策略决定。

##### 准备与提交

1. 扫描仍按现有六个完整窗口及回复历史生成候选。执行器取得 O→P 和身份快照，确认目标专用、当前代、精确作用域与实际传输能力。预留预算前后均核对 owner；缺项有独立排除原因。
2. 使用当前节点、network、mark 和 P 拨号。调用现有 `ContextWithUDPReplyAddr(ctx, P.String(), O)`，明确实际发送目标和客户端回包地址；同时验证实际 PacketConn 仍能提供本地发送完成、独立关联与真实 peer 元数据。prepare 不重新解析业务域名、不运行质量重选。代理节点自身是域名时，底层新关联可能正常解析外层 hop，单独记录，不能与业务目标重新解析混为一谈。
3. prepared endpoint 保留旧 key O 和域名、sticky site、QUIC 身份，创建独立 DNS state、绑定进程 recovery store。准备取消仅回收自己的 conn／observer／lease／tuple，不调用旧 pin 的 discard，不更新 QUIC／domain memory，也不产生可供正常新建命中的 recovery 记录。
4. P 的现有 claim 屏障排空实际写入。原节点、固定目标、DNS owner、身份 revision、Initial 边界、证据、当前配置及目标槽逐项复核。DNS owner 交接锁忙则取消；不能在 100 ms 屏障内等待 DNS、日志、全表遍历或 Close。
5. 在原槽 O 替换 owner：预算与三次新回复限制先登记，再发布 pool／override／slot revision；DNS pin 状态与发布同步交接。fixed endpoint 新旧 key 相同，复用现有同 shard 锁，不按 P 增设第二个客户端槽。
6. 提交后移除旧 tuple 引用，旧 target-bound endpoint 在锁外关闭；旧入队回复按原规则排空。它们只记旧 owner，不能给新账本增加回复，不能改写新 DNS pin。三个新 owner、P 的有效回复后才记录 recovered。

固定目标旧 endpoint 不必为发布写入新的退休 cache 条目；prepared 也不提前发布 pin。业务序号、payload 和尚不明确是否完成的包均不复制或重放。既有健康 native A 的共享关联不参与这次 target-bound B 替换。

##### DNS 状态与关闭竞态

DNS state 增加明确的 prepared／current／superseded 状态或等价 owner token；sync.Once 和 owner ID 不与旧 endpoint 共用。新 token 在 pool 发布的同一短临界区成为 current，旧 token 成为 superseded。Close／save／discard 按 token 和对应 key 复核；准备中的 token 无权修改进程恢复缓存。

提交与 `resolveDNSRecoveryStore.save` 的复核必须使用同一同步边界：提交以 TryLock 获取 store 锁，晚 save 获取该锁后再次检查 token。不能只在 save 入口读取一次 atomic 标记。禁用旧 state 使用 token／标志，绝不在 store 锁下调用或等待 sync.Once.Do：已有 save 可能正占用 Once 等待该锁，会形成死锁。提交不创建 recovery 记录、不改变上限 4096、不在锁内遍历缓存；锁忙取消并保留原关联。

提交锁序明确为配置发布租约 → endpoint 生命周期 → peer → 观察证据 → pool create／pool → 流身份保护 → DNS store → ledger，各新增锁均 TryLock。store 和 ledger 均取得后，最终复查 token、完整身份、fence 时限及 ledger 票据；必须先完成所有能失败的校验，才执行 commitLocked 的预算／新回复登记、DNS token 交接、旧 cache 的对应 owner 清理及新所有权发布。committed 计数先于新 owner 对发送端可见，后半段不再做可能失败的获取／安装。开始拨号已消耗的尝试不退款；发布失败不能改变旧 token、cache 或 committed 计数。

普通 save／discard 在释放 store 锁之后才进入其他生命周期操作，retire memory 写入完成后也要释放身份保护锁再 markDead；不能在 store 锁内等待生命周期锁或在 ledger 锁内再取 store／pool 锁。实施时核对完整调用图、现有注册方法及资源准备，防止 helper 内部重新加锁。同步回归须暂停 save 于 Once 内等待 store 的位置，再并发提交／取消，证明没有自等待且旧恢复记录保持。

| 生命周期 | DNS pin 与预算处理 |
| --- | --- |
| prepare 失败／取消 | 旧 owner、P 和 cache 不变；未开始 dial 退预留，已开始 dial 保留尝试 |
| U2 成功提交 | 新 state current，旧 state superseded；三次新回复限制保留 |
| 新 owner 普通 hard error／transport retire | 在既有身份和路由条件下保存 P；下一普通后代沿用同一 original／actual 关系、lineage 和回复限制 |
| 行政 Remove／Abort | 释放当前 pin，阻止晚 save；下一正常流按既有策略选择目标，执行预算仍保留 |
| 自然 NAT expiry | 结束活跃 pin，不续期 QUIC／domain memory；墓碑预算沿用既有 60 秒规则 |
| reload／关闭重建 | 未提交准备取消；已提交新 owner 继续收发，预算和 pin 随进程保留；无跨代观察交接时不再执行 |

普通后代恢复不是重新开始 U2：它必须验证实际 P 和 DNS 身份，按 P 安装原 slot，而不是按 key.Dst=O。未通过继承条件时先退出旧恢复所有权，再走明确的新流处理；不能让新目标 P2 占用旧 P 的 claim 或收到旧回复门槛。行政删除及新业务身份都不能仅靠相同五元组继承活跃 lineage。

##### QUIC 与 FakeIP 边界

QUIC Initial 检查必须位于 override／prefetch／retained 优先查找之前，复用 ingress 已有的 `UdpFlowDecision`，不再解密或解析每包 payload。只对已参与 DNS 恢复所有权的流检查可比较的客户端 Initial；同一初始身份保留 P，身份冲突或无法确认时冻结旧 U2 资格、取消未提交任务，并按既有规则重新判定连接。普通短头包不能被当成新连接证明。

身份变化需要递增独立 flow identity revision，不能只看 endpoint runtime。改变时在同一生命周期同步边界取消 ticket／阻止旧提交，退出旧 override 并阻止旧 pin 晚 save；不能仅删除 map 项后继续使用旧 sniffer／domain memory。重新建流应清理对应旧身份并重新完成既有 block_quic、domain、route 和目标选择。预算保留；新流不继承旧观察桶或三次新回复证据。

`rememberFlowIdentityOnRetire` 的 QUIC／domain memory 同样需要 owner 保护。对参与 DNS 恢复的流，token 检查与写入、旧身份撤销与 memory 清理置于同一流身份锁临界区，结合 memory shard 的既有同步；不能在函数入口检查一次后放锁再写。prepared 和 superseded transport 无权补写旧记忆。同身份的 U2 后代交接保留有效记忆；已确认新身份则先撤销旧 token 并完成清理，再让新流发布自己的记忆。旧 Close／retire 晚到不能恢复旧域名、误触 block_quic 或续期旧身份。冷启动 off 的普通流沿用原路径，不为未参与恢复的流增加这把锁。用例需把旧 memory 写入暂停在 token 复核前后，与新 Initial／新 memory 发布交错。

首批采用保守的账本处理：已确认身份冲突后，退出旧 owner 及其 override，新连接按新 flow 建立 slot；旧记录等全部 owner 结束后保留 60 秒墓碑。相同预算键在墓碑有效期间的 `lineage_conflict` 作为执行 defer，正常数据可以收发；过期后才以新 slot 预留执行。不因 DCID 变化清空记录或退款，不为赶快再次重建继承旧 slot。未知 Initial 只取消自动执行并交回既有判定，不能把解析失败直接当作已确认新连接并删除活跃 owner。

首批不放行 FakeIP。DNS FakeIP 目前有退休、墓碑及再分配流程，不能用一次 LookBack 成功或 24 小时 grace 证明整个活跃关联地址不会被重用。后续增加进程内映射引用 token，引用精确 store／映射记录／分配身份；当前、prepared 和待排空的旧 owner 分别持有引用，切换先取得新引用，再释放旧引用。持引用的地址不得被复用；状态只存在内存中，现有容量上限保留，容量满或无法安全清理时拒绝新增。

引用绑定 endpoint 的实际生命周期。off／reload 只取消未提交 prepared 并释放它的引用；仍收发的 current、仍排空的 superseded 各自保留引用，直到各自 I/O／回复排空并关闭后才释放一次。提交先取得新引用，不能提前释放旧 owner 排空所需引用。普通后代、行政 Close 和 NAT expiry 均按实际 owner 结束释放；不是观察器结束就释放。映射 store 重置／损坏时取消未提交工作并报告覆盖缺失，不重新绑定到同地址的其他域名。已提交者只能在旧映射仍有效时维持身份。跨族 UDP alias 的命名空间和稳定映射策略继续独立，此批不混合修改。

##### 信息渠道与延迟门槛

扩展现有 `/v1/udp-recovery`，候选、committed、recovered 和关闭记录携带 original、actual peer、target kind、DNS owner ID、flow identity revision 及 `pin_inherited`；domain／Initial 的完整内容不额外写入日志，身份核对使用进程内编号。旧档案字段缺失视为未知，不补造 native 或 pin 继承成功。

细分 `resolve_dns_target_unresolved`、`resolve_dns_peer_mismatch`、`resolve_dns_identity_uncertain`、`resolve_dns_pin_owner_changed`、`resolve_dns_pin_busy`、`resolve_dns_fakeip_unleased` 与 `resolve_dns_mapping_changed`。同时保留模式、范围、传输能力、预算和 coverage，避免混进泛化的 alias 排除。Python 分析器核对同一 original／actual／身份的 commit→新回复链，第三个回复后才允许 recovered。

重建期间不重新发起 resolve_dns 的业务域名查询；外层代理 hop 的正常解析单列。正常 off／observe 不增加进程 DNS 查表、字符串归一化或全局锁。元数据在建流及候选快照时固定，发包沿用已有 numeric target 和 claim，身份冲突检查只在现有 Initial 分支执行。新增 state／映射 token 的分配仅发生于建流和准备，无稳态每包堆分配。

以实施前正式依赖构建为基线，同工具链、固定 CPU、交错多轮比较 off／observe／scoped enforce 及 native／pinned DNS 的每包均值与 p99、完整 ingress 首包、堆分配和 GC；保留 raw 日志。多轮稳定出现至少 5% 的稳态处理延迟回退时先解释并修正，再进入现场。正常稳态零新增每包堆分配、健康 A 不等待 B 屏障是必须满足的门槛；100 ms fence、2 秒 prepare 及预算上限保持。现场 RTT 与故障等待单列，不用于证明处理开销。

##### 实施与验收

| 批次 | 主要修改 | 必须取得的证据 |
| --- | --- | --- |
| U2-R1 地址与身份 | `udp_reply_drought.go`、`udp_rebuild_peer.go`、`udp_endpoint_pool.go`、`udp.go`、`session_manager.go` | O≠P 的 slot／pool／override／cache／prefetch／retained 一致；native 行为保持；新目标不能共用旧证据 |
| U2-R2 DNS 所有权及生命周期 | `resolve_dns_recovery.go`、`udp_endpoint_lifecycle.go`、prepare／commit | 私有候选取消不删旧 cache；旧晚 save／discard 不覆盖新 pin；Once／store 竞争不死锁，发布失败不改 token 或 committed；行政／NAT／普通 hard error／reload race 无泄漏，预算及新回复限制保持 |
| U2-R3 QUIC 边界与受控开关 | `UdpFlowDecision` 使用点、已有 QUIC 身份路径、exclusion | 同 Initial 保持 pin，冲突／未知 Initial 取消旧执行；旧 Close 不能重新写已清理的 domain／QUIC memory，新连接遵守 block_quic；所有资格及作用域约束通过后放行 native pinned DNS |
| U2-R4 信息、性能、独立审查与现场 | 诊断、归档、真实 SS AEAD／SOCKS5 fixture 及有界 WAN 工具 | commit／recovered 链可复核，零稳态分配、延迟门槛、Astra 独立审查；220→223 先 observe 后精确 enforce，结束恢复 off |
| U2-R5 DNS FakeIP | `fakeip_store.go` 的映射引用及 DNS target 快照 | TTL／退休／再分配／store 切换／reload／长流引用保护，回包源仍为 FakeIP；通过独立验收后才扩展首批范围 |

真实本地 fixture 用 O≠P 的两个端点与可控 DNS：先取得 P1 固定目标，之后 DNS 改为 P2，再使 P1 旧代理映射不回复。新关联必须继续到 P1，P2 收到业务包为零，客户端回包源始终为 O；业务域名 DNS 查询数在 prepare／commit 前后不增加。数字代理 hop fixture 核对总查询增量零；域名代理 hop 用例把业务解析与外层解析分开核对。A 550/550 的现场数字是此前基线，不替代本节新验收。SS AEAD、SOCKS5 分别覆盖，本地时钟控制候选窗口，真实网络内容和映射不合成。

保护矩阵还包括 original=P、IPv4／IPv6／mapped IPv4、global mapping store 存在、真实跨族 alias、固定目标／端口不一致、域名未解析、未知 actual peer、并发新回复与准备、临时目标槽竞争、prepared 早到回复、普通后代再次干旱、queue acceptance／batch／SS2022 排除。故意破坏原地址、复制业务序号、旧 cache 删除、新回复归属或 DNS 重查时，验收必须失败。

WAN 继续使用 220→223→自管服务，仅一个 client／group、精确实际 peer；至少记录 off、observe、enforce、恢复 off 四段。应用序号／服务端映射、DNS 请求计数、配置／二进制来源、预算及恢复后采样共同验收。正常 A 全部回复且映射保持，B 新映射至少三次有效回复；没有无法解释的丢包、重复或重放。临时配置有独立回滚，服务、私有凭据和映射引用都确认回收。

本节目前不改依赖 pin；如实际 NAT 包装层不能同时提供 P 的元数据和所需能力，则先保守排除，再为该包装层单独修正及发布 outbound。quic-go 不因本设计更新。每批带对应回归及历史保护，完成代码后由 Astra 独立审查；223 默认 off、主要质量组 observe、CS2 unknown 保持到各自实际验收完成。

### 性能和构建能力

来源 S13。所有优化在正确性单元完成后评估。

| 单元 | 设计 | 历史关系 | 验收 |
| --- | --- | --- | --- |
| P1 MSS 与 socket control | Linux 的 TCP listener／主动连接选项分开；固定 1380 仅作为可关闭候选，先保持当前默认。TPROXY listener 不加 TFO | 改变分段行为，需要独立证据；上游最终版本已撤回 listener TFO | MTU、IPv4／IPv6、时间戳、直连／代理矩阵；吞吐、RTT、重传；非 Linux 构建使用受支持的 fallback |
| P2 gather write 与 onActive | 保留裸 TCP writev；包装连接可尝试合并小 segments；大数据不重复复制。复用当前 250 ms 活动刷新和 exact splice | 需适配已有优化；当前并非没有 gather write 或刷新节流 | partial write、错误、prefix 顺序、取消和半关闭；读成功而写阻塞时 idle 行为；采集字节只计实际写入一次 |
| P3 GSO GRO 与页回收 | 只评估最终仍在生产调用的实现；保留 connected socket segmentation control、FD 重用防护、runtime netpoll 和接收容量契约 | 需适配私有修复；中间 dae helper 已被上游删除 | GSO 分段和 GRO 拆分完整；关闭／重载／borrow-return 竞争；arena 未归还时不 trim／unmap；数据不丢，RSS 和 alloc/GC 有测量 |

P2 上游移除了读端 onActive 调用。当前刷新虽然已有 250 ms 节流，但回调仍会读取时钟；可以测量去除重复调用的收益。必须先证明读成功、写端长时间回压和半关闭情况下的 idle 语义，再确定活动刷新边界，不能仅凭减少一次调用改掉 watchdog。

P3 不对 Go 堆中仍可能被引用的切片直接 MADV_DONTNEED；仅使用可证明独占、已归还的 mmap arena 页。RSS 改善不能用队列积压、数据丢失或更高 p99 延迟换取。BBR3、CCOverride 或调度并行度的变化登记为独立实验，不混入协议正确性提交。

## 已有等价实现

以下项保留当前实现，作为回归保护，不重复移植：

- HTTP 请求行尚未读到换行时返回 ErrNeedMore。
- UDP 本机 bypass 精确匹配本机地址并排除 FakeIP。
- url_test 的实际选路优先已测量节点，并处理无测量 incumbent。
- uTLS 1.8.2 的 KeyShareKeys ECDHE 兼容。
- QUIC 启动失败清理、CapabilityCallback、peer params 原子发布和 stream waiter 交接。
- TCP 的 explicit splice、gather write 基础能力和 250 ms 活动刷新。

若后续测试发现 cached min／嵌套组投影与实际选路仍不同，只移植所缺的缓存一致性部分，保留 6afbf33c 的集中恢复发布。

## 实施顺序与提交方式

1. **阶段一：验证入口。** 完成 G0，记录三个有效依赖的基线测试；升级评估采用 strict，明确区分基础设施错误与代码失败。
2. **阶段二：QUIC。** 在当前 Fan-chou quic-go 上依次完成 Q1、Q2、Q3、Q4、Q5及相关 audit 测试。将修复发布为固定版本；outbound 集成测试在该版本下通过。
3. **阶段三：协议和 DNS。** outbound 完成 O1 至 O4，先发布与当前 dae 兼容的版本；dae 将新 pin、D1 至 D3作为同一部署单元。Vision 修复先于扩大 DNS buffer。
4. **阶段四：网关和配置。** 完成 D4、D5、C1 至 C4、N1。每个独立问题与测试单独提交，保留可回退的边界。
5. **阶段五：223 正确性观察。** 固定三仓版本，以现有主要 fallback／url_test 的 quality observe 范围和采集抽样验证；采集、预算、身份无异常后完成这批上线验收。
6. **阶段六：UDP 恢复。** 先交付 U1 的 off／observe，再交付 U2；observe 证据不足时继续留在观测状态。
7. **阶段七：性能。** P1 至 P3分别做 A/B，达到验收才启用。性能实验和 UDP 恢复执行模式分别部署，便于归因。

同一仓库内可按协议拆提交；跨仓库发布遵循“依赖测试 → 发布 immutable commit／pseudo-version → 消费者 pin 与适配 → 有效模块图验证”。临时集成可使用隔离工作树和 replace，正式产物必须恢复发布版本、关闭 GOWORK，并检查 go version -m。

为避免半套契约，D1 至 D3不能与依赖升级分成不同的部署批次。已经发布的兼容性协议修复不要求 dae 提前启用 UDP 恢复或性能开关。

## 验证与 223 验收

### 开发与构建

Go 操作先使用项目的持久缓存：

    export PATH="$PWD/hack/bin:$PATH"
    . hack/env.sh
    make print-go-env

各单元先执行能覆盖自身风险的测试。依赖 pin 完成后执行：

    scripts/fork-cross-repo-test.sh --strict --short --clone-missing -- -race -p=1
    go vet -tags dae_stub_ebpf ./common/... ./component/... ./config/... ./control/... ./cmd/... ./tools/dae-rule-sync/... ./scripts/...
    make test
    make test-race
    make dae

上面的跨仓库命令要求 G0 已完成；脚本已按有效模块图识别 Fan-chou 依赖；本轮采用 strict 并测试固定提交。发布前还要跑依赖的相关完整集成测试，short 不是替代。eBPF 未改时验证正常编译及既有 relay/live smoke；P1 至 P3若涉及 kernel／offload 能力，追加 make ebpf-test、make ebpf-lint 与对应内核实测。

386 的长度与 padding 用例要执行。race 留在支持 race 的 amd64／arm64 平台。状态发布、预算和重载测试覆盖 ARM64；需要检查合法状态组合，单纯 race 通过不足以证明多 atomic 的一致性。

### 线上比较口径

先记录升级前基线，再在相近流量与时段比较。RSS、吞吐、p95／p99、重传、CPU 和分配分别记录，不把 RSS 波动直接归因于队列修复。

| 检查 | 验收要求 |
| --- | --- |
| capture stats | 按新代重新读取、取区间增量；各比例明确分母，分别看 sampled、窗口数与 queue 入队。invalid_window、queue_dropped 的增长需要定位 |
| offload_unmeasured | 按 offload／splice／用户态路径和组分别解释。不能为了降低这个比例关闭 offload，也不能把 unmeasured 当零流量 |
| splice 字节 | 复用本次 20 MiB 真实传输的核对方法，增加双向及并发场景；核对实际传输、节点、本流及归档，研究窗口快照偏差单独统计 |
| quality observe | 记录会提出切换的原因、频率和站点分布；区分 observe 建议与实际首选恢复，不根据包丢失计数直接降级节点 |
| recovery 预算 | 检查只由成功首选恢复提交递增；真实故障切换、预算竞争和 UDP rebuild 不消耗它；保留每站点 2、每组 10／30 分钟与组间隔 |
| QUIC 生命周期 | DATAGRAM queue storage 有界；取消不关闭共享会话；日志不阻塞；原始发送观测与应用供给状态仍可读取 |
| UDP 身份与重载 | H3／WG 暂停前后源端口稳定；TCP pin 不被 UDP 改写；跨地址族别名和 retained endpoint 能交接 |
| DNS 与 REALITY | 大应答、TCP 升级、IPv6 bootstrap、新旧 REALITY 形态分别验证；日志不能把可恢复丢包算作节点失效 |

对新 UDP 策略，至少覆盖完整的视频暂停和游戏往返场景，并观察候选在各类端口／协议上的分布；只按运行时间到点不能开启 enforce。先确认没有密集候选和源端口扰动，再考虑限制范围执行。

性能验收使用同一工具链、配置、GOMAXPROCS、采样率和依赖版本做多轮 A/B。收益必须超过测量噪声；关键延迟、丢包和内存不能出现稳定恶化。没有足够流量覆盖的场景标记为未验证。

### 回退

每次部署保存二进制、有效模块图、配置及基线指标。UDP 或性能候选出现问题时先关闭对应开关；正确性批次失败时回退整个固定产物及适配配置。归档证据保留，代际切换记录新的 generation／cursor，不回退或抹除历史数据。

## 已有复现证据与设计状态

上一轮在隔离源代码副本中做了四项定向复现：

| 用例 | 当前基线结果 |
| --- | --- |
| QUIC queue 持续不排空 | live=2；20,000 次循环后容量由 512 增至 24,576 |
| 内部 DNS 大应答 | dns: overflow unpacking uint16 |
| Vision 全范围 buffer | len(p)=65,536 时返回 short buffer |
| QUIC Initial 超大 token，GOARCH=386 | slice bounds panic；protected payload 还需独立构造有效前缀验证 |

这些证明相应缺陷可以复现，不代表所有推荐项已有回归测试，也不代表修复后的 gate 已通过。复现使用项目 wrapper 选择的 Go 1.27.0；方案基线中的 go.mod 要求为 Go 1.26.0。正式比较沿用项目构建工具链，并记录实际版本。

本轮交付为方案及历史复核。实施状态按 G0、Q、O、D、C、N、U、P 各单元记录，完成条件为对应测试、依赖发布、消费者验证及线上观察全部满足。


## 上游来源

下面的来源固定到本次审计 commit。实现前以原始补丁、当前文件和历史约定三方对照；不直接按提交日期排序覆盖。

| 来源 | 内容 | 仓库与提交 |
| --- | --- | --- |
| S1 | QUIC DATAGRAM queue bounds and send-frame ownership | olicesx/quic-go：[edf4a231](https://github.com/olicesx/quic-go/commit/edf4a2315414bca8f902b568762896701dc4a2da) |
| S2 | REALITY authentication and fingerprint compatibility | olicesx/outbound：[05bf2759](https://github.com/olicesx/outbound/commit/05bf2759bfd8ab67189f7348cd27316280093ffa)、[f0fdbaa1](https://github.com/olicesx/outbound/commit/f0fdbaa1125bd8359b918a5666a7e71d5b759483)、[cbc7ff26](https://github.com/olicesx/outbound/commit/cbc7ff26257ca95fb9d3b607c2523f3b57c42db8)、[29060b67](https://github.com/olicesx/outbound/commit/29060b6733c73d471535d93e5004190dafeaee32)、[cc86ced2](https://github.com/olicesx/outbound/commit/cc86ced2e683b91387f2cde7cfcadcb5ac2adbc3) |
| S3 | UDP datagram integrity | olicesx/outbound：[6504594f](https://github.com/olicesx/outbound/commit/6504594f1e918dcf8d73421c416501fb632d4ff5)、[d0a4aa65](https://github.com/olicesx/outbound/commit/d0a4aa6594bbb757f96e99a5c628b567f754759c)、[759b1253](https://github.com/olicesx/outbound/commit/759b1253c5845fb54dc264edf772d184ac11f349)、[70dfd0b8](https://github.com/olicesx/outbound/commit/70dfd0b84a560318b97e73607f5b58123f9ee88f)、[c8e883c0](https://github.com/olicesx/outbound/commit/c8e883c0007ebbee4edecf0f8c1a6392478bb6b2)、[37417ec9](https://github.com/olicesx/outbound/commit/37417ec9a7cf2fd8ed7719b5a52fa65bf5a44462)、[4163e01a](https://github.com/olicesx/outbound/commit/4163e01a20a9a78d00d2839a71444658f2c3dadd) |
| S4 | DNS dropped-datagram handling and full-message internal buffer | olicesx/dae：[56ffe564](https://github.com/olicesx/dae/commit/56ffe5643613fc5f2c1cbb1ab620ddcfa924e555)、[1b7aeb70](https://github.com/olicesx/dae/commit/1b7aeb70e7e1d82d31a4c55284063a62490dc08f)、[6f80502f](https://github.com/olicesx/dae/commit/6f80502f11266f5bd4eefa66ab6ebe3029fbfd66)、[a1fb0117](https://github.com/olicesx/dae/commit/a1fb01174d65b1f06e3d59ddfade7846c9c7f542) |
| S5 | Protocol E2E defects | olicesx/outbound：[165d0397](https://github.com/olicesx/outbound/commit/165d03975b5bb000bc99ca7cc5b5c635d29c9483)、[6a44445c](https://github.com/olicesx/outbound/commit/6a44445c910611f127dafb0ee1a0c12baeb00d80) |
| S6 | IPv4 gateway redirect policy | daeuniverse/dae：[e3fee8fb](https://github.com/daeuniverse/dae/commit/e3fee8fbc68a65167af13b685ab0b958757e20ee) |
| S7 | Bootstrap resolver address family | daeuniverse/dae：[e6e52bbc](https://github.com/daeuniverse/dae/commit/e6e52bbc3c75211f318c59f5890f6ba13e7effde) |
| S8 | Malformed ext routing input and 32-bit QUIC sniffing bounds | olicesx/dae：[39c764f7](https://github.com/olicesx/dae/commit/39c764f7f53a41cd4c09d50f43921ca82c1b936a)、[0ab7b6e0](https://github.com/olicesx/dae/commit/0ab7b6e05541b6ce1065df9199137e5dea35882a) |
| S9 | Configuration and subscription determinism | olicesx/dae：[f07f81c9](https://github.com/olicesx/dae/commit/f07f81c9ed40c6b3db83f514026c17f35591388e)、[69ac2234](https://github.com/olicesx/dae/commit/69ac223409b63f411025210f84f94b71f8e79167)、[1e4e47cf](https://github.com/olicesx/dae/commit/1e4e47cf59b23b6853bf0ae0ea49e733adf58bbf)、[ea0eb3ad](https://github.com/olicesx/dae/commit/ea0eb3ad8309c77108280ab92a01bb47c43d79fe) |
| S10 | Stale named netns cleanup and startup failure diagnostics | daeuniverse/dae：[2649d5b3](https://github.com/daeuniverse/dae/commit/2649d5b3e853249ccb45527066a0d7cbffff465d) |
| S11 | QUIC shutdown, HTTP/3 GOAWAY and trace behavior | olicesx/quic-go：[ba274cf4](https://github.com/olicesx/quic-go/commit/ba274cf41f18c1221de1fdf009d7fe211133e106)、[a3269acd](https://github.com/olicesx/quic-go/commit/a3269acddc81de5c06dd4f58c5e8cd58403b7638)、[271dd429](https://github.com/olicesx/quic-go/commit/271dd429f06b80ef1bda2cc50c3e058d7a2180d5)、[1c9ad297](https://github.com/olicesx/quic-go/commit/1c9ad29713b4a2433c062b60e9ab575bafa61e38)、[a7f4e18c](https://github.com/olicesx/quic-go/commit/a7f4e18c891ad28853f1a032dcd66cf7b5d5a032) |
| S12 | UDP reply-drought recovery | olicesx/dae：[12eccca3](https://github.com/olicesx/dae/commit/12eccca311b64f13c6beb80c57057c5a2068a3a5)、[907d1d7d](https://github.com/olicesx/dae/commit/907d1d7d28fff37b49264eab79af182c25e91ca2) |
| S13 | Transport optimization campaign | olicesx/dae：[555e2bd4](https://github.com/olicesx/dae/commit/555e2bd40aa69da3d6610a82e16f558650e2075c)、[b4a6352e](https://github.com/olicesx/dae/commit/b4a6352e82b8f526634caf150c70b77866070199)、[fce18b20](https://github.com/olicesx/dae/commit/fce18b201308d7f7a2ed8edc68da69ed5c834caa) |
| S14 | digit-prefix 提示、fixed_domain_ttl 校验、Marshaller.Bytes | daeuniverse/dae：[5a5473d5](https://github.com/daeuniverse/dae/commit/5a5473d5123983588f6d0befbb41ae3f7a744234)、[6f2f2aa6](https://github.com/daeuniverse/dae/commit/6f2f2aa66084f3d736e4bf86a327e3523b3cdede) |
| S15 | 可选 systemd 环境文件 | olicesx/dae：[c307cbee](https://github.com/olicesx/dae/commit/c307cbeec077177a3490d6313f6ea3188fe02817) |
| S13 补充 | 最终 socket control、GSO、arena 生命周期修复 | olicesx/outbound：[25dd1ad1](https://github.com/olicesx/outbound/commit/25dd1ad1c62d227bbc64fbb23d98d6d60ee5f5ab)、[49424e48](https://github.com/olicesx/outbound/commit/49424e4822908991e24a49504a3e3977e6cb8b7a)、[33ffd1da](https://github.com/olicesx/outbound/commit/33ffd1dab4954f894c2dcc0c43abe86da5a001b3)、[9c6c1b9a](https://github.com/olicesx/outbound/commit/9c6c1b9aaced3c78775f36d1ac3ef802808dc9be)、[04be789b](https://github.com/olicesx/outbound/commit/04be789bbeebff55c2eac3fcc50873398ae7ea07) |
| S11 补充 | 上游 qpack pin 供依赖评估 | olicesx/quic-go：[84fb05e4](https://github.com/olicesx/quic-go/commit/84fb05e43a62fd8368a6f91565afe111cc7e4b4e) |
