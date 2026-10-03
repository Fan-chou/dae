# 上游修改跟进方案与历史决策复核

日期：2026 年 10 月 2 日。状态：2026 年 10 月 3 日阶段一至四的正确性修复已提交；依赖已发布并固定，已部署到 223。阶段五初步实测通过，长期及定向场景仍待验证，详见[实施记录](upstream-followup-implementation-20261003.md)。

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

下表保留各单元的设计和验收要求。G0、Q1 至 Q5、O1 至 O4、D1 至 D5、C1 至 C4、N1、U1 已落地；P1、P2 的默认关闭候选已实现。P1 完成 220 的隔离内核矩阵及两种真实代理的 WAN 初测；P2 完成自然前缀与受控分段对照，尚无生产启用收益证据。P3 已复核最终生产调用：新增 GRO 与 arena 没有生产入口，保留既有 QUIC GSO，暂不移植未接入的 helper。U2 仍待真实业务语义验证。线上验收缺项见实施记录。来源对应文末的上游提交表。修复与能复现问题的测试放在同一提交；跨仓库依赖以发布版本连接。

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

独立的 global.udp_reply_drought_mode 已按 off／observe 实现，默认 off；配置拒绝尚未实现的 enforce。它不由 quality_mode 隐式启用。client IP、精确 outbound group 与可选 IP:port peer 限定观测范围；这些字段不建立业务回复语义。

| 单元 | 设计 | 历史关系 | 验收 |
| --- | --- | --- | --- |
| U1 证据与模式 | 有界记录代理 data session 的本地成功写与有效回复；DNS、直连退出。unknown 语义始终排除候选；明确服务可声明 request_reply，并限定 IP:port。六个完整 5 秒桶各至少 10 次非空成功写、至少 3 次回复历史、30 秒无回复，仅作为观察初值；队列接受不等于完成发送 | 新行为扩展，保留 6d167837 的静默保护 | H3 视频间歇、WG keepalive、长暂停后的单包、单向数据、回压、旧桶和错误后的当前桶不能触发；observe 不改源端口与 endpoint |
| U2 执行与 peer 隔离 | 独立 rebuild ledger，按稳定关联身份和 peer 隔离；初始上限沿用 256 项、1 分钟 TTL；重建后再次尝试前要求至少 3 个有效回复；先登记预算再发布 retire | 适配 FIFO、代际、身份与预算历史，来源 S12 的后续排序修复一同引入 | 全锥中故障 peer 拆出，健康 peer 保持；绑定目标协议不 promotion；重载、别名、批量 flush、预算竞争和晚回调测试 |

用户选择 CS2 官方匹配的 SDR 作为业务覆盖目标。[Valve 的 SDR 文档](https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay?l=english)描述了中继与连接票据。本项目当前只能看到代理侧 UDP 的 peer 和收发结果，无法确认游戏阶段及此时应有的回复，因此 CS2 保持 unknown。端口、域名、SDR 地址范围和过去曾有回复，都不能替代当前回复资格；没有合格候选时保留排除统计，不放宽条件制造候选。U2 要在真实对局阶段标注、请求／回复义务与暂停保护验证后再设计执行路径。

2026-10-03 的 201 实测新增 U1 验收门槛：先修复 NAT-preserving transport 的实际 peer 归属和 WriteTo 返回前的早到回复，再解释无回复频率。保留向客户端返回原 NAT 地址的契约，通过独立的实际 peer 元数据关联；不能把所有 raw reply 强行归到固定目标。补 Hysteria2 FakeIP 的 push／ReadFrom、写内同步回复、Shadowsocks 不同 IP／端口与 mapped IPv4 隔离回归。未归属计数需要按 association 定位，混合 Google／Steam 流量的全局数不能直接归因给游戏。reload 保留的旧流与新 observer 账本要明确标为覆盖缺失。

“客户端持续发送但没有回复”也可能是单向应用、对方策略或丢包，不能标注为节点已坏。在 observe 中先记录候选频率与协议／端口分布。enforce 初期仅覆盖有明确双向语义和已有回复历史的范围；只看端口或 SNI 不能认定 H3、游戏或 WG 的应用状态。

U2 的预算与站点首选恢复预算分开。UDP 重建不直接写 TCP 或 UDP 的站点 leaf，也不把稳定节点变更作为恢复成功；先保留当前身份和选路结果，经现有故障策略需要重新选路时再处理。旧代不能直接修改新代的关联／ledger，跨重载继承由明确的所有权交接完成。

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

    scripts/fork-cross-repo-test.sh --strict --short -- -race -p=1
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
