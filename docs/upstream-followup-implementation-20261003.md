# 上游跟进实施记录

日期：2026 年 10 月 3 日。对应[设计与历史复核](upstream-followup-plan-20261002.md)。

阶段一至四的 20 个单元已落地并提交；正确性批次已部署到 223。阶段五已完成初步健康检查、五分钟观测和真实 splice 核对，仍缺长时间业务覆盖。U1／U2 与 P1 至 P3 尚未实施，后续依照方案分别观测和做 A/B，不能将本记录理解为全部 25 个单元已经验收。

## 固定版本与历史约束

| 项目 | 本次有效版本 |
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
