# 被动 TCP 观测（capture-v1）

采集用于量化真实输入的可观测性，不改变选路、质量处罚、恢复试探或 offload，也不调用 Laya。默认关闭。当前记录不能直接作为 V4 的完整输入，适配状态固定为 `adapter_abstain`。

## 配置与读取

在现有 `global` 中增加：

```dae
capture_enabled: true
capture_sample_permille: 25
capture_group: AI
```

`capture_group` 为实际选路结果的顶层组名称，大小写精确匹配；空值覆盖所有组。`25` 表示 TCP 在选路前按连接抽取 2.5%，阶段证据与接管成功后的流窗口共享该次抽样；capture-v1 的复合选路记录另行独立抽样。DNS 按事件独立抽样。默认采样值为 100。Laya、quality_mode 保持各自原配置，不需要启用。

通过现有、带 Bearer 鉴权的管理接口读取 `GET /v1/capture?after=0`。每页最多 256 条，下一页使用 `next_sequence`；读取不删除记录。同一代内按 `(generation,id)` 去重。代次改变时从 0 重新读取；`oldest_sequence > after+1` 表示发生环形覆盖，必须记录缺口。接口沿用管理监听地址，不额外开放服务。

在研究机器保存响应为 `snapshot.json`，然后运行：

```sh
python3 tools/laya-capture/validate.py snapshot.json --output availability.json
python3 tools/laya-capture/archive.py snapshot.json data/laya-capture
```

归档包含 JSONL、SHA-256、缺失率及未标注状态；单日初始预算 100 MiB，超过预算拒绝写入。工具不请求网络、不读取凭据，也不自动删除文件。研究机定期人工检查超过 7 日的原始记录，保留需要复核的证据后再清理；路由器只保留 RAM 环，不写研究记录到闪存。

## 记录含义与不能推断的内容

| 字段 | 来源／限制 |
|---|---|
| `stage=route_resolve_dial` | 完整 routeDial 的耗时和结果，包含选路／解析／连接，失败不能直接视为叶节点握手失败 |
| `stage=relay` | 已选路后的流生命周期；接管失败为 `adopt_abandoned`，取消为 `canceled`，不计为质量失败 |
| `up_bytes/down_bytes` | 原 TCP accounting 回调，用户态 relay 每约 15 秒切窗，结束窗口标记 partial；不是链路容量 |
| `node_up_bytes/node_down_bytes` | 同一观测边界读取节点累计量的增量；独立原子计数存在快照偏差，标记 `best_effort_non_atomic_snapshots`；重置或节点量小于自身量时留空；结束窗口的节点快照晚于流结束，也留空，防止纳入结束后的其他流流量 |
| `first_downstream_callback_ms` | 从采集登记至首个下行 accounting 回调；不是纯远端 TTFB，不包含先前完整拨号耗时 |
| `offload_or_unmeasured` | 不尝试用 offload 回调恢复严格窗口，字节留空；不会为了测量禁用 offload |
| `scope` | 站点／叶节点／顶层组 HMAC 标识、所选健康网络、直连／代理／未知、策略代次；节点标识包含链接身份，输出不含链接 |
| `control/dependency/demand` | 当前均留空，附缺失原因；未接入独立对照、DNS／网关关联、应用 backlog |
| `active_ms/read_paused_ms` | 留空；连接存在或有字节不能证明应用在持续读取 |

HMAC 随控制平面代次生成随机密钥，代内稳定，重启／重载后改变。不输出 URL、原域名、节点名称、请求正文或凭据。未嗅探到站点时站点标识为空，不使用目标 IP 冒充域名。当前不输出完整嵌套路径／协议，也未对失败发生阶段作更细归因。

`episode_id` 只是临时流／选路事件标识，同一流窗口共享它。选路事件与后续 relay 独立采样，不能相加当作独立故障；共享 DNS／网关根因仍需人工合并。校验报告明确标记 `root_cause_independence=unreviewed`，不会生成 gold。

## 资源与诊断

- 登记最多 512 条流；登记锁忙或满时放弃研究采集，不等待。
- 已登记流的字节热路径更新原子计数，并在首次下行回调记录一次时间；后续回调不再读取时钟。DNS 先抽样，入选后才为采集解包回复、遍历答案并生成伪名。入选 TCP 的流登记、阶段标识及队列仍有开销；热路径不进行序列化、磁盘、网络或模型调用。
- 后台一秒检查一次窗口，队列 256 条；队列满丢研究记录。
- 单记录最多 16 KiB，RAM 环按序列化内容最多 8 MiB；这不是进程 RSS 上限，还存在 Go 对象／队列开销。
- API `stats` 中 considered 计 TCP 抽样机会一次，sampled 计接管成功且登记成功的流；route_considered / route_sampled 单独计复合选路抽样。另提供 admission_dropped、queue_dropped、oversize、invalid_window、offload_unmeasured、ring_evicted。出现采集丢失时不能将样本当作无偏完整分布；`inclusion_probability` 仅指入选概率，不包含负载丢弃概率。
- 启动日志 `event=passive_capture` 给出采样和上限。关闭／重载会终止该代采集，尚未导出的尾部可能丢失；已有业务流继续运行，不持有模型依赖。

本阶段交付是被动采集与可观测性审计。缺失独立对照、应用需求和严格对齐证据时保持弃权。真实标注、完整证据关联器、V4 隔离 CPU shadow 与风险阈值验收仍是后续阶段，不能仅凭这里的流量数据宣称置信度有效。


新增的独立证据流及跨主机关联见 [证据采集与关联](evidence-correlation.md)。原始 v1 格式保持不变；新流阶段与 relay 使用同一次 trace 抽样，旧复合 route 记录仍独立抽样。
