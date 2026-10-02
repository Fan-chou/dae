# 被动证据采集与关联

本功能扩展现有 `kdae-capture-v1`，新增 `kdae-evidence-events-v1` 事件流；两者均不是 V4 模型输入，也不生成训练标签。模型离线、归档失败、队列满均不能影响选路。原 Laya／quality 开关不变。

## 已采集事实

- `selection_resolution`：选择与内部解析的复合阶段，不能当作节点握手失败。
- `dial`：实际所选 Dialer 的拨号阶段；代理协议握手可能包含其中，不冒充目标网站 TLS 测量。取消、超时、其他错误分开，不输出原始错误文本。
- `flow_link`、`relay_end`：统一 flow_id，连接到原 capture episode；流抽样与阶段抽样共享同一次选择，避免独立抽样使关联率降为概率平方。
- `load_window`：同一流窗口自己的累计量、节点累计量减去自己的量；非原子快照、计数器异常、offload、结束窗口缺失明确保留。活跃连接数和 starts_total 是快照计数，不是同窗口平均或需求指标。
- `dns_upstream`：本机实际上游调用的协议响应码、A/AAAA 数、FakeIP 数、TC、耗时、脱敏上游和地址；不代表上游内部缓存／过滤已可见。
- `dns_cache_hit`：明确的本机 cache/stale cache 命中分支；不伪造最初填充缓存时的 DNS event ID。
- `dns_client_reply`：准备交付客户端的回复（FakeIP rewrite 后），不是客户端确认收包；cache_status=unknown，因为这个公共回复路径也可能发送新解析结果。
- 222 `smartdns_audit`：审计行中的耗时和结果。在内存中脱敏再落盘，原域名、客户端地址和 IP 不进研究归档。没有 RCODE/TC/缓存来源/具体上游/过滤原因的字段保持未知。空结果只能叫 empty_result，不能伪造 NOERROR 或节点故障。

域名、节点、目标、上游、客户端均使用分类型 HMAC 标识。`KDAE_EVIDENCE_KEY_FILE` 可指定 32 字节私密关联密钥；只有观测进程和归档端持有。不同进程代次仍使用随机 generation，不能把重启前后计数器拼起来。密钥不是训练材料，不能打入数据包。未指定时证据只能在本进程代次内匹配。

## 有界资源与配置

`capture_enabled` 仍是总开关；`capture_sample_permille` 是固定抽样率；`capture_group` 仅限制 TCP 选路结果，DNS 事件按同一比例跨组采集，因为 DNS 发生时未必已知最终业务组。

- 原流缓存 8 MiB，新增证据缓存 4 MiB；各有 256 条有界队列。
- 热路径不落盘、不访问模型、不新增测速、也不重放用户请求。
- 新认证端点 `GET /v1/evidence?after=...`，每页最多 256 条。端点使用原 admin secret。
- queue_dropped/ring_evicted/oversize 分别可见。关闭／重启时未导出的尾部可能丢失，generation/gap 必须保留。
- 采集初始化失败写警告并停止采集，正常路由继续。

## 220 归档

安装后的目录：`/root/dev/laya/data/kdae-real-evidence-v1/`。

```sh
python3 tools/laya-capture/collect_evidence.py \
  --key-file /root/.config/kdae-evidence/identity.key \
  --output archive
```

从 223 读取带认证的 capture/evidence 分页，校验后写不可变 SHA-256 文件和 manifest，之后才提交游标。manifest 保留运行二进制 SHA、generation、采集统计、丢失区间。文件／游标落盘使用 fsync。单次默认每类最多 4 页，磁盘每日预算 100 MiB；达到预算即报错并保持相应未归档游标。新 generation 从 0 重新读取，不沿用旧游标。

222 每轮读取最近 2000 行审计日志，仅保留在已选流最早观测事件开始之前 10 秒内结束的同域名记录、空 A 结果和按哈希抽取的 2.5% 背景记录，并对重叠尾部去重。这是有偏的尾部样本，不是完整事件流，不能给它填写抽样概率 1；可能漏掉高峰期日志，也会重复。事件 ID 由行内容稳定生成，合并时去重。不存在的原始事实不通过字符串猜测。

生产定时器每 2 分钟执行一次；断开 220 不影响 223 转发。日志由 systemd journal 保留，`archive/latest-status.json` 给出本轮计数和 gap。原始文件不自动清理，以免删掉已标注事件的证据引用；每日预算不等于总磁盘预算，需定期归档或停用定时器。

## 离线关联与审核

```sh
python3 tools/laya-capture/evidence.py evidence-page.jsonl smartdns-page.jsonl \
  --captures capture-page.jsonl --output review.json
python3 tools/laya-capture/annotations.py review.json annotations.json
```

不能把 capture JSONL 混进第一个参数列表。使用 manifest.endpoint 区分文件类别。

关联规则：

1. 同 generation+flow_id 的阶段是精确流关联；capture_episode_id 连原始字节窗口。
2. DNS 仅按脱敏域名、可用的客户端及时间匹配候选，默认 10 秒；DNS 与连接实际消费关系尚未端到端打通，不能标记为精确引用。
3. 不同节点的拨号只有同代次、同策略版本、同网络、同目标并在时间范围内才列为候选；同 IP 候选与同主机名候选分开。相同主机名可能对应不同 CDN，不算强对照。
4. 跨主机时钟未经过精度验收，所以 222↔223 一律候选关联。
5. 每条流以第一个关闭窗口或首个拨号结束为回放判定时刻。只有当时已经结束的事实能进入 input_event_ids；后续恢复另列 followup_event_ids_not_model_input。
6. incident_id 留空，必须人工将同一 DNS/网关故障的多个域名合并为根因事件。原始窗口数、抽样数和独立事件数不等价。

审核使用两个不同、未看模型答案的人工复核者。每个任务填写 supported/contradicted/unknown、证据 ID 与理由。分歧未解决不能通过审核；相同 incident_id 不能跨 train/calibration_fit/policy_select/final_test。校验器只能检查格式和声明，不能证明复核者真实独立或判断正确。

## 尚不可观测的边界

应用持续需求、加密应用读取背压、SmartDNS 内部丢弃原因、网关丢包的单节点归因、缓存最初填充 ID、独立控制请求均没有凭空补齐。没有足够事实仍 adapter_abstain。第一批数据只作 development/research，不能宣传为置信度已校准或可启动自动降级。

按归档 manifest 自动区分数据类型、验证哈希并生成可填写的标注模板：

```sh
python3 tools/laya-capture/review_archive.py --archive archive --day 20260926 \
  --output review-20260926.json --annotation-template annotations-20260926.pending.json
```

模板的 label、复核者、incident_id 均未填写，故意不能通过 annotations.py；填写前不是训练数据。审核事件与原始源文件 SHA 一起保存。审计尾部样本去重后仍不能当作自然抽样校准集。

## 归档一致性与伪名威胁模型

客户端 DNS 候选必须在流内最早事件开始前结束，并处于之前 10 秒内；本机发起的 `dns_upstream` 单独列入 `dns_upstream_candidates`，只表示同站点及时间相关的上游调用，不当作客户端前置解析。模型决策时刻仍使用首个已关闭负载窗口的结束时间。连接开始之后的 DNS 回复不作为该连接的前置解析证据。跨主机时钟未验证，关联只表示候选关系。

归档数据和清单分别用同目录临时文件写入、fsync 后原子替换，并同步目录；完整数据先于清单发布。中断留下完整数据而无清单时，下次补写清单，已有数据不重复计入预算。evidence 游标与对应 DNS 锚点写入同一次状态提交，因此 SmartDNS 主机失败后可以继续关联已采集连接。

共享 HMAC 密钥支持跨主机关联，支持 32 原始字节或 64 个十六进制字符，密钥必须是仅属主可读的普通文件。密钥错误只关闭 evidence，capture-v1 继续使用本代随机密钥。`flow_link.outcome=unmeasured` 表示采集登记未成功，不能当作已取得负载窗口。

持有共享 HMAC 密钥的归档端可对常见域名和客户端地址执行字典枚举，反推出 site/client 伪名；伪名不能对密钥持有者提供匿名性。威胁模型将研究归档端和密钥持有者视为可信主体；密钥与归档应限制访问权限，避免将密钥随数据分发。capture-v1 的随机代际密钥不落盘，不具备相同的跨代关联能力。

复核身份按 Unicode NFKC、大小写折叠及空白合并校验。校验 incident 是否跨 split 时，应把所有相关标注文件一起传给 `annotations.py`；单独校验一天的文件不能排除其他日期中的冲突。
