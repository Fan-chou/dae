# 本地 TCP 下载质量与可选 Laya

本功能默认关闭。`quality_mode` 属于组的本地规则，与 Laya 是否开启无关。只对 fallback / url_test 选中路径的 TCP 新连接进行受限试探，既有连接不迁移、不重放请求、不因低速标记节点 dead。

## 配置

在源 `.dae` 配置的对应组中设置，而非手改转换器生成文件：

```dae
global {
    laya_enabled: false
}
group {
    Download {
        filter: name(keyword: download)
        policy: fallback
        quality_mode: observe
        quality_min_download_bytes: 65536
        severe_speed_ratio: 0.30
        recovery_speed_ratio: 0.60
        quality_window: 15s
        severe_speed_windows: 3
        recovery_speed_windows: 3
        quality_evidence_ttl: 2m
        speed_improvement_ratio: 1.5
        speed_improvement_bytes: 262144
    }
}
```

这是嵌入已有配置的片段，需保留原节点、路由及其他配置。`off` 关闭本地吞吐质量判断，主动节点健康检查和站点首选恢复继续运行；`observe` 只采样和对比，不改变选择；`enforce` 执行本地局部试探与提交。正式切换固定为至少间隔 5 分钟，每站点/网络槽每 30 分钟最多 2 次，每组最多 10 次、组内两次提交至少间隔 5 秒。试探租约 60 秒，失败/样本不足按 2/5/10 分钟退避。

`quality_window` 必须为 5 秒的整数倍，范围 10–60 秒。默认三次 15 秒有效窗口，即约 45 秒持续下降后获得质量试探资格；正式试探还须满足驻留和预算，不保证第 45 秒必然换节点。

`quality_min_download_bytes` 是绝对不可接受的活动下行速度，单位 bytes/s；默认 `0` 关闭。当前配置示例下调为 `65536` = 64 KiB/s，对应恢复门槛 96 KiB/s；这是保守的初始设置，尚未经实际线路验证。低于绝对下限或低于相对参考比例，任一条件持续满足即可进入本站点问题评估；绝对下限不依赖历史基线，并且不会被“相对历史正常”或另一条规则恢复所覆盖。绝对规则恢复需连续 `recovery_speed_windows` 个有效窗口达到下限的 1.5 倍。备选也必须达到该绝对恢复门槛，有相对参考时还须同时通过相对恢复门槛。

绝对下限仍只作用于有效传输窗口；小流、暂停、背压、offload 缺测不算节点故障，仍有 1 MiB 采样登记门槛。因此不是连接建立 45 秒后无条件判坏。该值是整个组的最低运营标准，应只用于符合这种下载预期的组，不能拿来惩罚本来只有少量流量的业务。

`quality_required_download_bytes` 可选，默认 0（未知）。只有能验证整个组业务要求时才设置，单位 bytes/s。设置后以该需求为参考，满足需求时不因历史峰值更高而降级；已进入低速状态后仍需连续 `recovery_speed_windows` 个恢复窗口才能清除标记；单独配置的绝对最低标准仍生效；普通混合用途组应保持 0，不根据主机名猜一个需求。

Mihomo 源 YAML 使用明确的 kdae 扩展，转换时保留：

```yaml
proxy-groups:
  - name: Download
    type: fallback
    proxies: [node-a, node-b]
    x-kdae-quality:
      mode: observe
      min-download-bytes: 65536
      severe-speed-ratio: 0.30
      recovery-speed-ratio: 0.60
```

这是 kdae 转换器扩展，不是 Mihomo 原生选路选项。其余本地参数使用默认值；Laya 全局开关放在主 `.dae` 源配置，不从订阅获取密钥。

## Laya 可选配置

```dae
global {
    laya_enabled: true
    laya_mode: shadow
    laya_endpoint: 'https://laya.example:8765'
    laya_credential_file: '/etc/laya/api.key'
    laya_ca_file: '/etc/laya/ca.pem' # 可选；系统信任的证书无需配置
}
```

凭据文件位于**运行网关的机器**，支持单独 token 或 `LAYA_API_KEY=...`，不要把密钥写进日志或组配置。关闭时不会读取密钥、启动 worker 或请求模型。开启后只有状态变化摘要进入后台，最多一个在途请求和一个最新待处理摘要；请求必须使用 HTTPS，不读取 HTTP_PROXY/HTTPS_PROXY 环境变量；3 秒超时，输出上限 64 KiB，不跟随重定向，失败退避且不阻塞选路。

使用 220 的自签证书或私有 CA 时，将签发 CA 的 PEM 文件放在运行网关的机器，配置绝对路径 `laya_ca_file`。该证书加入系统信任根，仍验证服务端主机名／IP；访问 IP 时证书的 SAN 必须包含该 IP。CA 文件缺失或无有效证书时模型请求失败并退避，本地规则继续运行；不会跳过 TLS 验证。关闭 Laya 时不读取 CA 文件；修改 CA 文件后需重载 dae。

目前模型仅作影子对照。`laya_mode: assist` 会明确记录 `effective_mode=shadow / reason=model_action_not_validated`，不会把未验收模型变成自动降级授权。模型在线、离线、超时、返回无效概率，都不改变本地规则资格。关闭或重载取消 worker 和未完成请求；两分钟前的排队摘要丢弃。

## 怎样判定速度

每个启用组使用一个共享采样器，每 5 秒检查达到 1 MiB 的候选流，最多 4096 条；每组最多 4096 个主机/网络槽记录、8192 个节点质量记录，每个记录最多 32 个节点。没有每条连接独立的 ticker。

只在用户态下行写入处测量数据与写阻塞时间，上行复制和半关闭继续使用原连接；先尝试内核 offload，已 offload 的流不为观测降回用户态。样本要求窗口内每次采样都有数据、阻塞时间低于窗口的 20%；握手、小流、暂停、缺测不会直接判坏。可使用 splice 的 TCP 连接保留原快速路径，其吞吐质量窗口记为缺测。其余用户态下行连接先用原子计数累计字节，达到 1 MiB 后登记一次，成功登记的流才测量后续写入阻塞时间；登记被拒绝后不重复抢锁。observe 也有这些用户态计量成本，应先验证资源开销。

需求未知时，参考为同完整主机、节点和 TCP 地址族至少六个有效窗口、来自至少两个自然流的吞吐中位数，有效 30 分钟。异常期间不降低基线；缺少基线只靠周期恢复取证。多个重叠流不累加成独立窗口。没有背压不能证明应用需求，因此此时日志明确是 `relative_speed_collapse`（局部比较信号），不宣称节点容量不足。

备选必须有自己的有效参考（或启用了绝对最低标准），连续两个有效窗口比当前至少快 1.5 倍且增加 256 KiB/s、自己达到恢复比例（默认参考的 60%），才可提交质量切换。没有可比证据就保留原稳定节点。周期恢复仅试探 fallback 声明顺序更前的合法节点，可以非慢首包作为恢复依据；质量试探不能靠首包提交。

URL-test 在严重局部下降时通过同一有界试探验证备选；平时仍用原分数及 tolerance。候选通过原嵌套选择图产生，不展开所有叶子绕过 fixed；子组启用质量不能跳出该子组。完整主机名键不改其他使用 eTLD+1 的缓存。

## 日志与只读诊断

Info 级结构化日志：`event=local_quality`，含 group、host、network、mode、reason；试探/提交额外含 probe_id、generation、old_leaf、candidate、deadline/next_probe_at。没有完整 URL、请求内容或凭据。一般事件每组每分钟最多 20 条，多余计入 suppressed_logs；正式切换日志完整保留，次数由切换预算单独约束。

| reason | 含义 |
|---|---|
| baseline_ready / baseline_expired | 参考建立或失效 |
| insufficient_activity / client_backpressure | 样本被排除 |
| below_sampling_threshold / offload_or_unmeasured | 小流或无法可靠观测 |
| absolute_speed_below_floor / absolute_speed_recovered | 持续低于绝对下限 / 达到绝对恢复门槛 |
| relative_speed_collapse | 持续相对下降，尚非容量结论 |
| severe_speed_probe / preferred_recovery_probe | 开始质量试探/恢复试探 |
| no_eligible_alternative | 没有合格备选，继续原路径 |
| verified_throughput_improvement | 可比窗口验证后正式提交 |
| preferred_recovery | 按声明顺序恢复，不宣称吞吐提高 |
| probe_expired / probe_inconclusive_or_closed | 试探未完成，退避，不惩罚节点 |
| relative_speed_recovered / evidence_expired | 有证据恢复/无新证据到期退出 |
| connection_failed | 真实拨号失败，释放本地稳定记录 |

`event=laya_quality` 的 `laya_shadow_comparison` 包含本地建议、模型选择、原始模型置信度、证据 ID 和耗时；置信度不是实际正确率。`laya_unavailable_local_rules_continue` 表示回退本地。模型日志不输出原始错误字符串，避免 URL/凭据泄露。

管理 API 沿用现有鉴权：

```text
GET /v1/quality?group=Download&host=download.example.com
```

最多 256 条，显示本站点实际稳定节点、试探、当前/参考速率、样本时间、代次及排除/限频计数；读取不触发探测。`/v1/groups` 中默认 selected 不代表每个站点的实际选择。

速率字段可能保留旧样本或已过期的参考值。判断证据是否仍有效，应结合 `last_sample_at`、`quality_evidence_ttl` 和 `baseline_ready` 日志的 `valid_until`；字段有数值不表示当前仍有有效证据。

## 回退与验证边界

先 observe，再对一个组改 enforce。关闭 Laya 只停止模型对照；将组改回 off 并重载才关闭本地优化。旧代次反馈不能写入新表，已有连接继续正常转发。

已用可控时间的单元与集成测试验证限速、背压、两窗口提交、并发、过期、配置重载、模型错误/阻塞与 fixed 边界。2026-10-02 已将修复版本部署到 223，并核验服务、DNS/HTTPS 连通性、路由组及采集记录。随后在 4 个主要 fallback 组启用 observe，保持 2.5% 被动采样，未启用 enforce；该观察配置使用临时 generation，后续订阅同步可能覆盖。目标机的独立 20 MiB splice 测试中，节点、本流及归档字节计数一致；自然采集仍无法区分 splice 与缓冲复制。尚未在真实双出口验收吞吐收益或完整 CPU/RSS 开销，不能把测试中的合成速度当真实提速证据。v1 微调数据仍是旧策略，不能直接作为新规则的动作授权模型。

## 旧站点固定逻辑的首选恢复

即使 `quality_mode: off`、Laya 关闭，fallback 的 TCP 站点固定也会在驻留至少 5 分钟后，允许一个新连接验证声明顺序更靠前、健康状态为 alive 的节点。此前的 `triedAlts` / `converged` 不再永久阻止这种恢复。访问和成功首包不会推迟恢复期限；没有新请求时不主动发送探测流量。

试探租约为 60 秒，其余请求保留原稳定节点。只有该试探的正常首包才能提交恢复；慢首包、连接失败、提前结束或超时保留原节点，依次退避 2、5、10 分钟。过期试探和旧配置代际的回调不能提交。恢复后至少驻留 5 分钟，期间不因慢首包再次启动质量试探；真实连接失败仍允许避让。

只有首选恢复的成功提交计入恢复预算：每站点 30 分钟最多允许 2 次预算内切换、每组最多 10 次，预算限制首选恢复，不阻断真实故障逃逸，故障切换不会消耗恢复次数。提交时若预算或组内 5 秒间隔发生竞争，释放试探并重新排期，不增加候选失败次数。组内恢复试探至少间隔 5 秒。UDP 保留原有回归行为，使用独立站点表。

新增 `event=site_recovery` 日志，包含组、站点、稳定节点、候选、试探截止及下次允许试探时间。原因包括 `probe_started`、`recovered`、`slow_first_byte`、`closed_or_failed`、`expired`、`candidate_not_healthy`、`stable_changed`、`switch_budget`。这里的首包验证只处理旧版站点恢复；启用质量 enforce 后，持续低速的恢复仍走吞吐验证流程。

旧版 TCP 和 UDP 各自按主域名共享站点状态，每张表最多 4096 个条目；UDP 回归及已有 UDP 流的首包不改变 TCP 钉选、驻留时间或试探租约。旧版慢首包仍使用连续两次的判据。恢复预算不是故障切换的硬上限。

## 区分负载压力与节点质量

节点负载统计覆盖已登记 TCP/UDP 连接的上下行流量（包括现有 offload 回调），同源节点克隆共享统计。按至少 5 秒的间隔计算双向速率、新建连接速率和活动连接数；不使用连接结束后的全程均速代替当前负载。计量为本机实际观测，未覆盖其他网关、服务端其他用户或未登记流量，不能证明远端容量已耗尽。

保守的初始负载线索（尚未在线校准）：活动连接至少 64 条，并且双向合计至少 2 MiB/s 或新建连接至少 16 条/秒；或者至少 6 次采样后，某方向达到本轮观测峰值的 80%，且上行参考至少 1 MiB/s、下行参考至少 4 MiB/s。峰值参考每 30 分钟重建。这些值用于识别忙碌背景，不是线路容量配置；大量空闲连接本身不会被判为忙碌。

`load.class` 区分 `warming_up`（首次登记后至少 30 秒且已有速率样本）、`busy`、`settling`（忙碌回落后 30 秒）、`ordinary`、`unobserved`。ordinary 只表示未命中本地忙碌线索，不能解释为已证明线路空闲。

预热、忙碌和回落期间不累计绝对/相对低速窗口，不学习健康吞吐基线，不累计慢首包切换证据。成功首包仍更新钉选，候选节点的成功首包仍可提交首选恢复；当前节点的负载不否决候选的正向恢复证据。负载回落后重新累计有效窗口；从开始就只有低吞吐的节点，不会仅因接近自己的低峰值而获得忙碌豁免。url_test 保留 RTT/拥塞的 degraded 惩罚和原始延迟、失败/丢失证据及退避。主动探测连续三次慢才按 RTT 劣化降级；普通节点的主动探测失败一次即降级，QUIC 传输节点的 TCP 健康槽沿用连续三次失败门槛，数据 UDP 槽仍使用严格门槛。失败判据不受负载状态豁免；原有 alive 检查判定不通时仍立即标记 dead。业务握手使用自己的基线，不更改主动 RTT 的健康状态。

诊断中的 `quality_deferred` 表示暂缓质量判断，`historical_severe` 保留尚未过期的旧低速证据；可执行的 `severe` 在暂缓时为 false。Laya 的证据摘要包含同一负载背景。`load_deferred` 日志输出连接数、新建连接速率、双向速率、参考及分类。站点恢复日志每组每分钟最多 20 条普通事件，恢复提交单独记录，后续日志给出抑制条数。
