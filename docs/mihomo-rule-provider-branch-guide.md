# Mihomo 规则集与代理组开发分支说明

## 1. 文档目的

本文说明开发分支 `feat/mihomo-rule-provider-groups` 为什么需要这些修改、当前已经修改了什么、
如何运行转换工具，以及转换结果有哪些不能忽略的限制。

本文撰写时的代码基线是 `c1a5d6c`。当前开发分支使用的 `kix` 远程仓库是：

```text
git@github.com:Fan-chou/dae.git
```

官方仓库仍保留为 `origin`，用于对照上游代码。本文面向“验证 Mihomo 配置能否迁移到 kdae
routing”这一开发和评估场景，不代表当前功能已经适合直接替换生产配置。

## 2. 为什么要做这组修改

### 2.1 原有 kdae 配置不能直接承载 Mihomo routing

用户的 Mihomo 配置把以下内容放在同一个 routing 配置中：

- 远程 `rule-providers`；
- 有顺序的 `rules`；
- `AND`、`OR`、`NOT` 和 `sub-rules`；
- 节点、代理组、嵌套代理组和健康检查；
- `DIRECT`、`REJECT`、`REJECT-DROP` 以及代理组动作。

kdae 原有配置和数据面没有对应的完整 Mihomo 配置模型。如果只把 provider 数据写成 DAT，
只能保存域名或 IP 集合，不能保存规则顺序、命中动作、端口、进程、逻辑条件和子规则调用。
因此本分支增加了用户态的转换流水线，把 Mihomo routing 先解析成中间表示，再生成 kdae routes、
nodes、groups 和 DAT。

### 2.2 不修改 kdae 基本数据面

迁移目标是在不修改以下部分的前提下完成：

- eBPF 数据面；
- outbound ID 编码和 kernel map 协议；
- 透明代理和现有 routing result 格式；
- kdae 原有节点连接和转发逻辑。

所以转换逻辑放在 `tools/dae-rule-sync` 用户态工具中。远程 YAML、文本 provider 和 DAT 都作为
不可信输入处理，不执行 Mihomo 脚本、命令或远程配置指令。

### 2.3 防止远程更新破坏当前有效配置

远程规则集可能出现网络失败、空内容、格式错误、内容不兼容或恶意地址。分支因此增加了：

- URL、重定向、解析后 IP 和响应大小检查；
- provider body 解析成功后才接受为候选版本；
- generation 内 provider snapshot、routes、nodes、groups、DAT 和 metadata 一起发布；
- 新 generation 验证失败时保留旧的 `current`；
- provider 刷新失败时使用校验通过的 last-good snapshot。

这就是这里的 `fail-closed`：出现会破坏整体配置的问题时，不发布半份新配置，而继续使用上一份
完整有效配置。

### 2.4 为什么部分规则允许“记录后跳过”

完整配置中可能只有某一条规则无法无损转换。如果因为一条 `IP-ASN` 或未知条件让全部可转换
规则都无法生成，不能完成实际迁移验证；如果把它强行转换，又会制造看似成功但语义错误的规则。

当前策略是：

- 能精确表达的规则按等价路径生成；
- 用户明确允许的有损条件记录 warning 后跳过；
- 单条无法 lowering 的规则记录源位置、原文和原因后跳过；
- provider、引用关系、节点/组结构和活动脚本等候选级错误仍 fail-closed。

因此“转换命令成功”只表示候选 generation 成功生成，不表示所有 Mihomo 规则都保持了完整语义。

## 3. 当前分支的主要修改

| 模块 | 修改内容 | 目的 |
| --- | --- | --- |
| Provider | 解析、归一化 HTTP/file rule provider，保留来源和缓存校验 | 让远程规则可以进入统一转换流程 |
| DAT | domain/IP provider 生成 geosite/geoip DAT，并由 routes 引用 | 处理大型规则集，避免把所有数据内联到 routes |
| Rules IR | 保留源顺序、源索引、源行号、条件组合和动作 | 保持 Mihomo 的 first-match 规则顺序 |
| Sub-rules | 校验引用、循环、深度和展开上限，再编译为有序 routes | 保留子规则的 guard、分支动作和顺序 |
| Nodes | 将 Mihomo 节点转换为 kdae link，建立安全名称映射 | 让 routes 可以引用转换后的节点 |
| Groups | 支持 select、fallback、url-test、嵌套组和健康检查语义 | 尽量保留代理组运行时行为 |
| Generation | `nodes.dae`、`groups.dae`、`routes.dae`、DAT、provider snapshot 和 metadata 一起发布 | 避免不同文件来自不同版本 |
| Diagnostics | 对无法无损转换的单条规则输出带来源的 warning | 便于定位迁移损失，不阻断其它可转换规则 |

## 4. 当前转换语义

### 4.1 可直接转换的部分

当前已纳入等价 lowering 的主要内容包括：

- `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-REGEX`；
- `DOMAIN-WILDCARD`，包括大小写规范化、字面字符转义和完整锚定；
- IPv4/IPv6、源 IP、目的 IP 和 CIDR；
- 源/目的端口、网络类型、进程名；
- `AND`、`OR`、`NOT` 和有序 first-match 规则；
- `RULE-SET`、provider leaf 和 provider DAT；
- `SUB-RULE` 的有界展开；
- `DIRECT`、`REJECT`、节点名和代理组名动作；
- 节点、嵌套代理组、选择组、fallback、url-test 和健康检查的已支持字段。

### 4.2 当前明确的有损兼容策略

| Mihomo 内容 | 当前处理 | 使用者必须知道的影响 |
| --- | --- | --- |
| `IN-PORT` | 忽略条件 | 不转换成 `sport`、`dport` 或 `tproxy_port`；仅有该条件的规则不生成，OR 分支只移除该分支 |
| `IP-ASN` | 暂时忽略条件 | ASN 匹配不会在 kdae 中生效；包含该条件的 AND 分支整体不生成，避免错误变成更宽的规则；OR 中只移除该分支 |
| `match-mac` 条件选项 | 忽略选项 | 保留同一条规则的源 IP 条件，但 MAC 限定不再生效，匹配范围可能扩大 |
| `match-mac` 动作选项 | 忽略选项 | 规则主体继续转换，但 MAC 限定不再生效 |
| `REJECT-DROP` | 降级为 kdae `block` | 不保证与 Mihomo 的 drop 时机和连接处理完全一致 |
| `GEO*`、未知条件、未知 option/action | 记录 warning，跳过该条规则 | 该条规则不会生成伪等价 route，后续规则继续转换 |
| 活动 `SCRIPT` | 直接拒绝完整 generation | 当前没有脚本执行器，不能把脚本静默当作普通规则 |
| `anytls client-fingerprint` | 按当前约束忽略 | 不验证或迁移该客户端指纹配置 |

日志中的 warning 是判断转换损失的主要依据。当前 routes 汇总中的 `Generated` 只表示实际生成
的 route 数量，不能单独证明没有规则被跳过；使用时必须同时查看 warning 日志。

## 5. 如何使用

### 5.1 准备输入

完整转换需要一个本地 Mihomo YAML 文件，其中可以包含：

- `proxies`；
- `proxy-groups`；
- `rule-providers`；
- `rules`；
- `sub-rules`。

远程 provider 必须能从当前运行环境访问。配置中的活动 `SCRIPT`、未定义的 provider/group、
不支持的代理节点字段等问题会导致完整 generation 不发布。

### 5.2 推荐命令

在仓库根目录执行：

```bash
go run ./tools/dae-rule-sync \
  -mihomo-routing-config /absolute/path/config-home-mihomo.yaml \
  -generation-dir /absolute/path/mihomo-generation \
  -cache-dir /absolute/path/mihomo-cache \
  > /absolute/path/mihomo-sync-report.json \
  2> /absolute/path/mihomo-sync-warnings.log
```

参数含义：

- `-mihomo-routing-config`：完整 Mihomo routing 配置路径；
- `-generation-dir`：generation 根目录，完整 Mihomo 转换必填；
- `-cache-dir`：provider 缓存目录，建议使用固定且专用的目录；
- `-strict`：主要影响 manifest/旧兼容路径；完整 Mihomo generation 对 provider、引用和节点/组结构始终严格校验，但单条 rule lowering 仍按本分支的日志后跳过策略处理；
- stdout：转换汇总 JSON；
- stderr：无法无损转换、忽略条件和 provider fallback 等 warning。

也可以先构建工具：

```bash
go build -o /absolute/path/dae-rule-sync ./tools/dae-rule-sync
```

再将上面的 `go run ./tools/dae-rule-sync` 替换为构建出的工具路径。

完整 Mihomo 模式不能同时使用 `-manifest`、`-mihomo-config`、`-routes-output`、
`-groups-output` 或 `-nodes-output`。这些参数属于旧的 provider/flat group 兼容路径，不具备
完整配置的 generation-atomic 语义。

### 5.3 检查生成结果

成功后，generation 根目录通常包含：

```text
mihomo-generation/
├── current -> generations/<generation-id>
├── generation.lock
└── generations/
    └── <generation-id>/
        ├── nodes.dae
        ├── groups.dae
        ├── routes.dae
        ├── metadata.json
        ├── providers/
        └── generated/
```

应重点检查：

1. 命令退出码为 0；
2. warning 日志中是否出现 `IP-ASN`、`GEO*`、未知规则或其它预期外的跳过；
3. `current` 是否指向最新完整 generation；
4. `routes.dae` 是否包含预期的顺序和 outbound；
5. `groups.dae` 中的节点/组名称是否都使用安全映射名；
6. `metadata.json` 中的 provider、DAT、routes/groups/nodes checksum 是否完整。

当前工具只负责生成和发布候选 generation，不会自动修改 dae 主配置，也不会自动启动或重载
dae。将生成文件接入实际运行环境前，必须先按项目现有的配置加载方式进行人工确认。

## 6. 实际转换结果应如何理解

使用用户提供的完整 Mihomo 配置进行实测时，结果为：

- 8 个节点转换成功；
- 36 个代理组转换成功；
- 282 条 routes 生成；
- 远程规则集快照和 geoip/geosite DAT 生成；
- `IN-PORT`、`IP-ASN`、`match-mac` 等有损点被 warning 记录；
- 命令没有因为这些单条规则问题中止。

这证明“当前配置可以进入 kdae 的生成链路”，不等价于“当前配置已经完全无损迁移”。尤其要
确认被忽略的入口、ASN、MAC 条件是否会影响实际网络策略。

## 7. 使用注意事项

### 7.1 不要把 warning 当作普通噪声

建议每次转换都保存 stdout 和 stderr。至少要记录：

- source index；
- source line；
- 原始规则文本；
- 被忽略的条件或 option；
- 跳过原因。

如果 warning 数量或内容发生变化，应先比较转换结果，再决定是否使用新的 generation。

### 7.2 不要手工拼接 generation 文件

不要单独替换 `routes.dae`、`groups.dae`、DAT 或 provider snapshot。这样会破坏 generation 的
一致性校验，导致 routes 引用错误的 provider/DAT 或节点名。应修改输入配置后重新运行工具，
让工具生成新的完整 generation。

### 7.3 不要用测试绕过开关运行生产转换

测试代码可以允许特定私网地址或测试 HTTP 服务，但生产路径不能使用等价绕过。远程 provider
地址应经过正常的 URL、DNS、重定向和目标 IP 检查。

### 7.4 远程 provider 不是普通下载文件

provider 内容会影响最终路由，必须视为不可信输入。不要把带有敏感 token 的 URL 写入日志、
提交到 Git 或复制到公开 issue。provider 失败时应确认使用的是可信的 last-good snapshot，而
不是空 provider 或半份新内容。

### 7.5 注意有损规则扩大匹配范围的风险

忽略 `match-mac` 后，保留的源 IP 规则可能匹配更多设备；忽略 `IN-PORT` 后，入口分流可能
消失；跳过 ASN/GEO 规则后，原本由这些分类保护的流量可能落到后续规则。对于安全、审计、
分流和拒绝规则，必须逐条确认后再使用。

### 7.6 活动脚本和结构错误不能靠重试解决

活动 `SCRIPT`、循环 sub-rule、缺失引用、无法转换的节点/组结构等问题不是普通 warning，
重试不会自动得到正确语义。需要先修改输入配置，或者另行实现对应 kdae 能力。

## 8. 推荐工作流程

```text
备份原始 Mihomo 配置
        ↓
使用独立 generation-dir/cache-dir 执行转换
        ↓
分别保存 JSON 报告和 warning 日志
        ↓
逐条确认被忽略/跳过的规则是否可接受
        ↓
检查 current、routes、groups、nodes、DAT 和 metadata
        ↓
在测试环境加载生成结果
        ↓
确认流量、拒绝规则、入口分流和代理组行为
        ↓
再考虑接入实际运行环境
```

开发阶段建议保留旧 generation 和原始配置，不要在第一次成功生成后立即覆盖生产配置。

## 9. 当前明确不包含的能力

- Mihomo `script` 的执行和表达式求值；
- Mihomo `dns`、`tun`、`listeners`、`inbounds`、`hosts` 等非 routing 配置迁移；
- `IP-ASN` 的 kdae 原生等价匹配；
- `IN-PORT` 的入站监听器身份匹配；
- `match-mac` 的 kdae 数据面语义；
- `REJECT-DROP` 的完全等价 drop 行为；
- 所有 Mihomo 私有 option、plugin 和动作的自动推断。

因此，当前分支适合用于“验证迁移可行性、生成候选 routes、定位语义差异”，不应把一次成功
生成误认为完整的 Mihomo 运行时兼容。

## 10. 关联文档

- [Mihomo 规则集与代理组兼容性改造执行计划](mihomo-rule-provider-execution-plan.md)
- [Mihomo 规则集 / 代理组改造进展](mihomo-rule-provider-progress.md)
