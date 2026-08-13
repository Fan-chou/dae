# Mihomo 规则集 / 代理组改造进展与后续方案

> 状态更新（2026-08-14）：本文件曾是早期 WIP 进度记录，下面关于 DAT/ext 尚未实现、TDD 和
> 独立审查的表述已经过时。当前代码已完成 DAT/ext 基础能力；后续以
> `docs/mihomo-rule-provider-execution-plan.md` 第 17 节的 routing sections 编译设计为准。

## 1. 目标与架构约束

最终目标是在不修改 kdae eBPF 数据面和基本转发架构的前提下，将 Mihomo `rules` 逐条转换
为语义等价的 kdae routes；同时接入 rule-providers、sub-rules 和必要的节点/代理组引用。
不能保持匹配条件、顺序、命中动作或选项语义的规则必须显式失败，不能静默丢弃或近似转换。

必须保持的约束：

- 不修改 `control/kern/*.c`、eBPF outbound ID 编码、kernel map 协议和现有透明代理数据面；
- 远程 YAML、文本和 HTTP 只在用户态解析，最终归一化为现有 routing IR；
- 远程内容视为不可信输入，不执行其中的脚本、命令或配置指令；
- provider 下载失败或解析失败时保留最后一个有效版本，不能用空规则覆盖有效配置；
- 当前按用户要求直接开发，不强制 TDD；未明确要求时不启动独立审查和额外验证流程。
- 每个明确垂直步骤单独提交，保持安全边界、last-good 和 generation-atomic 约束不变。

## 2. 当前代码基线

### 2.1 阶段一：外部同步器加固

涉及 `tools/dae-rule-sync`：

- provider fetch/cache：
  - 默认 HTTP 总超时和响应头/响应体限制；
  - redirect 限制和逐跳 URL 校验；
  - DNS 解析后再次校验 loopback、private、link-local、multicast、unspecified、CGNAT、benchmark 和云 metadata 地址；
  - 默认禁用环境代理，避免代理绕过本地 SSRF 拨号检查；
  - provider 名称安全标识符校验；
  - cache body 大小限制、SHA-256 校验和 source-key 绑定；
  - provider body 解析通过后才替换当前 cache；
  - cache body/metadata fsync，目录同步，随机临时 symlink 名称和原子 rename；
  - 同一 fetcher 内同一 provider 的 single-flight；
  - 错误信息和 cache metadata 中的 URL 查询参数脱敏。

- parser/writer：
  - route 值控制字符和双引号冲突检测；
  - 实际 kdae parser round-trip 测试；
  - classical 裸 IP/CIDR 的分类修正；
  - route 生成 0 条时拒绝替换旧 routes 文件。

- flat Mihomo group：
  - unknown member 直接拒绝；
  - group member literal 进行控制字符/引号校验；
  - nested group、DIRECT、REJECT、proxy-provider 继续进入 unsupported/approximate 报告；
  - 转换结果为空时拒绝替换旧 groups 文件；
  - groups 成功转换后才写 routes，避免 routes/groups 部分 apply。

- 测试：
  - 增加 SSRF、拨号时 IP 检查、特殊内网地址、代理禁用、URL token 脱敏、YAML alias、超时、空输出、未知 group member、危险 group literal、缓存失败回退等回归测试。

### 2.2 阶段二：原生 rule provider runtime 初版

涉及：

- `component/ruleprovider/rule_provider.go`；
- `component/ruleprovider/security.go`；
- `component/ruleprovider/rule_provider_test.go`；
- `cmd/run_config.go`；
- `cmd/rule_provider_config_test.go`。

已实现的初版能力：

- `Registry` 和 `LoadWithOptions`；
- file/http provider 加载；
- YAML/text provider 内容解析；
- domain、domain-suffix、domain-keyword、domain-regex、IP-CIDR 的基本转换；
- HTTP 失败时使用 cache；
- `ruleset(name)` 替换为现有 routing function，同时保留 `&&` 条件和 outbound；
- unknown provider 和 negated `ruleset()` 拒绝；
- `readConfig()` 加载配置后调用 `LoadAndExpand()`。

配置 schema 已在此前提交 `5153920` 中完成；本次提交补上 runtime 初版和 config→runtime 接入测试文件。

### 2.3 文档关系

本文件记录当前代码基线、历史验证事实、未完成事项和后续实施顺序；本轮只更新文档，不把
文档更新描述成代码功能提交。

## 3. 已完成事项

- provider manifest 校验、HTTP/file fetch/cache、规则解析和 generation-atomic 发布已具备；
- `98f4321` 已实现 GeoSite/GeoIP DAT writer；`ac187b9` 已将大 provider 接入 `domain(ext: ...)`
  和 `dip(ext: ...)` 路由；DAT/ext 不再是待实现事项；
- `141247e`、`48ac1fd`、`05bfb67`、`55493b8`、`b167c4f`、`56e3fa9` 已完成节点、特殊
  outbound、select/fallback、健康检查和 generation fail-closed 相关转换；
- `4c6e1a4` 已补充非 Linux 链路验证中的 `shadowsocks_2022` 注册；
- 未修改 eBPF 数据面、outbound ID 编码和 kernel map 协议；
- 当前仍没有“原始 Mihomo YAML 直接生成 routing manifest/IR”的入口，manifest 还是独立
  中间输入；这一项是下一阶段设计目标。

## 4. 验证结果

以下命令在本次整理前已实际执行并通过：

```text
TMPDIR=/root/go-tmp go test ./tools/dae-rule-sync -count=1
ok

TMPDIR=/root/go-tmp go test ./component/ruleprovider ./config -count=1
ok
```

以上是历史记录，不代表本轮文档更新会重新执行验证；后续验证按用户明确要求进行。

cmd 集成测试当前不能执行，原因是仓库当前分支缺少 eBPF 生成 Go 文件，属于现有环境/分支基线阻塞：

```text
undefined: bpfObjects
undefined: bpfTuplesKey
undefined: bpfDomainRouting
undefined: bpfRedirectTuple
```

因此不能把 `go test ./cmd/...` 或 `go test ./...` 报告为通过。

## 5. 当前仍未完成的事项

### 5.1 routing sections 入口缺口

1. `MihomoConfig` 目前只读取 `proxies` 和 `proxy-groups`，不能直接读取
   `rule-providers`、有序 `rules`、`sub-rules`。
2. 当前 manifest 只描述 provider 和“provider → outbound”映射，不能表达原始规则的顺序、
   `AND/OR/NOT`、`SUB-RULE`、动作选项和继续匹配语义。
3. 需要新增 routing document extractor、ordered rule IR 和 sub-rule graph compiler；详细
   设计见 [执行计划第 17 节](docs/mihomo-rule-provider-execution-plan.md)。
4. `script` 明确不在本轮实现范围：未引用的定义允许记录 ignored，被活动规则引用时必须
   明确失败，不能静默执行或近似。

### 5.2 `rule-providers` 转换设计仍待落地

DAT/ext 已经完成，但它只负责保存 provider 的匹配数据，不负责保存规则顺序、匹配条件组合或命中后的动作。当前仍缺少以下入口和绑定：

1. 从原始 Mihomo YAML 读取 provider 声明，并保留 `url`、`path`、`interval`、`behavior`、`format` 等来源信息；
2. 将 HTTP/file provider 统一归一化到现有 fetch/cache/snapshot 语义，失败时继续使用 last-good；
3. 将 `domain`/`ipcidr`/`classical` 内容分成可内联的小集合和写入 DAT 的大集合；
4. 为每个 provider 建立稳定的 `ProviderName → DAT/source` 映射，多个规则引用同一 provider 时共享数据但不共享动作；
5. 对 `PROCESS-NAME`、端口、复合条件等不能表达为 domain/IP 集合的 classical 条目保留来源位置，并在生产转换中显式失败，不能静默丢弃。

### 5.3 有序 `rules` 转换设计仍待落地

当前 manifest 不能替代原始 `rules`。新入口需要保留每条规则的 source index、匹配表达式、动作、选项和原始位置，并转换成有序 routing IR：

1. 原子条件包括 DOMAIN 系列、IP-CIDR、端口/网络条件、provider 引用和 `SUB-RULE` 引用；
2. `AND`、`OR`、`NOT` 只在目标 IR 有等价表达时下沉，否则阻断该规则生成；
3. `DIRECT`、`REJECT`、节点名和代理组名通过显式 action lowerer 映射；`REJECT-DROP`、`MATCH` 等没有等价实现时不能偷偷改成相近动作；
4. 保持 Mihomo 的 first-match 顺序；不能把规则集合无序合并后再生成 routes；
5. `no-resolve`、`src-ip-cidr`、`PROCESS-NAME`、`match-mac` 等能力必须逐项声明支持或失败原因。

### 5.4 `sub-rules` 图编译设计仍待落地

`sub-rules` 不应当直接展开成一个无边界的字符串列表，而应先建立命名图：

1. 检查重复定义、未解析引用、循环引用、最大深度和展开规模；
2. 只编译被有效 `rules` 引用的子规则；
3. 保留调用点的外层条件、子规则内部顺序和最终 action；
4. 用共享 IR 或有界展开避免重复展开造成指数增长；
5. 图校验或 action lower 不完整时，整次 generation 失败并保留上一代。

### 5.5 script 边界

本轮不实现 script engine，也不把 script 表达式近似翻译成普通规则。顶层存在但没有活动引用的 script 定义可以记录为 ignored；活动 `SCRIPT` 规则或间接引用必须显式失败。这样不会因为无关的 script 定义阻断其它 routing sections，也不会把未实现能力伪装成已支持。

### 5.6 其余运行时缺口

以下事项属于 routing sections 编译完成后的运行时工作，不应与本轮 parser/IR 入口混为一谈：

- native provider 的 interval refresh、single-flight、staged reload 和运行时 snapshot 切换；
- native cache 的完整安全约束（路径 containment、`O_NOFOLLOW`、YAML alias/深度/节点数限制）；
- flat `select`/`fallback`/`url-test` 的 outbound policy 接入；
- 恢复 eBPF 生成文件后的 cmd/control-plane 集成验证。

## 6. 后续设计与实现顺序

本阶段只规划和实现 `rule-providers`、`rules`、`sub-rules` 及其与现有 nodes/groups/DAT 的连接，不实现 script 表达式。每个明确的垂直步骤都必须以“已转换规则语义等价，无法等价则 fail-closed”为出口，并单独提交；未明确要求时不追加 TDD、独立审查或额外验证流程。

### Step 1：建立 routing document extractor

- 放宽当前只含 `proxies`/`proxy-groups` 的输入模型，增加 `rule-providers`、有序 `rules`、`sub-rules` 和 script 引用记录；
- 使用 YAML Node 或等价结构保留列表顺序、source line 和未知字段，不再用无序 map 代替规则列表；
- 先完成语法/结构读取，不在 extractor 中生成 routes 或执行远程内容；
- 对 script 只做识别和引用扫描。

### Step 2：实现 provider normalizer 与 DAT binding

- 将 provider 声明映射到现有 fetch/cache/last-good 组件；
- 解析 domain/IP/classical provider，并按规模选择 inline 或已有 DAT/ext writer；
- 为 provider 生成稳定映射、checksum 和来源元数据；
- 未使用 provider 只记录状态，引用缺失或内容不支持则阻断 generation。

### Step 3：实现 ordered rules IR 与 action lowerer

- 定义原子条件、`AND`/`OR`/`NOT`、provider leaf、`SUB-RULE` leaf 和 source index；
- 保持 first-match 顺序，把每条规则的匹配条件与 action 分开建模；
- 显式映射节点、组、DIRECT、REJECT 等动作，所有近似或不支持能力进入错误/报告；
- 只有能证明与 Mihomo 规则等价的 action 才能进入 routes，近似映射一律阻断无损发布；
- 把 IR 编译到现有 route writer，不修改 eBPF 数据面、outbound ID 或 kernel map 协议。

### Step 4：实现 sub-rules graph compiler

- 先做引用解析、循环/深度/规模限制，再生成共享 IR；
- 在调用点合并外层 guard 与子规则条件，保留内部顺序和 action；
- 对无法等价下沉的子规则显式失败，不生成部分 routes。

### Step 5：接入 generation-atomic 发布

- 将 nodes、groups、routes、provider snapshot、DAT/ext 和 metadata 写入同一候选 generation；
- 任一 provider、规则、子规则、action 或 DAT 失败都保留上一代；
- metadata 记录 input checksum、provider map、source index、DAT 统计和 ignored/unsupported 原因，不写入敏感内容。

### Step 6：补齐代理组连接

- 复用已有 flat group 转换，把规则 action 指向稳定的 node/group outbound；
- 对 nested group 先沿用 `sub-rules` 同样的图校验原则，另行实现 group graph，不在规则编译器里隐式展开；
- select/fallback/url-test 的运行时策略单独接入，不改变 routing IR 的 action 语义。

## 7. 当前文档和提交边界

本次只更新两份设计/进度文档，不改变代码，也不把“DAT 已完成”重复列为待办：

- [执行计划](docs/mihomo-rule-provider-execution-plan.md) 第 2 节修正当前事实，第 17 节记录完整 routing sections 设计；
- 本文件记录当前完成项、真实缺口和实施顺序；
- 本次文档更新完成后，两个文档作为一个文档阶段提交；后续每个明确垂直功能单独提交。
