# Mihomo 规则集 / 代理组改造进展与后续方案

> 本文件随一次性整理提交保存，用于记录当前工作区中所有未提交代码的范围、验证结果、后续步骤和已知问题。它不是“阶段一已完成”的声明；阶段一仍需完成 DAT/ext 输出并通过独立审查门禁。

## 1. 目标与架构约束

目标是在不修改 kdae eBPF 数据面和基本转发架构的前提下，增加 Mihomo 风格的远程规则集、扁平代理组，并为后续原生 provider / group runtime 铺路。

必须保持的约束：

- 不修改 `control/kern/*.c`、eBPF outbound ID 编码、kernel map 协议和现有透明代理数据面；
- 远程 YAML、文本和 HTTP 只在用户态解析，最终归一化为现有 routing IR；
- 远程内容视为不可信输入，不执行其中的脚本、命令或配置指令；
- provider 下载失败或解析失败时保留最后一个有效版本，不能用空规则覆盖有效配置；
- 新行为采用 RED → GREEN → REFACTOR，并在阶段出口进行独立规格审查和安全审查。

## 2. 本次整理提交包含的代码

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

### 2.3 文档

本文件记录本次提交的修改方案、步骤、验证结果、未完成事项和问题细节。

## 3. 已完成事项

- 阶段一首轮审查指出的主要缓存污染、规则转义、SSRF、超时、YAML alias、路径符号链接和空输出问题已处理一轮；
- 重新独立审查确认：直接拨号 SSRF、redirect、响应大小、YAML alias/node/depth、cache 校验和、atomic current、last-good-cache 等主体能力有效；
- group 资源注入和空 groups 覆盖问题已按第二轮审查意见补充拒绝逻辑；
- 原生 provider 配置 schema 已提交；
- 原生 provider runtime 的 file/http 加载、基础解析、ruleset 展开已完成初版；
- 阶段一工具包测试通过；
- 阶段二 `component/ruleprovider` 与 `config` 包测试通过；
- 未修改 eBPF 数据面。

## 4. 验证结果

以下命令在本次整理前已实际执行并通过：

```text
TMPDIR=/root/go-tmp go test ./tools/dae-rule-sync -count=1
ok

TMPDIR=/root/go-tmp go test ./component/ruleprovider ./config -count=1
ok
```

阶段一此前也已通过 race/vet；本次最终提交前会再次运行相关 race/vet 和 `git diff --check`。

cmd 集成测试当前不能执行，原因是仓库当前分支缺少 eBPF 生成 Go 文件，属于现有环境/分支基线阻塞：

```text
undefined: bpfObjects
undefined: bpfTuplesKey
undefined: bpfDomainRouting
undefined: bpfRedirectTuple
```

因此不能把 `go test ./cmd/...` 或 `go test ./...` 报告为通过。

## 5. 当前仍未完成的事项

### 5.1 阶段一出口缺口

1. **DAT/ext 输出尚未实现**：计划要求生成可被 `DatReaderOptimizer` 读取的 geosite/geoip DAT，并输出类似：

   ```dae
   domain(ext:"generated/geosite/name.dat:name") -> outbound
   dip(ext:"generated/geoip/name.dat:name") -> outbound
   ```

   当前实现仍以内联 `domain()` / `dip()` 规则为主，功能可工作但不满足计划中 DAT/ext 的输出契约和大规则集扩展路径。

2. 尚无 groups 输出经真实 `config.New` 的提交测试；目前 route round-trip 覆盖比 groups 完整。

3. outbound 是否真实存在还不能由同步器验证；当前只验证 outbound 标识符格式。

### 5.2 原生 provider runtime 缺口

1. 尚未实现 interval 生命周期、后台刷新、staged reload 和运行时快照切换；当前是在配置加载时同步加载。
2. native provider 的 cache 元数据和 stale snapshot 能力比阶段一简化，尚未完全复用阶段一的强校验 cache。
3. native `security.go` 还需要同步阶段一的 proxy 禁用、特殊内网地址集合和完整 DNS rebinding 测试。
4. native file provider 目前需要补充 `EvalSymlinks` containment、`O_NOFOLLOW` 和 regular-file 检查；schema 层路径检查目前主要是词法路径检查。
5. native YAML parser 还需要加入 alias 拒绝、节点数和深度上限，不能只依赖普通 `yaml.Unmarshal`。
6. `LoadOptions{AllowPrivate: true}` 是测试便利开关，不能暴露给生产配置路径。
7. classical provider 目前只覆盖可直接归一化为 domain/IP 的基本条目；PROCESS-NAME、DST-PORT、AND/OR 等语义需要明确 unsupported 并在生产路径上阻止静默丢失。
8. 原生 flat select/fallback/url-test 的 outbound policy 接入尚未完成；当前只完成规则 provider runtime 的第一步。

### 5.3 仓库基线阻塞

完整 cmd/全仓测试依赖本分支缺失的 eBPF 生成文件。后续需要先恢复或执行仓库规定的 eBPF 生成流程，再验证：

- `go test ./cmd/...`；
- `go test ./...`；
- config → `readConfig()` → provider load → routing/control-plane 的真实集成路径。

## 6. 后续修改方案与步骤

按以下顺序继续，避免在阶段一出口未关闭前扩大阶段三范围：

### Step 1：收口本次提交

- 格式化所有改动；
- 运行阶段一、阶段二包测试、race、vet 和 diff 检查；
- 记录 cmd/eBPF 基线失败，不伪造全量通过；
- 将当前全部未提交代码和本文件放入一个整理提交。

### Step 2：完成阶段一 DAT writer

- 先写 `dat_writer_test.go`，构造 geosite/geoip fixture；
- 使用现有 `pkg/geodata` protobuf 类型生成 DAT；
- 用 `DatReaderOptimizer` 真实读取生成的文件；
- 将 route writer 改为 `ext` 引用；
- 加入 DAT 原子写、空 DAT 防覆盖、checksum/统计报告测试；
- 重新执行两名独立审查。

### Step 3：补齐阶段一安全和一致性细节

- 补 groups → `config.New` round-trip；
- 补 outbound existence 校验或明确配置边界；
- 统一 native/provider 与 sidecar 的 URL 脱敏、cache snapshot、proxy/SSRF 和 YAML 限制；
- 补跨进程 cache writer 并发测试；
- 检查所有 stale path 不会产生空规则 reload。

### Step 4：完成阶段二原生生命周期

- 抽取可复用的 provider snapshot/store；
- 实现 interval refresh 和单 provider single-flight；
- 失败时保留最后快照；
- 将刷新结果接入现有 staged reload，而不是直接修改运行中 routing IR；
- 在 eBPF 生成文件恢复后跑真实 cmd/control-plane 测试。

### Step 5：实现 flat group runtime

- 复用现有 `component/outbound` 的 concrete dialer group；
- 映射 select、fallback、url-test 到已有 policy；
- 保留 unsupported/approximate 报告；
- 不在此阶段引入嵌套 group graph。

### Step 6：阶段三再处理 nested group

- 单独设计 group graph、循环检测、状态继承和运行时控制；
- 保持 eBPF outbound ID 和 routing result 不变；
- 先写设计和独立审查，再实现代码。

## 7. 当前提交边界

本次提交的性质是**未提交代码整理提交 / WIP checkpoint**，不是阶段一或阶段二完成提交。它的目的：

- 固化当前已经完成的代码和测试；
- 让后续 DAT、native lifecycle、group runtime 工作有清晰基线；
- 通过本文件避免遗漏已发现的审查问题和环境阻塞。

后续每个垂直功能仍应单独提交，不能继续把所有阶段性改动堆到本提交中。
