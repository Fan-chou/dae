# Mihomo 规则集 / 代理组改造进展与后续方案

> 本文件保留 `kix/kdae` (`4f7e283`) 到历史 checkpoint 的阶段 1 runtime 记录；当前执行基线
> 以 `docs/mihomo-rule-provider-execution-plan.md` 为准，当前分支已推进到 `4a282de`。下文关于
> TDD、独立审查、DAT 尚未实现和旧阶段出口的描述属于历史记录，不覆盖当前 routing 实现状态。
> 当前已完成原始 Mihomo YAML routing、provider/DAT、rules/sub-rules、节点/代理组和同 generation
> 发布；按当前兼容策略 `IN-PORT`/`match-mac` 被忽略、`REJECT-DROP` 降级为 block，完整用户配置
> 仍在 `IP-ASN` 处 fail closed，详见执行计划的当前基线与 capability matrix。

## 1. 目标与架构约束

目标是在不修改 kdae eBPF 数据面和基本转发架构的前提下，增加 Mihomo 风格的远程规则集、扁平代理组，并为后续原生 provider / group runtime 铺路。

必须保持的约束：

- 不修改 `control/kern/*.c`、eBPF outbound ID 编码、kernel map 协议和现有透明代理数据面；
- 远程 YAML、文本和 HTTP 只在用户态解析，最终归一化为现有 routing IR；
- 远程内容视为不可信输入，不执行其中的脚本、命令或配置指令；
- provider 下载失败或解析失败时保留最后一个有效版本，不能用空规则覆盖有效配置；
- 新行为采用 RED → GREEN → REFACTOR，并在阶段出口进行独立规格审查和安全审查。

## 2. 历史 WIP checkpoint 与当前阶段 1 runtime

### 2.1 历史 sidecar 外部同步器加固（execution plan Stage 2 scope）

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
  - 初版路径在 groups 成功转换后才写 routes，减少该顺序下的部分 apply 风险；这不是完整的
    routes/groups generation-atomic 发布。sidecar 的统一 generation、单一 `current` 指针和失败
    rollback 明确属于 execution plan Stage 2 deferred，不能作为阶段 1/native provider 已完成项。

- 测试：
  - 增加 SSRF、拨号时 IP 检查、特殊内网地址、代理禁用、URL token 脱敏、YAML alias、超时、空输出、未知 group member、危险 group literal、缓存失败回退等回归测试。

### 2.2 阶段 1：原生 rule provider runtime 初版

涉及：

- `component/ruleprovider/rule_provider.go`；
- `component/ruleprovider/security.go`；
- `component/ruleprovider/rule_provider_test.go`；
- `cmd/run_config.go`；
- `cmd/rule_provider_config_test.go`。

当前已实现并由测试覆盖的能力：

- `Registry`、生产 `Load` / `LoadAndExpand`，以及仅供同包测试使用的私有加载选项；
- file/http provider 加载；
- YAML/text provider 内容解析；
- domain、domain-suffix、domain-keyword、domain-regex、IP-CIDR 的基本转换；
- HTTP 坏内容、普通网络失败和安全策略拒绝时，使用校验通过的 last-good cache；
- cache metadata/source/provider/behavior/format 绑定、SHA-256 校验、原子 current 发布和失败回滚；
- text provider 的逐行长度/规则数限制，以及 YAML alias/node/depth 限制；
- file provider 的 canonical base containment、`O_NOFOLLOW`、`O_NONBLOCK`、`O_DIRECTORY` 和 regular-file 检查；
- URL redirect 逐跳校验、代理禁用、解析后 IP 检查和特殊 blocked ranges；
- `ruleset(name)` 替换为现有 routing function，同时保留 `&&` 条件和 outbound；
- unknown provider 和 negated `ruleset()` 拒绝；
- native `LoadAndExpand()` 与 file-provider 的低层/受控集成验证已通过；真实 `cmd/readConfig()` 生产入口仍未验证，当前受 Darwin netlink/eBPF 编译基线阻塞，不能据此宣称 cmd 或全仓通过。

配置 schema 已在此前提交 `5153920` 中完成；历史 WIP checkpoint `bf855b9` 补上 runtime 初版和
config→runtime 接入测试文件，随后已有的 `d0126a6` 完成阶段 0 gate。当前阶段 1 在此基础上
完成安全收口和 test-only 验证。

### 2.3 文档

本文件记录本次提交的修改方案、步骤、验证结果、未完成事项和问题细节。

## 3. 已完成事项

- 历史 sidecar 首轮审查指出的主要缓存污染、规则转义、SSRF、超时、YAML alias、路径符号链接和空输出问题已处理一轮；
- 重新独立审查确认：直接拨号 SSRF、redirect、响应大小、YAML alias/node/depth、cache 校验和、atomic current、last-good-cache 等主体能力有效；
- group 资源注入和空 groups 覆盖问题已按第二轮审查意见补充拒绝逻辑；
- 原生 provider 配置 schema 已提交；
- 原生 provider runtime 的 file/http 加载、基础解析、ruleset 展开已完成初版；
- native provider 生产集成入口已启用，并在加载、解析、缓存发布和 routing 展开失败时保持事务性；
- Hubble fix-first 轮次修复了“安全 fetch error 不应绕过已验证 cache 回退”、text provider streaming
  limits，以及 file path 的 `O_NONBLOCK` / `O_DIRECTORY` 打开语义；
- Nash fix-first 轮次补上了 YAML 预扫描、IPv6 保留网段拒绝、cache `versions` 有界清理和
  transaction journal/recovery；
- 历史 sidecar 工具包测试通过；
- 阶段 1 `component/ruleprovider` 与 `config` 包测试通过；
- 未修改 eBPF 数据面。

上述 sidecar 项目是历史实现/测试事实，不等于 Stage 2 的 generation-atomic 出口已经通过；本轮
只收口 Stage 1 native provider 的文档审计。

## 4. 验证结果

历史命令结果保留如下；各轮 test-only RED → code-only GREEN → independent verification 的
可审计汇总见第 9 节。缺失完整 stdout 的历史结果会明确标为“记录来自本轮代理报告”。

```text
TMPDIR=/root/go-tmp go test ./tools/dae-rule-sync -count=1
ok

TMPDIR=/root/go-tmp go test ./component/ruleprovider ./config -count=1
ok
```

阶段 1 的 package race/vet 已在本轮独立复验。cmd 仍受现有 netlink 平台依赖阻塞；本轮没有把
cmd 或全仓测试报告为通过。

## 5.4 阶段 1：Hubble fix-first 与 test-only 轮次

Hubble 仅修改生产 `component/ruleprovider/rule_provider.go`，修复 Sol findings；本 test-only
轮次只修改测试和本进展文档，不提交 commit。

- 安全 fetch error 现在会在已验证 cache 可用时回退到 last-good snapshot；新增直接覆盖该路径的测试。
- text provider 通过逐行扫描提前执行 rule length/count 限制，避免先构造无界字符串切片。
- file path 打开使用 `O_NONBLOCK`，目录组件使用 `O_DIRECTORY`，FIFO/Unix socket 等 non-regular
  path 不会让测试或生产读取阻塞。
- RED 复现发现的是测试错误：在 `TMPDIR=/tmp`（macOS `/tmp` → `/private/tmp`）下，测试直接用
  未 canonicalize 的原始目录构造 descriptor，触发 `cache root path contains a symlink`；生产加载
  本身会先 canonicalize base directory。另一个测试断言把合法 clone 的 nil/empty slice 规范化
  当成配置变更。两处均只在测试文件中修复，未发现生产缺陷。

## 5. 当前仍未完成的事项

### 5.1 Sidecar / Stage 2 deferred 出口缺口

1. **DAT/ext 输出尚未实现**：计划要求生成可被 `DatReaderOptimizer` 读取的 geosite/geoip DAT，并输出类似：

   ```dae
   domain(ext:"generated/geosite/name.dat:name") -> outbound
   dip(ext:"generated/geoip/name.dat:name") -> outbound
   ```

   当前实现仍以内联 `domain()` / `dip()` 规则为主，功能可工作但不满足计划中 DAT/ext 的输出契约和大规则集扩展路径。

2. 尚无 groups 输出经真实 `config.New` 的提交测试；目前 route round-trip 覆盖比 groups 完整。

3. outbound 是否真实存在还不能由同步器验证；当前只验证 outbound 标识符格式。

4. sidecar `routes`、`groups` 与 provider snapshot 的完整 generation-atomic 发布尚未实现，
   属于 execution plan Stage 2 deferred；阶段 1/native provider 的 current/journal 事务不能
   代表 sidecar 输出已经原子发布。

### 5.2 原生 provider runtime 缺口

1. 尚未实现 interval 生命周期、后台刷新、staged reload 和运行时快照切换；当前是在配置加载时同步加载。
2. cache metadata、source-key、checksum、原子 current 和 last-good snapshot 已完成首轮强校验；仍需跨进程 writer 并发和长期刷新生命周期测试。
3. native `security.go` 已覆盖代理禁用、特殊 blocked ranges 和解析后 IP 检查；受控 fixture 已覆盖
   fetch redirect/hostname 拨号拒绝；`TestFetchHTTPRejectsRedirectToBlockedEndpoint` 已实际经过
   production `fetchHTTP` 且由独立 test-only GREEN 复验通过，因此 redirect-to-blocked 不再是 gap；
   仅完整 DNS rebinding E2E 仍是 gap。
4. native file provider 已有 canonical base、`O_NOFOLLOW`、`O_NONBLOCK`、`O_DIRECTORY` 和 regular-file 检查；仍需在真实 cmd/control-plane 路径恢复后做集成验证。
5. native YAML parser 已有 alias、node/depth、body/rule length/count 限制；仍需压力/模糊测试。
6. 私有 `loadOptions{allowPrivate:true}` 仅限同包测试，不能暴露给生产配置路径。
7. classical provider 目前只覆盖可直接归一化为 domain/IP 的基本条目；PROCESS-NAME、DST-PORT、AND/OR 等语义需要明确 unsupported 并在生产路径上阻止静默丢失。
8. 原生 flat select/fallback/url-test 的 outbound policy 接入尚未完成；当前只完成规则 provider runtime 的第一步。

### 5.3 仓库基线阻塞

完整 cmd/全仓测试依赖本分支缺失的 eBPF 生成文件。后续需要先恢复或执行仓库规定的 eBPF 生成流程，再验证：

- `go test ./cmd/...`；
- `go test ./...`；
- config → `readConfig()` → provider load → routing/control-plane 的真实集成路径。

## 6. 后续修改方案与步骤

按以下顺序继续，避免在阶段 1 runtime 出口未关闭前扩大 Stage 2/后续阶段范围：

### Step 1：完成阶段 1 runtime fix-first 出口

- 保持 production/test-only 子代理分离，分别完成代码修复和测试验证；
- 运行 ruleprovider/config 包测试、race、vet 和 diff 检查；
- 记录 cmd/eBPF 基线失败，不伪造全量通过；
- 不把 DAT、native lifecycle 或 group runtime 混入本轮提交。

### Step 2：完成后续 DAT writer

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

`bf855b9` 的性质是**历史未提交代码整理 / WIP checkpoint**，不是阶段一或阶段二完成提交；当前
HEAD 的 `d0126a6` 已是阶段 0 gate 提交。当前工作区的阶段 1 runtime、测试和文档仍待主线程独立
审查；本轮不提交 commit。其目的：

- 固化当前已经完成的代码和测试；
- 让后续 DAT、native lifecycle、group runtime 工作有清晰基线；
- 通过本文件避免遗漏已发现的审查问题和环境阻塞；
- 将每个后续垂直功能保持在独立 commit 中。

不能把阶段 1 runtime、DAT、native lifecycle 或 group runtime 堆进同一个提交。sidecar
routes/groups 的完整 generation-atomic 发布仍是 execution plan Stage 2 deferred，不因本轮
native provider GREEN 而改变范围。

## 8. 阶段 1 test-only 子代理验证记录

本轮由独立 test-only 子代理完成；没有创建子代理、没有提交 commit，也没有修改生产 Go
文件。修改范围仅为：

- `component/ruleprovider/rule_provider_test.go`：补齐 file/http load→expand、空/全不支持
  provider、last-good cache、缓存元数据隔离与 checksum/corrupt cache、cache publish 失败
  事务性、YAML alias/depth/node/rule 限制、symlink/directory/non-regular file、SSRF/重定向
  目标/代理钩子、特殊 blocked IP、展开上限和 unknown/negated ruleset 覆盖；新增 security
  fetch error 的 validated-cache 回退、坏内容→断网回退、cache/conf 不变和 canonical cache
  descriptor 测试辅助；本轮新增 YAML 预扫描分配量、IPv6 保留网段、cache versions 有界清理和
  多 provider transaction journal/recovery 测试。
- `cmd/rule_provider_config_test.go`：验收真实 `readConfig()` → local file provider
  `LoadAndExpand()` → routing rule 展开成功。
- `config/rule_provider_test.go`：补齐特殊 blocked IP/metadata 地址在 schema 层的拒绝。

### TDD / RED

Hubble fix-first 后先用 `/tmp` 复现报告，得到的是测试错误而非生产失败：

```text
TMPDIR=/tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -count=1
-> FAIL: TestLoadHTTPProviderRetainsLastGoodAfterInvalidUpdateAndNetworkFailure: cache root path contains a symlink
-> FAIL: TestReadCacheRejectsMetadataIsolationAndCorruption/*: cache root path contains a symlink
-> FAIL: TestLoadDoesNotUseCacheWhenHTTPSourceChanges: cache root path contains a symlink

原因：测试直接用未 canonicalize 的 t.TempDir() 构造 newCacheDescriptor；生产 prepareProviders
会先 EvalSymlinks(baseDir)。

修正 canonical descriptor 后的第二个测试 RED：
-> FAIL: TestLoadHTTPProviderRetainsLastGoodAfterInvalidUpdateAndNetworkFailure:
   conf changed after invalid HTTP update (nil/empty slice clone normalization)
```

两次均只修改测试：加入 canonical test descriptor，并以 canonical clone 比较语义配置；未发现
生产缺陷，也没有需要交给下一 code-only 子代理的生产定位。

### 5.5 Nash / Sol fix-first 与独立 GREEN 轮次

Nash 只修改了生产代码；本轮 test-only 子代理没有修改生产 Go 文件、没有派生子代理，也没有提交。
本轮新增测试保持行为断言：YAML 测试检查拒绝前的实际分配量，版本测试检查多次不同内容后的
`versions` 保留上限，journal 测试制造一方已切换/一方未切换的中断状态并检查重启后的两个
provider 都回到同一 generation；没有放宽断言或删除失败测试。

生产修复覆盖：

- YAML 先做资源预扫描，再进入完整 YAML 解码；
- 补充 IPv6 特殊/保留网段的组件和配置入口拒绝；
- 发布成功后清理旧 cache versions，避免无界累积；
- 多 provider 发布写入 transaction journal，并在重启时恢复未完成事务。

#### RED（Nash 修复前）

先运行聚焦命令，得到以下真实生产失败：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -run 'TestParseYAMLRejectsNodeLimitBeforeMaterializingLargeTrailingScalar|TestBlockedIPRejectsReservedIPv6Ranges|TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates|TestRestartRecoversInterruptedMultiProviderPublishWithoutMixedGeneration|TestValidateRuleProvidersRejectsReservedIPv6Ranges' -count=1

FAIL: TestParseYAMLRejectsNodeLimitBeforeMaterializingLargeTrailingScalar
  parseBody() allocated 263156432 bytes before rejecting YAML node limit; want less than trailing scalar size 33554432

FAIL: TestBlockedIPRejectsReservedIPv6Ranges
  blockedIP(2001:0::1) = false for reserved IPv6 range

FAIL: TestValidateRuleProvidersRejectsReservedIPv6Ranges
  An error is expected but got nil for http://[2001:0::1]/rules.yaml
```

同一次默认沙箱执行中，cache 测试在进入生产逻辑前触发：

```text
panic: httptest: failed to listen on a port: listen tcp6 [::1]:0: bind: operation not permitted
```

这是测试环境的本地 socket 权限阻塞，不是 cache 生产失败；取得受控本地 socket 权限后重新执行同一
聚焦命令。

#### GREEN / VERIFIED（Nash 修复后）

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -run 'TestParseYAMLRejectsNodeLimitBeforeMaterializingLargeTrailingScalar|TestBlockedIPRejectsReservedIPv6Ranges|TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates|TestRestartRecoversInterruptedMultiProviderPublishWithoutMixedGeneration|TestValidateRuleProvidersRejectsReservedIPv6Ranges' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  1.062s
ok  github.com/daeuniverse/dae/config  0.370s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  1.258s
ok  github.com/daeuniverse/dae/config  0.715s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  3.611s
ok  github.com/daeuniverse/dae/config  1.562s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
exit 0, no output
```

本轮剩余 gap：cmd 仍受现有 netlink 平台依赖阻塞；完整 DNS rebinding e2e、interval 生命周期和
全仓验证仍未完成。上述 package GREEN 不代表 cmd 或全仓 GREEN；redirect-to-blocked 已由生产
`fetchHTTP` 路径的独立测试覆盖。

### 5.6 历史 Stage 1 RED（后续 GREEN 已完成）：file provider last-good snapshot

本轮继续严格 test-only；没有修改生产 Go 文件、没有派生子代理、没有提交。新增测试 patch 文件为：

- `component/ruleprovider/rule_provider_test.go`：file provider 首次有效加载后源文件消失，以及空/坏
  更新不得覆盖 last-good snapshot；
- `cmd/rule_provider_config_test.go`：真实 `readConfig()` 路径在 file provider 源文件消失后的
  last-good 行为。

先运行最小聚焦 RED 命令：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestLoadFileProviderUsesPersistedLastGoodAfterFileDisappears|TestLoadFileProviderBadUpdateDoesNotReplaceLastGoodSnapshot' -count=1

--- FAIL: TestLoadFileProviderUsesPersistedLastGoodAfterFileDisappears (0.00s)
    rule_provider_test.go:446: file provider load after source disappearance error = rule provider "local": open provider path: no such file or directory, want last-good snapshot
--- FAIL: TestLoadFileProviderBadUpdateDoesNotReplaceLastGoodSnapshot (0.00s)
    rule_provider_test.go:468: read initial file-provider snapshot error = cache current is missing
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.634s
FAIL
```

首个真实生产失败是 `TestLoadFileProviderUsesPersistedLastGoodAfterFileDisappears`：生产
`prepareProvider` 的 file 分支在源文件消失后直接返回 `open provider path`，没有读取首次有效加载的
持久化 snapshot。第二个失败进一步证明首次 file provider load 没有发布 `current` cache。该命令没有
网络或本地 socket 阻塞，失败属于生产行为，不是测试环境问题。

当时按照 TDD 要求在首个真实 RED 后立即暂停；以下项目在该历史轮次尚未运行或继续扩展：负数
`MaxResponseHeaderBytes`、public hostname/redirect 的真实 fetch e2e（后续
`TestFetchHTTPRejectsRedirectToBlockedEndpoint` 已经过生产 `fetchHTTP` 并独立 GREEN）、journal
并发/崩溃窗口、text materialization 前限制，以及旧 `ruleset()` 语义复核。
`readConfig()` file-provider 测试已写入但因首个生产 RED 未在该轮继续执行；component/config 的
后续 GREEN 见第 10 节，cmd/readConfig 仍保留 Darwin netlink/eBPF 编译限制。

Scope decision：routes/groups 非原子发布属于 execution plan Stage 2；本轮不修改 `tools` 生产代码，
也不把该问题伪装成 Stage 1 已完成。后续 Stage 2 必须单独补 generation-atomic routes/groups
测试和实现。

### 5.7 历史 Stage 1 RED（后续 GREEN 已完成）：负响应头限制的实际 fetch 路径

本轮在 file snapshot GREEN 后继续 test-only；没有修改生产 Go 文件、没有派生子代理、没有提交。先审查
现有 `TestSafeTransportDisablesProxyAndDialBypassHooks`，确认它只验证 transport hook 清理，没有通过
实际响应头验证 `fetchHTTP` 的 1 MiB 上限。本轮只新增/修改：

- `component/ruleprovider/rule_provider_test.go`：新增 `newPublicHTTPTestServer`，从本机接口选择
  non-blocked global-unicast 地址，实际调用 `fetchHTTP(..., allowPrivate=false)`；新增
  `TestFetchHTTPRejectsResponseHeadersWhenCustomTransportLimitIsNegative`，使用
  `MaxResponseHeaderBytes: -1` 和超过 1 MiB 的真实 HTTP 响应头。
- `docs/mihomo-rule-provider-progress.md`：记录本轮 RED。

最初的 loopback-only 草稿被判定为测试假阳性并改写：它在 `safeDialContext` 的 blocked-IP 拒绝处失败，
没有抵达响应头检查，不能作为 RED 证据。最终测试使用 public-interface fixture 后才执行了生产 fetch
路径。命令使用受控本地 listener 权限，但没有环境失败：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestFetchHTTPRejectsResponseHeadersWhenCustomTransportLimitIsNegative$' -count=1

--- FAIL: TestFetchHTTPRejectsResponseHeadersWhenCustomTransportLimitIsNegative (0.01s)
    rule_provider_test.go:360: fetchHTTP() error = nil for response headers larger than the 1 MiB production limit
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.670s
FAIL
```

这是生产 RED，不是测试环境阻塞：请求经过 `fetchHTTP`、`validatePublicURL`、`safeTransport`、
`safeDialContext` 和真实 `http.Transport`，但负值 `MaxResponseHeaderBytes` 没有被归一到 1 MiB，
导致约 1 MiB 以上响应头被接受。生产定位为 `component/ruleprovider/security.go` 的
`safeTransport` MaxResponseHeaderBytes 归一化条件（当前只处理 `== 0` 或 `> maxResponseHeaderBytes`）。

当时按 TDD 要求在取得首个真实 RED 后立即暂停；该历史轮次未继续运行 public hostname/redirect
额外 seam、并发 journal、text materialization 前分配限制或 cmd `readConfig()` 回退测试；后续
`TestFetchHTTPRejectsRedirectToBlockedEndpoint` 已经过生产 `fetchHTTP` 并独立 GREEN。旧
`ruleset()` 语义已有 `TestExpandRulesetPreservesAndFunctionsAndOutbound` 的实际展开覆盖，本轮没有
重复修改；routes/groups 非原子发布仍属于 execution plan Stage 2。

### 5.8 James GREEN：text provider 预扫描与独立 test-only 复验

James 的 code-only 修复范围仅为 `component/ruleprovider/rule_provider.go`，加入 text provider
资源预扫描；本轮独立 test-only 复验没有修改任何测试或生产文件，只更新本进度文档，没有派生子代理、
没有提交。

先前 test-only RED 证据保留：

```text
TestParseTextRejectsExcessiveRuleCountBeforeMaterializingAllRules
parseBody() allocated 198692240 bytes while rejecting excessive text rule count; want less than 16777216
```

本轮聚焦 GREEN：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestParseTextRejectsExcessiveRuleCountBeforeMaterializingAllRules$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.775s
```

本轮 A/B 聚焦复核使用的命令如下；输出只有 text 超规则数测试失败，A 的实际 redirect、hostname
resolver/dial 和 B 的 journal 并发测试没有失败，因此记录为 PASS，而不是把聚焦命令整体误写成全绿：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestFetchHTTPRejectsRedirectToBlockedEndpoint$|^TestSafeDialRejectsHostnameResolvingToBlockedIP$|^TestConcurrentPublishAndRecoveryKeepsTransactionRootConsistent$|^TestParseTextRejectsOversizedLineBeforeMaterializingString$|^TestParseTextRejectsExcessiveRuleCountBeforeMaterializingAllRules$' -count=1

--- FAIL: TestParseTextRejectsExcessiveRuleCountBeforeMaterializingAllRules
    rule_provider_test.go:259: parseBody() allocated 198692240 bytes while rejecting excessive text rule count; want less than 16777216
```

全量、race、vet 和 diff check 的独立 GREEN 证据：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  1.737s
ok  github.com/daeuniverse/dae/config  0.705s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  4.997s
ok  github.com/daeuniverse/dae/config  1.937s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
exit 0, no output

git diff --check
exit 0, no output
```


## 10. Stage 1 TDD 审计/证据补全（最终 current-state reconciliation）

本节是对前述代理轮次历史记录的最终证据收口。上文的 RED 保留其发生时的真实上下文；本节
把已经完成的后续 code-only GREEN 和独立 test-only GREEN 明确接上。这里的“完整 stdout 未保存”
表示当前 canonical 历史没有保存该次输出全文；不补写虚构的失败行、耗时或代理名称。本文档本轮
仍严格是 documentation-only，没有修改生产 Go、测试、执行计划或 root 下的 legacy 未跟踪文件。

本节的证据等级需要明确区分：`TestLoadAcceptsFreshValidProviderSemanticChange` 有可回溯的
test-only RED 输出，失败原因为 `cache metadata source mismatch`，随后有 code-only GREEN；
`TestFetchHTTPRedactsRedirectUserinfo`，以及 component 的 blockedIP/redirect-target IPv6 覆盖和
config 的 `TestValidateRuleProvidersRejectsReservedIPv6Ranges` 两组 IPv6 覆盖，是在同一
test-only RED 阶段写入，code-only 后由独立 test-only GREEN 运行通过，但首次 RED 阶段没有分别
保存 stdout。generation removal、304/no-token、source rotation、canonical target、HTTP/1-only 等
较早轮次的精确 stdout 也未全部保存。对这些项目，本文只记录“行为已独立验证，历史 RED 证据来自
代理报告/未保存原始 stdout”，不把它们写成可审计的完整三段证据；已有的真实命令结果和环境限制
仍保持原样。

### 10.1 Generation token fence：same-token body drift、token removal 与 304

1. TestLoadRejectsFreshBodyChangeWithinSameGeneration

   test-only RED 的精确命令和失败证据已保存：

   ~~~text
   TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-go-gopath go test ./component/ruleprovider -run '^TestLoadRejectsFreshBodyChangeWithinSameGeneration$' -count=1

   --- FAIL: TestLoadRejectsFreshBodyChangeWithinSameGeneration (0.06s)
       rule_provider_test.go:1738: same-generation body change returned accepted registry: ruleprovider.Registry{"p":ruleprovider.ProviderRules{Functions:[]*config_parser.Function{(*config_parser.Function)(0x2c362d1f1b60)}}}
   FAIL
   FAIL github.com/daeuniverse/dae/component/ruleprovider 0.735s
   ~~~

   该 RED 是生产行为：G1 的 A2 fresh body 被接受，未保持 G1/A1 last-good。code-only GREEN
   在 component/ruleprovider/rule_provider.go 完成 generationHistory、current identity CAS、
   “一个 generation 绑定一个 body”以及 publish 前 history fence。该 code-only 轮次的完整
   stdout 未保存在当前 canonical 历史，故只记录实现事实，不伪造命令结果。

2. TestLoadRejectsFreshBodyWhenGenerationHeaderDisappears

   test-only RED 已实际执行：第一次 200 建立 G1/A1，第二次 fresh 200 返回 A2 但删除
   X-Dae-Rule-Provider-Generation；失败契约是不得接受 fresh body、不得改变 current/body/
   metadata/history。该行为已独立验证，历史 RED 证据来自代理报告，首次 RED 原始 stdout 未保存；
   本文不虚构 failure 行。code-only GREEN 与上项相同，并在 prepareProvider 中对“已有 cached
   generation + fresh response 无 token” fail closed。

3. 304 generation fence/no-token cached snapshot

   相关 test-only RED 测试名为：

   - TestLoadRejects304GenerationDriftAgainstCachedSnapshot：缓存 generation=one，304 携带
     generation=two；
   - TestLoadRejects304GenerationWhenCachedSnapshotHasNoToken：缓存没有 generation token，
     304 却携带 G1。

   两个 RED fixture 都已实际运行；这些行为已独立验证，历史 RED 证据来自代理报告，首次 RED
   原始 stdout 未保存，因此只记录失败契约：304 不得把不一致的 generation 写入 cache，也不得在
   no-token cached snapshot 上接受新的 token。code-only GREEN 在 fetchHTTP/prepareProvider 中
   校验 304 token 与 cached snapshot，并在拒绝时保持 current、body、metadata/history 和
   transaction journal 不变。

   上述三类 fresh/304 fence 的独立 test-only GREEN 使用同一真实 focused 命令完成：

   ~~~text
   TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestLoadRejectsFreshBodyChangeWithinSameGeneration|TestLoadRejectsFreshBodyWhenGenerationHeaderDisappears|TestLoadRejects304GenerationDriftAgainstCachedSnapshot|TestLoadRejects304GenerationWhenCachedSnapshotHasNoToken|TestLoadAcceptsFreshValidProviderSourceChange|TestReadCurrentStateRejectsNonCanonicalTarget|TestPublishPreparedRejectsRemoteOldGenerationReplayAfterNewerCurrent|TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule|TestSafeTransportAllowsOnlyHTTP1Protocols' -count=1
   ok   github.com/daeuniverse/dae/component/ruleprovider  0.676s
   ~~~

### 10.2 Source rotation 与 canonical current target

- `TestLoadAcceptsFreshValidProviderSemanticChange` 覆盖保持同一 source、仅改变 behavior 的
  fresh candidate。test-only RED 的可回溯输出是 `cache metadata source mismatch`：旧实现把
  semantic rotation 当成不可用的 cache metadata mismatch，不能发布 fresh candidate；随后
  code-only GREEN 允许已验证 fresh candidate 在 `source type`、`source`、`behavior`、`format` 或
  `max_size` 变化时发布，并在 fresh failure 时不使用旧 descriptor 的 cache。该测试的独立
  focused/full/race/vet/diff GREEN 结果见 10.8。

- TestLoadAcceptsFreshValidProviderSourceChange 的 fixture 先发布 old/G1，再切换到
  new/G2，检查 registry、body、source、source_key、generation 均切换到新 source，随后
  新 source 网络失败仍回退到 new/G2 last-good。该行为已独立验证；该 test-only RED 轮次的
  历史证据来自代理报告，精确 RED stdout 未保存在当前 canonical 历史，不补造失败文本。
  code-only GREEN 在
  component/ruleprovider/rule_provider.go 增加受 current identity CAS 保护的 source-change
  integrity read，并只在 fresh candidate 发布时携带 generation history。上面的 focused
  命令已独立复验该测试为 GREEN。

- TestReadCurrentStateRejectsNonCanonicalTarget 覆盖 versions/./version-1、
  versions/nested/../version-1 和 versions/../versions/version-1。该行为已独立验证；其
  test-only RED 的历史证据来自代理报告，精确原始 stdout 未保存。code-only GREEN 由 readCurrentState/
  validateCacheCurrentTarget 拒绝非 clean relative、非 versions/<basename>、越界和非目录
  target。上面的 focused 命令已独立复验该测试为 GREEN。

### 10.3 config 6to4 relay policy consistency

这是最后一轮 config 6to4 relay 的完整审计链，不能只引用 component 的同名网段覆盖。

- test-only RED 的真实失败断言是：

  ~~~text
  command: TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./config -run '^TestBlockedRuleProviderIPRejectsSixToFourRelayRange$' -count=1
  rule_provider_test.go:85: blockedRuleProviderIP(192.88.99.1) = false, want true
  ~~~

  这是实际的 blockedRuleProviderIP=false production RED；这里仅保留已知的失败断言，不声称
  当前保存了该轮完整 stdout。

- code-only GREEN 在 config/rule_provider.go 的 blockedRuleProviderNetworks 加入
  192.88.99.0/24（6to4 relay anycast addresses），并与
  component/ruleprovider/security.go 的 provider blocked network policy 保持一致。该修复
  使 config validation 与 native fetch security 对同一 relay range 都 fail closed。

- 独立 focused GREEN：

  ~~~text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./config -run '^TestBlockedRuleProviderIPRejectsSixToFourRelayRange$' -count=1
  ok  	github.com/daeuniverse/dae/config	0.469s
  ~~~

  同一 production GREEN 后的 component/config full、race、vet 和 git diff --check 结果见
  10.7；这些独立 gate 包含 TestBlockedRuleProviderIPRejectsSixToFourRelayRange，因此最后一轮
  config 6to4 的 focused/full/race/vet/diff GREEN 链完整闭合。

### 10.4 Old-generation replay/history 与 malformed URL redaction

- Old candidate/replay 的 test-only RED 已在同一审查轮次实际取得。已保存的失败为
  TestPublishPreparedRejectsOlderCandidateThanCurrent：generation/two current 被旧
  generation/one candidate 回退；同一命令还保存了
  TestValidateRuleProvidersRedactsCredentialsFromMalformedURL 的失败，原始错误包含
  user 和 stage1-secret。code-only GREEN 分别在 component/ruleprovider/rule_provider.go
  增加 bounded GenerationHistory、旧 generation replay/history fence 和 expected-current
  CAS，在 config/rule_provider.go 的 malformed-url 分支使用脱敏 URL。

  ~~~text
  RED command: TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -run 'TestPublishPreparedRejectsOlderCandidateThanCurrent|TestValidateRuleProvidersRedactsCredentialsFromMalformedURL|TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration|TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration' -count=1

  --- FAIL: TestPublishPreparedRejectsOlderCandidateThanCurrent
      rule_provider_test.go:1253: older candidate replaced newer current: initial=...Generation:"two"... after=...Generation:"one"...
  --- FAIL: TestValidateRuleProvidersRedactsCredentialsFromMalformedURL
      Error: "rule provider \"credentialed\": invalid url \"http://user:stage1-secret%zz@example.com/rules\"" should not contain "user"
  ~~~

- 后续独立 test-only GREEN 覆盖 TestPublishPreparedRejectsOlderCandidateThanCurrent 和
  TestPublishPreparedRejectsRemoteOldGenerationReplayAfterNewerCurrent；后者还确认旧 remote
  token 在 generation/two 已成为 current 后不能留下 journal 或回退 body/current：

  ~~~text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestPublishPreparedRejectsOlderCandidateThanCurrent|TestPublishPreparedRejectsRemoteOldGenerationReplayAfterNewerCurrent' -count=1
  ok  	github.com/daeuniverse/dae/component/ruleprovider	0.790s

  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./config -run '^TestValidateRuleProvidersRedactsCredentialsFromMalformedURL$' -count=1
  ok  	github.com/daeuniverse/dae/config	0.368s
  ~~~

### 10.5 YAML multiline scalar/flow-depth 资源边界

已保存的首个 YAML 跨行 RED 是
TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule：quoted/plain/folded
fixture 的物理行和 body 均在限制内，但 parseBody 在拒绝约 2 MiB logical scalar 前分配约
25.4 MiB。code-only GREEN 在 component/ruleprovider/rule_provider.go 增加 YAML preflight，
覆盖 node/scalar 长度、跨行 scalar 和 multiline flow nesting，之后才进入完整 YAML decode。

flow collection/depth 的 test-only 补强测试名为：

- TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule；
- TestPreflightRejectsMultilineFlowDepthBeforeMaterializing。

前者的两个 flow scalar 子用例先由独立 yaml.Unmarshal 证明会合并成超长 logical scalar，再
断言 parseBody 拒绝且分配低于 scalar 大小；后者构造超过 maxProviderYAMLDepth 的跨行嵌套
flow collection。两项补强的独立 GREEN 命令和结果如下；该补强轮次没有保存新的生产 RED
stdout，不把它反写成 RED：

~~~text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule|TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule|TestPreflightRejectsMultilineFlowDepthBeforeMaterializing' -count=1
ok  	github.com/daeuniverse/dae/component/ruleprovider	0.483s
~~~

### 10.6 HTTP/1-only transport

TestSafeTransportAllowsOnlyHTTP1Protocols 的 test-only 契约把 caller transport 预置为 HTTP/1、
HTTP/2 和 unencrypted HTTP/2，要求生产 clone 显式只保留 HTTP/1。该行为已独立验证；该轮 RED
的历史证据来自代理报告，精确原始 stdout 未保存。code-only GREEN 在
component/ruleprovider/security.go 清除 TLSNextProto、ForceAttemptHTTP2、alternate protocol
hooks，并设置 Protocols.HTTP1=true、HTTP2/unencrypted HTTP2=false；10.1 的 generation-focused
focused 命令已独立复验该测试为 GREEN。

### 10.7 最终独立 package gate

10.1 至 10.6 的 focused 结果均来自生产修复完成后的独立 test-only 运行。随后 package
full/race、vet 和 diff check 结果为：

~~~text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
ok  	github.com/daeuniverse/dae/component/ruleprovider	3.545s
ok  	github.com/daeuniverse/dae/config	0.833s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
ok  	github.com/daeuniverse/dae/component/ruleprovider	12.414s
ok  	github.com/daeuniverse/dae/config	1.794s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
exit 0, no output

git diff --check
exit 0, no output
~~~

普通 Darwin 沙箱第一次运行带 httptest listener 的 focused/full/race 命令时真实失败于
listen tcp6 [::1]:0: bind: operation not permitted；在允许受控本地 listener 后同一组命令
如上通过。这是环境权限限制，不是 production RED。cmd/readConfig 仍不能写成 GREEN：现有
Darwin netlink/eBPF 编译基线缺少 netlink.LinkUpdate、LinkSubscribeWithOptions、
unix.RTM_NEWLINK/RTM_DELLINK、ethtool 与 transparent-socket 常量，必须在匹配平台/基线
重新执行。Stage 2 及以后（DAT/ext、interval lifecycle、完整 sidecar routes/groups
generation-atomic 发布和后续 group runtime）仍未开始，保持原有 deferred 结论。

本节之后保留的 5.x 小节是按代理轮次追加的历史记录；它们的 RED 中断语句描述当时的时序，
当前完成状态以本节 10.1 至 10.8 的审计证据为准。

### 10.8 本轮 code-only GREEN 范围与独立门禁

本轮 code-only GREEN 的真实范围是：

- cache 语义轮换允许已验证的 fresh candidate 在 `source type`、`source`、`behavior`、`format`
  或 `max_size` 变化时发布；fresh failure 不使用旧 cache，避免把旧语义快照当作新 descriptor
  的 last-good；
- redirect 错误保留结构化错误类型；正常可解析且带 credential 的 redirect `Location` 由
  `TestFetchHTTPRedactsRedirectUserinfo` 通过 production `fetchHTTP` 路径验证凭据/URL 脱敏；后续对
  malformed `Location` userinfo 的独立审查复核已通过，当前实现未复现该泄漏，保留
  `TestFetchHTTPRedactsMalformedRedirectLocationUserinfo` 作为回归测试。该复核不等同于原审查静态
  推断已经完成 TDD RED → code-only GREEN；该轮没有 production RED、没有 code-only GREEN，也没有
  生产修改。`TestFetchHTTPRejectsRedirectToBlockedEndpoint` 仍通过 production `fetchHTTP` 路径验证
  redirect-to-blocked 拒绝；
- runtime 与 config 的 blocked-network policy 同步加入 `100:0:0:1::/64` 与 `5f00::/16`。

上述 semantic-change、正常可解析 redirect-userinfo 和两组 IPv6 行为均有独立 focused GREEN；package
full、race、vet 与 `git diff --check` 也通过。malformed `Location` userinfo 的新复核仅有下述代理
报告中的 focused `-v` PASS，不升级为原审查的 RED → GREEN 证据，也不把它并入 10.7 的 package gate。
10.7 保留了既有独立门禁的实际命令结果；本段不为首次 RED 阶段未保存的逐项 stdout 补造输出。
cmd/readConfig 仍受 Darwin netlink/eBPF 基线阻塞，
完整 DNS rebinding E2E 仍是 gap，Stage 2 deferred 项保持不变。

### 10.9 空 provider 列表的 `LoadAndExpand` fail-closed

本轮补充空 provider 列表下的 `LoadAndExpand` fail-closed 审计。历史 RED 的精确 stdout 来自代理报告；
这里仅保留报告给出的真实失败文本，不补写未保存的命令、耗时或其它输出。

- test-only RED 首次聚焦测试为 `TestLoadAndExpandRejectsUnknownProviderWithEmptyProviderList`，真实失败为：

  ```text
  LoadAndExpand() error = nil for unknown provider with empty provider list
  ```

  同一轮还加入了 `TestLoadAndExpandRejectsNegatedRulesetWithEmptyProviderList`；但首次 RED 只运行
  unknown focused，没有运行第二个测试，不能将第二个测试写成首次 RED 的运行项。
- code-only GREEN 仅修改 `component/ruleprovider/rule_provider.go`：`conf == nil` 仍保持 no-op；
  空 provider 列表使用空 `Registry` 执行 `ExpandRoutingRules`；无 ruleset 的空配置仍成功；
  unknown provider 和 negated `ruleset()` 均 fail closed。
- independent test-only GREEN 由代理报告记录为 PASS：unknown、negated 和 empty no-op 的 focused
  覆盖，`component/ruleprovider` 与 `config` full，race，vet，以及 `git diff --check` 均通过。

本轮不改变既有未完成项：execution plan Stage 2（包括 sidecar routes/groups 的完整
generation-atomic 发布）仍 deferred；cmd/readConfig 仍受 Darwin netlink/eBPF 基线阻塞；完整 DNS
rebinding E2E 仍未完成。

### 10.10 malformed redirect `Location` userinfo：审查复核与回归

独立审查曾将 malformed redirect `Location` 中的 userinfo 视为 blocker。随后 test-only 代理新增
`TestFetchHTTPRedactsMalformedRedirectLocationUserinfo`：测试使用 public raw HTTP listener，真实
进入 production `fetchHTTP`，并以 `allowPrivate=false` 执行；它检查错误中未泄漏用户名、密码、目标主机
路径或完整 `Location`。

普通 sandbox 创建 listener 时被权限阻塞；在受控授权环境中，请求真实到达 listener，focused `-v`
运行通过。以下命令和 PASS 摘要来自代理报告，当前 canonical 记录没有保存完整 stdout：

~~~text
go test ./component/ruleprovider -run '^TestFetchHTTPRedactsMalformedRedirectLocationUserinfo$' -v -count=1
PASS: TestFetchHTTPRedactsMalformedRedirectLocationUserinfo
PASS
~~~

该复核结论是：审查复核已通过，当前实现未复现该泄漏；保留测试作为回归。它不是原审查静态推断
已经通过 TDD RED → code-only GREEN 的证明；该轮没有 production RED、没有 code-only GREEN，也没有
生产修改。因而本文不捏造 malformed redirect 的 RED stdout，也不把受控 focused PASS 扩写成生产修复
或完整 package/full-repo GREEN。

### 历史 Stage 1 test-only RED（后续 GREEN 已完成）：同一 opaque generation 的 fresh body 轮换

本轮严格保持 test-only；只修改了 `component/ruleprovider/rule_provider_test.go` 和本进度文档，
未修改生产 Go 文件、未派生子代理、未提交。新增测试
`TestLoadRejectsFreshBodyChangeWithinSameGeneration` 以确定性 HTTP fixture 先返回 body A1 /
generation `G1`，再返回 body A2 / 同一 generation `G1`；测试无论第二次 Load 返回何值，都检查
registry、current target、body、完整 metadata（含 generation history）和 transaction journal。

唯一聚焦命令及实际 RED：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestLoadRejectsFreshBodyChangeWithinSameGeneration$' -count=1

--- FAIL: TestLoadRejectsFreshBodyChangeWithinSameGeneration (0.06s)
    rule_provider_test.go:1738: same-generation body change returned accepted registry: ruleprovider.Registry{"p":ruleprovider.ProviderRules{Functions:[]*config_parser.Function{(*config_parser.Function)(0x2c362d1f1b60)}}}
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.735s
```

这是生产行为 RED，不是测试环境阻塞：当前实现接受同一 opaque token `G1` 的 A2 fresh body，
因而未能保持 A1 last-good snapshot。生产定位为
`component/ruleprovider/rule_provider.go` 的 `validatePreparedCandidates` / generation
history fence；当时在该首个真实 RED 后停止。source/descriptor 轮换、非规范 current target、
304 无 token、config 6to4 和 YAML flow 的后续 GREEN/独立复验已完成，见第 10 节。

### 5.24 历史 Stage 1 test-only RED（后续 GREEN 已完成）：旧 candidate 降级与 malformed URL 凭据脱敏

本轮严格保持 test-only，未修改任何生产 Go 文件、未派生子代理、未提交。测试修改范围为：

- `component/ruleprovider/rule_provider_test.go`：修正
  `TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration`，goroutine 现在使用与磁盘断言
  相同的 `dir`；修正 `TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration`，`/a`、`/b` 都
  返回共享 `X-Dae-Rule-Provider-Generation`，body 随动态 generation 变化，错误分支只接受明确
  generation mismatch/drift/batch 拒绝，并检查同一实际 cache root；新增
  `TestPublishPreparedRejectsOlderCandidateThanCurrent`，先建立 generation/two current，再直接
  通过 `publishPrepared` 提交 generation/one candidate。
- `config/rule_provider_test.go`：新增
  `TestValidateRuleProvidersRedactsCredentialsFromMalformedURL`，使用
  `http://user:stage1-secret%zz@example.com/rules`，断言错误不含用户名或 secret。

唯一相关聚焦命令：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -run 'TestPublishPreparedRejectsOlderCandidateThanCurrent|TestValidateRuleProvidersRedactsCredentialsFromMalformedURL|TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration|TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration' -count=1

--- FAIL: TestPublishPreparedRejectsOlderCandidateThanCurrent (0.08s)
    rule_provider_test.go:1253: older candidate replaced newer current: initial=...Generation:"two"... after=...Generation:"one"...
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 1.150s
--- FAIL: TestValidateRuleProvidersRedactsCredentialsFromMalformedURL (0.00s)
    rule_provider_test.go:110:
        Error: "rule provider \"credentialed\": invalid url \"http://user:stage1-secret%zz@example.com/rules\"" should not contain "user"
FAIL
FAIL github.com/daeuniverse/dae/config 0.633s
FAIL
```

两项均为真实 production RED，不是测试环境阻塞：

1. `publishPrepared` 接受旧 generation/one candidate 并替换已有 generation/two current；测试
   的 expected 是拒绝或保持 generation/two，actual 是返回成功且 current 变为 generation/one。
2. `config.validateRuleProviderURL` 的 malformed-url 分支返回包含完整 raw URL 的错误，泄露
   `user` 和 `stage1-secret`；expected 是完全脱敏。

两个 mixed-generation 测试在同一命令中通过，说明本轮的目录/token 修正没有制造额外失败：
`TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration` 使用动态 shared token，
`TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration` 使用实际 Load 的 `dir`。按首个
相关审查缺口当时取得真实 RED 后停止；后续 code-only 修复与独立 GREEN 见第 10 节。

### 5.23 Archimedes GREEN：无 candidate journal TOCTOU 与 `version-*` 独立复验

Archimedes 仅修改生产 `component/ruleprovider/rule_provider.go`：`candidate == nil` 的 prepared
provider 保留 descriptor，非空 batch 始终确定 transaction root，在 transaction flock 内复查并
恢复/拒绝 journal；新发布目录命名为 `version-*`。本轮独立 test-only 没有修改生产或测试文件、
没有派生子代理、没有提交；只运行验证命令并更新本进度文档。

聚焦 journal GREEN：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.724s
```

用户指定的组合聚焦命令也通过：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare|TestCrossProcessRecoveryHonorsTransactionFlock|TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates|TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration|TestMultiProviderLoadRejectsFreshAndLastGoodGenerationMix|TestParseYAMLRejectsMultilineOversized|TestParseYAMLRejectsMultilineFlowScalarsBeforeMaterializingOversizedRule' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  1.776s
```

该正则中的两个 YAML 名称与当前测试实际名称顺序不一致，因此上述命令没有选择 YAML 用例；
为避免虚报，另行运行当前实际名称并通过：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule|TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.443s
```

包级独立验证：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  3.251s
ok  github.com/daeuniverse/dae/config  0.759s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  12.167s
ok  github.com/daeuniverse/dae/config  1.945s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
exit 0, no output

git diff --check
exit 0, no output
```

`TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates` 通过真实 `version-*` 目录计数，并断言
`current` 存在、`readCacheSnapshot` 成功、body 等于最后一次 fresh 更新；因此版本/current 主
断言未因目录改名失效。当前 TOCTOU 测试的残余清理断言仍只匹配旧的 `.candidate-*` 前缀；本轮
禁止修改测试，故不把该断言当作 `version-*` 临时目录清理的完整证据，后续应由独立 test-only
轮次修正。该观察不是本轮 production failure。

cmd/readConfig 仍仅受 Darwin netlink/eBPF 编译基线阻塞，本轮没有宣称 cmd GREEN；routes/groups
完整 generation-atomic 发布仍 deferred 到 execution plan Stage 2。

### 5.22 历史 Stage 1 test-only RED（后续 GREEN 已完成）：无 candidate 时 journal TOCTOU

Bohr 的标准 `64:ff9b::/96` code-only GREEN 独立复验已完成后，本轮继续 test-only；未修改生产
Go 文件、未派生子代理、未提交。测试 patch 仅修改
`component/ruleprovider/rule_provider_test.go`，将
`TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare` 修正为：

- 第一次使用真实同一 `dir` 加载固定 body、ETag、Last-Modified 和 generation，建立可校验的
  last-good snapshot；
- 第二次 HTTP 响应复用完全相同的 body/headers，并验证请求携带相同的条件请求头；响应 body
  已 flush 后保持 barrier，使第二次准备路径在相同快照下完成，candidate 应为 nil；
- barrier 内写入带唯一 marker 的 `transaction.journal`，释放响应后检查 Load 必须拒绝/恢复，
  marker 不得被覆盖，旧 `current`/snapshot 不得改变，且不得留下 `.candidate-*` 目录；
- 错误分支使用实际第二次 Load 的 `dir` 检查 cache，不再使用与 Load 不同的 `t.TempDir()`。

最小聚焦命令及首个真实 production RED：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare$' -count=1

--- FAIL: TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare (0.04s)
    rule_provider_test.go:1298: Load() silently accepted/published over an existing journal marker: registry=ruleprovider.Registry{"p":ruleprovider.ProviderRules{Functions:[]*config_parser.Function{(*config_parser.Function)(0x22d799830360)}}}
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.493s
FAIL
```

这不是 listener/权限环境阻塞：同一测试已完成第一次 cache 建立、第二次同 body/headers HTTP
barrier 和 marker 写入。生产定位为 `component/ruleprovider/rule_provider.go`：
`publishPrepared:1012-1030` 仅在 `preparedTransactionRoot` 非空时获取 transaction lock 并
复查 journal；`preparedTransactionRoot:1155-1159` 跳过所有 `candidate == nil` 的 provider，
因此本 fixture 得到空 transaction root，`publishPrepared:1096-1097` 随后直接返回 nil，静默
接受 marker。该失败交给下一 code-only 修复轮次。

当时按“首个真实 production RED 立即暂停”；后续 code-only 与独立 GREEN 已完成，见第 9.9 节及第 10 节。

### 5.21 历史 Stage 1 test-only RED（后续 GREEN 已完成）：标准 IPv4-embedded NAT64

本轮严格保持 test-only，未修改生产 Go 文件、未派生子代理、未提交。测试 patch 仅修改：

- `component/ruleprovider/rule_provider_test.go`：在 `blockedIP` 和 `validatePublicURL` 的真实
  生产路径测试中加入标准 NAT64 well-known prefix `64:ff9b::/96` 的两个 IPv4-embedded 地址：
  `64:ff9b::a00:1`（10.0.0.1）和 `64:ff9b::a9fe:a9fe`（169.254.169.254）；保留已有的
  `64:ff9b:1::/48` 测试，不以旧用例代替本轮覆盖。
- `config/rule_provider_test.go`：在 `ValidateRuleProviders` 的 URL validation 测试中加入同样
  两个 endpoint。由于首个 component 聚焦已经取得真实 production RED，按时序要求本轮没有
  继续运行 config 聚焦命令。

首个最小聚焦命令及实际输出：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestBlockedIPRejectsReservedIPv6Ranges|TestProviderSecurityRejectsBlockedRedirectTargets' -count=1

--- FAIL: TestBlockedIPRejectsReservedIPv6Ranges (0.00s)
    rule_provider_test.go:518: blockedIP(64:ff9b::a00:1) = false for reserved IPv6 range
--- FAIL: TestProviderSecurityRejectsBlockedRedirectTargets (0.00s)
    --- FAIL: TestProviderSecurityRejectsBlockedRedirectTargets/http://[64:ff9b::a00:1]/rules.yaml (0.00s)
        rule_provider_test.go:541: validatePublicURL("http://[64:ff9b::a00:1]/rules.yaml") error = nil
    --- FAIL: TestProviderSecurityRejectsBlockedRedirectTargets/http://[64:ff9b::a9fe:a9fe]/rules.yaml (0.00s)
        rule_provider_test.go:541: validatePublicURL("http://[64:ff9b::a9fe:a9fe]/rules.yaml") error = nil
    FAIL
    FAIL github.com/daeuniverse/dae/component/ruleprovider 0.653s
    FAIL
```

这是 production RED，不是监听器或权限阻塞。生产定位为
`component/ruleprovider/security.go` 的 `blockedProviderNetworks`（当前有
`64:ff9b:1::/48`，没有标准 `64:ff9b::/96`）以及其被 `validatePublicURL` 调用的
`blockedIP` 路径。config 层的对应缺口位于 `config/rule_provider.go` 的
`blockedRuleProviderNetworks` / `blockedRuleProviderIP` 路径，尚未在本轮 RED 前运行测试。
当时按“首个真实 production RED 立即暂停”，该轮不运行其它 special-range、版本或
全量验证。

本轮仅检查、未修正的 mixed-generation 测试问题：

- `TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration` 的 `/a` handler 在
  `component/ruleprovider/rule_provider_test.go:1010` 固定返回
  `generation-one.example`，而 `/b` 使用可变 generation；这不是对称的共享 token fixture，
  后续应改为明确的 token/response 契约，不能把 fixture 不对称误当成 generation 证明。
- `TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration` 在 `:1103` 创建 `dir`，但
  `loadWithOptions` 在 `:1110` 传入另一个 `t.TempDir()`；随后错误分支用 `dir` 检查 current，
  可能检查错误的 cache root，属于测试断言假阳性风险。后续 test-only 修正应复用同一个 `dir`。

上述 mixed-generation 问题本轮只记录，没有修改或重跑；等待 code-only 修复 NAT64 缺口后再
进行独立 GREEN。

## 9. 严格 TDD 审计收口：test-only RED → code-only GREEN → independent verification

> **章节位置说明：** 本节是本轮 documentation-only 收口时插入的 canonical reconciliation block。
> 文件中随后出现的 `5.x` 小节是按代理轮次追加的历史记录，不代表比本节更新的结论；其中保留的
> RED 仍是历史证据，当前状态以各自后续 code-only GREEN 和本节的 independent verification 为准。

本节是对前述按代理轮次追加的历史记录的收口，不替代原始证据，也不把缺失的命令输出补写成
“全绿”。每一项都区分三种角色：test-only 只修改允许的测试/文档文件；code-only 只修改生产
文件；independent verification 重新运行测试。若历史代理只报告了结果而当前 canonical 文档
没有完整 stdout，以下明确写“记录来自本轮代理报告”。本节本身只由 documentation-only 收口
修改，不改变任何生产或测试范围。

### 9.1 File provider last-good snapshot

- test-only RED 文件：`component/ruleprovider/rule_provider_test.go`、
  `cmd/rule_provider_config_test.go`。
- RED 命令：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestLoadFileProviderUsesPersistedLastGoodAfterFileDisappears|TestLoadFileProviderBadUpdateDoesNotReplaceLastGoodSnapshot' -count=1
  ```

  实际首个失败为 `TestLoadFileProviderUsesPersistedLastGoodAfterFileDisappears`：源文件消失后
  返回 `open provider path: no such file or directory`；同命令还记录首次 file load 没有
  `current`。这是真实生产 RED，见 5.6。
- code-only GREEN：`component/ruleprovider/rule_provider.go`（Lagrange，file source
  failure 使用持久化 last-good）。
- independent verification：上述聚焦测试、component/config 全量、race、vet 均由代理报告
  通过；完整 GREEN stdout 未保存在当前 canonical 历史中，结果标记为“记录来自本轮代理报告”，
  不补写耗时或伪造输出。cmd 侧对应 `readConfig` 测试仍受 Darwin 编译基线限制，见 9.8。

### 9.2 HTTP response header limit (`MaxResponseHeaderBytes <= 0`)

- test-only RED 文件：`component/ruleprovider/rule_provider_test.go`。
- RED 命令和真实输出：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestFetchHTTPRejectsResponseHeadersWhenCustomTransportLimitIsNegative$' -count=1

  --- FAIL: TestFetchHTTPRejectsResponseHeadersWhenCustomTransportLimitIsNegative (0.01s)
      rule_provider_test.go:360: fetchHTTP() error = nil for response headers larger than the 1 MiB production limit
  FAIL
  ```

- code-only GREEN：`component/ruleprovider/security.go`（Boole，将 `<=0` 或超过上限收敛到
  1 MiB）。
- independent verification：聚焦、component/config 全量、race、vet、`git diff --check` 均报告
  通过；完整 stdout/耗时未保存在 canonical 文档中，记录来自本轮代理报告。

### 9.3 Text/YAML 解析前资源限制（含跨行和 flow collection）

- text RED 文件：`component/ruleprovider/rule_provider_test.go`。命令为
  `go test ./component/ruleprovider -run '^TestParseTextRejectsExcessiveRuleCountBeforeMaterializingAllRules$' -count=1`；实际失败为
  `parseBody() allocated 198692240 bytes while rejecting excessive text rule count; want less than 16777216`。
- text code-only GREEN：`component/ruleprovider/rule_provider.go`（James，逐行预扫描 rule
  length/count）。GREEN 聚焦命令实际记录为：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestParseTextRejectsExcessiveRuleCountBeforeMaterializingAllRules$' -count=1
  ok  github.com/daeuniverse/dae/component/ruleprovider  0.775s
  ```

- YAML node RED：`component/ruleprovider/rule_provider_test.go` 的
  `TestParseYAMLRejectsNodeLimitBeforeMaterializingLargeTrailingScalar` 实际记录为
  `parseBody() allocated 263156432 bytes before rejecting YAML node limit; want less than trailing scalar size 33554432`；修复前聚焦命令及输出见 5.5。
- YAML 跨行 RED：同一测试文件的 quoted/plain/folded fixture 实际记录约 25.4 MiB 分配，
  逻辑 scalar 约 2 MiB；完整失败命令和输出见 5.10。
- YAML code-only GREEN：`component/ruleprovider/rule_provider.go`（Nash/Beauvoir，预扫描
  YAML node/scalar 以及跨行 scalar）。对应 node 聚焦 GREEN、component/config 全量、race、vet
  已记录于 5.5；跨行聚焦 GREEN 由代理报告确认，完整 stdout 未在当时 canonical 记录中保存。
- flow collection 补强 test-only 文件：`component/ruleprovider/rule_provider_test.go` 新增
  `TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule`，独立
  `yaml.Unmarshal` 先确认 quoted/plain 各自合并为超长单一 scalar，再检查 `parseBody` 拒绝和
  分配上限。实际聚焦命令：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule$' -count=1
  ok  github.com/daeuniverse/dae/component/ruleprovider  0.698s
  ```

### 9.4 FIFO cache 读取

- test-only RED 文件：`component/ruleprovider/rule_provider_test.go`。body 子用例命令及输出：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestCacheFIFOLoadIsBounded/body$' -count=1

  --- FAIL: TestCacheFIFOLoadIsBounded (1.05s)
      --- FAIL: TestCacheFIFOLoadIsBounded/body (1.05s)
          rule_provider_test.go:800: FIFO child blocked reading body; killed child: kill=<nil> wait=signal: killed
  FAIL
  ```

- code-only GREEN：`component/ruleprovider/rule_provider.go`（Plato，cache regular-file read
  使用 `O_NONBLOCK`）。test-only 同时修正合法 interrupted journal fixture，再覆盖 body、
  `metadata.json`、`transaction.journal`。
- GREEN 聚焦命令实际记录为：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestCacheFIFOLoadIsBounded/(body|metadata|journal)$' -count=1
  ok  github.com/daeuniverse/dae/component/ruleprovider  0.781s
  ```

  后续 component/config 全量、race、vet 也有实际通过记录；第一次 race child timeout 是夹具
  启动窗口，增至仍有界的 5 秒后通过，不能记为生产 RED。

### 9.5 Cache permissions

- test-only RED 文件：`component/ruleprovider/rule_provider_test.go`。
- 聚焦命令和实际失败见 5.13：body `0666`、metadata `0660`、provider root `0777` 三个回退
  子用例均被接受，形成真实 production RED。
- code-only GREEN：`component/ruleprovider/rule_provider.go`（Sartre，拒绝权限位
  `0o022`）。GREEN 聚焦、全量、race、vet、diff check 通过，完整 stdout 未保存在 canonical
  文档中，结果来自本轮代理报告。

### 9.6 Special blocked ranges

- test-only RED 文件：`component/ruleprovider/rule_provider_test.go`、
  `config/rule_provider_test.go`。
- component 最小命令和首个真实失败见 5.14：`240.0.0.1` 与 `2001:20::1` 未被
  `blockedIP()` 拒绝；由于首个 component 聚焦已失败，`fec0::1` 与 broadcast 当时没有被单独
  写成独立结果。
- code-only GREEN：`component/ruleprovider/security.go`、`config/rule_provider.go`
  （Kierkegaard，补 `240.0.0.0/4`、`2001:20::/28`、`fec0::/10` 等集合）。component/config
  special-range 聚焦、全量、race、vet、diff check 通过；精确 stdout 未保存在 canonical 文档，
  结果来自本轮代理报告。

### 9.7 Mixed generation 与显式 token 协议

- 初始无 token 的 reverse fetch fence RED 以及随后显式 token drift RED 均只修改
  `component/ruleprovider/rule_provider_test.go`；最终 token RED 的实际命令和输出见 5.17，
  失败为 `a="a-two.example" b="b-one.example"`。
- fresh/last-good test-only 覆盖先发布 A1/B1，再让 A fresh=`two`、B 网络失败回退=`one`，
  实际聚焦通过并检查 cache 未变；命令和结果见 5.18。
- code-only GREEN：`component/ruleprovider/rule_provider.go`（Euclid/Gibbs，批次 generation
  token 校验、fresh/last-good/304/cache metadata 传递和 publish 前 fail closed）。
- independent verification：token 聚焦、重复运行 20 次、component/config 全量、race、vet、
  diff check 均由代理报告通过；重复命令的完整 stdout 未保存，记录来自本轮代理报告。不得将
  “稳定逆序 fetch”本身解释成 generation fence；安全契约是显式 shared token。

### 9.8 NAT64 special range 与 cmd/readConfig 边界

- test-only NAT64 RED 文件：`component/ruleprovider/rule_provider_test.go`、
  `config/rule_provider_test.go`。实际失败见 5.18：component `blockedIP`、component
  `validatePublicURL`、config `ValidateRuleProviders` 均接受
  `64:ff9b:1::a00:1`。
- code-only GREEN：`component/ruleprovider/security.go`、`config/rule_provider.go`
  （Lovelace，加入 `64:ff9b:1::/48`）；independent NAT64 聚焦、component/config 全量、race、
  vet 均有精确通过记录：聚焦 `0.414s/0.745s`，全量 `3.309s/0.365s`，race `11.033s/1.453s`，
  vet 退出 0 无输出。test-only 文件为上述两个测试文件。
- cmd/readConfig 实际尝试命令：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./cmd -run 'TestReadConfigExpandsHardenedNativeRuleProvider|TestReadConfigUsesFileProviderLastGoodAfterSourceDisappears' -count=1
  ```

  Darwin 编译阻塞精确包含：`netlink.LinkUpdate`、`netlink.LinkSubscribeWithOptions`、
  `netlink.LinkSubscribeOptions`、`unix.RTM_NEWLINK`、`unix.RTM_DELLINK`、
  `unix.ETHTOOL_GLINKSETTINGS`、`unix.ETHTOOL_SLINKSETTINGS`、`unix.SOCK_CLOEXEC`、
  `syscall.SOL_IP`、`syscall.SOL_IPV6`、`unix.IP_RECVORIGDSTADDR`、
  `unix.IPV6_RECVORIGDSTADDR`、`unix.IP_TRANSPARENT`、`unix.IPV6_TRANSPARENT`。因此
  `cmd/readConfig` 不宣称 GREEN；stub compile 或目标包通过都不能替代真实 cmd/control-plane。

### 9.9 Journal TOCTOU

- test-only RED 文件：`component/ruleprovider/rule_provider_test.go`。测试以 HTTP handler
  barrier 确认已经越过初始“无 journal” preflight，在同一 transaction root 写入唯一 marker，
  再释放响应；要求 marker 保留、Load 拒绝、无 current、无 registry。
- RED 命令和实际输出（失败行按原始输出缩略）：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare$' -count=1

  --- FAIL: TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare (0.03s)
      rule_provider_test.go:1231: Load() silently accepted/published over an existing journal marker: registry=ruleprovider.Registry{"p":...}
  FAIL
  ```

- code-only GREEN：`component/ruleprovider/rule_provider.go`（Kuhn，在 transaction flock 内
  再检查 journal，使用持锁 recovery helper；marker 失败时保留并拒绝发布）。
- independent GREEN 的实际命令/结果：

  ```text
  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare$' -count=1
  ok  github.com/daeuniverse/dae/component/ruleprovider  0.576s

  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestCrossProcessRecoveryHonorsTransactionFlock|TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare' -count=1
  ok  github.com/daeuniverse/dae/component/ruleprovider  1.451s

  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
  ok  github.com/daeuniverse/dae/component/ruleprovider  3.264s
  ok  github.com/daeuniverse/dae/config  0.372s

  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
  ok  github.com/daeuniverse/dae/component/ruleprovider  12.006s
  ok  github.com/daeuniverse/dae/config  1.907s

  TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
  exit 0, no output

  git diff --check
  exit 0, no output
  ```

  这些 GREEN 命令在本轮文档修改前实际完成；本次 docs-only 修改完成后执行的
  `git diff --check` 也为 `exit 0, no output`。

### 9.10 Package gate、Stage 2 scope 与文档权限

- component/config 包的普通测试、race、vet 已在多个独立 GREEN 轮次实际通过；本节最新一组
  精确结果见 9.9。它们只证明目标包，不证明 cmd 或全仓库。
- `cmd/readConfig` 的 Darwin netlink/eBPF 编译阻塞保持为环境/基线问题，不写成 GREEN。
- routes/groups 的 full generation-atomic sidecar 发布、统一 `current`、跨资源 rollback 和
  provider/routes/groups 同 generation 明确 deferred 到 execution plan Stage 2；本轮没有修改
  `tools` 生产实现，也没有扩大 Stage 1/native provider 的完成声明。
- 根目录未跟踪的 `mihomo-rule-provider-progress.md` 是 legacy user file；本轮没有删除、修改
  或以其内容覆盖 canonical `docs/mihomo-rule-provider-progress.md`。执行计划 canonical 是
  `docs/mihomo-rule-provider-execution-plan.md`。
- 本文及执行计划的修改均为本轮 documentation-only；生产 Go、测试文件、根目录 legacy 文件和
  execution plan 的生产语义均未被本轮代码修改。工作区保持未提交。

### 5.20 历史 Stage 1 Journal TOCTOU test-only RED（后续 GREEN 已完成）

本轮只修改了 `component/ruleprovider/rule_provider_test.go` 和本进度文档；未修改生产代码、未
派生子代理、未提交。新增测试
`TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare` 使用进程内 HTTP barrier：

1. 启动时确认 `transaction.journal` 不存在，使 `loadWithOptions` 的初始 recovery preflight
   必须走“journal absent”路径；
2. HTTP handler 收到请求后阻塞，测试由此确认已越过 preflight 并进入 HTTP prepare；
3. 测试在同一 transaction root 写入带唯一名称 marker 的非法 journal；
4. 释放 HTTP handler，要求 Load 拒绝该 marker、保留 marker、没有 cache `current`，且不返回
   registry。

最小聚焦命令及首个真实 production RED：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare$' -count=1

--- FAIL: TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare (0.03s)
    rule_provider_test.go:1231: Load() silently accepted/published over an existing journal marker: registry=ruleprovider.Registry{"p":ruleprovider.ProviderRules{Functions:[]*config_parser.Function{(*config_parser.Function)(0x2976e1b36390)}}}
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.684s
FAIL
```

这不是测试环境阻塞：HTTP barrier 已完成，fixture 在 Load 的 HTTP 请求等待期间成功写入 marker，
随后 Load 返回 nil 和 provider registry，违反了“publish lock 内必须发现既有 journal 并拒绝/恢复”
契约。生产定位：`component/ruleprovider/rule_provider.go:155-168` 的
`loadWithOptions` 在初始 `recoverPendingPublish` 后直接进入 prepare/publish；
`:1009-1022` 获得 transaction flock 后没有检查 journal 是否在 preflight 之后出现；
`:1093-1109` 随后调用 `writeCacheTransaction`，而 `:1419-1448` 通过临时文件 `Rename` 到
同一路径，能够静默替换 marker。该失败交给下一 code-only 修复轮次。

按“首个真实 production RED 立即暂停”，该轮没有运行后续 GREEN、全量、race、NAT64、version prune
或 YAML flow 测试。现有 `TestCrossProcessRecoveryHonorsTransactionFlock` 仍只证明已有 journal
的跨进程 flock 阻塞/恢复，不覆盖本轮确定性 HTTP-prepare TOCTOU 窗口。

第一次无额外权限执行全量命令时，component 的既有 `httptest.NewServer` 因沙箱禁止绑定
`[::1]:0` 失败，config 同次通过；使用同一临时 TMPDIR/GOCACHE/GOPATH 和受控本地 listener 权限
重跑后通过。这是环境权限阻塞，不是生产测试失败。

本轮 A/B 实际覆盖与结论：

- `TestFetchHTTPRejectsRedirectToBlockedEndpoint`：真实 `fetchHTTP` redirect callback 拒绝
  `http://127.0.0.1:1/blocked`，PASS；
- `TestSafeDialRejectsHostnameResolvingToBlockedIP`：真实 `safeDialContext` 解析 `localhost`，
  在原始 dial 前拒绝 blocked IP，PASS；
- `TestConcurrentPublishAndRecoveryKeepsTransactionRootConsistent`：同 transaction root 的并发
  recovery/publish 最终无混合 current 且 journal 被一致消费，PASS。

D 项无需重复新增测试，已有覆盖名为：

- `cmd/rule_provider_config_test.go:TestReadConfigExpandsHardenedNativeRuleProvider`；
- `cmd/rule_provider_config_test.go:TestReadConfigUsesFileProviderLastGoodAfterSourceDisappears`；
- `component/ruleprovider/rule_provider_test.go:TestExpandRulesetPreservesAndFunctionsAndOutbound`；
- `component/ruleprovider/rule_provider_test.go:TestExpandRulesetRejectsUnknownAndNegatedProvider`。

这些 cmd/readConfig 与 ruleset 语义测试本轮未因首个 C RED 再扩展；已有测试覆盖保留。routes/groups
非原子发布仍明确 deferred 到 execution plan Stage 2，不修改 `tools` 生产代码，也不宣称 Stage 1
已完成该项。

### 5.9 历史 Stage 1 test-only RED（后续 GREEN 已完成）：mixed-registry generation coherence

本轮严格保持 test-only，未修改任何生产 Go 文件、未派生子代理、未提交。测试 patch 仅在
`component/ruleprovider/rule_provider_test.go` 新增
`TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration`；`config/rule_provider_test.go`、
`cmd/rule_provider_config_test.go` 本轮未改动。

该测试使用确定性的真实 `httptest` 阻塞 fixture：同一次 `loadWithOptions()` 先让 provider A
停在请求中，随后切换服务端 generation，再释放 A，让 provider B 读取新 generation；断言返回的
registry 中 A/B 必须属于同一 generation，而不是只检查磁盘 `current`。最小聚焦命令及首个真实
生产失败如下：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration$' -count=1

--- FAIL: TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration (0.06s)
    rule_provider_test.go:724: Load() returned mixed provider generations: a="generation-one.example" b="generation-two.example"
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.709s
FAIL
```

这是可重复的生产行为 RED，不是测试断言或环境失败：返回的 registry 本身已经同时包含
`generation-one` 和 `generation-two`，说明一次多 provider Load 在准备阶段观察到了不同
generation。定位为 `component/ruleprovider/rule_provider.go` 的 `prepareProviders`：它逐个
调用 `prepareProvider`/`fetchHTTP` 后立即把每个 provider 的规则写入 registry（当前约在
`:246`，单 provider fetch 约在 `:317-355`）；发布阶段的 journal/transaction root 保护磁盘
发布，不能回溯保证本次 Load 返回的 registry 是单一 generation。该失败应交给下一 code-only
修复轮次，test-only 阶段在此暂停。

按“首个真实生产失败即暂停”的要求，该轮没有继续运行 YAML 跨行 scalar、FIFO 非阻塞、缓存
权限、special ranges、version prune、cross-process recovery 或 cmd `readConfig` 新增/聚焦测试，
也没有在该轮执行 GREEN；它们当时不是该轮 PASS 或环境失败。后续完成证据见第 10 节；此前已有的
redirect/hostname、journal 并发、text 预扫描、cmd/readConfig 和 `ruleset()` 覆盖证据仍保留在
上文；routes/groups 非原子发布继续 deferred 到 execution plan Stage 2。

本轮环境方面没有阻塞：测试使用受控本地 listener 并实际进入生产 Load/fetch 路径；没有因权限、
网络或平台依赖伪造 RED。

### 5.10 历史 Stage 1 test-only RED（后续 GREEN 已完成）：跨行 YAML scalar 预解析资源限制

本轮继续严格 test-only，未修改生产 Go 文件、未派生子代理、未提交。新增测试 patch 仅为
`component/ruleprovider/rule_provider_test.go` 中的
`TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule`；没有修改
`config/rule_provider_test.go` 或 `cmd/rule_provider_config_test.go`。

测试构造 quoted、plain、folded 三种跨行 YAML scalar。每个物理行约 8 KiB，低于
`maxProviderRuleLength` 16 KiB；逻辑 scalar 约 2 MiB，整个 body 小于生产 `maxSize` 64 MiB，
因此不会被 body 大小门禁提前拒绝。测试通过真实 `parseBody()` 检查规则最终必须拒绝，并用
`runtime.MemStats.TotalAlloc` 证明拒绝应发生在 YAML 合并/大规则 materialize 之前。

首个聚焦命令及实际输出：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule$' -count=1

--- FAIL: TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule (0.15s)
    --- FAIL: TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule/quoted (0.07s)
        rule_provider_test.go:364: parseBody() allocated 25410344 bytes while rejecting quoted scalar of 2097152 bytes; want rejection before materialization
    --- FAIL: TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule/plain (0.05s)
        rule_provider_test.go:364: parseBody() allocated 25414480 bytes while rejecting plain scalar of 2097152 bytes; want rejection before materialization
    --- FAIL: TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule/folded (0.04s)
        rule_provider_test.go:364: parseBody() allocated 25409096 bytes while rejecting folded scalar of 2097152 bytes; want rejection before materialization
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.795s
FAIL
```

这是首个真实生产 RED，不是测试环境阻塞：三种 fixture 都满足物理行和 body 上限，
`parseBody()` 确实返回了规则长度错误，但在拒绝前累计分配约 25.4 MiB，超过逻辑 scalar
大小约 2 MiB。生产定位为 `component/ruleprovider/rule_provider.go:1597-1615` 的
`parseBody()` → `providerItems()` → YAML 解码路径，以及 `:1666-1675` 在 materialize
之后才检查合并规则长度；现有 `preflightProviderYAML()`（`:1818` 起）没有覆盖这些
跨行 quoted/plain/folded sequence scalar 的合并长度。

按“首个真实生产失败即暂停”的要求，该轮没有继续运行后续组，也不在该段报告 GREEN；后续完成证据见第 10 节：

- FIFO cache body/metadata/transaction journal：未执行；未生成可能阻塞主测试的 fixture；
- cache permissions：未执行；
- component/config special ranges（`2001:20::/28`、`fec0::/10`、`240.0.0.1`）：未执行；
- 修正 hidden `.candidate-*` 后的真实 version prune 统计：未执行；
- cross-process flock/recovery helper：未执行；
- cmd `readConfig`：未执行；此前 plain cmd 的 eBPF/netlink 平台阻塞记录仍有效。

本组无测试环境阻塞：使用可写 `TMPDIR/GOCACHE/GOPATH`，测试在真实 parser 路径运行并稳定复现；
后续各组必须等待 code-only 修复后另行 RED/GREEN 轮次。

### 5.11 历史 Stage 1 test-only RED（后续 GREEN 已完成）：FIFO cache 读取必须有界拒绝

本轮在跨行 YAML GREEN 后继续严格 test-only；未修改生产 Go 文件、未派生子代理、未提交。新增
patch 仅为 `component/ruleprovider/rule_provider_test.go`：

- `TestCacheFIFOLoadIsBounded/body` 先完成一次真实 HTTP provider Load，取得有效 last-good
  cache；
- 随后把当前 version 的 `body` 替换成 FIFO；父测试通过同一测试二进制启动 helper 子进程，
  让 helper 调用真实 `loadWithOptions()`，并用 1 秒有限超时杀死阻塞 child；
- `metadata` 和共享 `transaction.journal` 的 FIFO 子用例已写入同一测试，但按首个真实 RED
  规则尚未运行。

最小聚焦命令及实际输出：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestCacheFIFOLoadIsBounded/body$' -count=1

--- FAIL: TestCacheFIFOLoadIsBounded (1.05s)
    --- FAIL: TestCacheFIFOLoadIsBounded/body (1.05s)
        rule_provider_test.go:800: FIFO child blocked reading body; killed child: kill=<nil> wait=signal: killed
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 1.694s
FAIL
```

这是可观察的生产阻塞 RED，不是主测试挂死或环境阻塞：父测试在限定时间内回收 child，child
实际进入 `loadWithOptions()`，并卡在当前 cache version 的 FIFO `body` 打开/读取。生产定位为
`component/ruleprovider/rule_provider.go:793-825` 的 `readCacheSnapshot()` → `readRegularFile()`，
以及 `:641` 的 `os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)`；cache regular-file
读取没有 `O_NONBLOCK`，因此 FIFO 打开会等待 writer。该失败交给下一 code-only 修复轮次。

按“首个真实生产失败即暂停”的要求，该轮未继续执行以下组；后续 PASS/GREEN 见第 10 节：

- FIFO `metadata.json` / `transaction.journal` 子用例；
- cache body/metadata/root group/world-writable 权限回退；
- component/config 的 `2001:20::/28`、`fec0::/10`、`240.0.0.0/4` special ranges；
- 修正 hidden `.candidate-*` 忽略后的真实 version prune 统计；
- cross-process flock/recovery helper；
- cmd `readConfig` 现有测试。

本组使用可写 `TMPDIR/GOCACHE/GOPATH`，本地 listener 和子进程均成功创建；没有测试环境阻塞。

### 5.12 Plato GREEN：FIFO cache body/metadata/journal 有界拒绝

Plato 的 code-only 修复范围仅为 `component/ruleprovider/rule_provider.go`，在
`readRegularFile()` 打开 cache 文件时加入 `O_NONBLOCK`。本轮 test-only 没有修改生产代码、
没有派生子代理、没有提交；测试/文档 patch 仅涉及 `component/ruleprovider/rule_provider_test.go`
和本文件。

先修正 journal 测试夹具：正常首次发布后，生产会清理 `transaction.journal`，因此不能直接
`Remove` 一个不存在的路径。测试现在读取已发布的 `current`，通过 `writeCacheTransaction()`
显式写入 schema/state/provider target 均合法的 interrupted `publishing` journal，再将该
真实存在的 journal 替换为 FIFO。body/metadata 仍从已发布 version 替换为 FIFO。父测试继续
通过 helper 子进程和有限超时验证，超时会杀 child，不会让主测试挂死。

FIFO 三个聚焦测试 GREEN：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestCacheFIFOLoadIsBounded/(body|metadata|journal)$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.781s
```

普通全量、race、vet 和 diff check GREEN：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  2.256s
ok  github.com/daeuniverse/dae/config  0.385s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  9.128s
ok  github.com/daeuniverse/dae/config  1.492s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
exit 0, no output

git diff --check
exit 0, no output
```

第一次使用 1 秒 child 超时运行 race 全量时，FIFO 三个子用例被误判为超时并杀 child；这是
race 子进程启动开销造成的测试夹具超时，不是生产阻塞。将仍然有限的 child 超时调整为 5 秒后，
同一 race 全量命令通过。普通聚焦和 race 均未发现新的生产失败。

本轮 FIFO 证据覆盖了真实 cache body、metadata 和 transaction recovery journal 的读取路径；
cache permissions、special ranges、version prune、cross-process recovery helper 和 cmd
`readConfig` 仍待后续 test-only 轮次，不在本轮扩大范围。

### 5.13 历史 Stage 1 test-only RED（后续 GREEN 已完成）：不安全 cache 权限不得参与回退

本轮在 FIFO GREEN 后继续严格 test-only；未修改任何生产 Go 文件、未派生子代理、未提交。新增
patch 仅为 `component/ruleprovider/rule_provider_test.go` 的
`TestLoadRejectsInsecureCachePermissions`，覆盖三种真实 last-good 回退场景：

- 首次 HTTP Load 生成有效 cache 后，将当前 version 的 `body` 设为 world-writable `0666`；
- 将 `metadata.json` 设为 group-writable `0660`；
- 将 provider cache root 设为 world-writable `0777`。

每个子用例随后关闭 HTTP server，调用真实 `loadWithOptions()` 模拟网络失败，要求生产拒绝
不安全持久层，而不是信任低权限用户可修改的快照。

最小聚焦命令及实际输出：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestLoadRejectsInsecureCachePermissions$' -count=1

--- FAIL: TestLoadRejectsInsecureCachePermissions (0.10s)
    --- FAIL: TestLoadRejectsInsecureCachePermissions/body-world-writable (0.04s)
        rule_provider_test.go:796: Load() accepted body-world-writable persistent cache after network failure
    --- FAIL: TestLoadRejectsInsecureCachePermissions/metadata-group-writable (0.03s)
        rule_provider_test.go:796: Load() accepted metadata-group-writable persistent cache after network failure
    --- FAIL: TestLoadRejectsInsecureCachePermissions/provider-root-world-writable (0.03s)
        rule_provider_test.go:796: Load() accepted provider-root-world-writable persistent cache after network failure
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.766s
FAIL
```

这是生产行为 RED，不是权限环境阻塞：三种 fixture 都成功设置了目标 mode，网络失败后真实
HTTP provider 路径仍返回 last-good。生产定位为 `component/ruleprovider/rule_provider.go:793-825`
的 `readCacheSnapshot()`、`:1351-1400` 的 `readCurrentState()` 和 `:637-661` 的
`readRegularFile()`；这些读取路径检查 regular file、symlink 和 checksum，但没有拒绝
group/world-writable 的 body、metadata 或 provider cache root。

按“首个真实生产失败即暂停”的要求，该轮没有继续运行以下组；后续 PASS/GREEN 见第 10 节：

- component/config special ranges：`2001:20::/28`、`fec0::/10`、`240.0.0.0/4`；
- 修正 hidden `.candidate-*` 忽略后的真实 version prune 统计；
- cross-process flock/recovery helper；
- cmd `readConfig` 现有测试及其平台阻塞复核。

本组使用可写 `TMPDIR/GOCACHE/GOPATH` 和真实本地 HTTP fixture，无测试环境阻塞。后续组需等待
下一 code-only 修复轮次后再做独立 GREEN。

### 5.14 历史 Stage 1 test-only RED（后续 GREEN 已完成）：special blocked IP ranges

本轮在 cache permissions GREEN 后继续严格 test-only；未修改任何生产 Go 文件、未派生子代理、
未提交。测试 patch 修改范围为：

- `component/ruleprovider/rule_provider_test.go`：在真实 `blockedIP()` 测试中加入
  `2001:20::1`、`fec0::1`、`240.0.0.1`、`255.255.255.255`；
- `config/rule_provider_test.go`：在真实 `ValidateRuleProviders()` URL 测试中加入对应
  IPv6/IPv4 endpoint；
- `docs/mihomo-rule-provider-progress.md`：记录本轮 RED。

按“首个真实生产失败即暂停”，先运行 component 最小聚焦命令：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestBlockedIPRejectsSpecialInternalRanges|TestBlockedIPRejectsReservedIPv6Ranges' -count=1

--- FAIL: TestBlockedIPRejectsSpecialInternalRanges (0.00s)
    rule_provider_test.go:411: blockedIP(240.0.0.1) = false
--- FAIL: TestBlockedIPRejectsReservedIPv6Ranges (0.00s)
    rule_provider_test.go:427: blockedIP(2001:20::1) = false for reserved IPv6 range
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.648s
FAIL
```

这是生产行为 RED，不是环境阻塞：测试直接调用 component 的生产 `blockedIP()`，确认
`240.0.0.1`（`240.0.0.0/4`）和 `2001:20::1`（正确 ORCHIDv2 范围）未被拒绝。生产定位为
`component/ruleprovider/security.go` 的 `blockedProviderNetworks` 与 `blockedIP()` 检查路径；
当前特殊网段集合缺少 `2001:20::/28`、`fec0::/10` 和 `240.0.0.0/4`。由于 component 聚焦已
失败，`fec0::1` 与 `255.255.255.255` 尚未单独运行到断言，不能把它们写成 PASS 或独立 RED。

本轮没有运行 `config/rule_provider_test.go` 的 `ValidateRuleProviders()` 聚焦命令，也没有继续
version prune、cross-process recovery 或 cmd `readConfig`；不得把 config 层或后续组报告为 GREEN。
本组使用可写 `TMPDIR/GOCACHE/GOPATH`，无测试环境阻塞。

### 5.15 当前 test-only：version prune PASS、跨进程 recovery PASS、cmd 环境阻塞

本轮严格保持 test-only，未修改生产 Go 文件、未派生子代理、未提交。测试/文档 patch 为：

- `component/ruleprovider/rule_provider_test.go`：修正
  `TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates`，统计 `versions` 下所有真实目录，
  不再以 `.candidate-*` 前缀作为测试侧排除条件；新增
  `TestCrossProcessRecoveryHonorsTransactionFlock` 及 helper 子进程，验证真实 transaction-root
  `flock` 在跨进程 recovery 中生效；
- `docs/mihomo-rule-provider-progress.md`：记录本轮命令和结果。

version prune 聚焦命令：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.887s
```

该 PASS 使用修正后的统计逻辑：不忽略隐藏目录，重复 fresh update 后真实目录数仍满足
`<= maxCacheVersions`；没有修改生产 prune 实现，也没有把测试假阳性当成生产修复。

跨进程 recovery/flock 聚焦命令：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestCrossProcessRecoveryHonorsTransactionFlock$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  1.730s
```

该测试由两个 helper 子进程组成：第一个在同一 transaction root 持有 `flock` 并通过 stdin
同步释放；第二个先发出 started 标记，再真实调用 `recoverPendingPublish()`。释放前 recovery
不能完成，释放后成功恢复并消费 journal，且 cache snapshot 仍可读。等待均有上限，没有使用
无界 sleep；本轮未发现跨进程 recovery 生产失败。

cmd 现有 `readConfig` 测试尝试命令：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./cmd -run 'TestReadConfigExpandsHardenedNativeRuleProvider|TestReadConfigUsesFileProviderLastGoodAfterSourceDisappears' -count=1

# github.com/daeuniverse/dae/component
component/interface_manager.go:43:26: undefined: netlink.LinkUpdate
component/interface_manager.go:45:18: undefined: netlink.LinkSubscribeWithOptions
component/interface_manager.go:45:61: undefined: netlink.LinkSubscribeOptions
component/interface_manager.go:95:54: undefined: netlink.LinkUpdate
component/interface_manager.go:135:14: undefined: unix.RTM_NEWLINK
component/interface_manager.go:148:14: undefined: unix.RTM_DELLINK
# github.com/safchain/ethtool
/private/tmp/dae-gopath/pkg/mod/github.com/safchain/ethtool@v0.7.0/ethtool.go:64:31: undefined: unix.ETHTOOL_GLINKSETTINGS
/private/tmp/dae-gopath/pkg/mod/github.com/safchain/ethtool@v0.7.0/ethtool.go:65:31: undefined: unix.ETHTOOL_SLINKSETTINGS
/private/tmp/dae-gopath/pkg/mod/github.com/safchain/ethtool@v0.7.0/ethtool.go:1253:60: undefined: unix.SOCK_CLOEXEC
# github.com/daeuniverse/dae/component/outbound/dialer
component/outbound/dialer/sockopt.go:63:45: undefined: syscall.SOL_IP
component/outbound/dialer/sockopt.go:63:58: undefined: unix.IP_RECVORIGDSTADDR
component/outbound/dialer/sockopt.go:64:45: undefined: syscall.SOL_IPV6
component/outbound/dialer/sockopt.go:64:60: undefined: unix.IPV6_RECVORIGDSTADDR
component/outbound/dialer/sockopt.go:79:53: undefined: unix.IP_TRANSPARENT
component/outbound/dialer/sockopt.go:80:55: undefined: unix.IPV6_TRANSPARENT
FAIL github.com/daeuniverse/dae/cmd [build failed]
FAIL
```

这是当前 Darwin/netlink/eBPF 平台/依赖编译阻塞，不是 `readConfig` 断言失败；不能将 cmd
测试写成 GREEN。后续仍可在具备仓库所需 netlink/eBPF 构建基线的平台上复验。

本轮没有开始生产修复，也没有继续扩大到其他测试组。

### 5.16 阶段性独立 test-only 验证（历史记录）

本节是当时的阶段性独立 test-only 验证，不是当前整项工作的最终结论：没有修改任何生产 Go 文件
或测试文件，没有派生子代理，也没有提交；仅补充本进度文档。工作区中生产 code-only 轮次的范围仍为
`component/ruleprovider/rule_provider.go`、`component/ruleprovider/security.go` 和
`config/rule_provider.go`；test-only 轮次的测试范围为
`component/ruleprovider/rule_provider_test.go`、`config/rule_provider_test.go`、
`cmd/rule_provider_config_test.go`，本轮没有新增测试 patch。

使用可写 `TMPDIR/GOCACHE/GOPATH` 和受控本地 listener，最终命令结果如下：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  3.759s
ok  github.com/daeuniverse/dae/config  0.662s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  11.061s
ok  github.com/daeuniverse/dae/config  2.058s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
exit 0, no output

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run 'TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates|TestCrossProcessRecoveryHonorsTransactionFlock|TestCacheFIFOLoadIsBounded|TestLoadRejectsInsecureCachePermissions|TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration|TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  1.898s

git diff --check
exit 0, no output
```

注：上面的聚焦命令实际使用的 `GOCACHE` 为 `/private/tmp/dae-go-cache`；其余命令也均使用该
可写 cache。最终验证没有出现新的 production RED。已完成的 RED→GREEN 覆盖包括 mixed-registry、
跨行 YAML scalar、FIFO body/metadata/journal、cache permissions、special ranges、version
prune 和跨进程 transaction-root flock/recovery。

cmd `readConfig` 仍不能在当前 Darwin 环境执行；此前精确命令和错误记录在 5.15，阻塞发生在
现有 netlink/eBPF 依赖编译而非 readConfig 断言：`netlink.LinkUpdate`、
`netlink.LinkSubscribeWithOptions`、`unix.RTM_NEWLINK`/`RTM_DELLINK`、
`unix.ETHTOOL_GLINKSETTINGS`、`unix.SOCK_CLOEXEC`、`syscall.SOL_IP`、
`unix.IP_RECVORIGDSTADDR`、`unix.IPV6_RECVORIGDSTADDR`、`unix.IP_TRANSPARENT` 和
`unix.IPV6_TRANSPARENT` 均缺失。因此 cmd 不宣称 GREEN；需在匹配的 Darwin/netlink/eBPF 构建
基线或目标平台重新执行。

### 5.17 历史 Stage 1 test-only RED（后续 GREEN 已完成）：反转 fetch fence 仍返回 mixed registry

本轮严格进入 test-only RED；未修改任何生产 Go 文件、未派生子代理、未提交。新增测试 patch
仅为 `component/ruleprovider/rule_provider_test.go` 中的
`TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration`。

该 fixture 不复用此前会被排序绕过的测试：`/b` 先实际返回 `b-one.example`，随后 `/a` 到达
阻塞点；测试再把共享 source 切换为 `two` 并释放 `/a`，因此 `/a` 返回 `a-two.example`。
断言直接检查一次 `loadWithOptions()` 返回的 registry，禁止 `a=two/b=one` 这一混合结果。

最小聚焦命令及首个真实生产失败：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration$' -count=1

--- FAIL: TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration (0.04s)
    rule_provider_test.go:1058: Load() returned reverse-fence mixed generations: a="a-two.example" b="b-one.example"
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.718s
FAIL
```

这是确定性的生产行为 RED，不是测试环境问题：fixture 使用受控本地 HTTP listener 和可写临时
目录，且两个请求屏障均已完成。生产定位为
`component/ruleprovider/rule_provider.go:249-270` 的稳定逆序逐 provider fetch，以及
`:274-280` 将各自接受的结果直接装入同一个返回 registry；排序只规定了观察顺序，不能保证
source generation 一致，也没有在 fresh/stale 组合上执行整批拒绝或整批回退。

按“首个真实 production RED 立即暂停”的要求，该轮没有继续新增或运行：

- fresh/stale（A1/B1 → A2/B1）整批一致性测试；
- journal TOCTOU 创建/切换窗口测试；
- component/config NAT64 `64:ff9b:1::a00:1` 测试；
- version prune 的 current/readCacheSnapshot/最后内容断言；
- cmd `readConfig`（既有 Darwin netlink/eBPF 编译阻塞仍按 5.15 记录）。

这些项目不是本轮 PASS 或 GREEN；不能把此前独立验证证据扩写为本轮新测试结果。

### 5.17 历史 Stage 1 test-only RED（后续 GREEN 已完成）：显式 generation token drift 必须 fail closed

本轮严格保持 test-only；未修改任何生产 Go 文件、未派生子代理、未提交。测试 patch 仅修改
`component/ruleprovider/rule_provider_test.go`，将
`TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration` 改为显式 generation-token
契约测试；本进度文档同步记录证据，未修改 execution plan。

协议假设是：参与同一批次的 HTTP provider response 都带有
`X-Dae-Rule-Provider-Generation`，生产 fetch 必须读取并比较该共享 token。token drift 时，
生产必须在返回 registry/cache publish 前拒绝整批，并给出可审计的 generation drift/mismatch
类错误；或者在已有 last-good 时整批回退到同一 generation。测试不会接受任意错误，也不会接受
部分 current。

本测试使用反转 fetch fence：`/b` 先返回 body `b-one.example` 和 header `one`，随后阻塞 `/a`；
测试将 source 切换为 `two` 后释放 `/a`，使 `/a` 返回 body `a-two.example` 和 header `two`。
如果生产明确拒绝，测试只接受包含 `generation` 且包含 `drift`、`mismatch`、`inconsistent` 或
`batch` 之一的错误，并验证没有部分 cache current；如果生产返回 registry，则要求两个规则的
generation token 相同，禁止 `a=two/b=one`。

最小聚焦命令及实际 RED：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration$' -count=1

--- FAIL: TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration (0.05s)
    rule_provider_test.go:1083: Load() returned reverse-fence mixed generations: a="a-two.example" b="b-one.example"
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.691s
FAIL
```

这是确定性的生产 RED，不是测试环境问题：受控 HTTP fixture 确实发送了不同 generation
header，当前 `component/ruleprovider/rule_provider.go` 的 `prepareProviders`（约
`:249-270`）只做稳定逆序 fetch，`prepareProvider`/`fetchHTTP` 没有把 response generation
token 纳入批次一致性检查，随后在约 `:274-280` 将不同 generation 的规则直接装入返回
registry。该失败交给下一 code-only 修复轮次。

按“首个真实 production RED 立即暂停”，该轮没有继续新增或运行 fresh/stale A1/B1 → A2/B1
整批一致性、journal TOCTOU、NAT64、version prune 内容/current 断言或 cmd `readConfig`。
此前 cmd 的 Darwin netlink/eBPF 编译阻塞记录仍在 5.15；本轮没有伪造新的 cmd 结果，也没有把
未执行项目写成 PASS。测试使用可写临时目录和受控本地 listener，无环境阻塞。

### 5.18 历史 Stage 1 test-only：fresh/last-good PASS，NAT64 special-range RED（后续 GREEN 已完成）

本轮严格保持 test-only；未修改生产 Go 文件、未派生子代理、未提交，也未修改 execution plan。
新增/修改测试 patch 为：

- `component/ruleprovider/rule_provider_test.go`：新增
  `TestMultiProviderLoadRejectsFreshAndLastGoodGenerationMix`，并在 component 的
  `blockedIP`、`validatePublicURL` 真实测试中加入 `64:ff9b:1::a00:1`；
- `config/rule_provider_test.go`：在真实 `ValidateRuleProviders` URL 测试中加入
  `http://[64:ff9b:1::a00:1]/rules.yaml`；
- `docs/mihomo-rule-provider-progress.md`：记录本轮命令和证据。

fresh/last-good 最小聚焦命令通过：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestMultiProviderLoadRejectsFreshAndLastGoodGenerationMix$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.716s
```

该测试先真实发布 A1/B1（两者 response header generation=`one`），确认两份 cache metadata
也是 `one`；第二次关闭 B server 触发网络失败并回退 B1，同时让 A 返回 fresh generation=`two`。
生产当前正确地拒绝 batch generation mismatch；测试也验证 A/B cache body 和 metadata 未被
发布为 A2/B1。测试不接受任意错误，只接受明确 generation mismatch，或同一 generation 的
整批回退。

随后 NAT64 最小聚焦命令取得本轮首个真实 production RED：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -run 'TestBlockedIPRejectsReservedIPv6Ranges|TestProviderSecurityRejectsBlockedRedirectTargets|TestValidateRuleProvidersRejectsReservedIPv6Ranges' -count=1

--- FAIL: TestBlockedIPRejectsReservedIPv6Ranges (0.00s)
    rule_provider_test.go:430: blockedIP(64:ff9b:1::a00:1) = false for reserved IPv6 range
--- FAIL: TestProviderSecurityRejectsBlockedRedirectTargets (0.00s)
    --- FAIL: TestProviderSecurityRejectsBlockedRedirectTargets/http://[64:ff9b:1::a00:1]/rules.yaml (0.00s)
        rule_provider_test.go:451: validatePublicURL("http://[64:ff9b:1::a00:1]/rules.yaml") error = nil
FAIL
FAIL github.com/daeuniverse/dae/component/ruleprovider 0.642s
--- FAIL: TestValidateRuleProvidersRejectsReservedIPv6Ranges (0.00s)
    rule_provider_test.go:97:
        Error Trace: /path/to/dae/config/rule_provider_test.go:97
        Error:       An error is expected but got nil.
        Test:        TestValidateRuleProvidersRejectsReservedIPv6Ranges
        Messages:    url http://[64:ff9b:1::a00:1]/rules.yaml
FAIL
FAIL github.com/daeuniverse/dae/config 1.056s
FAIL
```

这是生产行为 RED，不是环境阻塞：component 的 `blockedIP()` 和 `validatePublicURL()`，以及
config 的 `ValidateRuleProviders()` 均接受 `64:ff9b:1::a00:1`（NAT64 local-use translation
of `10.0.0.1`）。生产定位为 component `security.go` 与 config `rule_provider.go` 的 blocked
network 集合/边界检查缺少该 NAT64 prefix。

按首个真实 RED 立即暂停，该轮没有继续 version prune current/readCacheSnapshot/最后内容
断言、journal TOCTOU helper 或 cmd `readConfig`。这些项目不是本轮 PASS；cmd 的 Darwin
netlink/eBPF 编译阻塞仍以既有 5.15 记录为准。本轮使用可写临时目录和受控本地 HTTP servers，
无测试环境阻塞。

### Hubble 轮次 GREEN / VERIFIED（历史记录）

```text
TMPDIR=/tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
-> ok  github.com/daeuniverse/dae/component/ruleprovider  1.308s
-> ok  github.com/daeuniverse/dae/config  0.664s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
-> ok  github.com/daeuniverse/dae/component/ruleprovider  0.677s
-> ok  github.com/daeuniverse/dae/config  0.706s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
-> ok  github.com/daeuniverse/dae/component/ruleprovider  3.431s
-> ok  github.com/daeuniverse/dae/config  1.557s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
-> exit 0, no output

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath GOOS=linux GOARCH=amd64 go test -c -tags dae_stub_ebpf -o /private/tmp/dae-cmd-stage1.test ./cmd
-> exit 0, no output

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath GOOS=linux GOARCH=amd64 go test -c -o /private/tmp/dae-cmd-stage1-plain.test ./cmd
-> exit 1: undefined: bpfObjects, bpfTuplesKey, bpfDomainRouting, bpfRedirectTuple

git diff --check
-> exit 0, no output
```

### Hubble 轮次 GAPS / 风险（历史记录）

- 重定向安全覆盖已由 `TestFetchHTTPRejectsRedirectToBlockedEndpoint` 实际经过 production
  `fetchHTTP`，并由独立 test-only GREEN 验证 redirect-to-blocked 拒绝；该项不再列为 gap。
- plain cmd 编译仍受当前分支缺少 eBPF 生成符号阻塞；stub 编译已通过，不能据此宣称 cmd
  集成或全仓测试通过。
- interval 后台刷新、运行时 staged reload、DAT/ext 和完整 DNS rebinding E2E 集成仍不在本轮
  test-only 范围内。

### 5.19 Lovelace 后的独立 test-only GREEN 与 coverage 补强

本轮未修改生产 Go 文件、未派生子代理、未提交。Lovelace 的 code-only 范围为
`component/ruleprovider/security.go` 与 `config/rule_provider.go`，加入 NAT64
`64:ff9b:1::/48`；本轮 test-only patch 仅修改
`component/ruleprovider/rule_provider_test.go`，并更新本进度文档。测试 patch 做了两项补强：

- `TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates` 除统计 `versions` 下所有真实目录（包括
  隐藏 `.candidate-*`）外，还断言 `current` 存在、`readCacheSnapshot` 能校验读取，且 body 等于
  最后一次 fresh 更新 `generation-6.example`；聚焦测试通过。
- 新增 `TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule`，分别构造
  flow collection 中跨行 quoted/plain scalar。每个物理行低于
  `maxProviderRuleLength`，整个 body 低于 `maxSize`；测试先用独立 `yaml.Unmarshal` 证明 fixture
  是一个超过限制的逻辑 scalar，再断言 `parseBody` 拒绝且分配低于逻辑 scalar 大小。quoted/plain
  两个子测试均通过，未产生 production RED。

NAT64 独立 GREEN 复验：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -run 'TestBlockedIPRejectsReservedIPv6Ranges|TestProviderSecurityRejectsBlockedRedirectTargets|TestValidateRuleProvidersRejectsReservedIPv6Ranges' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.414s
ok  github.com/daeuniverse/dae/config  0.745s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  3.309s
ok  github.com/daeuniverse/dae/config  0.365s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  11.033s
ok  github.com/daeuniverse/dae/config  1.453s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
exit 0, no output
```

版本内容断言与已有跨进程 flock/recovery 的实际证据：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.719s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestCrossProcessRecoveryHonorsTransactionFlock$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  1.432s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider -run '^TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule$' -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  0.698s
```

首次运行版本聚焦时，普通沙箱因 `httptest.NewServer` 的 IPv6 loopback listener 被拒绝：
`listen tcp6 [::1]:0: bind: operation not permitted`。这是测试环境阻塞；在获得本地 listener
权限后同一命令如上通过，不是 production RED。

journal TOCTOU：本轮审查了 `recoverPendingPublish` 的“journal `Lstat` 后、transaction
flock 前”窗口。当前生产接口没有可注入屏障或 hook；已有 helper 能确定性覆盖跨进程 flock
阻塞/释放和 journal recovery，但不能无 sleep 地证明恰好越过该窗口。因此没有添加竞态重试或
脆弱 sleep 测试，记录为 coverage gap，不把它写成 PASS。

本轮没有新的 production RED。cmd `readConfig` 仍受既有 Darwin netlink/eBPF 平台编译阻塞，
不得以 stub 编译替代真实 GREEN；routes/groups 非原子发布仍属于 Stage 2。最终工作区仍未提交，
生产 code-only 文件范围与 test-only 文件范围保持分离。

补强测试加入并 gofmt 后的最终复验也完整通过：

```text
TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  3.692s
ok  github.com/daeuniverse/dae/config  0.641s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go test -race ./component/ruleprovider ./config -count=1
ok  github.com/daeuniverse/dae/component/ruleprovider  12.098s
ok  github.com/daeuniverse/dae/config  1.966s

TMPDIR=/private/tmp/dae-go-tmp GOCACHE=/private/tmp/dae-go-cache GOPATH=/private/tmp/dae-gopath go vet ./component/ruleprovider ./config
exit 0, no output

git diff --check
exit 0, no output
```
