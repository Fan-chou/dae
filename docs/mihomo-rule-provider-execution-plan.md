# Mihomo 规则集与代理组兼容性改造执行计划

## 1. 文档目的

本文档是当前执行基线，合并了以下内容：

- 原有目标和约束：`docs/mihomo-rule-provider-progress.md`；
- 交接要求和阶段划分：`HANDOFF_PROMPT.md`；
- 对当前 `kix/kdae..HEAD` 历史提交的代码审查结果。

原始交接中引用的 `/root/.hermes/plans/2026-08-12_060204-mihomo-rule-provider-proxy-group.md` 在当前环境不存在，因此本文档不假设能够恢复该文件中的隐含要求；所有验收要求都在这里显式列出。

本文档描述“做到什么、按什么顺序做、如何验收”。其中第 2 节和第 17 节是当前状态与
后续规则编译设计的优先依据；前面保留的阶段说明包含历史计划，若与当前状态冲突，以当前
状态为准。

> 状态修正（2026-08-14）：截至 `2b0b8bc`，原始 Mihomo YAML routing 入口、provider 归一化、
> 有序 rules IR、sub-rules 展开、provider/DAT 绑定和同 generation 原子发布均已实现；
> `b3868c1` 进一步补齐了已支持规则的选项保真。先前把这些能力列为待实现的段落仅保留为
> 历史设计记录，不能再作为当前状态或后续步骤。
> `3ff9f3f` 随后完成 `DOMAIN-WILDCARD` capability stage：模式经小写规范化、字面正则
> 转义和完整锚定后，按 `*` 为零或多个字符、`?` 为一个字符降低为 kdae domain regex；显式
> classical-provider 的 `DOMAIN-WILDCARD` 条目复用 `DomainRegex`/DAT 路径。
> `2b0b8bc` 完成非阻断 rule lowering：`IP-ASN` 条件跳过、`match-mac` 条件/动作选项忽略、
> 其它无法降低的单条规则记录源位置和原因后跳过，完整转换继续；相同来源的重复警告只记录一次。

> 最终目标修正：本项目仍以 Mihomo `rules` 到 kdae routes 的语义等价为目标。能够保持匹配
> 条件、规则顺序、命中动作和选项语义的规则按等价路径转换；用户明确允许的有损例外必须
> 通过日志报告源位置和原因，并跳过受影响的条件/规则继续转换，不能用静默丢弃或未声明的
> 近似动作冒充无损结果。

> 历史段落说明：第 4～16 节保留了此前阶段的实现契约、风险记录和历史验收条件。它们不再
> 代表当前执行顺序；其中关于 TDD、独立审查或额外验证的文字也不构成当前工作要求。当前
> 以第 17 节的 routing sections 设计和用户明确的逐步开发要求为准。

## 2. 当前基线

当前分支的实现基线是 `2b0b8bc`（包含 `7470e48` 的 fixed 组成员元数据修复、
`5cec0d0` 的 Mihomo DAT 前缀复制修复、`4585d21` 的 MATCH/fallback 修复，以及此前
`dc59e45` 的 nested group health 语义修复、`81b972f` 的单成员 `url-test` 精确降低和
`b3868c1`、`3ff9f3f` 等 routing 提交），
不再使用 `4c6e1a4` 或“转换入口只建模 proxies/proxy-groups”的旧状态。与本次设计直接相关的
已完成能力包括：

- manifest 校验、HTTP/file provider fetch/cache、规则解析和 generation-atomic 发布；
- `98f4321`：GeoSite/GeoIP DAT writer；
- `ac187b9`：大型 provider 自动生成 `domain(ext: ...)` / `dip(ext: ...)` 路由；
- 原始 Mihomo YAML routing document 读取：`rule-providers`、有序 `rules`、`sub-rules` 与
  script 引用分析；
- provider 规范化、ordered routing IR、sub-rule graph 展开、provider leaf 的 inline/DAT 绑定，
  并将 routes、provider snapshot、DAT 和 metadata 作为同一 generation 发布；
- 已支持规则选项的保真 lowering（`b3868c1`）；lowerer 默认仍可 fail closed，完整 Mihomo
  routing 入口则对单条无法降低的规则记录日志并跳过，不阻断其它规则；
- `3ff9f3f`：`DOMAIN-WILDCARD` 降低为完整锚定、字面正则转义的 kdae domain regex：`*` 表示
  零或多个字符，`?` 表示一个字符，输入先小写规范化；显式 classical-provider 条目复用
  `DomainRegex`/DAT binding；
- Mihomo 节点、DIRECT/REJECT、nested group、select/fallback/health-check 的用户态转换；
- `4c6e1a4`：非 Linux 链路验证注册 `shadowsocks_2022`。

这不表示任意 Mihomo 配置都已无损转换。当前等价路径覆盖 domain（含 `DOMAIN-WILDCARD`）/IP/
port/network/process/逻辑条件、sub-rule、provider 和 DAT 数据；明确的有损兼容策略是：
忽略 `IN-PORT`、`IP-ASN` 条件和 `match-mac` 条件/动作选项，`REJECT-DROP` 降级为
`REJECT`/`block`。完整 routing 入口对其它单条 lowering 失败（例如 `GEO*`、未知条件、无法
表达的选项/动作或单条展开超限）记录 warning 后跳过该规则，继续生成其它 routes；这不宣称
该规则仍保持语义等价。provider 获取/解析、引用完整性、节点/代理组结构和活动 `SCRIPT` 等
候选级失败仍 fail closed，避免发布结构不完整的 generation。

2026-08-14 使用用户提供的完整 Mihomo 配置进行了真实转换，命令退出码为 0。日志报告了
`IN-PORT`（源文件第 1232、1233 行）、`IP-ASN`（第 1297 行）、`match-mac` 条件/动作选项
（第 1403、1425、1426、1433、1436、1441 行）等明确有损点，没有因为这些规则中有无法无损
表达的部分而中止。最终生成 282 条 routes、36 个代理组、8 个节点、远程规则集快照以及
geoip/geosite DAT；活动 `SCRIPT` 和候选级结构错误仍不在这个非阻断范围内。

## 3. 不可改变的约束

所有阶段都必须遵守：

1. 不修改 `control/kern/*.c`、eBPF outbound ID 编码、kernel map 协议、透明代理数据面和 routing result 格式。
2. 远程 YAML、文本和 HTTP 只在用户态处理；远程内容不得作为 dae 配置直接执行或加载。
3. provider 下载、解析、转换或编译失败时保留最后一个有效版本。
4. 空 provider、空 DAT、空 groups 和全 unsupported 输出不能覆盖有效版本。
5. 生产路径不能暴露测试用的 `AllowPrivate` 或等价绕过开关。
6. 当前执行按直接开发推进，不强制 TDD；未明确要求时不启动独立审查和额外验证流程。
7. 每个明确的垂直步骤单独提交一个 commit，提交只包含该步骤涉及的文件；安全边界和
   generation-atomic 约束仍然有效。

## 4. 当前执行顺序

```text
已完成：provider fetch/cache、generation-atomic、DAT writer、DAT-backed routes、节点/组基础转换
    ↓
已完成（截至 `910ecb3`）：原始 Mihomo YAML → routing document extractor
    ↓
已完成（截至 `910ecb3`）：rule-providers → normalized provider snapshot / inline 或 DAT
    ↓
已完成（截至 `910ecb3`）：有序 rules → routing IR 与 action lowerer
    ↓
已完成（截至 `910ecb3`）：sub-rules → 有界 graph compiler
    ↓
已完成（截至 `910ecb3`）：nodes、groups、routes、provider snapshot、DAT → 同一 generation 发布
    ↓
已完成（`b3868c1`）：已支持 rule options 的保真；完整入口对不支持的单条 option/action 记录日志并跳过
    ↓
已完成（`2b0b8bc`）：`IP-ASN`/其它单条 lowering 失败非阻断，源位置和原因通过 warning 输出
    ↓
已完成（`3ff9f3f`）：`DOMAIN-WILDCARD` → 小写、转义、完整锚定的 kdae domain regex；
显式 classical-provider 条目复用 `DomainRegex`/DAT
    ↓
仍待未来证明精确等价后再实现：未支持的条件/选项/动作；不包含 script engine 或数据面重设计
```

本顺序中的 routing 步骤已经完成，保留它们是为了说明依赖和提交边界。它不包含 script engine
或 script 表达式编译：未使用定义不会阻断其它 routing sections，活动引用不能近似转换。DAT/ext
继续只是 provider 数据载体，不重新设计或重复实现。

## 5. 阶段 0：计划纠偏、状态冻结与安全入口收口

### 目标

让仓库状态、计划状态和生产行为一致，避免在未加固的 native runtime 上继续扩大功能。

### 工作项

- 保留 `bf855b9` 作为历史 WIP checkpoint，不 amend、不重写历史；不把它当作当前 HEAD。
- 保留已经存在的 `d0126a6` 阶段 0 gate 提交，不重写历史。
- 以本文档作为执行计划，以 `mihomo-rule-provider-progress.md` 作为当前进展记录；两份文档
  同步维护，不能让已完成的 DAT/ext 或当前 routing sections 缺口停留在旧状态。
- 在 native provider 安全收口前，生产入口对非空 `rule_provider` fail closed，不能静默跳过配置。
- 更新进展文档中的过时表述：
  - “未提交代码整理”改为当前十个提交的 WIP checkpoint；
  - “后续会运行”改为实际已运行或明确待运行；
  - 记录 `-tags dae_stub_ebpf` 编译通过和普通 Linux 构建缺少生成 `bpf*` 类型的事实。
- 历史执行记录保留 commit、命令、输出和未解决风险；当前新步骤按用户要求直接开发并单独提交。

### 出口门禁

- 生产入口不会以不安全的 native provider 继续运行；
- `docs/mihomo-rule-provider-execution-plan.md` 是执行计划 canonical 版本；根目录未跟踪的
  `mihomo-rule-provider-progress.md` 是 legacy user file，不能删除或改写。
- `mihomo-rule-provider-progress.md` 是进度记录 canonical 版本；
- 工作区和 `kix/kdae..HEAD` 范围被记录清楚。

### 建议提交

```text
chore: gate incomplete native rule provider runtime
```

## 6. 阶段 1：native provider 安全与 last-good snapshot

### 目标

把 native provider 从“同步加载初版”提升为可以安全进入生产配置路径的用户态 snapshot loader。

### 责任文件

- `component/ruleprovider/rule_provider.go`
- `component/ruleprovider/security.go`
- `component/ruleprovider/rule_provider_test.go`
- `config/rule_provider.go`
- `cmd/run_config.go`
- 新增或扩展相关测试文件

### 实现步骤

1. **定义接受流水线**

   ```text
   fetch/read
       → URL/DNS/transport 校验
       → body 大小校验
       → YAML/text 结构校验
       → 规则语义解析
       → provider 规则非空校验
       → ruleset 展开和数量上限校验
       → 写入候选 cache
       → 原子发布 snapshot
   ```

   cache current 只能在完整接受之后替换，不能在 `yaml.Unmarshal` 或普通 HTTP 200 后替换。

2. **修复 last-good 语义**

   - 坏内容、空内容、全 unsupported 内容不污染 current cache；
   - fetch 失败时只读取通过 checksum/source binding 的旧 snapshot；
   - 首次加载没有有效 snapshot 时直接失败；
   - 已引用 provider 展开为零条规则时直接失败，不能让 routing rule 消失。

3. **修复 cache 隔离**

   - cache key 至少包含 provider name、来源类型、规范化 URL/path；
   - metadata 保存 source key、checksum、更新时间和版本；
   - 不允许不同 provider 或不同来源共用一个未绑定的 cache 文件；
   - cache 写入使用候选目录和单一 current 指针。

4. **统一 SSRF 和 transport 安全**

   - 默认清除环境代理；
   - redirect 每跳重新校验；
   - DNS 解析后逐 IP 校验并在实际拨号路径再次校验；
   - 统一拦截 loopback、private、link-local、multicast、unspecified、CGNAT、benchmark、Azure/Alibaba/GCP metadata 等地址；
   - 设置总超时、响应头上限和响应体上限；
   - `AllowPrivate` 限制为测试内部能力，不从生产配置传入。

5. **限制不可信输入复杂度**

   - 拒绝 YAML alias；
   - 限制 YAML node 数、深度和单条规则长度；
   - 限制 provider rule 数和展开后的 routing rule 数；
   - 对多个 `ruleset()` 的笛卡尔积设置硬上限，超限 fail closed。

6. **保留文件安全边界**

   - 使用 `EvalSymlinks` containment；
   - 使用 `O_NOFOLLOW`；
   - 只读取 regular file；
   - provider 路径和 cache 路径分离，避免把用户指定数据文件直接当作可写 cache。

### 必须新增的回归测试

- 坏更新 → 网络失败 → 旧规则仍被使用；
- 空 provider → 旧路由不消失；
- 全 unsupported provider → fail closed；
- 代理环境变量存在时不能绕过目标 IP 检查；
- hostname 解析到私网、CGNAT、benchmark 和 metadata 地址；
- redirect 到受限地址；
- YAML alias、超深、超节点和超规则数；
- 多 provider cache source/path 隔离；
- 展开数量超过上限时不修改 current snapshot。

### 出口门禁

- native provider 可以安全地被 `readConfig()` 调用；
- 以上 P1 findings 全部有测试覆盖；
- `go test`、`go test -race`、`go vet` 通过；
- 规格审查和安全审查均为 `ship`。

### 建议提交

```text
fix: harden native provider snapshot and SSRF boundary
```

## 7. 阶段 2：sidecar provider 与输出 generation 一致性

### 目标

确保外部同步器不会缓存或发布无法完整应用的 provider、routes、groups 结果。

### 责任文件

- `tools/dae-rule-sync/fetch.go`
- `tools/dae-rule-sync/runner.go`
- `tools/dae-rule-sync/manifest.go`
- `tools/dae-rule-sync/groups.go`
- `tools/dae-rule-sync/*_test.go`

### 实现步骤

1. **按 provider 接受结果**

   - fetcher 的 `ValidateBody` 必须包含解析、转换和非空语义校验；
   - 对每个被 route 引用的 provider 单独判断是否有生成结果；
   - 不能用其他 provider 的生成规则掩盖当前 provider 为空；
   - all-skipped 或 empty provider 更新时保留该 provider 的旧 snapshot。

2. **设计 generation 发布协议**

   推荐目录结构：

   ```text
   generated/
     generations/<id>/routes.dae
     generations/<id>/groups.dae
     generations/<id>/metadata.json
     current -> generations/<id>
   ```

   - routes、groups、metadata 全部写入候选 generation；
   - 对候选 generation 做真实 parser/config 校验；
   - 最后只原子替换 `current`；
   - current generation 保留一段时间，旧 generation 按数量或时间清理。

如果必须保留两个独立输出路径，则必须在文档中明确这是非原子兼容模式，不能继续宣称“避免 routes/groups 部分 apply”。
完整 routes/groups generation-atomic 发布属于本执行计划的阶段 2；在阶段 1/native provider
验证中不得把 sidecar 的顺序写入或局部 gate 描述成已经完成的 generation-atomic 能力。

3. **补齐失败一致性**

   - routes 写失败不能留下新 groups；
   - groups 写失败不能留下新 routes；
   - generation 验证失败不能改变 current；
   - 空 routes、空 groups、空 DAT 均不得替换旧 generation。

4. **强化 cache 维护**

   - 保留 last-good current；
   - metadata 与 body 通过 checksum/source key 绑定；
   - 版本目录增加清理策略；
   - 保留并测试单 fetcher single-flight、waiter context cancellation 和跨进程写入策略。

### 必须新增的回归测试

- 空 provider 更新后网络失败仍使用旧 cache；
- 多 provider 只有一个变空时，旧 provider 仍正确保留；
- generation 第二个文件写入失败时 current 不切换；
- routes/groups 通过真实 `config.New` round-trip；
- strict mode 端到端测试；
- cache 版本清理和并发 writer 测试；
- metadata 和错误信息不包含 URL query token。

### 出口门禁

- sidecar 的 current snapshot、routes、groups 属于同一 generation；
- 任一输入失败都不会产生新旧资源混合状态；
- `go test`、race、vet 和 diff check 通过；
- 规格和安全审查均为 `ship`。

### 建议提交

```text
fix: make rule sync snapshots and outputs generation-atomic
```

## 8. 阶段 3：DAT/ext writer（已完成）

本阶段已经由以下提交完成：

```text
98f4321 feat: add geosite and geoip dat writer
ac187b9 feat: generate DAT-backed routes for large providers
```

后续规则编译设计应复用本阶段的 DAT binding，不得重新把大型 provider 展开成无限内联规则。
本节以下内容保留实现契约和出口条件，作为后续 `rules` / `sub-rules` 编译器的依赖说明。

### 目标

把大型 provider 从内联大量 `domain()`/`dip()` 规则迁移到现有 geodata/DAT 与 `DatReaderOptimizer` 路径。

### 责任文件

- 新增 `tools/dae-rule-sync/dat_writer.go`
- 新增 `tools/dae-rule-sync/dat_writer_test.go`
- `tools/dae-rule-sync/parser.go`
- `tools/dae-rule-sync/runner.go`
- 相关 geodata/routing 测试

### 实现步骤

1. 先写 RED 测试，使用现有 `pkg/geodata` protobuf 类型构造 fixture。
2. 实现 GeoSite full、suffix、keyword、regex。
3. 实现 GeoIP IPv4、IPv6、重复 prefix 去重和非法 prefix 拒绝。
4. 生成 DAT 到候选 generation，完成 fsync、checksum、原子发布。
5. 使用 `component/routing.DatReaderOptimizer` 真实读取生成文件。
6. 将输出改为：

   ```dae
   domain(ext:"generated/geosite/provider.dat:provider") -> outbound
   dip(ext:"generated/geoip/provider.dat:provider") -> outbound
   ```

7. empty DAT、parse/compile failure、provider failure 时保持旧 generation。
8. report 记录规则数、unsupported 数、checksum、更新时间和脱敏后的来源信息。

### 必须覆盖的测试

- GeoSite 四种 domain 类型；
- GeoIP v4/v6；
- 重复规则和空规则；
- 非法 prefix；
- classical unsupported 条目；
- DAT writer → `DatReaderOptimizer` → normalized routing 的真实 round-trip；
- DAT 与 routes/groups 同一 generation 发布。

### 出口门禁

- 生成 DAT 可由现有 optimizer 真实读取；
- 生成的 ext route 可由 kdae parser/config/routing 接受；
- 大规则集不再依赖无限内联 expansion；
- 独立规格审查和安全审查均为 `ship`。

### 已完成提交

```text
98f4321 feat: add geosite and geoip dat writer
ac187b9 feat: generate DAT-backed routes for large providers
```

## 9. 阶段 4：native provider 生命周期与 staged reload

### 目标

让 native provider 在运行中按 interval 刷新，并以不可变 snapshot 进入现有 staged reload/control-plane 流程。

### 实现步骤

- 抽取阶段 1 的 safe fetch、cache、parse、compile 为可复用 provider store；
- 实现 interval refresh 和同一 provider single-flight；
- 使用 immutable snapshot，刷新失败不修改当前运行 generation；
- 新 generation 通过 staged reload 进入 routing/control-plane；
- reload 失败时保留旧 generation；
- 记录 provider 状态、last success、last error、stale age 和 checksum；
- 明确定义 interval 为零、超大 interval 和进程退出时的行为。

### 必须覆盖的测试

- refresh 成功切换 generation；
- refresh 失败继续使用旧 snapshot；
- parse/compile 失败不切换；
- 多个 waiter 共享一次 fetch；
- context cancellation 不破坏 single-flight；
- staged reload 失败不修改正在运行的 routing IR；
- reload 后现有流量和 eBPF outbound ID 不变。

### 出口门禁

- provider 更新不直接修改运行中 IR；
- 失败始终保留 last-good；
- 真实 control-plane 测试在 eBPF 生成文件恢复后通过；
- 生命周期设计和安全实现分别通过独立审查。

### 建议提交

```text
feat: add native provider refresh lifecycle
```

## 10. 阶段 5：flat proxy group runtime

### 目标

把 select、fallback、url-test 的可支持子集映射到现有 `component/outbound` concrete dialer group。

### 实现步骤

1. 先保证 sidecar 生成的 groups 经真实 `config.New` round-trip。
2. 验证 group/member 名称、filter 和 policy 的 parser 语义。
3. 映射：
   - `fallback` → `fallback`（声明顺序 + Alive/Degraded/Dead 准入）；
   - `url-test` → `url_test`（质量分 + tolerance）；
   - `select` → 只有在选择语义明确且顺序稳定时才映射；否则保持 unsupported/approximate，不能伪装成完整兼容。
4. unknown node、重复 group、nested group、DIRECT、REJECT、proxy-provider 成员必须拒绝或进入明确报告。
5. 验证生成 group outbound 的存在性和 reload 行为。
6. 不修改 eBPF outbound ID 和 routing result。

### 必须覆盖的测试

- select/fallback/url-test 的配置解析和策略行为；
- group filter 的 OR/AND 语义；
- unknown member、特殊 member、nested group；
- group 名称和成员名称包含引号、控制字符或非 ASCII；
- group 输出进入真实 control-plane；
- fallback/url-test 节点故障时的选择行为。

### 出口门禁

- flat group 的支持边界在文档和报告中清楚标记；
- unsupported/approximate 不会静默丢失；
- control-plane 行为测试通过；
- 规格和安全审查均为 `ship`。

### 建议提交

```text
test: verify generated groups through dae config parser
feat: add flat native proxy group policies
```

## 11. 阶段 6：完整集成与发布验收

### eBPF 生成文件恢复前

先执行 stub 编译门禁，确认接口和包结构没有明显错误：

```text
GOOS=linux GOARCH=amd64 go test -run '^$' -tags dae_stub_ebpf ./cmd/...
```

该命令不能替代真实 control-plane 测试。

### eBPF 生成文件恢复后

执行仓库规定的生成流程，再运行：

```text
go test ./cmd/...
go test ./...
```

同时检查：

- 生成 routes/groups/DAT 的真实 reload；
- provider 网络失败、解析失败、空输出时的 rollback；
- control-plane、routing、DNS、outbound 和 eBPF ABI 未改变；
- 资源占用、规则规模和刷新频率处于预期范围。

### 每个阶段通用验证

以下命令中的路径应替换为当前环境可写的临时目录和 Go cache：

```text
TMPDIR=<writable-tmp> GOCACHE=<writable-go-cache> GOPATH=<writable-gopath> \
  go test <affected-packages> -count=1

TMPDIR=<writable-tmp> GOCACHE=<writable-go-cache> GOPATH=<writable-gopath> \
  go test -race <affected-packages> -count=1

TMPDIR=<writable-tmp> GOCACHE=<writable-go-cache> GOPATH=<writable-gopath> \
  go vet <affected-packages>

git diff --check
```

最终报告必须列出实际命令、实际输出、未执行范围和环境阻塞；不能把 stub 编译或目标包测试写成全仓库通过。

### 发布条件

- 所有 P1/P2 findings 关闭或有明确的非生产范围说明；
- DAT/ext、native lifecycle、flat group 的目标功能均有真实测试；
- eBPF 数据面、outbound ID 和 kernel map 协议无差异；
- 最终 fresh Sol review 返回 `ship`；
- 工作区只包含预期文件，且每个垂直功能有独立 commit。

## 12. 阶段 7：nested group（原计划阶段三）

该阶段只有在阶段 4、5、6 全部通过后开始。

### 设计先行

- 定义 group graph 和节点/组的统一引用模型；
- 设计循环检测和最大深度；
- 定义状态继承、故障传播和 reload 行为；
- 定义 nested group 与现有 outbound group 的边界；
- 证明 eBPF outbound ID、routing result 和现有 control-plane 接口无需改变。

### 实现顺序

1. 先写 graph validation 和 cycle detection 测试；
2. 实现只读、不可变 group graph；
3. 接入 staged reload 和状态继承；
4. 增加故障、回滚和并发刷新测试；
5. 进行独立规格审查和安全审查；
6. 最后才允许接入默认生产配置路径。

## 13. 推荐提交序列

```text
已完成历史提交：
4c6e1a4 fix: register SS2022 for non-linux link validation
56e3fa9 fix: fail closed on incomplete Mihomo generations
98f4321 feat: add geosite and geoip dat writer
ac187b9 feat: generate DAT-backed routes for large providers
910ecb3 routing: 原始 YAML routing entry、provider normalization、ordered rules IR、
        sub-rules expansion、provider/DAT binding 与 generation-atomic publish
b3868c1 routing: 已支持 rule options 的语义保真；无精确等价的 option/action 继续 fail closed
3ff9f3f routing: DOMAIN-WILDCARD 以小写、转义和完整锚定的 domain regex 降低；
        显式 classical-provider 条目复用 DomainRegex/DAT

规则编译垂直步骤：全部完成（截至 `3ff9f3f`）。当前没有可在既定能力边界内继续实现的
pending routing 步骤；不支持的条件、选项和动作只能在证明精确 kdae 等价后另行立项。
```

已完成的规则编译提交保持原有分步边界；`script` 表达式编译不在本轮范围内。读取完整 YAML
时可以记录未使用定义，但活动引用必须显式失败，不能把 script 作为近似功能实现。

## 14. 风险与回滚策略

| 风险 | 预防 | 失败时处理 |
| --- | --- | --- |
| 远程内容污染 cache | parse/compile/non-empty 后才 publish | 删除候选 generation，保留 current |
| DNS rebinding/代理绕过 | 禁用环境代理、逐跳和拨号校验 | 拒绝 fetch，使用 last-good |
| 空 provider 删除路由 | 每 provider 非空门禁和旧 snapshot | 不切换 generation |
| routes/groups 部分发布 | generation 目录 + 单 current 指针 | 保留旧 generation |
| DAT 无法读取 | `DatReaderOptimizer` 真实 round-trip | 不发布 DAT/ext route |
| reload 破坏 control-plane | staged reload 和 rollback | 保留运行中的旧 generation |
| nested group 循环 | graph validation、深度上限 | 配置加载失败，不启动新 generation |
| eBPF 生成环境缺失 | stub compile + 明确记录阻塞 | 不宣称全量测试通过 |

## 15. 完成定义

本节是早期全局阶段的历史完成定义；当前 routing sections 的完成条件以第 17.9 节为准，
并遵循用户当前指定的直接开发和提交节奏。

只有同时满足以下条件，才能把整个改造标记为完成：

- Mihomo rule-provider 的 HTTP/file 输入可安全加载并保持 last-good；
- domain、IP-CIDR、classical 支持边界明确，unsupported 不静默丢失；
- 大规则集通过 DAT/ext 和现有 optimizer 工作；
- routes、groups、DAT 作为一致 generation 发布；
- native provider 支持 interval、single-flight、snapshot 和 staged reload；
- flat select/fallback/url-test 的支持边界和 approximate 语义有真实测试；
- nested group 经过独立设计、循环检测和运行时回滚验证；
- 全量测试、race、vet、真实 control-plane 验证和最终独立审查均通过；
- 没有修改 eBPF 数据面、outbound ID 或 kernel map 协议。

## 16. Mihomo 配置兼容补充设计（需求 2～7）

本节针对当时真实配置验证暴露的六项缺口补充设计。其历史描述中的 `PROCESS-NAME` 已由当前
routing lowerer 支持，`DOMAIN-WILDCARD` 也已由 `3ff9f3f` 支持；其余 capability matrix 所列
不支持项仍 fail closed。本节假设规则转换器已经能把每条被引用规则明确表示为“可转换”或
“不可转换”，不在这里重新定义规则匹配语法。

本节保留 routing sections 之外的历史扩展设计，不是对当前 routing 实现状态的否定或待办
清单。无论未来是否采用其中的 group-runtime 方案，仍必须遵守“不改 eBPF 数据面、outbound
ID、kernel map 协议”和“候选 generation 完整通过后才发布”的约束。

### 16.1 `DIRECT` / `REJECT` 映射

当前 converter 把这两个 Mihomo 特殊成员记为 unsupported 并删除，导致组行为改变。不能用
`filter: name('direct')` 代替，因为 dae 的普通 `name()` filter 只搜索用户 node 池，而
`direct` 和 `block` 是 control-plane 预先创建的内置 outbound。

采用以下表示：

| Mihomo 成员 | 生成的组成员 | 运行时对象 |
| --- | --- | --- |
| `DIRECT` | `group('direct')` | 现有内置 `direct` outbound |
| `REJECT` | `group('block')` | 现有内置 `block` outbound |

具体约束：

1. `groups.go` 生成特殊成员时保留其原始顺序，不再删除；普通 node 仍使用
   `filter: name(...)`。
2. `control.planNestedGroupBuild` 将 `direct`、`block` 作为两个保留 group reference，初始
   `builtGroups` 直接绑定 control-plane 已创建的两个内置组。用户配置不得再声明同名 group。
3. `group('direct')` / `group('block')` 只能是单独的精确成员引用，不能放入 `name()`、正则、
   `!`、AND 或 OR 表达式中。
4. `select` 中的两个成员按普通有序成员处理；`fallback` 中按声明顺序参与选择；没有父级
   显式 health spec 时，`DIRECT` 视为始终可用，`REJECT` 视为可选择的终止动作，内置
   concrete member 不执行网络健康探测。若 nested parent 显式配置 health spec，则只为该
   parent 创建可探测的独立 health view，不能因为内置 concrete member 的 `DisableCheck`
   而静默跳过 parent check。
5. `url-test` 包含 `REJECT` 时，在无损模式直接拒绝生成，因为 `REJECT` 没有可测量延迟。
   `url-test` 仅包含 `DIRECT` 时固定映射为可用的直连成员，并在报告中记录该特殊语义。
6. 特殊成员处理后为空的 group、只剩 unsupported 成员的 group，以及父 group 引用的空 child
   都使候选 generation 失败，不能继续生成“少一个成员”的近似配置。

这样做只扩展用户态 group graph 的成员解析，不改变 direct/block 的保留 outbound ID，也不
改变 eBPF routing result。

### 16.2 Mihomo proxy 到 dae node/link 的转换

当前 `MihomoProxy` 只有 `name` 和 `type`，因此 converter 能生成 group 名称，却没有生成实际
可拨号的 node。设计新增一个 typed intermediate model，再统一输出 dae 已支持的 link，而不是
在 group runtime 中增加 Mihomo 协议分支。

#### 输入与输出

`MihomoProxy` 至少读取以下字段：

```text
name, type, server, port,
username, password,
cipher, sni, servername, client-fingerprint,
tls, skip-cert-verify, udp, plugin, plugin-opts
```

转换器输出同一 generation 下的 `nodes.dae`：

```dae
node {
    node_safe_name: 'canonical dae link'
}
```

`groups.dae` 中的成员统一使用 `node_safe_name`。原始 Mihomo 名称、safe-name 映射、输入
checksum 和协议类型写入 `metadata.json`，不把密码写入 report、日志或 metadata。

#### 当前真实配置的协议映射

| Mihomo type | dae link | 最小必需字段 | 处理原则 |
| --- | --- | --- | --- |
| `anytls` | `anytls://...` | server、port、password | 保留 SNI、TLS、client fingerprint；密码和 query 必须 URI 编码 |
| `ss` | `ss://...` | server、port、cipher、password | 使用现有 Shadowsocks URI 编码；plugin 仅允许 dae 已支持的形式 |
| `socks5` | `socks5://...` | server、port | 保留 username/password；TLS 或其他 Mihomo 扩展没有明确 dae 等价物时拒绝 |

本配置中的 8 个活动节点（3 anytls、3 ss、2 socks5）应全部通过上述 encoder 生成，并逐个
交给现有 `dialer.NewFromLink` 做协议解析。节点名称需要独立建立 `NodeNameMap`：

- ASCII 安全名称可原样保留；Unicode、引号、控制字符和过长名称映射为稳定 hash 名称；
- 映射冲突、重复 Mihomo 名称、缺少必需字段、未知 type、未支持的 plugin/options 都直接失败；
- group 成员只引用映射后的名称，不能再引用原始 emoji 名称；
- 不因“节点未被某个 group 引用”而默认吞掉解析失败，默认模式要求所有声明节点可转换；
  如未来需要忽略未使用节点，必须是显式的非生产兼容选项。

节点文件、groups 文件和 routes/DAT 必须一起进入 generation。这样 control-plane 仍然沿用
现有 `node` 解析、`NewFromLink`、health check 和 transport cache，不需要新增代理协议运行时。

### 16.3 `select` 的持久选择

当前 `select` 被降成 `fixed(0)`，每次 reload 都回到第一个成员。Mihomo 的
`profile.store-selected: true` 要求保存“成员身份”，不能只保存数组下标，因为 provider 更新
或组顺序变化后下标可能指向另一个节点。

#### 状态模型

新增用户态 `GroupSelectionStore`，默认文件为：

```text
persist.d/mihomo-group-selection.json
```

建议结构：

```json
{
  "version": 1,
  "source_sha256": "...",
  "groups": {
    "🎯 Final": {"member": "🍎 Proxy"},
    "🍎 Proxy": {"member": "🇭🇰 DMIT.HK | Hysteria"}
  }
}
```

文件权限为 `0600`，写入采用临时文件、`fsync`、原子 rename 和目录同步；进程内使用互斥锁，
跨进程使用已有 generation/持久化锁策略。状态只保存 group 名称和成员逻辑身份，不保存 link
或密码。

#### 加载与修改规则

1. 生成 group 时保留稳定的原始成员身份和 safe-name 映射；nested group 保存 child group 名称。
2. control-plane 构建 group 后读取 store：成员仍存在则换算成当前 generation 的位置并使用
   `fixed(index)`；成员不存在则选择当前声明顺序的第一个可用成员，并写出一次告警。
3. 没有历史状态时，行为与 Mihomo 一致地从第一个成员开始。
4. 提供一个只在用户态运行的 `GroupSelectionController`，让已有管理入口可以按 group name
   设置成员；设置成功后更新内存 policy，再异步持久化。不能通过修改 eBPF map 表示选择。
5. reload 时先校验旧成员身份，再应用新 generation；旧成员消失不阻止整个 generation，
   但不得把未知状态当作合法成员。
6. 该持久化只适用于 `select`，`fallback` 和 `url-test` 不写选择状态。

`select` 的 health check 与 selection policy 要分开：`fixed` 只表示不自动换节点，不能因此
把用户配置的健康检查参数静默丢掉。健康检查生命周期按 16.5 处理。

### 16.4 `fallback` 的声明顺序故障回退

`fallback` 不能继续映射为 `min_moving_avg`，否则会从“第一个可用节点”变成“延迟最低节点”。
新增用户态策略 `first_alive`：

1. 新增 `consts.DialerSelectionPolicy_FirstAlive = "first_alive"`，由 config parser、
   `NewDialerSelectionPolicyFromGroupParam` 和 nested selection 共同支持。
2. flat group 按 `DialerGroup.Dialers` 声明顺序遍历；对当前 IP family 使用 health set 判断，
   找到第一个 alive 就返回，不比较延迟，不打乱顺序。
3. 若当前 family 没有可用成员，沿用现有 IPv4/IPv6 fallback；所有 family 都无成员时返回
   `ErrNoAliveDialer`。
4. nested child 的可用性通过 child group 的递归选择判断；child 失败后继续检查下一个 sibling。
5. `DIRECT`/`REJECT` 按 16.1 的保留 outbound 规则参与有序选择。
6. 节点健康状态变化只影响“当前是否可用”，不改变 Mihomo 声明顺序；reload 也不按延迟重排。

该策略只位于 `component/outbound` 用户态选择路径，不增加 kernel map 字段，也不改 routing
result。`min_moving_avg` 仍保留给原生 dae 配置，不能全局替换。

### 16.5 组级 URL、interval、lazy、tolerance

将 Mihomo group 的健康检查字段扩展到 converter 中：

| Mihomo | dae 配置/运行时 | 规则 |
| --- | --- | --- |
| `url` | `tcp_check_url` | 只接受已支持的 HTTP/HTTPS URL，按现有 parser 校验；不记录凭据 |
| `interval`（秒） | `check_interval` | 转为 duration；小于 dae 最小安全周期时拒绝或按明确下限处理并报告 |
| `tolerance`（毫秒） | `check_tolerance` | 只影响 latency policy 的切换阈值，不伪装成 fallback 顺序逻辑 |
| `lazy` | group runtime 的 lazy flag | `true` 延迟到首次实际选择，`false` 在 generation 激活时启动 |

实现要求：

1. `MihomoGroup` 保存上述字段，区分“未配置”和“显式配置 0”；未配置时继承 dae global
   默认值，不能把 Mihomo 的显式值覆盖成当前默认 `30s`/默认 URL。
2. `DialerGroup` 增加 group 级 health-check activation 状态。`ControlPlane.ActivateCheck`
   对 `lazy=true` 的组不立即启动，首次进入该组选择路径时再调用 `ActivateCheck`；并发首次
   选择只能启动一个 worker。
3. `select` 的固定选择不等于禁止健康检查：需要把“是否自动选择”和“是否运行检查”拆开，
   不能继续仅由 `DisableCheck` 推导两者。
4. flat group 可以完整承载自己的 URL、interval、lazy、tolerance。nested group 的 child
   保留自己的 health spec；parent 没有显式 health spec 时只消费 child 的可用性。
5. nested parent 的显式 health spec 为每个可递归选中的 concrete leaf 创建独立的 parent
   health view：parent 只以该 view 准入，不覆盖 child 的 option/state。parent 拒绝 child
   选中的 leaf 时，child 的非 fixed policy 先排除该 leaf 重选一次；fixed 保留用户指定意图。
   parent lazy 只延迟 parent view，不能绕过 child 的 lazy；显式 parent option 必须原样使用，
   不能静默退回 global 配置。parent 的 min-latency policy 在 parent view 已有观测时使用
   parent view latency；冷启动无 parent 观测时保留既有 child selection 作为排序回退。
6. `url-test` 使用 `url_test`（质量分 + `check_tolerance`）；只有单一 `DIRECT` 成员的 `url-test` 映射为
   `fixed(0)`，因为没有可竞速的选择空间；`fallback` 使用同名 `fallback` 策略：声明顺序、跳过 Dead，
   在后面仍有 Alive 时跳过 Degraded。旧的 `first_alive` / `min_avg10` 仍可用但不含失能语义。
7. 通过 `config.New` 后，还要检查最终 runtime 的 `CheckInterval`、`CheckTolerance`、
   check URL 和 lazy 状态，防止只验证配置文本而漏掉运行时默认值。

### 16.6 失败即拒绝发布（fail-closed）

完整 Mihomo 兼容转换必须使用 generation 模式；带 `-mihomo-config` 时禁止 routes/groups
独立输出模式，因为两个独立文件无法提供无损的发布边界。

候选 generation 的流水线固定为：

```text
读取配置/规则
  → 规则、特殊成员、节点和 group graph 归一化
  → 生成 nodes.dae、groups.dae、routes.dae、DAT/ext、metadata
  → 检查引用完整性、无空 group、无 unknown、无 cycle、无 unsupported
  → 用真实 config_parser.Parse + config.New round-trip
  → 对每个 node link 做 NewFromLink 协议解析
  → fsync 候选目录
  → 原子切换 current
```

发布门禁：

- 任何被 route 或 group 引用的 provider、rule、node、child group 无法转换时，候选失败；
- `DIRECT`/`REJECT` 未映射、组为空、节点名映射冲突、节点 link 无法解析、显式健康检查字段
  无法表达时，候选失败；
- 任何 `Unsupported`、`Approximated` 在无损模式下都是错误，不再只写 JSON warning；
- current generation 切换前，旧 generation、旧 cache 和当前运行 control-plane 保持不变；
- 写 routes、groups、nodes、DAT 或 metadata 任一失败，都删除候选目录，不留下部分新文件；
- reload 构建失败继续使用 last-good generation；不能用“能解析的半份组配置”替换旧版本。

为保留调试能力可以提供显式 `allow-approximate`，但该模式必须：

1. 只能写到单独的候选目录或测试输出路径；
2. 报告中逐项列出丢失的规则、成员和字段；
3. 不能作为生产默认，也不能覆盖 production `current`；
4. 不得改变 last-good rollback 逻辑。

### 16.7 实现顺序与阶段出口

上述六项按以下依赖实现，避免在 group runtime 尚未能识别节点时先做策略优化：

1. **成员与节点模型**：特殊 outbound reference、`MihomoProxy` typed model、NodeNameMap、
   `nodes.dae` 和 protocol/link validation。
2. **策略实现**：`first_alive`、select stable member identity、selection store 和 control
   setter。
3. **健康检查**：URL/interval/tolerance/lazy 字段、leaf group runtime 和 activation 生命周期。
4. **发布门禁**：将 nodes/groups/routes/DAT 纳入同一 generation，增加 round-trip、完整引用
   和 fail-closed gate。
5. **真实配置验收**：使用用户配置验证 8 个节点、36 个 group、nested depth、DIRECT/REJECT、
   `GGIPLC-KeepAlive` 和全部被引用规则；任何 approximate 结果都只能停留在测试候选目录。

建议拆成四个独立 commit：

```text
feat: add mihomo node and reserved outbound conversion
feat: add first-alive fallback and persistent select state
feat: preserve mihomo group health-check options
fix: fail closed before publishing incompatible mihomo generation
```

阶段完成标准不是“生成文件存在”，而是：生成的 nodes/groups/routes/DAT 属于同一 generation，
真实 `config.New` 和 node link 解析均通过，且无损模式下 `Unsupported=0`、`Approximated=0`。

## 17. Mihomo routing sections 编译设计（不包含 script）

### 17.1 范围和目标

本节记录已完成的“原始 Mihomo 配置 → manifest/DAT/routes”实现。其目标是将用户关心的
Mihomo `rules` 逐条降低为语义等价的 kdae routes；不宣称迁移 Mihomo 的全部运行时配置，
但对纳入范围的每条规则都要求条件、顺序、动作和选项保持等价。

本节纳入：

- `rule-providers`：远程/本地规则集声明、缓存来源、格式和刷新参数；
- `rules`：有序顶层规则、匹配条件、动作和规则选项；
- `sub-rules`：命名子规则、嵌套调用、条件组合和继续匹配语义；
- 这些部分对 `proxies`、`proxy-groups` 和现有节点/组 generation 的引用关系。

本节明确不实现：

- `script` 表达式求值、`SCRIPT` 规则执行和脚本快捷方式编译；
- `dns`、`tun`、`listeners`、`inbounds`、`hosts`、`proxy-providers` 等非 routing 目标配置；
- 不能由 kdae routing IR 表达的 Mihomo 私有动作。

`script` 顶层字段仍需被识别，不能因为不实现而静默删除：未被有效规则引用的 script 定义
可以记录为 ignored；仍被 `SCRIPT` 规则引用时，生产无损模式必须明确失败。

### 17.2 输入模型和中间表示

实现已新增独立 routing 文档模型来读取 `rule-providers`、`rules`、`sub-rules` 和 script
引用，不再以“`MihomoConfig` 只有 `proxies` 和 `proxy-groups`”作为转换边界；仍不把全部
Mihomo 顶层字段塞进一个无限扩大的结构体。

实现模型的语义如下：

```go
type MihomoRoutingDocument struct {
    Proxies       []MihomoProxy
    Groups        []MihomoGroup
    Providers     map[string]MihomoRuleProvider
    Rules         []MihomoRule
    SubRules      map[string][]MihomoRule
    ScriptRefs    []MihomoScriptReference
    IgnoredFields []string
}

type MihomoRuleProvider struct {
    Name, Type, URL, Path, Behavior, Format string
    Interval                               time.Duration
}

type MihomoRule struct {
    SourceIndex int
    Expr        MihomoExpr
    Action      MihomoAction
    NoResolve   bool
}
```

解析分两层：

1. 用 `yaml.Node` 读取顶层和规则数组，保留原始顺序、源行号和未识别字段；
2. 把规则字符串解析成 typed AST，再降低为 kdae routing IR。

禁止直接把 `rules` 拆成无序的 `manifest.Routes`。manifest 只能作为 provider 来源的兼容
表示；规则的顺序、条件组合和动作必须在新的 routing IR 中保留。

### 17.3 `rule-providers` 转换

#### 归一化

每个 Mihomo provider 已转换为现有 `ProviderSpec`，字段映射如下：

| Mihomo | 中间表示 | 约束 |
| --- | --- | --- |
| `type: http` | HTTP provider | URL 继续经过现有 SSRF、redirect 和响应限制 |
| `type: file` | file provider | 路径必须在允许的配置/provider 根目录内 |
| `behavior` | `domain` / `ipcidr` / `classical` | 未知行为直接失败 |
| `format` | `yaml` / `text` | 未知格式直接失败 |
| `interval` | `RefreshPolicy` | 保留原始秒数，不能静默改成全局默认 |
| `path` | cache/source path | 不把远程路径当作生成 DAT 路径 |

provider 名称必须通过现有安全标识符校验，并建立 `ProviderNameMap`。原始名称只保存在
metadata 的脱敏映射中，不拼入 dae 配置语法。

#### 使用分析

实现先扫描 `rules` 和 `sub-rules` 中的 provider 引用，再决定输出：

- 未被引用的 provider 不生成 route，可以保留快照并在报告中标记 unused；
- 被引用的 provider 必须非空、可解析且所有被使用的条目可分类；
- `classical` provider 按 domain/IP 两类拆分，只有实际被 route 表达式使用的类型才生成；
- 同一个 provider 被多个动作或多个子规则使用时共享 DAT，但每个调用点保留自己的 route
  条件和动作。

#### DAT 绑定

大于现有阈值的 domain/IP 集合生成：

```dae
domain(ext: 'generated/geosite/<provider>.dat:<provider>') -> <outbound>
dip(ext: 'generated/geoip/<provider>.dat:<provider>') -> <outbound>
```

DAT 只保存匹配数据，不能保存“匹配后走哪个 outbound”、规则顺序、`AND/OR/NOT` 条件、
进程/端口等运行时条件、规则选项或 `sub-rules` 调用。这些控制语义已经留在 routing IR 和
`routes.dae` 中；因此不能把任何不支持的非数据语义塞进 DAT 后宣称可转换。

### 17.4 `rules` 有序规则编译

#### AST

已实现的 `MihomoExpr` 覆盖以下可精确 lowering 的节点；列举不等于把未列类型视为可近似：

```text
Atom(DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX)
Atom(IP-CIDR / IP-CIDR6 / SRC-IP-CIDR)
Atom(DST-PORT / NETWORK / PROCESS-NAME)
ProviderRef(RULE-SET, provider)
All(AND, children...)
Any(OR, children...)
Not(NOT, child)
SubRuleRef(SUB-RULE, name, guard)
```

每个节点保留 `SourceIndex`，编译器只允许对同一个规则内部做等价表达式归一化，不能把
不同源行的规则排序、合并或按 provider 分组。Mihomo 的基本语义是“按声明顺序首个命中”，
生成 `routes.dae` 也必须保持这个顺序。

#### 动作和选项

已建立显式 `ActionLowerer`：

| Mihomo 动作 | 目标 | 当前策略 |
| --- | --- | --- |
| `DIRECT` | `direct` | 直接映射内置 outbound |
| `REJECT` | `block` | 映射到 kdae `block` |
| `REJECT-DROP` | `block` | 按当前兼容策略降级为 `REJECT`/`block` |
| group/node 名称 | safe outbound/group 名称 | 使用现有 NodeNameMap/GroupNameMap |
| `MATCH` | 默认目标 | 必须解析为明确 group/node，不能凭空选第一个节点 |

`b3868c1` 已确保已支持规则的选项不会在 parser/lowerer 中被静默丢弃。当前用户指定的
兼容例外是：`match-mac` 选项直接忽略但保留同一 `SRC-IP-CIDR` 条件；`IN-PORT` 条件按
分支忽略，整条只含该条件的规则不生成，避免错误变成无条件规则。`2b0b8bc` 同时允许完整
routing 入口对其它单条 lowering 失败记录源位置、原文和原因后跳过；lowerer API 未启用
`SkipUnsupported` 时仍返回错误，供需要 fail-closed 的调用方使用。

#### 条件能力边界

`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-REGEX`、`DOMAIN-WILDCARD`、IP-CIDR、
网络、端口、`PROCESS-NAME` 和 provider leaf 已按 kdae routing function registry 降低。
`DOMAIN-WILDCARD` 先小写规范化，转义字面正则字符，再将 `*` 降低为零或多个字符、`?` 降低为
一个字符，并将得到的 kdae domain regex 完整锚定；显式 classical-provider 的同类条目复用
`DomainRegex`/DAT。`IP-ASN`、`match-mac` 等不是 provider 数据，不能借 DAT 绕过 capability gate。

#### 用户配置 capability matrix

下表是当前已提交实现的边界，不是对用户完整配置可转换的声明。只有“支持”行在条件、顺序、
动作和选项均可精确保留时才允许进入 published generation。

| Mihomo 条件、选项或动作 | 当前状态 | 发布规则 |
| --- | --- | --- |
| domain（含 suffix/keyword/regex） | 支持 | 降低为等价 domain 条件；provider 大集合可经 DAT |
| IP / CIDR（含 v4/v6、源/目的 IP 路径） | 支持 | 降低为等价 IP 条件；provider 大集合可经 DAT |
| port、network | 支持 | 降低为等价运行时 routing 条件 |
| `PROCESS-NAME` | 支持 | 作为进程条件保留在 IR/routes，不进入 DAT |
| `AND` / `OR` / `NOT`、first-match 顺序 | 支持 | 保留在 ordered IR；不得按 provider 重排或合并源行 |
| `SUB-RULE` | 支持 | 有界 graph 展开，保留 guard、分支动作和顺序 |
| `RULE-SET` / provider | 支持 | 归一化后使用 inline 或 DAT binding；调用点仍保留自身条件和动作 |
| provider/DAT | 支持 | DAT 仅编码 domain/IP 数据；不编码 action、顺序、逻辑、端口、进程或 option |
| 已支持规则 option（含可精确表达的 `no-resolve`） | 支持 | `b3868c1` 保留语义；不能表达时不发布 |
| `DOMAIN-WILDCARD` | 支持 | 小写规范化后降低为 kdae domain regex：字面正则字符转义，`*` 为零或多个字符，`?` 为一个字符，整体完整锚定；显式 classical-provider 条目复用 `DomainRegex`/DAT binding |
| `IN-PORT` | 忽略 | 不映射为 `sport`/`dport`/`tproxy_port`；整条仅含该条件的规则跳过，OR 中仅移除该分支 |
| `IP-ASN` | 忽略 | 记录源位置后忽略该条件；整条仅含该条件的规则不生成，OR 中仅移除该分支 |
| `GEO*`、其它无法降低的单条条件/选项/动作 | 非阻断跳过 | 记录源位置、原文和原因后跳过该规则；不生成伪等价 route |
| `match-mac` | 忽略 | 忽略条件参数或动作选项，保留同一规则中的源 IP 条件 |
| 活动 `SCRIPT` | 不支持 | 显式错误；未使用 script 定义可仅记录 ignored |
| `REJECT-DROP` | 兼容降级 | 映射为 `REJECT`/`block` |

`忽略`、`非阻断跳过`和`兼容降级`是当前明确选择的有损兼容策略，不宣称与 Mihomo 完全
等价；特别地，DAT 是 domain/IP 数据文件而不是规则执行语言，不能承载这些非数据语义。
完整 routing 入口只对单条 rule lowering 错误非阻断；provider 读取/解析、规则引用、
代理节点/代理组结构或活动 `SCRIPT` 等候选级错误仍 fail closed，不发布结构不完整的 generation。

`IN-PORT` 的精确语义仍未实现：Mihomo 将它定义为入站监听器端口，而当前 kdae 没有对应的
入站监听器身份。按当前兼容选择不猜测映射，直接忽略该条件；这会有意丢失入口分流语义，
但不会把它错误转换成 `sport`、`dport` 或固定的 `tproxy_port`。

### 17.5 `sub-rules` 图编译

#### 图模型

实现把 `sub-rules` 解析为有向图：节点是命名子规则，边是 `SUB-RULE` 引用。加载后立即执行：

1. 重复名称检查；
2. 未定义引用检查；
3. DFS cycle detection；
4. 最大深度和最大展开节点数限制；
5. 只有被顶层 `rules` 引用的子规则才进入发布候选。

循环、深度超限、被引用的空子规则和未定义引用都直接使 generation 失败；未被引用的空
子规则只记录 unused，不影响其它有效规则。

#### 语义降低

`SUB-RULE,(guard),name` 不作为普通 provider 名称处理。编译器先把 `name` 编译成有序
`RuleProgram`，再把调用 guard 作为继承条件附加到每个可达子规则分支：

```text
parent: SUB-RULE,(A),child
child:
  B -> X
  C -> Y

lower:
  (A AND B) -> X
  (A AND C) -> Y
```

子规则内部的 `AND/OR/NOT`、provider ref 和下一层 `SUB-RULE` 递归使用同一 lowering；
子规则的动作和顺序不能被 parent 的默认动作覆盖。`MATCH` 只在当前子程序的末端表示
“该分支命中”，不能把它错误提升成全局 fallback。

为避免组合条件导致指数级膨胀：

- IR 阶段保留共享节点，只有目标 routing DSL 不支持共享时才展开；
- 展开前计算上限，超过上限直接失败；
- 只做不改变顺序的局部去重；不同动作或不同源行绝不合并。

### 17.6 `script` 边界处理

本轮不实现 script engine，也不把 Mihomo Expr 翻译成另一套表达式语言。

实现的解析器只做引用分析：

- 顶层 `script` 定义存在但没有活动 `SCRIPT` 引用：允许继续转换，报告 ignored；
- 有活动 `SCRIPT` 规则或被 `sub-rules` 间接引用：无损模式明确报错，指出源规则和 shortcut；
- 注释中的 `SCRIPT` 不参与引用分析；
- 不因为 script 定义存在而整份 routing 文档被 YAML strict parser 拒绝。

这样可以转换“带有未使用 script 定义、但实际 routing 不依赖 script”的配置，同时不把
未实现的脚本语义伪装成已实现。

### 17.7 已实现的总体流水线和发布边界

```text
原始 Mihomo YAML
  → RoutingDocument extractor
  → provider source normalization
  → rules/sub-rules AST
  → sub-rule graph validation
  → ordered routing IR
  → provider leaf 使用分析
  → inline rule 或 DAT/ext binding
  → nodes/groups/routes/DAT/metadata
  → 引用完整性和 capability gate
  → generation-atomic publish
```

metadata 至少记录：

- 输入 checksum；
- provider 原名到 safe name 的映射；
- 每条输出 route 的 source index；
- DAT path、provider、kind、checksum 和 generated/skipped 数量；
- ignored/unsupported 的源行和原因（不记录密码和 URL query token）。

候选 generation 必须同时具备 nodes、groups、routes、provider snapshots、DAT 和 metadata；
任何一项失败都保留上一代 current。不能用“provider/DAT 已生成”来掩盖 `rules` 或
`sub-rules` 尚未完整编译。该 publication boundary 已在 `910ecb3` 前后的 routing 提交中完成；
本次文档同步没有重新执行其测试或运行时验证。

### 17.8 实现步骤和提交边界

下列垂直步骤均已完成；它们按原有分步边界提交，汇总状态截至 `2b0b8bc`：`b3868c1`
补齐 rule-option fidelity，`3ff9f3f` 补齐 `DOMAIN-WILDCARD`，`2b0b8bc` 补齐非阻断
lowering diagnostics：

1. **已完成：routing document extractor**：读取 `rule-providers`、`rules`、`sub-rules`，
   保留顺序、源位置和 script 引用；输出兼容旧工具的 manifest。
2. **已完成：ordered rule IR/lowerer**：provider leaf、domain/IP/port/network/process 条件、
   动作映射和 capability gate 已实现；不再把 provider route 当作完整 `rules`。
3. **已完成：sub-rule graph compiler**：引用、循环、深度/展开上限和 guard 继承已实现，
   保持首个命中顺序。
4. **已完成：DAT binding integration**：IR 的 provider leaf 已复用 DAT writer/ext route；
   多调用点共享 DAT，但不共享动作、顺序或非数据条件。
5. **已完成：full routing generation**：extractor、nodes/groups、IR、DAT 和 generation
   metadata 已接入同一发布路径；不实现 script engine 或 script 表达式编译。
6. **已完成：rule-option fidelity**：`b3868c1` 使可精确表达的规则选项保留到 IR/routes；
   `2b0b8bc` 对完整入口中没有精确等价的单条 option/action 记录日志并跳过，lowerer 默认
   模式仍可 fail closed。
7. **已完成：wildcard capability**：`3ff9f3f` 将 `DOMAIN-WILDCARD` 以小写规范化、字面
   正则转义和完整锚定降低为 kdae domain regex，其中 `*` 表示零或多个字符、`?` 表示一个字符；
   显式 classical-provider 的同类条目复用 `DomainRegex`/DAT。

8. **已完成：non-blocking compatibility diagnostics**：`2b0b8bc` 忽略 `IP-ASN` 条件和
   `match-mac` 条件/动作选项，对其它单条 lowering 失败输出带 index/line/raw/reason 的 warning
   并继续转换；`REJECT-DROP` 仍按既定策略降级为 `block`。

仍 pending 的是活动 `SCRIPT`、候选级结构错误和其它需要真正实现才能恢复语义的能力；它们不是
通过日志跳过后就能宣称无损的功能。

### 17.9 设计出口条件

截至 `2b0b8bc`，实现状态已满足以下设计出口；代码测试和用户完整配置的真实转换均已执行：

- 原始 `rule-providers` 不再需要手工先写 manifest；
- provider 内容、规则顺序、动作、条件组合和 sub-rule 调用均有对应 IR 或明确失败诊断；
- 每条进入等价路径的 Mihomo rule 都能证明其 kdae route 在匹配条件、first-match 顺序、命中
  动作和规则选项上语义等价；不能证明等价的单条规则会记录原因并跳过，不进入发布结果；
- 大 provider 使用现有 DAT/ext，不把规则数据和控制语义混在 DAT 中；
- 未使用 script 不阻断 routing 转换，活动 script 不被静默近似；
- 单条 routing lowering 无法无损转换时有带源位置的 warning，且不阻断其它规则；
- 被引用 provider、sub-rule、group/node 不存在或不可表达时不发布半成品；
- 不修改 eBPF 数据面、outbound ID、kernel map 协议和现有透明代理路径。
