# 配置与规则获取重构设计(草案)

> 状态:设计草案,尚未实现。目标是去掉对外部二进制 `dae-rule-sync` 和 OpenWrt shell 脚本的依赖。

## 1. 现状

规则/配置的获取目前有四条互相独立的路径:

| 路径 | 位置 | 说明 |
| --- | --- | --- |
| 原生 rule-provider | `component/ruleprovider/rule_provider.go`(3.6k 行)、`cmd/run_config.go:212`、`cmd/rule_provider_lifecycle.go` | `readConfig` 时同步 `LoadAndExpand`;自带 fetch/SSRF 防护/cache/journal/last-good;`RefreshLifecycle` 到期后 `queueReload` |
| sidecar `dae-rule-sync` | `tools/dae-rule-sync/`(约 1.9 万行) | 把完整 Mihomo YAML 转成 nodes/groups/routes/DAT;自带 `fetch.go`(1046 行)和 `runner.go` 的 generation 发布(`current/` 符号链接、锁、保留 N 代) |
| shell 编排 | `openwrt/luci-app-kdae/root/usr/libexec/dae/kdae-sync.sh`、`kdae-write-local.sh` | 读 uci、写 0600 URL 文件、备份/回滚 `local.dae`、`routing.dae`、`current`、调用 `dae validate`、写 `/var/run/kdae-last-sync.json` |
| geo `.dat` | `Dockerfile`、`.github/actions/cache-geo-dat`、release workflow;运行时 `common/assets/assets.go` 在 `DAE_LOCATION_ASSET` 等目录查找 | 构建期用 wget/curl 下载,运行时只读 |

另外还有上游的节点订阅 `common/subscription/subscription.go`(第三套 fetch 栈,保持不动)。

### 主要问题

1. **两套抓取与原子发布**:`ruleprovider` 与 `dae-rule-sync/fetch.go` 各自实现 SSRF 防护、cache、last-good、原子发布,语义重复,修一处漏一处。
2. **文本回环**:sidecar 生成 `.dae` 文本 → shell 包一层 `routing { }` → `config.dae` include → 再解析。中间多出 `routing.dae`、`generated` 符号链接、DAT 相对路径约定,任何一环错位都会表现为 "validate 失败"。
3. **事务靠 shell**:回滚逻辑(`restore_publication` 等)在 shell 里,只有 `kdae-sync-rollback_test.sh` 覆盖,和 Go 侧 reload 回滚(`cmd/run_reload.go`)是两套语义。
4. **状态面是文件**:`/var/run/kdae-last-sync.json` 被 `cmd/admin_server.go:571`、LuCI `sync.js`、rpcd ACL 三处直接读,没有稳定接口。
5. **sidecar 与主程序脱钩**:同步发生在 daemon 之外,daemon 不知道规则是否过期,也无法在刷新后自己 reload。
6. **geo `.dat` 靠打包期下载**:二进制本身不可自洽,版本无法回滚,更新必须换包。

## 2. 目标架构

核心思想:**只保留 `component/ruleprovider` 这一套抓取/缓存/last-good,把 Mihomo 转换变成库,在 `readConfig` 阶段直接产出内存配置对象;原子性交给 reload manager。**

```text
订阅/规则源 (http/file)
   │  component/ruleprovider.Fetcher   ← 唯一的抓取、SSRF 防护、cache、last-good
   ▼
mihomo 转换库 (新包 component/mihomo,由 tools/dae-rule-sync 抽出)
   RoutingDocument → IR → lowerer → sub-rules → nodes / groups / routing rules
   │
   ▼
readConfig() 产出 *config.Config(含 routing、group、node)
   │
   ▼
reload manager:整体切换配置对象,失败回滚到旧对象(现有机制)
```

### 2.1 删除/收敛项

- `tools/dae-rule-sync/fetch.go`、`runner.go` 中的 generation/current/锁/保留 N 代:删除,由 ruleprovider cache + reload 回滚取代。
- shell:`kdae-sync.sh` 缩成「uci → 写一份 `[mihomo]` 配置段 → 触发 reload」;备份/回滚/validate/`routing.dae` 包装全部移除。
- `routing.dae`、`generated/` 符号链接、`current/`:移除。
- `/var/run/kdae-last-sync.json`:迁移为 admin API(`/api/.../sync-state`),LuCI 与 web-next 改读 API;admin 内部保留最近一次刷新报告(`RefreshReport` 已存在)。

### 2.2 保留/复用

- `RefreshLifecycle → queueReload`(已有)接管 Mihomo 路由源的定时刷新。
- 转换层的 IR、lowerer、subrule 编译器、name sanitize、node 解析:整体搬进库包,**测试同步搬迁**,行为不变。
- 不改 eBPF、outbound ID 编码、kernel map;provider 失败不得用空规则覆盖有效配置;不执行远端脚本。

### 2.3 配置形态(建议)

```dae
mihomo {
  routing_subscription: 'https://…'     # 或 file: 'mihomo.yaml'
  interval: 1h
  node_resolve_dns: { … }
  isolate_transport_groups: 'a,b'
}
```

由 `config` 包解析,`readConfig` 内展开为 node/group/routing。订阅 URL 属机密,`marshal.go`、`admin_config`、`sysdump` 导出时必须脱敏(替代原来的 0600 URL 文件)。

### 2.4 大 provider:是否还需要 DAT/ext

DAT/ext 当初是为绕开内联规则体积。进程内之后,先确认 `component/routing/optimizer.go` 的 `DatReaderOptimizer` 能否接受内存集合(而不是文件路径 + code)。若能,直接在内存构造 domain/ip 集合,不再落盘 DAT;若 matcher 构建仍只认文件,则保留「写 cache 目录下的 DAT」作为内部实现细节,不再暴露为配置约定。

## 3. 需要明确的取舍

- **离线首启**:无缓存且无网络时,建议 fail-closed 到「仅本地节点 + 空 Mihomo 路由」并给出明确告警,而不是拒绝启动;有缓存一律从 last-good 启动。
- **内存**:转换从「跑完即退」的 sidecar 移进常驻进程。需要在 `gcMemoryCeiling`/cgroup 限制下测大订阅的峰值内存;转换完成后释放 IR,只保留产物。
- **抓取不走代理**:保持现状(防 SSRF 被代理绕过),不要顺带让订阅走 dae 自己的 outbound。
- **与上游 `subscription {}`**:节点订阅仍走 `common/subscription`;长期可考虑复用同一个 Fetcher,但不在本次范围。
- **依赖已有设计**:本方案是 `docs/mihomo-rule-provider-execution-plan.md` §17.7 流水线的「进程内化」,管线阶段与 fail-closed 规则不变,变的是发布边界:由 "磁盘 generation" 变为 "内存配置对象 + ruleprovider cache"。

## 4. 迁移与分步

每一步独立提交、可回退:

1. **抽库**:`tools/dae-rule-sync` 的转换层搬到 `component/mihomo`,CLI 变成薄壳;测试全部随迁,行为零变化。
2. **统一抓取**:转换库改用 `ruleprovider` 的 Fetcher/cache,删除 `dae-rule-sync/fetch.go` 与重复 SSRF 代码。
3. **进程内入口**:新增 `mihomo {}` 配置段,`readConfig` 直接产出 node/group/routing;接入 `RefreshLifecycle`。
4. **状态 API**:admin 暴露 sync 状态;LuCI/web-next 改读 API。
5. **清理 OpenWrt**:`kdae-sync.sh` 缩减,删除 `kdae-rule-sync` ipk;提供一次性迁移脚本。
6. **(可选)geo `.dat` 进程内更新**,见下。

已部署实例的迁移:`config.dae` 里对 `routing.dae` / `generated/...` 的引用需要改写;升级脚本把现有 `dae.config.mihomo_config` 与 routing 订阅映射成 `mihomo {}` 段,首次启动用旧 `current/` 作为种子 cache,避免升级后断网窗口。

## 5. 已确定的决策(2026-10-09)

1. **geo `.dat`**:改为进程内获取(校验和、last-good、可回滚),不再依赖打包/CI 下载。
2. **旧 sidecar**:迁出为独立仓库 `/root/dev/dae-rule-sync`(保留 62 个提交的历史,`go.mod` 用 `replace => ../kdae`),仅作归档与离线调试,**不被 dae 依赖**。dae 内的进程内实现按新设计重写,不复用该包的代码结构。
3. **迁移**:一次性切换,不做双轨。切换前必须有完整测试;先在 220 验证,通过后再切 223。

## 6. 实施计划(转换层从零重写)

转换层不移植旧代码。旧仓库 `/root/dev/dae-rule-sync` 的作用是**行为基准(oracle)**:同一份 Mihomo YAML,旧 sidecar 生成的 `.dae` 经 `config.New` 得到的 Node/Group/Routing,必须与新实现直接产出的配置对象逐项一致(归一化后比较)。差异只允许出现在显式记录的有意变更清单里。

切片(每片独立提交,各自带测试):

1. **文档抓取层**(已完成,见下):`ruleprovider.FetchDocument`,复用现有 SSRF/cache/last-good/事务发布。
2. `mihomo {}` 配置段:`routing_subscription`/`routing_file`/`interval`/`node_resolve_dns`/`isolate_transport_groups`;URL 在 marshal/admin/sysdump 中脱敏。
3. 文档模型:带体积/深度/alias 上限的 YAML 解码,类型化的 `proxies`/`proxy-groups`/`rules`/`sub-rules`/`rule-providers`。
4. 节点转换(proxies → node link),逐协议对照基准。
5. 分组转换(select/fallback/url-test 等)。
6. 规则编译(rules、rule-providers、sub-rules 图、no-resolve、通配域名、fail-closed 能力闸门)。
7. 装配与刷新:`readConfig` 产出内存配置;接入 `RefreshLifecycle`;失败保持 last-good。
8. 对照测试:基准 fixture 集上新旧输出比对。
9. geo `.dat` 进程内获取。
10. 状态 API;OpenWrt 脚本/ipk 清理;同一提交移除 `tools/dae-rule-sync` 等旧入口。
11. 220 实机验证 → 切 223。

## 7. 进度

- [x] 旧 sidecar 迁出为独立仓库(62 个提交历史),独立 `go test ./...` 通过。
- [x] 切片 1:`component/ruleprovider/document.go`——`FetchDocument`。内部 `document` 行为不对用户配置开放;非法/超限/不可达的源回退到 last-good,无缓存则报错,从不返回未校验内容。`go test -race ./component/ruleprovider ./config` 通过。
- [x] 切片 2:`mihomo {}` 配置段(`config/mihomo.go`):`routing_subscription`/`routing_file`(互斥)/`interval`/`max_size`;订阅 URL 视为机密,错误与诊断仅使用脱敏形式。admin 配置接口只暴露 `global`/`routing` 两段,不会泄露该段。`node_resolve_dns`/`isolate_transport_groups` 待节点/分组转换切片按实际形态再加。
- [x] 切片 3:`component/mihomo/document.go`——`Parse` 把 Mihomo YAML 解成按源顺序的文档模型(proxies/groups 保留节点,rule-providers/rules/sub-rules 类型化);新增旧实现没有的防护:别名展开节点数上限(200 万)、嵌套深度上限(64);错误信息不回显字段值。
- [x] 切片 4:节点转换(`proxy.go`、`names.go`):anytls/ss(含 obfs/shadow-tls/v2ray-plugin)/socks5/hysteria2,名称清洗、重名与保留名检查,链接最终由 dae 自己的 dialer 解析器校验(注入式 `LinkValidator`)。
  - **对照基准已建立**:`hack/mihomo-oracle/gen_node_goldens.py` 用归档的旧 sidecar 对 `testdata/nodes/cases.yaml` 的 137 个单代理用例生成 `golden.json`(67 转换 / 70 拒绝);`TestProxyConversionMatchesArchivedSidecar` 要求接受/拒绝、安全名、协议、链接逐项一致。当前 137/137 一致,并用人为改坏验证过测试有效。
  - **有意偏离旧行为(2026-10-09 已决定,测试里以 `intentionalDeviations` 显式登记,过期会失败)**:
    1. 代理里出现不认识的字段(`dialer-proxy`、`tfo`、`smux` 等,含经 YAML merge key 带入的)一律拒绝,报错只含代理名与字段名。旧 sidecar 的设计注释本意即拒绝(`ParseMihomoConfigStrict`),但整份路由订阅实际走的路径漏了严格模式。顶层未知键(`mixed-port`、`dns` 等)不影响路由,只记录不拒绝。放行清单待 220 真实订阅数据再定。
    2. 撞名不再失败:内部名(`Node.Safe`)沿用原清洗结果——因为 `persist.d/group-selections/state.json` 按内部名保存 select 选择且只接受安全标识符,升级后必须仍然有效;只有撞名或清洗成保留名 `direct`/`block` 的才追加由**自身原名**哈希出的后缀,与顺序无关;展示名(`Node.Name`)始终是原名,保留 emoji/空格。单个不撞名的节点名与旧输出完全一致(金样本照常通过)。
  - 仍待办:`node_resolve_dns` 覆盖(待配置形态确定)。
- [ ] 展示名透出(新增切片):`config.Group`/节点需携带展示名,admin API(`control/admin_api.go`)与 web-next 展示 `display_name || name`,日志同理;内部标识仍用安全名。依赖切片 5(分组同样处理)。
- [x] 切片 5:分组转换(`groups.go`、`names_assign.go`、`config.DecodeGroups`):select/fallback/url-test,成员顺序、`DIRECT`/`REJECT`、嵌套(环与深度 32 上限)、健康检查选项、`x-kdae-quality`、`isolate_transport`。输出直接是 `config.Group`(经 `DecodeGroups` 应用与文本解析相同的默认值和 presence 位),不经过 `.dae` 文本。`hack/mihomo-oracle/gen_group_goldens.py` 对 68 个用例生成金样本(30 转换 / 38 拒绝),测试把金样本的 `groups.dae` 交给 dae 自己的解析器后与内存结果逐字段比较;68/68 一致,3 处人为改坏均被发现。
  - 有意偏离(`groupDeviations` 显式登记):① 分组里不认识的字段一律拒绝(`include-all`、`filter`、`interface-name`、`disable-udp` 等会改变成员或传输;仅 `hidden`、`icon` 这类纯展示字段放行);② 分组内部名撞名,或与节点内部名撞名,改为追加哈希后缀(节点优先保留原名,分组让位),展示名 `Group.Name` 仍是原名。
  - 与 Mihomo 语义一致仍保持拒绝:同名的代理与分组、`direct`/`reject`/`block` 作分组名、`load-balance`/`relay`、`use:`(proxy-providers)、空成员、重复成员、未知成员、环。
- [x] 切片 6(6a-6e 全部完成,见下):规则编译,按顾问建议拆为 6a(规则字符串→IR,仅比对接受/拒绝)、6b(原子与动作降级、跳过策略)、6c(sub-rules 图)、6d(provider)、6e(包装分组 + fallback 装配,得到 `Convert(doc)→{Nodes,Groups,Rules,Fallback,Report}`)。
  - **6d 路径已用数据确定(2026-10-09)**:转换器只输出 `config.RuleProvider` 与 `ruleset(安全名)`/`ruleset_no_resolve(安全名)`,抓取、缓存、last-good、刷新全部复用原生 `component/ruleprovider`(它已支持有序 `route_expr` 与 `ruleset` 展开)。同一批 provider 夹具分别交给旧 sidecar 和原生解析:domain/ipcidr/classical 的接受与拒绝一致(`SRC-IP-CIDR`/`PROCESS-NAME`/`GEOIP`/非法域名均拒绝)。需在原生侧补的差异:① classical 里的 `DOMAIN-WILDCARD`(旧实现降为锚定 regex,原生直接拒绝);② 域名大小写(旧实现小写化,原生保留);③ `NOT(RULE-SET)`(原生 `expandRule` 拒绝取反 `ruleset`,但有序表达式路径已支持 `Not`,需走 route_expr)。展开形态不同(旧实现把同一 provider 合并成一个多参数函数,原生每条一个规则)但语义等价,由下面的规范化比较吸收;原生展开上限 10 万条规则。DAT 不再需要:`DatReaderOptimizer` 展开结果就是普通 Param 列表。
  - **对照比较方式**:不比文本。双方的规则列表经原生 provider 展开后,交给 dae 自己的 `routing.NewNormalizedProgram(...)`(与数据面同一规范化),比较规范化后的程序。
  - **6a+6b 已完成**(`rules_parse.go`、`rules_lower.go`):规则字符串解析 + 原子/动作/逻辑表达式降级,含 `no-resolve` 有序路径(`route_expr`)、`src`/`match-mac` 选项、`DOMAIN-WILDCARD`→锚定 regex、1024 展开上限、MATCH→fallback、按用户兼容策略的跳过/忽略并产出结构化 `Event`(`skip`/`ignore`,带规则序号、行号、原文、原因)。`hack/mihomo-oracle/gen_rule_goldens.py` 生成 116 个用例的金样本(99 转换 / 17 拒绝),测试用 `canonProgram` 把双方规则列表规范化成与写法无关的 DNF 后逐条比较,并比较"哪些规则被跳过/忽略";116/116 一致,4 处人为改坏(De Morgan、忽略语义、上限 break、REJECT-DROP)均被发现。
  - **6c 已完成**(`rules_subrules.go`):sub-rules 图展开。只展开被顶层规则引用的子规则;调用的守卫条件作为继承条件 AND 进被调用子规则的每条规则,每次调用带一个共享的 memo 编号并因此走有序 `route_expr`;`MATCH` 在子规则里只表示该分支命中;嵌套 `SUB-RULE` 递归展开。整份失败的情形(`ErrSubRule*` 哨兵错误,带规则位置):未定义、循环、被引用的空子规则、深度超过 32、展开后规则总数(含普通顶层规则)超过 1024、`SUB-RULE` 嵌在 AND/OR/NOT 里、调用带动作或选项;所有子规则(含未被引用的)仍要通过语法检查,未被引用的子规则其余问题被忽略。金样本扩到 164 个用例(130 转换 / 34 拒绝),拒绝类用例还按旧实现的错误类别断言;全部一致,6 处人为改坏(丢继承守卫、深度边界、`no-resolve` 时机、上限差 1、丢 memo、关循环检测)均被发现。
  - **6c 优化:先合并、后计数(`rules_compact.go`)**。旧实现按合并前的条数套 1024 上限:子规则里一长串同出口的 `DOMAIN-SUFFIX` 会让整份转换失败,顶层长列表则静默丢掉上限之后的所有规则(含 `MATCH`)。现在对相邻规则做 dae 自己优化器也会做的、不改变匹配结果的合并,再按合并后的条数计数:① 普通规则:相邻、各自只有一个正向集合函数(domain/ip/dip/sip/dport/sport/pname/l4proto)、同函数名、同出口;② 同一次 SUB-RULE 调用里相邻、同出口的有序叶子:合并为 `守卫 AND (叶子1 OR 叶子2 …)`,守卫仍只判定一次,叶子保持原顺序,dae 规范化会再把 OR 里相邻的域名集合并成一个集合;③ OR 展开的项合并后再参与笛卡尔积,`AND(OR(25 个域名), OR(41 个域名))` 从 1025 条降为 1 条。不跨越不同出口的规则,不合并取反项(`!f(a) OR !f(b)` ≠ `!f(a,b)`),不合并 `ruleset`/`route_expr`。实测:800 行 `DOMAIN-SUFFIX` 的子规则变成 1 条规则、规范化后 1 个含 800 个值的域名集合;3000 条顶层同出口规则变成 1 条且 `MATCH` 保留。子规则展开本身的输入上限放宽为 50000(仅防恶意文档),1024 的预算只针对合并后的规则。
  - **有意偏离(`devMergeCap`)**:`expand_*`、`fatal_sub_expansion_*` 共 7 个用例,旧实现因上限整份失败或丢规则,现在保留;测试要求旧实现确实触顶(否则登记过期)、新结果没有因上限产生的 skip、`MATCH` 保留。另有差分不变量 `TestMergingDoesNotChangeWhatRulesMatch`:对全部 177 个夹具,"合并后"与"不合并且不限条数"的规范化程序必须相同。其余 170 个用例与旧实现逐一一致不变。人为改坏(忽略出口、忽略 memo、合并取反项、合并取反规则、跨有序/普通合并)均被发现。
  - **6d 已完成**(`providers.go`):规则集声明归一化 + 与原生 `component/ruleprovider` 的衔接。`NewProviderTable` 校验**所有**声明(用到与否):名称非空且为合法 UTF-8;内部名在已是合法标识符且 ≤64 时保持原名(它同时是缓存目录名),否则取 `mihomo_<原名哈希>`;类型(`http`/`file`,缺省按有无 url 推断)、行为(`domain`/`ipcidr`/`classical`,必填)、格式(`yaml`/`text`,`mrs` 等拒绝)、间隔(≤30 天)、`file` 不得带 url、`http` 必须有 url;再交给 `config.ValidateRuleProviders` 做 URL(回环/元数据地址/userinfo/协议)和路径(绝对/越界)检查。`Select(used)` 只返回被引用的规则集(按声明顺序)给原生加载器,未被引用的不抓取。`LowerRules` 现在返回 `UsedProviders`,引用未声明规则集整份失败(`UndeclaredProviderError`,与 Mihomo 拒绝加载一致)。转换器只产出 `ruleset(内部名)`/`ruleset_no_resolve(内部名)`;取反的规则集一律走 `route_expr`(原生展开器拒绝裸的 `!ruleset`,但在有序表达式里支持取反),守卫里的 `NOT(RULE-SET)` 同理。抓取、缓存、last-good、刷新全部复用原生实现,没有新写抓取代码。
  - **6d 对照**:`gen_provider_goldens.py` 对 73 个用例(49 转换、5 个带 DAT 的大规则集、24 拒绝)生成金样本,含 domain/ipcidr/classical、yaml/text、`no-resolve`、取反、守卫、子规则内引用、未声明/未使用、非法声明与非法内容、URL 与路径校验、名称。旧实现超过 256 条用 DAT,测试把金样本里的 DAT 文件写入临时目录,用 dae 自己的 `DatReaderOptimizer` 展开后再比较(含 `route_expr` 内的 `ext:`);新旧经原生展开后的规范化程序逐项一致,73/73。改坏验证:跳过 URL/路径校验、通配符转换、取反规则集不走 `route_expr`、选用全部声明而非仅被引用者,均被发现。
  - **6d 的有意偏离**:CIDR 文本放进 `domain` 行为的规则集——旧实现当作永远匹配不到的域名后缀接受,原生解析器拒绝(fail closed,不保留无效条目)。注意 Mihomo 的 `-t` 不加载规则集内容(运行时才加载,失败只记日志),所以内容类用例无法用 `-t` 对 Mihomo 复核;规则集内容仍沿用项目既定的严格取向。
  - **6e 已完成**(`convert.go`、`wrappers.go`、`resolve_dns.go`):总入口 `Convert(doc, Options) → Result{Nodes, Groups, Rules, Fallback, Providers, Report}`。流程:节点 → 分组 → 规则集声明表 → 展开子规则并统计用到的规则集与出口目标 → 为被规则直接指向的代理生成单成员包装分组(命名候选 `node_<名>`、`node_<名>_g`、`node_<3 字节哈希>`、`node_mihomo_<哈希>`,避开所有已用名;按原名排序;展示名为代理原名)→ 降级规则 → 选出用到的规则集。`Options` 带 `BaseDir`、链接校验函数、`ResolveDNS`(原代理名→DNS,规范化为 `ip:port`,默认 53,拒绝主机名与未指定地址,追加 `resolve_dns` 查询参数)、`IsolateTransportGroups`。`Report` 承载被跳过/忽略的事件、未使用的规则集、被忽略的顶层键、是否有未使用的 script。整份失败:无代理、无分组、规则全部被跳过且无 `MATCH`("没有可用规则",保留上一份有效配置而不是让流量全部直连)。
  - **6e 对照**:`gen_convert_goldens.py` 对 31 个完整配置(18 转换、13 拒绝)生成金样本——含五种协议、嵌套分组、规则集+子规则+取反守卫、超过 256 条的大规则集(旧实现 DAT)、带 emoji/中文的真实风格名称、包装分组与已有组名/节点名冲突、`resolve_dns` 覆盖(IPv4/带端口/IPv6/未知名/空值/主机名/0.0.0.0)、传输隔离、未使用的 script、各种整份失败;节点内部名与链接、分组(含包装,逐字段)、规则(经原生展开后规范化)、两张名称映射、跳过事件均与旧实现一致,31/31。改坏验证:包装命名回退、包装顺序、`resolve_dns` 默认端口、空规则保护、包装出口映射,均被发现。
  - **以真实 Mihomo 为准的交叉验证(2026-10-09,v1.19.8,`hack/mihomo-oracle/crosscheck_mihomo.py`)**:旧 sidecar 只是"过去转换器怎么做"的参照,Mihomo 才是"配置是什么意思"的参照。对全部规则夹具跑 `mihomo -t`:
    1. **`SUB-RULE`(以及 `MATCH`)嵌在 AND/OR/NOT 里,Mihomo 自己拒绝加载**(`unsupported rule type [SUB-RULE] on logic rule`)。子规则产出的是出口而不是真假条件,没有可对齐的语义,所以不支持嵌入、不发明含义;现有的明确报错与 Mihomo 一致。`SUB-RULE` 的守卫本身可以是 AND/OR/NOT(Mihomo 接受,已支持),子规则里再调用子规则(最深 32 层)也已支持。
    2. Mihomo 拒绝而 sidecar 放行的,都是 Mihomo 根本加载不了的配置(未知出口、未知规则类型、多层括号、未匹配的引号等),对现网订阅无影响;其中 v1.19.8 还不认识 `DOMAIN-WILDCARD`(较新版本才有)。
    3. **Mihomo 接受而 sidecar/新实现拒绝的**,是需要评估的真实兼容缺口:被引用的空子规则(Mihomo 视为"匹配不到任何东西"并继续)、子规则调用链超过 32 层、`SUB-RULE` 调用后面多带动作、规则末尾多余逗号或空字段。这些在真实订阅里都很少见;目前保持"拒绝并报错"(项目既定的 fail-closed 取向),待 220 上用真实订阅验证后再决定是否放宽。
  - **向 Mihomo 的真实行为对齐(2026-10-09)**:以真实 Mihomo v1.19.8 的 `-t` 与源码为准,把此前"Mihomo 接受而我们拒绝"的缺口补上。复核结果:对 204 个规则夹具(含 220 分支专有的 `match-mac`、`SRC-MAC`),**Mihomo 接受而本转换器拒绝的为 0**(`crosscheck_mihomo.py` 加 `OURS=` 可复现,Go 测试 `TestDumpAcceptance` 导出本转换器的结果)。改动均以 `mihomoAligned` 登记并要求旧 sidecar 确实不同才算有效:
    1. 规则行切分:Mihomo 只按逗号切分、没有引号语义。引号只在字段开头且有配对时才分组,否则是普通字符(进程名里的撇号 `Foo's App` 可用);空字段不再是语法错误(空值的规则被跳过并说明原因,空选项被忽略,末尾多余逗号被忽略)。
    2. `DOMAIN-REGEX`/`PROCESS-NAME-REGEX`/`PROCESS-PATH-REGEX`:取最后一个字段为出口,中间全部拼回正则,所以 `^a{1,3}\.example\.com$`、含括号和引号的正则可用(旧实现会在逗号处切断并把出口取错)。
    3. `SUB-RULE`:子规则名取最后一个字段;若它不是子规则而是出口(例如多带了一个动作),Mihomo 加载成功但该规则永远不命中,这里等价为"跳过并说明";被引用的空子规则表示什么都不匹配并继续;嵌套深度上限从 32 放宽到 256(仅防恶意文档)。
    4. 选项:上游 Mihomo 只读 `no-resolve`/`src` 且只对 IP 规则,其余选项一律忽略、规则照常生效。这里同样处理并产出 `ignore` 事件(此前是整条跳过,会让 Mihomo 里生效的规则在 kdae 里悄悄消失)。`RULE-SET` 加 `src` 仍然跳过(dae 没有源地址形式的规则集)。
    5. 新增 `DSCP`:展开 `46`、`0-10/46`、`10/20` 为 `dscp(...)`,与 Mihomo 一样读 IP 头 6 位 DSCP;`*`、超过 63、非法值仍跳过。
    6. **`match-mac` 与 `SRC-MAC`(220 上的 Mihomo 分支,`feat/dns-query-log`,提交 `c3776fbe` 等,已读源码并编出该分支二进制复核)**:`match-mac` 只对源地址规则有意义——`SRC-IP-CIDR`,或 `IP-CIDR/IP-CIDR6` 与 `src` 同用(代码为 `isSrc && HasMatchMAC`);`IP-CIDR` 不带 `src` 时被忽略、规则仍按目的地址生效;其他规则上是未知参数、被忽略。这里同样处理(忽略并记录 `ignore` 事件,规则保留)。该分支还新增规则类型 `SRC-MAC,aa:bb:..[/..]`(多个地址用 `/` 连接,大小写不敏感,地址去重),转成 dae 的 `mac(...)`;`NOT,(SRC-MAC)` 不无损(MAC 未知的流量在 Mihomo 里会命中取反,而 dae 的取反 `mac` 会排除未知 MAC),所以跳过并说明。无效 MAC 同样跳过。
    7. 原生规则集解析补上 classical 里的 `DOMAIN-WILDCARD`(转成与规则里同一份锚定正则,实现放在 `component/routing/wildcard.go` 共用),并修了一个预检误判:普通块里 `DOMAIN-WILDCARD,*.example.com` 的 `*` 紧跟逗号被当成 YAML 别名而整份规则集被拒。逗号、冒号、问号只有在 `[...]`/`{...}` 内才算分隔符。
  - 仍保持拒绝的 Mihomo 兼容点(有意):规则全部被跳过且无 `MATCH` 时整份失败("没有任何有效规则"会让全部流量悄悄直连,宁可保留上一份有效配置);这属于 6e 装配阶段。
  - **发现的旧 sidecar 缺陷(已作为有意偏离登记)**:dae 的解析器不会反转义双引号字符串里的 `\\`,而旧 sidecar 写 `routes.dae` 时把每个反斜杠写成两个,于是 dae 读回的正则带双反斜杠(`\\.` 匹配"字面反斜杠+任意字符"而非"字面点号")。**现网 220/223 上凡含 `\.` 的 `DOMAIN-REGEX` 和全部 `DOMAIN-WILDCARD` 规则实际都匹配不到任何域名。** 进程内转换不经过文本,保持原意。**根因与修复(2026-10-09)**:`config_parser.Param.String` 用 `strconv.Quote` 输出,而解析器按引号内原文读取、不做任何反转义,输出与解析不对称;`config/marshal.go` 同样。已新增 `config_parser.QuoteLiteral`(优先双引号,含 `"` 时用单引号,无法忠实表示的值——同时含两种引号、控制字符、非法 UTF-8、以反斜杠结尾——回退原 `strconv.Quote`),`Param.String` 与 `Marshal` 改用它;普通值输出与此前逐字相同,只有含反斜杠/双引号的值变化。用当前代码重建的 sidecar 实测:dae 读回的正则从 `^.*\\.example\\.org$`(双反斜杠)变为 `^.*\.example\.org$`,并有回归测试。**只需重新打包 `kdae-rule-sync`(以及 dae)即可在 220/223 上修复现网规则,不必等切换**;修复后这类规则从"不生效"变为"生效",可能改变现有流量走向,发布说明需列出。
  - 已知旧行为(保持一致,已被金样本固化):合并后的规则数仍达上限时,后续规则(包括 `MATCH`)被丢弃并记一次 skip,导致没有 fallback、回落为 `direct`(触顶条件已放宽,见上);指向不存在 outbound 的规则只记日志并跳过;规则全部被跳过且无 `MATCH` 时,旧实现整份失败("produced no routes"),此判断归 6e 装配阶段。
  - **旧 sidecar 的跳过/忽略语义**(必须原样保留,属用户指定的兼容策略,不与"未知字段拒绝"混淆):被忽略的条件等价于恒假——`AND` 里含 `IN-PORT`/`IP-ASN` 则整条丢弃,`OR` 里只去掉该分支;`GEO*` 等无法降级的单条规则跳过;指向不存在 outbound 的规则被跳过(只记日志);`match-mac` 忽略,`REJECT-DROP`→`block`;活动 `SCRIPT`、未声明的 RULE-SET、缺少条件的规则整份失败。旧实现只在 stderr 日志里记录跳过/忽略,stdout 报告里 `Skipped` 恒为 0,所以金样本要抓取 stderr 事件,新实现用结构化 `Report` 承载。
- [ ] kdae 中旧入口(`tools/dae-rule-sync`、`Makefile` 目标、`openwrt/kdae-rule-sync`、`build-ipk.sh`)暂不删除,切换 223 时同一提交移除。
