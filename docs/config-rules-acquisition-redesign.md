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
- [ ] 切片 2 起。
- [ ] kdae 中旧入口(`tools/dae-rule-sync`、`Makefile` 目标、`openwrt/kdae-rule-sync`、`build-ipk.sh`)暂不删除,切换 223 时同一提交移除。
