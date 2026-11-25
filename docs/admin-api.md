# fdae Admin API v1 接口对接文档

`fdae` 默认不打包、不内置前端二进制静态资源，核心控制面通过 `/api/v1/*` 与 `/api/v1/ws` 暴露。同时支持通过 `admin_web_dir` 按需挂载外部静态前端构建产物目录，使桌面面板、独立静态构建或 OpenWrt 本地面板均可统一接入。

---

## 目录

- [1. 服务端配置与传输安全](#1-服务端配置与传输安全)
- [2. 统一错误信封与错误码](#2-统一错误信封与错误码)
- [3. 全量接口速查目录](#3-全量接口速查目录)
- [4. 核心公共数据结构](#4-核心公共数据结构)
- [5. REST API 详细规范](#5-rest-api-详细规范)
  - [5.1 系统与控制](#51-系统与控制)
  - [5.2 运行时指标与历史趋势](#52-运行时指标与历史趋势)
  - [5.3 代理分组与节点管理](#53-代理分组与节点管理)
  - [5.4 活跃连接与连接打断](#54-活跃连接与连接打断)
  - [5.5 已关闭连接与多维度流量统计](#55-已关闭连接与多维度流量统计)
  - [5.6 入站（SOCKS5 Inbounds）管理](#56-入站socks5-inbounds管理)
  - [5.7 配置管理与生效配置](#57-配置管理与生效配置)
  - [5.8 外部数据源与刷新](#58-外部数据源与刷新)
  - [5.9 结构化日志](#59-结构化日志)
  - [5.10 高级诊断与观测接口](#510-高级诊断与观测接口)
- [6. 多路复用 WebSocket（`/api/v1/ws`）](#6-多路复用-websocketapiv1ws)
- [7. 独立前端对接指南与示例](#7-独立前端对接指南与示例)

---

## 1. 服务端配置与传输安全

### 1.1 `config.dae` 相关配置

`dae` 多值列表使用逗号分隔标量语法（不带方括号 `[]`）：

```dae
global {
    admin_listen: '192.168.1.1:2025'
    admin_secret: 'replace-with-strong-secret'
    admin_web_dir: '/usr/share/fdae/web'
    admin_cors_origins: 'https://panel.example.com', 'http://localhost:5173'
}
```

| 配置项 | 必填 | 校验规则与行为说明 |
| --- | --- | --- |
| `admin_listen` | 否 | 留空禁用管理接口。非空时（`host:port`）在配置校验/解析阶段通过 `config.ResolveAndValidateAdminListen` 解析所有 IP，必须全部为 Loopback（`127.0.0.0/8`、`::1`）、私有地址（RFC1918 / RFC4193 `fc00::/7`）或链路本地（`169.254.0.0/16`、`fe80::/10`）地址，禁止监听 `0.0.0.0`、`[::]` 或公网 IP，且明确拒绝端口 `9090`（`ClashCompatibleAdminPort`，防止误将 Clash 面板指向 kdae）。 |
| `admin_secret` | 当启用 `admin_listen` 时必填 | 空字符串会阻止 Admin HTTP 启动。使用 `crypto/subtle.ConstantTimeCompare` 常量时间校验。 |
| `admin_web_dir` | 否 | 宿主机静态 Web 面板目录的绝对路径（例如 `/usr/share/fdae/web`）。留空禁用静态托管；严格拒绝相对路径、`..` 路径穿越以及系统根目录（`/`、`/etc`、`/etc/dae`、`/proc`、`/sys`、`/dev` 等）。启用后：`adminHTTP` 在 `/web/`（以及兼容 Vite `base: '/'` 根引用资源的 `/assets/*` 等直接文件）下以 `os.OpenRoot` 沙箱只读托管静态文件与 SPA 路由回退，禁止目录浏览及隐藏文件（`.` 开头），并自动放行来自当前 `admin_listen` 同源页面的 API 与 `/api/v1/ws` 请求。为防止令牌泄露后被远程改写指向宿主机任意目录，`PUT /api/v1/config` **禁止修改或新增** `admin_web_dir`（仅可由管理员在宿主机本地修改）。 |
| `admin_cors_origins` | 否 | 精确 `Origin` 白名单（格式 `scheme://host[:port]`）。仅支持 `http`、`https`、`tauri`、`app` 协议；自动小写化 scheme/host 并去除默认端口（`http:80` / `https:443`）；**严格拒绝**通配符 `*`、路径（含结尾 `/`）、Query、Fragment、空白字符以及用户信息 `user:pass@`。**留空时拒绝所有跨源请求（返回 `403 origin_forbidden`）；若配置了 `admin_web_dir`，则额外放行严格匹配当前监听协议与 `Host` 的同源页面请求。** |

> OpenWrt LuCI 可另外在 `/etc/config/dae` 配置 `panel_url`（可选，用于在 LuCI 顶部显示“打开面板”外链按钮），该字段仅由 LuCI 前端界面使用，不影响 `fdae` 运行。

### 1.2 认证方式

- **HTTP REST**：必须在请求头携带 `Authorization: Bearer <admin_secret>`。不支持 URL Query 传 Token（例如 `?token=...`）和旧版 `X-Kdae-Authorization` 请求头。
- **WebSocket（`/api/v1/ws`）**：禁止在 URL 参数传密钥。建连后 **3 秒内** 发送首帧 JSON `{"type":"auth","token":"<admin_secret>"}` 完成鉴权。
- **已废弃路由**：所有旧 `/v1/*` 与内置 UI `/fdae-ui/*` 路由均已移除（在通过鉴权后返回 `404 not_found`）。

### 1.3 认证失败限流（Rate Limit）

- 基于源客户端 IP（`RemoteAddr` 归一化 IP，IPv4-mapped IPv6 会解包为 IPv4）维护滑动窗口。
- **阈值**：每 IP `60s` 窗口内最多允许 **20 次** 认证失败，最多追踪 `256` 个源 IP（超上限淘汰窗口最旧条目）。
- **正常请求无锁开销**：当前没有任何失败记录时快速路径直接放行。
- **超限行为**：
  - HTTP 返回 `429 Too Many Requests`，响应头带 `Retry-After: <秒>`，JSON `error.code = "rate_limited"`。
  - WebSocket 在升级握手前检查限流，超限直接返回 HTTP `429 Too Many Requests`（带 `Retry-After: <秒>`，JSON `error.code = "rate_limited"`）；若在并发竞争下已升级后触发限流，则发送 `{"type":"auth_error","code":"rate_limited","message":"..."}` 并发送 Close Frame `4001`。
  - 鉴权超时（`auth_timeout`）或首帧格式非法（`invalid_auth_frame`）同样计入来源 IP 的认证失败次数。
- **清零**：同一 IP 任一请求认证通过后立即清除其失败计数。

### 1.4 安全响应头、CORS 与 Chrome PNA

服务端在每条响应中固定下发：

- `Cache-Control: no-store`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Vary: Origin`

对 `OPTIONS` 预检额外附带：

- `Vary: Access-Control-Request-Private-Network`
- `Vary: Access-Control-Request-Method`

当请求携带合法白名单内的 `Origin` 时：

- `Access-Control-Allow-Origin: <origin>`
- `Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Authorization, Content-Type, If-Match`
- `Access-Control-Expose-Headers: ETag`
- `Access-Control-Max-Age: 600`
- 若请求头含 `Access-Control-Request-Private-Network: true`，则额外返回 `Access-Control-Allow-Private-Network: true`（支持 Chrome/Chromium 私有网络访问 PNA 预检）。
- `OPTIONS` 预检直接返回 `204 No Content`；`Origin` 不在白名单时立即在 CORS 层返回 `403 Forbidden`（不暴露 `Access-Control-Allow-Origin`）。

> **浏览器 HTTPS 混合内容 / PNA 说明**：若独立前端托管在公网 HTTPS（如 Cloudflare Pages / Vercel），浏览器从 `https://...` 直接请求 `http://192.168.x.x:2025` 通常会被混合内容策略拦截。建议：
> 1. 在路由器侧使用 Caddy / Nginx 为 `https://router.lan` 终结 TLS 并反代到 `http://127.0.0.1:2025`（同时转发 `Host`、`Upgrade`、`Connection` 以支持 `/api/v1/ws`）；或
> 2. 通过 SSH 隧道在本地 `127.0.0.1:2025` 接入，或部署在同一局域网 HTTP / HTTPS 域名下。

### 1.5 超时与请求体限制

| 参数 | 数值 | 说明 |
| --- | --- | --- |
| HTTP `ReadTimeout` | `10s` | 服务端读取请求超时 |
| HTTP `WriteTimeout` | `30s` | 服务端写出响应超时（`POST /api/v1/sources/refresh` 单独放宽为 `180s` / `3m`） |
| 常规 JSON 请求体上限 | `16 KiB` (`16384` bytes) | 适用于 `log-level`、`selection`、`connections/close`、`connections/kernel`（`DELETE`） |
| `PUT /api/v1/inbounds` 上限 | `64 KiB` (`65536` bytes) | 入站配置 JSON 上限 |
| `PUT /api/v1/config` 上限 | `2 MiB` (`2097152` bytes) | 配置文本 JSON 上限 |
| WebSocket 单帧读取上限 | `16 KiB` (`16384` bytes) | 超出将断开连接 |

### 1.6 外部静态 Web 面板托管（`admin_web_dir`）

- 当 `admin_web_dir` 配置为有效宿主机目录（例如 `/usr/share/fdae/web`）时，访问 `http://<admin_listen>/` 或 `/web` 会 `302` 重定向至 `/web/`，服务端通过 `os.OpenRoot` 沙箱只读输出该目录下的静态资源：
  - `/web/` 与无扩展名路径（例如 `/web/groups`）在文件不存在时回退至 `index.html`（支持前端 SPA History 路由）；
  - 静态资源响应带扩展名路径若不存在直接返回 `404`；所有 `.html` 下发 `Cache-Control: no-store`，JS/CSS/字体等资产下发 `Cache-Control: no-cache`（支持 `304 Not Modified`）；
  - 根路径 `/assets/*`、`/favicon.ico` 等带路径请求也会按非 SPA 模式匹配 `admin_web_dir`（便于 Vite 默认 `base: '/'` 构建直接开箱可用），但任何 `/api/*` 路由始终强制要求 Bearer 鉴权且绝不会回退到 HTML；
  - 禁用目录列表、拒绝路径穿越（`..`）、拒绝所有以 `.` 开头的隐藏文件/目录（`.env`、`.git` 等）以及跳出目录的符号链接；
  - 从 `/web/` 发起的同源 API / `/api/v1/ws` 请求自动被 CORS 与 Origin 校验放行，无需额外配置 `admin_cors_origins`；若需公网/局域网域名 HTTPS 访问，仍建议前置 Caddy/Nginx 反代至 `http://127.0.0.1:2025`。

---

## 2. 统一错误信封与错误码

除少数说明外，所有失败响应均返回 JSON（`Content-Type: application/json; charset=utf-8`）：

```json
{
  "error": {
    "code": "unauthorized",
    "message": "invalid or missing bearer token"
  }
}
```

### 常见 HTTP 状态码与 `error.code` 对照

| HTTP 状态 | `error.code` | 触发场景 |
| --- | --- | --- |
| `400` | `invalid_json` | 请求体 JSON 解析失败或超出体积上限 |
| `400` | `invalid_param` | Query 参数非法（`window`、`points`、`limit`、`top`、`after_seq`、`after`、`offloaded`、`process`、`src`、`mac`） |
| `400` | `invalid_log_level` | `level` 不是 `error`/`warn`/`warning`/`info`/`debug`/`trace` |
| `400` | `invalid_group` | `/api/v1/groups/{name}/{action}` 路径或分组名不合法 |
| `400` | `invalid_member` | `selection` 请求中 `member` 为空 |
| `400` | `selection_failed` | 切换分组成员失败（分组不支持 fixed、成员不存在等） |
| `400` | `probe_failed` | 触发分组测速失败（分组不存在或无可用测速目标） |
| `400` | `invalid_id` | `DELETE /api/v1/connections/{id}` 路径中的 ID 无法解码或为空 |
| `400` | `filter_required` | `POST /api/v1/connections/close` 未指定任何过滤条件且 `all != true` |
| `400` | `invalid_tuple` | `DELETE /api/v1/connections/kernel` 五元组参数不合法（协议非 tcp/udp、IP 非法、族不一致、端口为 0） |
| `400` | `inbounds_invalid` | `PUT /api/v1/inbounds` 入站定义或全局配置校验失败（已自动回滚） |
| `400` | `config_invalid` | `PUT /api/v1/config` 或 `POST /api/v1/system/reload` 配置语法/安全校验失败（已自动回滚） |
| `401` | `unauthorized` | 缺失或错误的 `Authorization: Bearer` 令牌 |
| `403` | `origin_forbidden` | 请求头 `Origin` 不在 `admin_cors_origins` 白名单内（含白名单为空时） |
| `404` | `not_found` | 路由不存在、分组动作非 `selection`/`probe`、或指定连接 ID 已关闭/不存在 |
| `405` | `method_not_allowed` | HTTP 方法与当前接口不匹配 |
| `409` | `reload_busy` | `PUT /api/v1/config` 或 `PUT /api/v1/inbounds` 时重载队列已满或不可用（已回滚） |
| `409` | `refresh_in_progress` | `POST /api/v1/sources/refresh` 已有刷新任务在执行 |
| `409` | *（无 error 信封）* | `POST /api/v1/system/reload` 当重载队列繁忙时直接返回 `409` + `{"queued": false}` |
| `412` | `precondition_failed` | `PUT /api/v1/config` 或 `PUT /api/v1/inbounds` 携带的 `If-Match` 与当前配置 `ETag` 不一致 |
| `429` | `rate_limited` | 认证失败次数超限，附带 `Retry-After` 秒数响应头 |
| `429` | `probe_cooldown` | `POST /api/v1/groups/{name}/probe` 或 `POST /api/v1/groups/probe` 处于 3 秒冷却期内（`Retry-After: 3`），或 `POST /api/v1/groups/{name}/members/{member}/probe` 处于 2 秒冷却期内（`Retry-After: 2`） |
| `500` | `config_read_failed` / `inbounds_read_failed` / `refresh_failed` | 磁盘读写异常或数据源刷新内部错误 |
| `503` | `plane_unavailable` / `logger_unavailable` / `config_unavailable` / `reload_unavailable` / `suspend_unavailable` / `refresh_unavailable` / `capture_unavailable` / `recovery_unavailable` / `evidence_unavailable` / `shutting_down` / `too_many_clients` | 控制面尚未就绪、功能未启用、正在停机或 WS 客户端达到 16 上限 |

> 错误信息会经过 `sanitizeAdminError`，移除含 `://` 的敏感连接串或还原默认提示。

---

## 3. 全量接口速查目录

### 3.1 REST 接口（34 个操作）

| 分类 | Method | Path | 说明 | 关键特性 / 缓存 / 副作用 |
| --- | --- | --- | --- | --- |
| 系统 | `GET` | `/api/v1/system` | 系统元信息、配置同步/重载与 `suspended` 状态 | 慢变化元数据 |
| 系统 | `PUT` | `/api/v1/system/log-level` | 动态调整运行时日志级别 | 不重载数据面；推 `log_level_changed` |
| 系统 | `POST` | `/api/v1/system/reload` | 校验并异步触发配置热重载（也可从 suspend 恢复） | `202` 入队 / `409` 队列忙 |
| 系统 | `POST` | `/api/v1/system/suspend` | 异步将运行面挂起为无负载状态（支持 `{"abort": bool}`） | `202` 入队 / `409` 队列忙；推 `system_suspended` |
| 指标 | `GET` | `/api/v1/metrics` | 实时运行指标、内存/FD、DNS/FakeIP、BPF 计数 | O(1) 无 STW；`/proc` 2s 缓存 |
| 指标 | `GET` | `/api/v1/metrics/history` | 历史上下行速率时间序列 | 最长 3600s、最多 720 点 |
| 代理组 | `GET` | `/api/v1/groups` | 全部代理分组、成员、多槽位健康/质量分/负载与展示名 | 无节点明文 URI/密码 |
| 代理组 | `PUT` | `/api/v1/groups/{name}/selection` | 切换 fixed 分组选中成员（支持 `close_existing`） | 不重载数据面；推 `group_selection_changed` |
| 代理组 | `POST` | `/api/v1/groups/{name}/probe` | 触发指定分组异步延迟探测 | 同组 `3s` 冷却（429）；推 `group_probe_triggered` |
| 代理组 | `POST` | `/api/v1/groups/probe` | 触发全部用户分组异步延迟探测 | 全局 `3s` 冷却（429）；返回 `202` |
| 代理组 | `POST` | `/api/v1/groups/{name}/members/{member}/probe` | 触发组内单个节点或子分组异步延迟探测 | 单成员 `2s` 冷却（429）；返回 `202` |
| 代理组 | `GET` | `/api/v1/groups/{name}/sticky` | 查询按站点粘滞（Site-Sticky）Pin 表 | 支持 `network`/`q`/`limit` |
| 代理组 | `DELETE` | `/api/v1/groups/{name}/sticky` | 清空分组站点粘滞表（支持 `?network=tcp\|udp`） | 推 `group_sticky_changed` |
| 代理组 | `DELETE` | `/api/v1/groups/{name}/sticky/{site}` | 解除单个站点的节点粘滞绑定 | 推 `group_sticky_changed` |
| 连接 | `GET` | `/api/v1/connections` | 查询活跃用户态连接（支持筛选与排序） | 500ms 快照合并 + 单连接实时网速 |
| 连接 | `DELETE` | `/api/v1/connections/{id}` | 打断并关闭单条活跃用户态连接（含 Sockmap offload） | `close_reason="aborted"`；推 `connections_closed` |
| 连接 | `POST` | `/api/v1/connections/close` | 按条件（或全量）批量打断用户态连接 | 需 filter 或 `all:true` |
| 内核连接 | `GET` | `/api/v1/connections/kernel` | 查询内核直通（conntrack）连接 | >=2s 读缓存与 CPU 退避；不自动逆向查域名 |
| 内核连接 | `DELETE` | `/api/v1/connections/kernel` | 尽力终止指定 5 元组（用户态 + conntrack + BPF） | 返回分层执行结果与 honest warning |
| 流量 | `GET` | `/api/v1/flows/closed` | 查询近期已关闭连接环形日志 | 容量 2048，倒序，支持连接过滤器 |
| 流量 | `GET` | `/api/v1/traffic/summary` | 8 维度累计流量汇总（叠加活跃流实时字节） | 支持 `top`（默认 50，上限 200） |
| 流量 | `POST` | `/api/v1/traffic/reset` | 重置多维度流量统计累计并重设活跃流基线 | 推 `traffic_reset` |
| 入站 | `GET` | `/api/v1/inbounds` | 获取入站定义与运行状态 | stat 缓存 + 返回 `ETag`（无明文密码） |
| 入站 | `PUT` | `/api/v1/inbounds` | 更新 `config.dae` 的 `inbound` 段并重载 | 支持 `If-Match`；失败自动回滚 |
| 配置 | `GET` | `/api/v1/config` | 读取 `global`/`routing` 及 `routing.dae` 文本 | stat 缓存 + `ETag` + `admin_secret`/节点脱敏 |
| 配置 | `PUT` | `/api/v1/config` | 原子更新配置与/或路由并触发热重载 | 支持 `If-Match`；失败自动回滚 |
| 配置 | `GET` | `/api/v1/config/effective` | 只读查看合并 Mihomo 后的完整生效配置 | `?format=text` 返回纯文本 |
| 数据源 | `GET` | `/api/v1/sources` | 查询 Mihomo、GeoData、RuleProvider 同步状态 | 只读状态 |
| 数据源 | `POST` | `/api/v1/sources/refresh` | 立即拉取更新所有远端数据源并在变更时重载 | 互斥锁防并发（`409`）；推 `sources_refreshed` |
| 日志 | `GET` | `/api/v1/logs` | 读取内存结构化日志环形缓冲区 | 容量 1024；支持 `level` 与 `after_seq` 游标 |
| 诊断 | `GET` | `/api/v1/debug/quality` | 节点质量调度与站点恢复诊断状态 | 上限 256 条，支持 `group`、`host` |
| 诊断 | `GET` | `/api/v1/debug/capture` | 被动观测抓包摘要环形记录 | 支持增量游标 `after` |
| 诊断 | `GET` | `/api/v1/debug/evidence` | 观测证据链（含 DNS/错误分类）记录 | 支持增量游标 `after` |
| 诊断 | `GET` | `/api/v1/debug/udp-recovery` | UDP 回复中断观测与恢复状态机快照 | 支持 `after` 与 `process` 过滤 |

### 3.2 WebSocket 接口（1 个复用通道）

| 协议 | Path | 说明 | 关键特性 |
| --- | --- | --- | --- |
| `WS` | `/api/v1/ws` | 多路复用实时推送通道 | 首帧 3s 鉴权；主题：`metrics` / `connections` / `groups` / `logs` / `flows` / `events`；无订阅零采样开销 |

---

## 4. 核心公共数据结构

### 4.1 `RoutingRuleMeta`（规则归因信息）

```json
{
  "index": 12,
  "raw": "domain(suffix: example.com) -> proxy",
  "origin": "config",
  "match_index": 15
}
```

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `index` | `int` | 是 | 来源规则序号（1-based；fallback 规则为 `0`） |
| `raw` | `string` | 是 | 规范化规则摘要（已脱敏、限长，包含 `-> outbound`） |
| `origin` | `string` | 否 | 规则来源：`"config"` \| `"rule_provider"` \| `"fallback"` \| `"auto"` |
| `match_index` | `uint16` | 否 | 编译器分配的匹配集下标，预留给未来方案 B 内核 eBPF 直出；未匹配/兼容场景省略 |

### 4.2 `AdminConnection`（单条活跃连接）

ID 带有显式类型命名空间，前端可直接按前缀区分：
- `"tcp:<uint64>"`：用户态透明代理或入站 TCP 流
- `"udp:<uint64>"`：用户态透明代理 UDP 会话
- `"in-udp:<uint64>"`：SOCKS5 等用户态入站创建的 UDP 关联会话

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `string` | 是 | 唯一连接 ID（如 `"tcp:42"`、`"udp:7"`、`"in-udp:3"`） |
| `network` | `string` | 是 | 协议族，如 `"tcp4"`、`"tcp6"`、`"udp4"`、`"udp6"` |
| `inbound` | `string` | 否 | 入站名称（仅 SOCKS5 等入站流量有值，透明代理省略） |
| `src_ip` | `string` | 是 | 源 IP（已去掉 IPv4-mapped IPv6 前缀） |
| `src_port` | `uint16` | 是 | 源端口 |
| `dst_ip` | `string` | 是 | 目标 IP |
| `dst_port` | `uint16` | 是 | 目标端口 |
| `target` | `string` | 否 | 格式化拨号目标（如 `"api.example.com:443"`） |
| `domain` | `string` | 否 | 归因域名（优先 `sniffed_domain`，其次域名形式的 `target` 去端口） |
| `sniffed_domain` | `string` | 否 | 协议嗅探得到的域名（如有） |
| `sticky_site` | `string` | 否 | 按站点粘滞选路时使用的站点键（如 eTLD+1） |
| `mac` | `string` | 否 | 客户端 MAC 地址（如 `"3e:0a:a5:de:ae:a3"`） |
| `process` | `string` | 否 | 客户端进程名（若已采集） |
| `rule` | `RoutingRuleMeta \| null` | 否 | 命中的路由规则元信息；部分直连/未归因连接可能省略 |
| `outbound` | `string` | 是 | 最终出站分组名或 `"direct"` / `"block"` / `"must_rules"` |
| `dialer` | `string` | 否 | 实际选中的节点 / 拨号器名 |
| `chain` | `string[]` | 否 | 选路链路序列（如 `["proxy", "auto-hk", "hk-01"]`） |
| `policy` | `string` | 否 | 出站选路策略或选路路径描述 |
| `offloaded` | `bool` | 否 | TCP Sockmap 内核卸载加速标志；为 `true` 时保留 `offloaded: true` |
| `start_time` | `string` | 否 | 连接建立时间（RFC3339 UTC，如 `"2026-11-19T02:00:00Z"`） |
| `duration_ms` | `int64` | 是 | 连接已持续时长（毫秒） |
| `upload` | `uint64` | 是 | 累计上行字节数 |
| `download` | `uint64` | 是 | 累计下行字节数 |
| `upload_rate` | `uint64` | 是 | 实时上行速率（bytes/s） |
| `download_rate` | `uint64` | 是 | 实时下行速率（bytes/s） |

### 4.3 `AdminConnectionFilter`（连接过滤条件）

该对象同时用于 `GET /api/v1/connections` 查询参数、`GET /api/v1/flows/closed` 查询参数、`POST /api/v1/connections/close` 请求体以及 WS `connections` / `flows` 主题订阅参数：

| 字段 (JSON / Query) | 类型 | 匹配语义 |
| --- | --- | --- |
| `network` | `string` | 小写精确匹配；传入 `"tcp"` 或 `"udp"` 时可前缀匹配 `"tcp4"`/`"tcp6"`/`"udp4"`/`"udp6"` |
| `outbound` | `string` | 出站名忽略大小写精确匹配 |
| `dialer` | `string` | 节点名忽略大小写精确匹配 |
| `src_ip` | `string` | 支持 **CIDR**（如 `"192.168.1.0/24"`）、**精确 IP** 或 **不区分大小写子串**；在 HTTP Query 中亦兼容别名 `src` |
| `dst_ip` | `string` | 支持 CIDR、精确 IP 或不区分大小写子串 |
| `domain` | `string` | 域名小写子串包含匹配 |
| `mac` | `string` | MAC 小写子串包含匹配 |
| `process` | `string` | 进程名忽略大小写精确匹配 |
| `inbound` | `string` | 入站名忽略大小写精确匹配 |
| `rule` | `string` | 精确匹配 `rule.index` 十进制数字，或对 `rule.raw` 做不区分大小写子串匹配 |
| `offloaded` | `bool` | 按 TCP Sockmap 内核卸载标志过滤（`true` \| `false`） |
| `close_reason` | `string` | 按已关闭流的 `close_reason` 过滤（`normal` \| `aborted` \| `reload` \| `shutdown`） |
| `q` | `string` | 通用搜索关键词（不区分大小写子串匹配以下 10 个字段之一：`domain`, `target`, `src_ip`, `dst_ip`, `process`, `outbound`, `dialer`, `mac`, `inbound`, `rule.raw`） |
| `all` | `bool` | 仅用于 `POST /api/v1/connections/close`：设为 `true` 时关闭全部活跃用户态连接 |

### 4.4 `AdminClosedFlow`（单条已关闭连接）

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `seq` | `uint64` | 是 | 单调递增序号 |
| `id` | `string` | 是 | 连接 ID |
| `network` | `string` | 是 | 协议族 |
| `inbound` | `string` | 否 | 入站名 |
| `src_ip` | `string` | 是 | 源 IP |
| `src_port` | `uint16` | 是 | 源端口 |
| `dst_ip` | `string` | 是 | 目标 IP |
| `dst_port` | `uint16` | 是 | 目标端口 |
| `target` | `string` | 否 | 拨号目标 |
| `domain` | `string` | 否 | 归因域名 |
| `mac` | `string` | 否 | 客户端 MAC |
| `process` | `string` | 否 | 进程名 |
| `rule` | `RoutingRuleMeta \| null` | 否 | 命中的规则元信息 |
| `outbound` | `string` | 是 | 最终出站 |
| `dialer` | `string` | 否 | 使用的节点名 |
| `policy` | `string` | 否 | 选路策略 |
| `offloaded` | `bool` | 否 | 结束前是否处于 offload 状态 |
| `start_time` | `string` | 否 | 开始时间（RFC3339 UTC） |
| `end_time` | `string` | 是 | 结束时间（RFC3339 UTC） |
| `duration_ms` | `int64` | 是 | 持续毫秒数 |
| `upload` | `uint64` | 是 | 最终上行总字节 |
| `download` | `uint64` | 是 | 最终下行总字节 |
| `close_reason` | `string` | 是 | 关闭原因：`"normal"` \| `"aborted"` \| `"reload"` \| `"shutdown"` |

### 4.5 `AdminTrafficBucket`（单维度流量桶）

```json
{
  "key": "proxy",
  "upload": 1048576,
  "download": 20971520,
  "connections": 148
}
```

- 空值键默认归入 `"(none)"`；其中 `by_domain` 空域名归入 `"(ip-only)"`，`by_rule` 无归因规则归入 `"(unattributed)"`。
- 超过该维度基数上限的尾部键会折叠合并到 `"other"`。
- 返回列表按总流量 `upload + download` 降序排列。

### 4.6 `AdminLogEntry`（单条结构化日志）

```json
{
  "seq": 88,
  "time": "2026-11-19T05:10:12.123456Z",
  "level": "info",
  "message": "192.168.124.220:34720 <-> chatgpt.com:443",
  "fields": {
    "dialer": "hk-node-01",
    "outbound": "proxy"
  }
}
```

- `message` 最长 `2048` 字节（超出截断 `...`），且自动脱敏所有 `scheme://...` 链接为 `[redacted-uri]`。
- `fields` 自动过滤包含 `password`/`passwd`/`secret`/`token`/`authorization`/`cookie`/`private_key`/`auth`/`link`/`key` 的敏感键，按 key 排序最多保留 `16` 个字段，单字段字符串最长 `512` 字节。

---

## 5. REST API 详细规范

所有接口基础路径为 `http://<admin_listen>`，除特别说明外均返回 `200 OK` 与 `application/json; charset=utf-8`。

### 5.1 系统与控制

#### `GET /api/v1/system`

获取运行环境元数据、配置生成代次、热重载与回滚状态。

**响应示例**：

```json
{
  "version": "unstable-20261119.r1415.77f13c54",
  "running": true,
  "hostname": "router",
  "go_version": "go1.27.2",
  "os": "linux",
  "arch": "amd64",
  "num_cpu": 4,
  "started_at": "2026-11-19T03:00:00Z",
  "uptime_sec": 7820,
  "dial_mode": "domain",
  "lan_interface": ["br-lan"],
  "wan_interface": ["pppoe-wan"],
  "ebpf_enabled": true,
  "log_level": "info",
  "inbounds_count": 1,
  "groups_count": 3,
  "policy_epoch": 5,
  "policy_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "generation": "20261119T030002Z",
  "sync_warning": "",
  "config_in_sync": true,
  "reload_pending": false,
  "last_reload_error": "",
  "last_reload_rolled_back": false
}
```

**字段说明**：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `version` | `string` | 是 | 编译版本号 |
| `running` | `bool` | 是 | 控制面是否运行中 |
| `hostname` | `string` | 否 | 宿主机主机名 |
| `go_version` | `string` | 是 | Go 运行时版本 |
| `os` / `arch` / `num_cpu` | `string` / `string` / `int` | 是 | 操作系统、架构、逻辑核数 |
| `started_at` | `string` | 是 | 进程启动时间（RFC3339 UTC） |
| `uptime_sec` | `int64` | 是 | 运行时长（秒） |
| `dial_mode` | `string` | 否 | 当前 `dial_mode`（`ip` / `domain` / `domain+` / `domain++`） |
| `lan_interface` / `wan_interface` | `string[]` | 是 | 绑定的 LAN / WAN 网卡列表（空时为 `[]`） |
| `ebpf_enabled` | `bool` | 是 | eBPF 对象是否已挂载 |
| `log_level` | `string` | 否 | 当前运行日志级别 |
| `inbounds_count` / `groups_count` | `int` | 是 | 当前入站数量、用户自定义代理分组数量 |
| `policy_epoch` | `uint64` | 否 | 当前策略世代号 |
| `policy_hash` | `string` | 否 | 规范化路由策略 SHA-256 十六进制摘要 |
| `generation` | `string` | 否 | 最近一次配置加载时间戳代次（`YYYYMMDDTHHMMSSZ`） |
| `sync_warning` | `string` | 否 | 当前 Mihomo 同步警告信息 |
| `config_in_sync` | `bool` | 是 | 磁盘上的配置文件是否与当前内存生效配置一致 |
| `reload_pending` | `bool` | 否 | 是否有热重载正在执行或排队 |
| `last_reload_error` | `string` | 否 | 最近一次重载失败错误信息（已脱敏） |
| `last_reload_rolled_back` | `bool` | 否 | 最近一次管理端写入触发的重载失败后是否已自动回滚 |
| `suspended` | `bool` | 是 | 守护进程当前是否处于 suspend（无负载挂起）状态 |
| `web_enabled` | `bool` | 否 | 是否已启用 `admin_web_dir` 外部静态面板托管 |
| `web_path` | `string` | 否 | 启用静态托管时的访问路径（固定为 `"/web/"`，不暴露宿主机磁盘路径） |

---

#### `PUT /api/v1/system/log-level`

动态调整运行期日志级别，不触发任何 eBPF 或连接重载。

- **请求体**：`{"level": "error" | "warn" | "warning" | "info" | "debug" | "trace"}`
- **成功响应**（`200`）：`{"level": "debug"}`（`warning` 会归一化为 `"warn"`）
- **事件推送**：向 WS `events` 主题广播 `log_level_changed`。
- **错误**：`400 invalid_json`、`400 invalid_log_level`、`503 logger_unavailable`。

---

#### `POST /api/v1/system/reload`

校验 `config.dae`（含 `admin_listen` 安全校验）后将异步热重载请求入队。若当前处于 `suspended` 状态，执行热重载将同时恢复数据面。

- **请求体**：无需请求体。
- **成功响应**：
  - `202 Accepted`：`{"queued": true}`
  - `409 Conflict`：`{"queued": false}`（重载队列繁忙或已有任务等待合并）
- **错误**：`400 config_invalid`、`503 reload_unavailable`。

---

#### `POST /api/v1/system/suspend`

将 `fdae` 数据面异步挂起为无负载直连状态（保留管理面 HTTP/WS 运行，可通过 `POST /api/v1/system/reload` 恢复）。

- **请求体**：可选 JSON `{"abort": false}`（设 `abort: true` 时立即中断既有连接）
- **成功响应**：
  - `202 Accepted`：`{"queued": true}`
  - `409 Conflict`：`{"queued": false}`
- **事件推送**：挂起完成后向 WS `events` 主题广播 `system_suspended`。
- **错误**：`400 invalid_json`、`503 suspend_unavailable`。

---

### 5.2 运行时指标与历史趋势

#### `GET /api/v1/metrics`

O(1) 实时指标快照；其中速率由单调时钟采样环计算，`/proc` 进程 stats（RSS、FD）带 `2s` TTL 缓存，`heap_bytes` 使用无 STW 的 `runtime/metrics` 读取。

**响应示例**：

```json
{
  "ts": 1763517600000,
  "upload_rate": 524288,
  "download_rate": 4194304,
  "upload_total": 1073741824,
  "download_total": 10737418240,
  "active_connections": 64,
  "tcp_connections": 48,
  "udp_sessions": 16,
  "offloaded_tcp": 12,
  "rss_bytes": 134217728,
  "heap_bytes": 67108864,
  "fd_count": 210,
  "goroutines": 95,
  "dns": {
    "cache_entries": 1024,
    "inflight": 2,
    "dropped_datagrams": 0,
    "dropped_retries": 0,
    "dropped_retry_failures": 0,
    "upstream_count": 3
  },
  "fakeip": {
    "ready": true,
    "disk_ok": true,
    "live_count": 512,
    "max_live": 4096,
    "leases": 128,
    "retained_tombstones": 4,
    "lease_limit": 2048,
    "load_warn": ""
  },
  "bpf_overflow": {
    "udp": 0,
    "tcp": 0
  },
  "tcp_conn_panic_count": 0
}
```

**字段说明**：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `ts` | `int64` | 是 | 采集 Unix 毫秒时间戳 |
| `upload_rate` / `download_rate` | `uint64` | 是 | 实时总上行 / 下行速率（bytes/s） |
| `upload_total` / `download_total` | `uint64` | 是 | 进程累计上行 / 下行字节 |
| `active_connections` | `int` | 是 | 活跃连接总数（TCP + UDP） |
| `tcp_connections` | `int` | 是 | 活跃 TCP 流数量 |
| `udp_sessions` | `int` | 是 | 活跃 UDP endpoint 数量（`O(1)` 原子计数） |
| `offloaded_tcp` | `int64` | 是 | 当前处于 TCP Sockmap offload 状态的流数量 |
| `rss_bytes` / `heap_bytes` | `uint64` | 是 | 进程常驻内存（Linux `/proc/self/status` `VmRSS`）、Go live heap 字节数 |
| `fd_count` / `goroutines` | `int` | 是 | 打开文件描述符数、当前 Goroutine 数 |
| `dns` | `AdminDNSStats` | 是 | `{cache_entries, inflight, dropped_datagrams, dropped_retries, dropped_retry_failures, upstream_count}` |
| `fakeip` | `AdminFakeIPStats \| null` | 否 | 未启用 FakeIP 时省略；启用时含 `{ready, disk_ok, live_count, max_live, leases, retained_tombstones, lease_limit, load_warn?}` |
| `resolve_dns` | `AdminResolveDNSStats \| null` | 否 | 仅当存在配置了 `node_resolve_dns` 的节点时返回：`{cache_entries, hits, stale_hits, misses, negative_hits, prefetch_started, prefetch_consumed, timeouts, failures, fail_open, passive_pins, pooled_dials, pooled_reuses}` |
| `bpf_overflow` | `object` | 是 | eBPF map 溢出计数：`{udp: uint64, tcp: uint64}` |
| `tcp_conn_panic_count` | `uint64` | 是 | TCP 处理路径恢复的 panic 次数 |
| `udp_reply_drought` | `object \| null` | 否 | 若启用了 UDP 回复中断观测时返回：`{mode, generation, group?, client?, contract?, stats, excluded?}` |

---

#### `GET /api/v1/metrics/history`

获取降采样历史网速折线图数据。

- **Query 参数**：
  - `window`：`int`，可选，默认 `1800`（30 分钟），最大 `3600`（1 小时），单位秒
  - `points`：`int`，可选，默认 `180`，最大 `720`，降采样点数
- **响应示例**：
  ```json
  {
    "window_sec": 1800,
    "points": 2,
    "samples": [
      {"ts": 1763517590000, "up": 102400, "down": 2048000},
      {"ts": 1763517600000, "up": 98304, "down": 1843200}
    ]
  }
  ```

---

### 5.3 代理分组与节点管理

#### `GET /api/v1/groups`

列出所有用户定义的出站分组及成员实时可用性/延迟状态（已过滤内建 `direct`/`block`/`must_rules`，**绝不返回**节点明文 URI、密钥或密码）。

**响应示例**：

```json
{
  "groups": [
    {
      "name": "proxy",
      "selectable": true,
      "policy": "fixed",
      "selected": "hk-01",
      "isolate_transport": false,
      "selection_members": ["hk-01", "sg-01", "auto-best"],
      "members": [
        {
          "name": "hk-01",
          "display_name": "HK BGP 01",
          "kind": "node",
          "protocol": "hysteria2",
          "endpoint": "198.51.100.10:443",
          "alive": true,
          "latency_ms": 42,
          "admission": "alive",
          "reason": "ok",
          "checked_at": "2026-11-19T05:09:50Z",
          "probes": {
            "tcp4": {
              "alive": true,
              "latency_ms": 42,
              "admission": "alive",
              "reason": "ok",
              "checked_at": "2026-11-19T05:09:50Z"
            }
          }
        }
      ]
    }
  ],
  "display_names": {
    "hk-01": "HK BGP 01"
  }
}
```

**字段说明**：
- `groups[]`:
  - `name` (`string`): 分组名
  - `display_name` (`string`, omitempty): 展示名（如有）
  - `origin` (`string`, omitempty): 来源（`"config"` \| `"mihomo"`）
  - `wrapper` (`bool`, omitempty): 是否为单节点规则兼容包装组
  - `selectable` (`bool`): 是否允许手动指定成员（`policy == "fixed"` 且存在可选列表时通常为 `true`）
  - `policy` (`string`): 选路策略（如 `fixed`、`min`、`min_avg10`、`min_moving_avg`、`fallback`、`urltest`、`first_alive` 等）
  - `selected` (`string`): 当前实际选中/生效的成员名称
  - `isolate_transport` (`bool`, omitempty): 是否启用同组独立传输连接
  - `quality_mode` (`string`, omitempty): 本地 TCP 吞吐质量调度模式（`"off"` \| `"observe"` \| `"enforce"`）
  - `check_tolerance_ms` (`int64`, omitempty): 选路滞后容差（ms）
  - `lazy` (`bool`, omitempty): 是否启用延迟健康检查
  - `sticky_count` (`int`, omitempty): 当前活跃站点粘滞（TCP+UDP）条目数
  - `selection_members` (`string[]`): 可切换成员有序列表
  - `members[]`:
    - `name` (`string`): 成员唯一标识（调用 `selection` 接口时传此值）
    - `display_name` (`string`, omitempty): Mihomo 源配置的展示名（如有）
    - `kind` (`string`, omitempty): `"node"` 或 `"group"`（嵌套子分组）
    - `resolved_leaf` (`string`, omitempty): 嵌套子分组当前解析出的实际叶子节点名
    - `protocol` (`string`, omitempty): 节点协议名（如 `vless`、`trojan`、`hysteria2`、`ss`）
    - `endpoint` (`string`, omitempty): 脱敏后的 `host:port`（不含协议串和认证信息）
    - `alive` (`bool`): 是否可用
    - `latency_ms` (`int32 | null`, omitempty): 代表性延迟（ms），未探测/失败时省略或 `null`
    - `baseline_ms` (`int32 | null`, omitempty): 代表性 RTT 基线（ms）
    - `quality_score_ms` (`int32 | null`, omitempty): `url_test` 综合质量分（含丢包/降级/时间衰减惩罚，单位 ms）
    - `loss_rate` (`float64 | null`, omitempty): 近期探测失败率（`0.0..1.0`）
    - `recent_latencies_ms` (`int32[]`, omitempty): 最近成功延迟样本列表（最多 10 点，用于火花线）
    - `load` (`LoadContext | null`, omitempty): 节点本地实时负载上下文（`class`, `active_connections`, `upload_bytes_per_second`, `download_bytes_per_second` 等）
    - `admission` (`string`, omitempty): 准入状态（`"alive"` / `"degraded"` / `"dead"`）
    - `reason` (`string`, omitempty): 准入判定原因（如 `"ok"` / `"not_alive"` / `"fail"` / `"rtt"` / `"congestion"`）
    - `checked_at` (`string`, omitempty): 最近检测时间（RFC3339 UTC）
    - `probes` (`Record<string, AdminProbeHealth>`, omitempty): 按传输路径区分的最近探测结果，常见键为 `"tcp4"`、`"tcp6"`、`"dns4"`、`"dns6"`、`"udp4"`、`"udp6"`；每槽含 `baseline_ms`、`quality_score_ms`、`loss_rate`、`recent_latencies_ms`、`congested`、`fail_streak`、`penalty_level` 等字段
    - `resolve_dns` (`ResolveDNSHealthSnapshot`, omitempty): 仅当该节点配置了 `resolve_dns` 时返回，含 `server`、`state`（`"closed"` \| `"open"` \| `"half_open"`）、`consecutive_failures`、`total_success`、`total_failure`、`total_timeout`、`total_fail_open`、`last_latency_ms`、`last_error`、`last_error_at`、`last_success_at`、`circuit_open_until`
- `display_names` (`Record<string, string>`): 成员名到展示名的映射表。

---

#### `PUT /api/v1/groups/{name}/selection`

在运行时切换 `fixed` 分组当前选中的成员（分组名如含 `%`、`/` 等特殊字符需做 URL Path 编码）。不触发重载，新连接立即生效。

- **请求体**：`{"member": "hk-01", "close_existing": false}`（`close_existing` 可选，为 `true` 时断开该分组下与新选中成员 `member` 不匹配的活跃连接；若重复选中当前成员且无残留旧连接，则返回 `closed_connections: 0`）
- **成功响应**（`200`）：`{"group": "proxy", "member": "hk-01"}`（启用 `close_existing` 时额外返回 `"closed_connections": N`）
- **事件推送**：向 WS `events` 主题广播 `group_selection_changed`（断开连接时另广播 `connections_closed`）。
- **错误**：`400 invalid_group`、`400 invalid_json`、`400 invalid_member`、`400 selection_failed`。

---

#### `POST /api/v1/groups/{name}/probe`

触发对指定分组的异步节点延迟探测。同一分组受 **3 秒** 防抖冷却限制。

- **请求体**：空
- **成功响应**（`202 Accepted`）：`{"group": "proxy", "action": "probe"}`
- **事件推送**：向 WS `events` 主题广播 `group_probe_triggered`。
- **冷却超频**（`429 Too Many Requests`）：`error.code = "probe_cooldown"` + `Retry-After: 3`
- **其他错误**：`400 invalid_group`、`400 probe_failed`。

---

#### `POST /api/v1/groups/probe`

触发全部用户分组的异步节点延迟探测（全局 **3 秒** 冷却）。

- **成功响应**（`202 Accepted`）：`{"action": "probe", "groups": N}`
- **事件推送**：向 WS `events` 主题广播 `group_probe_triggered`。

---

#### `POST /api/v1/groups/{name}/members/{member}/probe`

触发指定分组中单个节点或嵌套子分组的异步延迟探测（单成员 **2 秒** 冷却）。

- **成功响应**（`202 Accepted`）：`{"group": "proxy", "member": "hk-01", "action": "probe"}`
- **事件推送**：向 WS `events` 主题广播 `group_probe_triggered`。

---

#### `GET /api/v1/groups/{name}/sticky`

查看 `fallback` / `url_test` 分组的当前按站点粘滞（Site-Sticky）Pin 表。

- **Query 参数**：`network`（`tcp` \| `udp`）、`q`（按站点或叶子节点子串过滤）、`limit`（默认 `100`，上限 `500`）
- **成功响应**（`200`）：`{"group": "proxy", "total": 1, "truncated": false, "entries": [{"site": "youtube.com", "network": "tcp", "leaf": "hk-01", "pinned_at": "...", "last_success": "...", "touched_at": "...", "consecutive_slow": 0, "tried_alts": 0, "converged": false, "hold_down_leaves": [], "next_recovery_at": "..."}]}`

---

#### `DELETE /api/v1/groups/{name}/sticky` 与 `DELETE /api/v1/groups/{name}/sticky/{site}`

手动清除指定分组的全部或单个站点粘滞记录，使下次新连接重新按组策略选路（可选 `?network=tcp|udp`）。

- **成功响应**（`200`）：`{"group": "proxy", "site": "youtube.com", "cleared": 1}`
- **事件推送**：向 WS `events` 主题广播 `group_sticky_changed`。

---

### 5.4 活跃连接与连接打断

#### `GET /api/v1/connections`

查询当前所有活跃用户态连接（TCP + UDP + Inbound UDP），服务端对无过滤基础快照做 `500ms` 合并，并基于单调时间计算单条连接的实时 `upload_rate` 和 `download_rate`。

- **Query 参数**：
  - 所有 [4.3 `AdminConnectionFilter`](#43-adminconnectionfilter连接过滤条件) 字段：`network`, `outbound`, `dialer`, `src_ip`（或 `src`）, `dst_ip`, `domain`, `mac`, `process`, `inbound`, `rule`, `q`
  - `limit`：`int`，默认 `256`，最大 `1024`
  - `sort`：`total`（默认）\| `upload` \| `download` \| `upload_rate` \| `download_rate` \| `duration` \| `start_time`
  - `order`：`desc`（默认）\| `asc`
- **响应体**（`AdminConnectionsSnapshot`）：
  ```json
  {
    "scope": "1763517600000000000",
    "total": 42,
    "truncated": false,
    "connections": [ /* AdminConnection[] */ ],
    "snapshot_at_ms": 1763517605000,
    "upload_total": 1073741824,
    "download_total": 10737418240
  }
  ```

---

#### `DELETE /api/v1/connections/{id}`

立即打断并关闭指定 ID 的用户态活跃连接（支持正在使用 Sockmap offload 转发的 TCP 连接、UDP endpoint 及 Inbound UDP 会话）。注意 `{id}` 包含冒号时建议进行 URL 编码（如 `tcp%3A42`）。

- **成功响应**（`200`）：`{"closed": true, "id": "tcp:42"}`
- **未找到**：`404 not_found`
- **副作用**：关闭的连接以 `close_reason: "aborted"` 写入 `/api/v1/flows/closed` 并推送至 WS `flows` 主题，同时向 WS `events` 主题广播 `connections_closed`（`{"closed": 1, "id": "tcp:42"}`），并使 500ms 连接快照缓存立即失效。

---

#### `POST /api/v1/connections/close`

按过滤条件或全量批量打断当前活跃用户态连接（安全保护：既未传任何过滤条件也未设置 `all: true` 时拒绝执行）。

- **请求体**（[4.3 `AdminConnectionFilter`](#43-adminconnectionfilter连接过滤条件)）：
  - 示例 1（断开指定设备或节点）：`{"src_ip": "192.168.1.20", "dialer": "hk-01"}`
  - 示例 2（断开全部活跃连接）：`{"all": true}`
- **成功响应**（`200`）：`{"closed": 12}`
- **副作用**：当 `closed > 0` 时使快照缓存失效并向 WS `events` 推送 `connections_closed`。
- **错误**：`400 invalid_json`、`400 filter_required`。

---

#### `GET /api/v1/connections/kernel`

只读查询未被 `fdae` 用户态接管、由内核直通转发的连接（数据来自 Linux `/proc/net/nf_conntrack`）。具备至少 `2s` 缓存节流（高耗时情况下触发指数退避保护，避免扫描大表拖垮 CPU）。

- **Query 参数**：
  - `limit`：`int`，最大 `1024`
  - `src`：`string`，按单个源 IP 过滤（不支持 CIDR，非法值返回 `400 invalid_param`）
  - `mac`：`string`，按客户端 MAC（解析为控制面学到的 IP 集合后过滤）
  - `resolve_domains`：`true` \| `1` 开启基于 DNS 缓存（A/AAAA 应答）的 IP→域名反查；默认 `false`
- **响应体**（`AdminKernelConnectionsSnapshot`）：
  - 注意：`upload`/`download` 为内核 **IP 层字节数**（含 IP/L4 头部），且仅当系统开启 `net.netfilter.nf_conntrack_acct = 1` 时有计数；`admin_connections` 中的 `upload`/`download` 为应用载荷字节数，请勿直接混加。

```json
{
  "available": true,
  "accounting": true,
  "total": 1,
  "truncated": false,
  "excluded": {
    "userspace": 14,
    "dae": 14,
    "inactive": 3,
    "local": 2
  },
  "connections": [
    {
      "id": "udp:192.168.1.20:51234>119.29.29.29:53",
      "network": "udp",
      "src": "192.168.1.20:51234",
      "dst": "119.29.29.29:53",
      "domain": "",
      "mac": "3e:0a:a5:de:ae:a3",
      "state": "",
      "upload": 128,
      "download": 256,
      "upload_packets": 2,
      "download_packets": 2,
      "ttl": 28,
      "offloaded": false,
      "unreplied": false
    }
  ],
  "snapshot_at_ms": 1763517605000,
  "scan_ms": 4
}
```

---

#### `DELETE /api/v1/connections/kernel`

尽力而为地终止一条 5 元组连接，依次尝试：
1. 若匹配用户态流（含 Sockmap offload），先关闭用户态连接；
2. 通过 Netlink 删除 Linux conntrack 对应表项；
3. 删除 eBPF `conn_state_map` 正反向 5 元组状态。

- **请求体**：
  ```json
  {
    "protocol": "tcp",
    "src_ip": "192.168.1.20",
    "src_port": 51234,
    "dst_ip": "1.1.1.1",
    "dst_port": 443
  }
  ```
- **响应体**（`200`，诚实报告各层实际动作；非 Linux 平台会直接提示不支持）：
  ```json
  {
    "conntrack_deleted": true,
    "bpf_state_deleted": true,
    "userspace_closed": false,
    "warning": "direct bypass kernel sockets do not receive local FIN/RST from conntrack deletion alone"
  }
  ```
- **错误**：`400 invalid_json`、`400 invalid_tuple`。

---

### 5.5 已关闭连接与多维度流量统计

#### `GET /api/v1/flows/closed`

读取内存环形缓存（最近 `2048` 条已结束或被打断的连接），按结束时间**从新到旧**返回。

- **Query 参数**：支持全部 [4.3 `AdminConnectionFilter`](#43-adminconnectionfilter连接过滤条件) 字段（含 `offloaded`、`close_reason`） + `limit`（默认 `100`，最大 `500`） + `after_seq`（增量游标，仅返回 `seq > after_seq`）
- **响应体**（`AdminClosedFlowsSnapshot`）：
  ```json
  {
    "total": 1,
    "truncated": false,
    "flows": [ /* AdminClosedFlow[] */ ],
    "snapshot_at_ms": 1763517605000
  }
  ```

---

#### `GET /api/v1/traffic/summary`

返回自启动（或上次调用 `/api/v1/traffic/reset`）以来的多维度累计流量汇总（已关闭连接的精确累计 + 当前所有活跃连接扣除 reset 基线后的实时流量）。

- **Query 参数**：`top`，默认 `50`，最大 `200`（每个维度最多返回前 `top` 条并附带排序结果）
- **响应体**（`AdminTrafficSummary`）：
  ```json
  {
    "since": "2026-11-19T03:00:00Z",
    "snapshot_at_ms": 1763517605000,
    "upload_total": 1073741824,
    "download_total": 10737418240,
    "active_connections": 64,
    "closed_connections": 1520,
    "by_src_ip": [],
    "by_mac": [],
    "by_domain": [],
    "by_rule": [],
    "by_outbound": [],
    "by_dialer": [],
    "by_inbound": [],
    "by_process": []
  }
  ```

**8 个统计维度与内存基数保护上限**：

| 响应字段 | 统计维度 | 键格式说明 | 服务端最大保留键数 |
| --- | --- | --- | --- |
| `by_src_ip` | 客户端源 IP | 如 `"192.168.1.20"` | `256` |
| `by_mac` | 客户端 MAC | 如 `"3e:0a:a5:de:ae:a3"` | `256` |
| `by_domain` | 目标域名 | 如 `"api.example.com"`；无域名流归入 `"(ip-only)"` | `512` |
| `by_rule` | 命中规则 | 如 `"#12: domain(suffix: example.com) -> proxy"`（无序号则为 `raw`，未归因则为 `"(unattributed)"`） | `256` |
| `by_outbound` | 最终出站 | 如 `"proxy"`、`"direct"` | `64` |
| `by_dialer` | 最终节点 | 如 `"hk-node-01"` | `256` |
| `by_inbound` | 入站名称 | 如 `"socks-in"` | `32` |
| `by_process` | 进程名 | 如 `"curl"` | `128` |

---

#### `POST /api/v1/traffic/reset`

清空当前多维度流量累计并重置统计起点时间 `since`；对于当下仍存活的连接记录其当前字节数作为基线，保证在不断开活跃长连接的情况下，Reset 之后仅统计新增字节。

- **成功响应**（`200`）：`{"reset": true}`
- **事件推送**：向 WS `events` 主题广播 `traffic_reset`。

---

### 5.6 入站（SOCKS5 Inbounds）管理

#### `GET /api/v1/inbounds`

读取 `config.dae` / `routing.dae` 中配置的以及外部生成的正在运行的入站列表。文件未变时命中 stat 缓存。响应头附带强一致性 `ETag`。

**响应示例**：

```json
{
  "editable": true,
  "inbounds": [
    {
      "name": "socks-lan",
      "protocol": "socks5",
      "listen": "192.168.1.1:1080",
      "username": "user1",
      "has_password": true,
      "udp": true,
      "udp_advertise": "",
      "sniff": "auto",
      "resolve": "local",
      "state": "listening",
      "error": "",
      "conns": 2,
      "associations": 1,
      "udp_sessions": 3,
      "accepted": 48,
      "since": "2026-11-19T03:00:02Z",
      "origin": "config",
      "editable": true
    }
  ]
}
```

**字段补充说明**：
- 永不返回明文密码，仅返回 `has_password: bool`。
- `state`：`"listening"` \| `"failed"` \| `"pending"`（已写入磁盘尚未热重载生效时）。
- `origin`：`"config"`（`config.dae` 定义，可被 API 编辑） \| `"routing"`（`routing.dae` 定义） \| `"managed"`（如 OpenWrt/其他文件生成）。

---

#### `PUT /api/v1/inbounds`

原子覆写 `config.dae` 中的 `inbound {}` 配置段并入队热重载；若校验失败、重载队列满或异步重载失败则自动还原备份。

- **可选请求头**：`If-Match: "<etag>"`（与当前配置不一致时返回 `412 precondition_failed`）。
- **请求体**（最大 `64 KiB`）：
  ```json
  {
    "inbounds": [
      {
        "name": "socks-lan",
        "listen": "192.168.1.1:1080",
        "username": "user1",
        "password": null,
        "udp": true,
        "udp_advertise": "",
        "sniff": "auto",
        "resolve": "local"
      }
    ]
  }
  ```
- **密码语义**：
  - `password` **省略或传 `null`**：保留已保存的同名入站密码；
  - `password: ""`（或 `username: ""`）：清除密码；
  - `password: "new-pass"`：更新为新密码。
- **默认值**：`udp` 默认 `true`，`sniff` 默认 `"auto"`，`resolve` 默认 `"local"`。
- **成功响应**（`200`）：`{"queued": true}`（推送 WS 事件 `inbounds_updated`）。

---

### 5.7 配置管理与生效配置

#### `GET /api/v1/config`

返回当前 `config.dae`（仅提取 `global` 与 `routing` 段）及 `routing.dae`（若存在）原文。响应头附带 `ETag`。

- **脱敏规则**：
  - `global` 中 `admin_secret` 被替换为 `'***'`；
  - `config` 中的节点链接行会被剥离（`node` / `subscription` 不对管理 API 暴露）；
  - `routing` 中内联 `inbound` 的 `password` 会被替换为 `'***'`。
- **响应体**（`200`）：`{"config": "global { ... }\nrouting { ... }", "routing": "..."}`

---

#### `PUT /api/v1/config`

原子修改 `config.dae` 的 `global`/`routing` 段和/或 `routing.dae`，校验并触发热重载；任何失败都会从 `.admin-bak` / `.admin-last-good` 自动回滚。

- **可选请求头**：`If-Match: "<etag>"`（不一致返回 `412 precondition_failed`）。
- **请求体**（最大 `2 MiB`）：
  ```json
  {
    "config": "global {\n  ...\n  admin_secret: '***'\n}\nrouting {\n  ...\n}",
    "routing": "..."
  }
  ```
- **关键规则**：
  - `config` 省略、`null` 或空白字符串时保留原 `config.dae`；非空时只允许包含 `global` 和 `routing` 段（不可写入 `node`/`subscription`/`inbound` 或节点协议 URI）；
  - `config` 中若保持 `admin_secret: '***'`，服务端自动保留磁盘原有密钥（同理 `routing` 中 `password: '***'` 保留对应入站原密码）；
  - `routing` 省略或 `null` 时保留原 `routing.dae`，传入字符串则会完整覆写 `routing.dae`。
- **成功响应**（`200`）：`{"queued": true}`（推送 WS 事件 `config_updated`）。

---

#### `GET /api/v1/config/effective`

只读查看当前正在运行中的完整生效配置（已合并 Mihomo 订阅转换的节点、分组、规则与回退策略，不含明文凭据；`ruleset` 以可读形式呈现不展开成数千条规则）。

- **Query 参数**：`format`（传入 `"text"` 时返回 `text/plain; charset=utf-8` 文本视图；否则返回 JSON）
- **JSON 响应字段**（`EffectiveConfig`）：
  - `loaded_at` (`string`, RFC3339): 加载时间
  - `mihomo` (`MihomoStatus`): Mihomo 源状态
  - `subscriptions` (`int`): 配置的原生订阅数
  - `nodes[]`: `{"tag", "display_name?", "endpoint", "origin"}`（`endpoint` 仅 `"scheme host:port"` 或 `"(link)"`）
  - `groups[]`: `{"name", "display_name?", "policy", "members", "options?", "wrapper?", "origin"}`
  - `rule_providers[]`: `{"name", "type", "behavior", "source", "interval?", "origin"}`
  - `rules[]`: `{"index", "text", "origin"}`
  - `fallback`: `{"outbound", "origin"}`

---

### 5.8 外部数据源与刷新

#### `GET /api/v1/sources`

返回三类外部动态数据源状态：

```json
{
  "mihomo": {
    "enabled": true,
    "source": "https://sub.example.com/profile.yaml",
    "checked_at": "2026-11-19T04:00:00Z",
    "used_last_good": false,
    "error": "",
    "nodes": 30,
    "groups": 4,
    "rules": 120,
    "providers": 2,
    "degraded": false,
    "skipped_rules": [],
    "unused_providers": [],
    "ignored_fields": []
  },
  "geodata": {
    "enabled": true,
    "geoip": {
      "source": "https://.../geoip.dat",
      "checked_at": "2026-11-19T04:00:00Z",
      "present": true
    },
    "geosite": {
      "source": "https://.../geosite.dat",
      "checked_at": "2026-11-19T04:00:00Z",
      "present": true
    }
  },
  "rule_providers": {
    "checked_at": "2026-11-19T04:00:00Z",
    "used_last_good": false,
    "degraded": false
  },
  "sync_warning": ""
}
```

---

#### `POST /api/v1/sources/refresh`

立即拉取更新外部规则集、Mihomo 配置源与 GeoData，若有内容变更则自动入队热重载。该路由单次请求写超时放宽至 `180s`（`3m`），且部分失败时的 `warning` 与全失败时的 `refresh_failed` 错误信息均会经过 URI 脱敏与长度截断。

- **请求体**：空
- **成功响应**（`200`）：
  ```json
  {
    "refreshed": true,
    "changed": true,
    "used_last_good": false,
    "reload_queued": true,
    "warning": "",
    "sources": { /* 与 GET /api/v1/sources 结构相同 */ }
  }
  ```
- **事件推送**：向 WS `events` 主题广播 `sources_refreshed`（其中 `warning` 同样经过脱敏处理）。
- **错误**：`409 refresh_in_progress`（已有刷新进行中）、`500 refresh_failed`、`503 refresh_unavailable`。

---

### 5.9 结构化日志

#### `GET /api/v1/logs`

从进程内 `1024` 条环形内存日志缓冲区读取（不扫描磁盘日志文件）。

- **Query 参数**：
  - `limit`：`int`，默认 `200`，最大 `500`
  - `level`：`error` \| `warn` \| `info` \| `debug` \| `trace`（默认 `trace`；返回级别严重度 >= 所选最低级别，即 `entry.level <= minLevel`）
  - `after_seq`：`uint64`，增量拉取游标（仅返回 `seq > after_seq` 的新日志）
- **响应体**（`200`）：
  ```json
  {
    "entries": [ /* AdminLogEntry[] */ ],
    "latest_seq": 1024
  }
  ```

---

### 5.10 高级诊断与观测接口

此类接口面向调试与排障前端页面：

#### `GET /api/v1/debug/quality`

- **Query 参数**：`group`（可选，过滤分组名）、`host`（可选，过滤域名/主机名）
- **响应体**（`200`）：
  ```json
  {
    "entries": [
      {
        "group": "proxy",
        "host": "example.com",
        "network": "tcp4",
        "mode": "enforce",
        "stable_leaf": "hk-01",
        "next_probe_at": "2026-11-19T05:15:00Z",
        "generation": 1,
        "suppressed_logs": 0,
        "invalid_windows": 0,
        "current_bytes_per_second": 1048576,
        "reference_bytes_per_second": 2097152,
        "severe": false,
        "absolute_severe": false,
        "historical_severe": false,
        "quality_deferred": false,
        "last_sample_at": "2026-11-19T05:10:00Z"
      }
    ],
    "limit": 256,
    "recovery_diagnostics": [
      {
        "policy_epoch": 5,
        "group": "proxy",
        "quality_mode": "enforce",
        "quality_reasons": {},
        "quality_switches_in_window": 0,
        "quality_switch_limit": 10,
        "quality_window_ms": 1800000,
        "site_recovery": [
          {
            "network": "tcp",
            "reasons": {},
            "switches_in_window": 0,
            "switch_limit": 10,
            "window_ms": 1800000,
            "in_flight": 0,
            "last_probe_at": "0001-01-01T00:00:00Z",
            "last_recovery_at": "0001-01-01T00:00:00Z"
          }
        ]
      }
    ],
    "recovery_diagnostics_limit": 256
  }
  ```

#### `GET /api/v1/debug/capture`

- **Query 参数**：`after`（`uint64` 序列游标，默认 `0`）
- **响应体**（`observation.Snapshot`）：`{"enabled": bool, "generation": string, "stats": {...}, "records": [...], "next_sequence": uint64, "oldest_sequence": uint64}`

#### `GET /api/v1/debug/evidence`

- **Query 参数**：`after`（`uint64` 序列游标，默认 `0`）
- **响应体**（`observation.EvidenceSnapshot`）：`{"enabled": bool, "generation": string, "records": [...], "next_sequence": uint64, "oldest_sequence": uint64, "queue_dropped": uint64, "oversize": uint64, "ring_evicted": uint64}`

#### `GET /api/v1/debug/udp-recovery`

- **Query 参数**：`after`（`uint64` 序列游标，默认 `0`）、`process`（可选进程名筛选，长度上限 `64` 字符）
- **响应体**（`control.UDPRecoverySnapshot`）：包含 `schema`, `process`, `at_ms`, `mode`, `execution_implemented`, `thresholds`, `observation`, `coverage`, `records`, `oldest_sequence`, `latest_sequence`, `next_sequence`, `has_more`, `cursor_reset?`, `lost_records`, `ring_evicted`, `event_counts`, `fakeip_leases?`, `execution?`。

---

## 6. 多路复用 WebSocket（`/api/v1/ws`）

通过一条 WebSocket 连接按需订阅多个实时通道，**无活跃订阅者时后端零采样、零序列化开销**。

### 6.1 连接与流控限制

| 机制 | 参数 | 说明 |
| --- | --- | --- |
| 并发客户端上限 | `16` | 含待鉴权连接；超出返回 HTTP `503 too_many_clients` |
| Origin 校验 | `admin_cors_origins` | 若握手带 `Origin` 头且不在白名单内，返回 `403 origin_forbidden` |
| 失败限流与鉴权超时 | `3s` | 升级前即校验来源 IP 限流（超限直接返回 HTTP `429 rate_limited` + `Retry-After`）；握手后 3 秒内必须发首帧 `auth`；超时、格式非法或密钥错误返回 `auth_error`（均计入失败次数）并以 close code `4001` 关闭；停机或重载变更 `admin_secret`/`admin_listen` 会主动断开所有已连与待鉴权客户端 |
| 客户端发送队列 | `64` 帧 | 慢消费者满队时直接丢弃新帧（不阻塞数据面与正常客户端） |
| 单帧读取上限 | `16 KiB` | 控制帧以外 JSON 消息体大小上限 |
| 心跳（协议层 + 应用层） | Ping `25s` / Pong `60s` | 服务端每 25s 发送 WS Ping；同时支持客户端发送 JSON `{"type":"ping"}` |

### 6.2 建连与首帧鉴权流程

1. 发起连接：`ws://<admin_listen>/api/v1/ws`（经反代则为 `wss://<host>/api/v1/ws`）。
2. 首帧发送鉴权（`3s` 内）：
   ```json
   {"type": "auth", "token": "<admin_secret>"}
   ```
3. 服务端返回：
   - 成功：`{"type": "auth_ok", "version": "v1"}`
   - 失败：升级前限流返回 HTTP `429 rate_limited`（带 `Retry-After`）；握手后失败返回 `{"type": "auth_error", "code": "unauthorized" | "auth_timeout" | "invalid_auth_frame" | "rate_limited", "message": "..."}`，随后 Close `4001`。

### 6.3 客户端帧格式

#### 1. 订阅主题（`sub`）

```json
{
  "type": "sub",
  "topic": "connections",
  "interval_ms": 1000,
  "limit": 256,
  "sort": "total",
  "order": "desc",
  "filter": {
    "outbound": "proxy"
  }
}
```

**支持的 6 个主题（`topic`）**：

| `topic` | 驱动方式 | `interval_ms`（默认 / 范围） | 支持的附加订阅字段 | 订阅时立即推送首帧快照 | 推送 `data` 类型 |
| --- | --- | --- | --- | --- | --- |
| `metrics` | 定时采样 | 默认 `1000` (`500..10000`) | 无 | 是 | 同 `GET /api/v1/metrics` |
| `connections` | 定时采样 | 默认 `1000` (`500..10000`) | `filter`、`limit`（默认 `256`，上限 `1024`）、`sort`、`order` | 是 | 同 `GET /api/v1/connections` |
| `groups` | 定时采样 | 默认 `5000` (`1000..30000`) | 无 | 是 | 同 `GET /api/v1/groups` |
| `logs` | 事件驱动（实时 Hook） | 忽略 | `level`（默认 `trace`） | 否（历史日志用 `GET /api/v1/logs` 首屏加载） | 单条 `AdminLogEntry` |
| `flows` | 事件驱动（流结束回调） | 忽略 | `filter` | 否（历史关闭流用 `GET /api/v1/flows/closed` 首屏加载） | 单条 `AdminClosedFlow` |
| `events` | 事件驱动（控制面状态变更） | 忽略 | 无 | 否 | 见 6.4 事件列表 |

> 重复对同一 `topic` 发送 `sub` 可动态更新该连接上的 `interval_ms` / `filter` / `level` 等订阅条件。

#### 2. 取消订阅（`unsub`）

```json
{"type": "unsub", "topic": "connections"}
```

当全服务端对某一主题的订阅数降为 `0` 时，后端对应的采样协程 / Ring 订阅器 / `ClosedFlowObserver` 会**立即注销退出**。

#### 3. 应用层心跳（`ping`）

```json
{"type": "ping", "id": "heartbeat-1"}
```

服务端回传：

```json
{"type": "pong", "id": "heartbeat-1", "ts": 1763517605123}
```

### 6.4 服务端推送帧与控制面事件目录

- **主题数据帧**（`metrics` / `connections` / `groups` / `logs` / `flows`）：
  ```json
  {
    "type": "data",
    "topic": "metrics",
    "ts": 1763517605000,
    "seq": 12,
    "data": { }
  }
  ```
  > 对 `logs` 主题，`seq` 为全局日志序号；对 `flows` 主题，`seq` 为全局已关闭连接序号。
- **帧错误**（非断线级校验错误）：
  ```json
  {
    "type": "error",
    "code": "invalid_topic",
    "message": "unknown subscription topic"
  }
  ```
  可能的 `code`：`invalid_topic`、`invalid_level`、`unsupported_frame`。
- **控制面事件帧**（`topic: "events"`）：
  ```json
  {
    "type": "event",
    "topic": "events",
    "ts": 1763517605000,
    "seq": 3,
    "event": "reload_succeeded"
  }
  ```

**全部 14 种控制面事件（`event`）清单**：

| `event` | 触发时机 | `data` 内容 |
| --- | --- | --- |
| `reload_started` | 热重载开始执行 | 无（省略） |
| `reload_succeeded` | 热重载成功完成并切换新控制面 | 无（省略） |
| `reload_failed` | 异步热重载失败（含是否自动回滚） | `{"error": "...", "rolled_back": true \| false}` |
| `system_suspended` | `POST /api/v1/system/suspend` 挂起完成 | 无（省略） |
| `group_selection_changed` | `PUT /api/v1/groups/{name}/selection` 成功 | `{"group": "...", "member": "..."}` |
| `group_probe_triggered` | 组或单节点测速触发 | `{"group": "...", "member"?: "..."}` |
| `group_sticky_changed` | 清理分组站点粘滞记录成功 | `{"group": "...", "site"?: "...", "cleared": N}` |
| `node_health_changed` | 节点准入三态（alive/degraded/dead）发生变更 | `{"node": "...", "network": "...", "from": "...", "to": "...", "reason": "...", "latency_ms"?: N}` |
| `log_level_changed` | `PUT /api/v1/system/log-level` 成功 | `{"level": "..."}` |
| `config_updated` | `PUT /api/v1/config` 成功写入并触发重载 | `{"queued": true \| false}` |
| `inbounds_updated` | `PUT /api/v1/inbounds` 成功写入并触发重载 | `{"queued": true \| false}` |
| `sources_refreshed` | `POST /api/v1/sources/refresh` 成功完成 | `{"changed": bool, "used_last_good": bool, "reload_queued": bool, "warning": "..."}` |
| `connections_closed` | `DELETE /api/v1/connections/{id}`、批量 `close` 或切节点断旧流成功关闭流 | 单条时 `{"closed": 1, "id": "..."}`；批量时 `{"closed": N, "group"?: "..."}` |
| `traffic_reset` | `POST /api/v1/traffic/reset` 成功 | 无（省略） |

---

## 7. 独立前端对接指南与示例

### 7.1 推荐数据接入架构

1. **初始化阶段**：
   - 登录页/配置表单验证密钥：调用 `GET /api/v1/system` 验证 `Authorization: Bearer <secret>` 是否有效。
   - 建立一条全局单例 `WebSocket` 连接（`/api/v1/ws`），首帧鉴权通过后默认仅订阅轻量全局主题 `events`（以及总览/状态栏需要的 `metrics`）。
2. **按页面路由按需订阅**：
   - 进入「活跃连接」页 -> 发送 `{"type":"sub","topic":"connections","interval_ms":1000,...}`；离开页面立即发 `unsub`，避免后端持续轮询连接列表。
   - 进入「日志」页 -> 先调 `GET /api/v1/logs?limit=200` 拉取历史基线，记录 `latest_seq`，同时 WS `sub` `logs` 并将收到的条目按 `seq > latest_seq` 去重追加。
   - 进入「已关闭流 / 流量报表」页 -> 先调 `GET /api/v1/flows/closed` 与 `GET /api/v1/traffic/summary`，并按需 WS `sub` `flows` 增量接收新结束连接或触发防抖刷新。
3. **事件驱动联动**：
   - 订阅 `events` 后，收到 `reload_succeeded` / `group_selection_changed` / `config_updated` / `inbounds_updated` / `sources_refreshed` / `traffic_reset` 时再刷新对应页面 REST 数据，彻底替代高频 REST 轮询。
4. **配置/入站防并发覆盖（`ETag` + `If-Match`）**：
   - 调用 `GET /api/v1/config`（或 `/api/v1/inbounds`）时保存响应头 `ETag`；
   - 提交 `PUT` 时附带 `If-Match: <etag>`；
   - 若收到 `412 precondition_failed`，提示用户“配置已被其他终端或进程更新，请重新加载合并后再保存”。

### 7.2 TypeScript 参考客户端片段

```ts
export class FdaeClient {
  constructor(
    private readonly baseUrl: string, // 例如 "http://192.168.1.1:2025" 或 "https://router.lan"
    private readonly secret: string,
  ) {}

  async request<T>(path: string, init: RequestInit = {}): Promise<{ data: T; etag?: string }> {
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${this.secret}`);
    if (init.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    const res = await fetch(`${this.baseUrl}${path}`, { ...init, headers });
    if (!res.ok) {
      const errBody = await res.json().catch(() => null);
      const code = errBody?.error?.code ?? `http_${res.status}`;
      const msg = errBody?.error?.message ?? res.statusText;
      throw new Error(`[${res.status}:${code}] ${msg}`);
    }
    const etag = res.headers.get('ETag') ?? undefined;
    const data = (await res.json()) as T;
    return { data, etag };
  }

  connectWS(onFrame: (frame: any) => void): WebSocket {
    const wsUrl = this.baseUrl.replace(/^http/, 'ws') + '/api/v1/ws';
    const ws = new WebSocket(wsUrl);
    ws.addEventListener('open', () => {
      ws.send(JSON.stringify({ type: 'auth', token: this.secret }));
    });
    ws.addEventListener('message', (ev) => {
      const frame = JSON.parse(ev.data as string);
      if (frame.type === 'auth_ok') {
        ws.send(JSON.stringify({ type: 'sub', topic: 'events' }));
        ws.send(JSON.stringify({ type: 'sub', topic: 'metrics', interval_ms: 1000 }));
      }
      onFrame(frame);
    });
    return ws;
  }
}
```
