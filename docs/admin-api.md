# fdae Admin API v1 Reference

`fdae` exposes a standalone HTTP/WebSocket management backend without any built-in web assets. External web consoles and automation tools integrate exclusively through `/api/v1/*`.

---

## 1. Configuration & Transport Security

### `global` Options

```dae
global {
    admin_listen: '192.168.1.1:2025'
    admin_secret: 'replace-with-strong-secret'
    admin_cors_origins: 'https://panel.example.com', 'http://localhost:5173'
}
```

- **`admin_listen`**: Must resolve to loopback, private RFC1918/RFC4193, or link-local LAN addresses (`config.ResolveAndValidateAdminListen`). Empty disables the admin server.
- **`admin_secret`**: Required when `admin_listen` is non-empty. Compared with `subtle.ConstantTimeCompare` against `Authorization: Bearer <token>`.
- **`admin_cors_origins`**: Exact origin allowlist (`scheme://host[:port]`, scheme/host lowercased and default ports normalized).
  - Wildcards (`*`), paths, query strings, fragments, and embedded userinfo are rejected at config load time.
  - When empty or omitted, **all** browser cross-origin preflights and requests carrying an `Origin` header are rejected (`403 origin_forbidden`).

### Authentication, Rate Limiting & Headers

- **REST Auth**: Send `Authorization: Bearer <admin_secret>`. Query-string tokens and legacy `X-Kdae-Authorization` headers are not accepted.
- **Rate Limiter**: Per client IP failure cap of `20` failed attempts per `60s` sliding window (bounded LRU tracking up to `256` IPs). Locked-out requests receive `429 Too Many Requests` with `Retry-After` (and WebSocket close code `4001`).
- **Response Security Headers** (always emitted):
  - `Cache-Control: no-store`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `Vary: Origin`
- **CORS & Chrome Private Network Access (PNA)**:
  - Allowed origins receive `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS`, `Access-Control-Allow-Headers: Authorization, Content-Type, If-Match`, `Access-Control-Expose-Headers: ETag`, and `Access-Control-Max-Age: 600`.
  - Preflights (`OPTIONS`) sending `Access-Control-Request-Private-Network: true` receive `Access-Control-Allow-Private-Network: true`.

> **Browser Mixed Content / PNA Note**: If the standalone frontend is served over public HTTPS (e.g. Cloudflare Pages / Vercel / GitHub Pages), modern browsers may restrict `https:// -> http://192.168.x.x` private-network calls unless TLS is terminated in front of `fdae`. Recommended setups:
> 1. Terminate HTTPS on the router with Caddy/Nginx (`https://router.lan` -> `http://127.0.0.1:2025`), forwarding `Host`, `Upgrade`, and `Connection` headers for WebSocket `/api/v1/ws`.
> 2. Or bind `admin_listen: '127.0.0.1:2025'` behind an SSH tunnel or local HTTP frontend (`http://localhost:5173`).

---

## 2. Error Envelope & Legacy Routes

All error responses return JSON:

```json
{
  "error": {
    "code": "unauthorized",
    "message": "invalid or missing bearer token"
  }
}
```

Unknown routes (including removed `/v1/*` and `/fdae-ui/*`) return `404` with `code: "not_found"` (when authenticated).

---

## 3. REST Endpoints (`/api/v1`)

### System & Control

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/system` | Daemon metadata (`version`, `running`, `hostname`, `go_version`, `os`, `arch`, `num_cpu`, `started_at`, `uptime_sec`, `dial_mode`, `lan_interface`, `wan_interface`, `ebpf_enabled`, `log_level`, `inbounds_count`, `groups_count`, `policy_epoch`, `policy_hash`) and config sync state (`generation`, `sync_warning`, `config_in_sync`, `reload_pending`, `last_reload_error`, `last_reload_rolled_back`). |
| `PUT` | `/api/v1/system/log-level` | Body `{"level":"error\|warn\|info\|debug\|trace"}`. Dynamically updates logger verbosity without reloading datapath; emits WS `log_level_changed`. |
| `POST` | `/api/v1/system/reload` | Validates `config.dae` and queues async reload (`202 {"queued":true}` or `409` if queue busy). |

### Runtime Metrics

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/metrics` | O(1) real-time counters (`ts`, `upload_rate`, `download_rate`, `upload_total`, `download_total`, `active_connections`, `tcp_connections`, `udp_sessions`, `offloaded_tcp`, `rss_bytes`, `heap_bytes`, `fd_count`, `goroutines`, `dns`, `fakeip`, `bpf_overflow`, `tcp_conn_panic_count`, `udp_reply_drought`). Rate uses monotonic 1s sample ring; `/proc` stats cached 2s; heap read STW-free via `runtime/metrics`. |
| `GET` | `/api/v1/metrics/history` | Downsampled rate series. Query: `window` (seconds, default `1800`, max `3600`), `points` (default `180`, max `720`). Returns `{"window_sec", "points", "samples": [{"ts", "up", "down"}]}`. |

### Proxy Groups

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/groups` | Returns `{"groups": [...], "display_names": {...}}`. Each member includes `name`, optional `display_name`, `kind` (`"node"` \| `"group"`), `protocol`, safe `endpoint` (`host:port` without credentials or URIs), `alive`, `latency_ms`, `admission`, `reason`, `checked_at`, and per-transport `probes` (`tcp4`, `tcp6`, `dns4`, `dns6`). |
| `PUT` | `/api/v1/groups/{name}/selection` | Body `{"member":"<name>"}`. Switches fixed group member without reload; emits WS `group_selection_changed`. |
| `POST` | `/api/v1/groups/{name}/probe` | Triggers asynchronous latency checks for `group`. Subject to a **3-second per-group cooldown** (`429 probe_cooldown` + `Retry-After: 3`). |

### Connections & Interruption

IDs carry explicit namespaces: `"tcp:<id>"`, `"udp:<id>"`, `"in-udp:<id>"`.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/connections` | Active flows (500ms snapshot coalesced + per-flow monotonic rate smoothing). Query filters: `network` (`tcp`/`udp`/`tcp4`/etc.), `outbound`, `dialer`, `src_ip` (IP/CIDR/substring), `dst_ip`, `domain`, `mac`, `process`, `inbound`, `rule` (index or substring), `q` (multi-field search), `limit` (default `256`, max `1024`), `sort` (`total\|upload\|download\|upload_rate\|download_rate\|duration\|start_time`), `order` (`desc\|asc`). |
| `DELETE` | `/api/v1/connections/{id}` | Aborts one active userspace flow (including Sockmap-offloaded TCP, UDP endpoints, and inbound UDP relays). Returns `200 {"closed":true,"id":"..."}` or `404`. Emits closed flow (`close_reason: "aborted"`) and WS `connections_closed`. |
| `POST` | `/api/v1/connections/close` | Batch-closes active flows matching JSON filter body (`network`, `outbound`, `dialer`, `src_ip`, `dst_ip`, `domain`, `mac`, `process`, `inbound`, `rule`, `q`, `all`). Requires either at least one filter field or `"all": true` (`400 filter_required` otherwise). Returns `{"closed": N}`. |
| `GET` | `/api/v1/connections/kernel` | Kernel bypass/conntrack flows. Query: `limit`, `src`, `mac`, `resolve_domains` (`true\|1`, default `false`). Read-only, cached >= 2s with CPU-time backoff. |
| `DELETE` | `/api/v1/connections/kernel` | Best-effort kernel 5-tuple termination. Body: `{"protocol":"tcp\|udp","src_ip":"...","src_port":N,"dst_ip":"...","dst_port":N}`. Attempts userspace tuple abort + Netlink `conntrack` delete + BPF `conn_state_map` delete. Returns honest status `{"conntrack_deleted","bpf_state_deleted","userspace_closed","warning"}`. |

#### `AdminConnection` Schema

```json
{
  "id": "tcp:42",
  "network": "tcp4",
  "inbound": "",
  "src_ip": "192.168.1.20",
  "src_port": 51234,
  "dst_ip": "198.51.100.10",
  "dst_port": 443,
  "target": "api.example.com:443",
  "domain": "api.example.com",
  "mac": "3e:0a:a5:de:ae:a3",
  "process": "curl",
  "rule": {
    "index": 12,
    "raw": "domain(suffix:example.com) -> proxy",
    "origin": "config",
    "match_index": 15
  },
  "outbound": "proxy",
  "dialer": "hk-node-01",
  "policy": "min_moving_avg",
  "offloaded": true,
  "start_time": "2026-11-19T02:00:00Z",
  "duration_ms": 4210,
  "upload": 10240,
  "download": 98304,
  "upload_rate": 2048,
  "download_rate": 16384
}
```

### Closed Flows & Multi-Dimensional Traffic Accounting

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/flows/closed` | Queries the bounded `2048`-entry closed-flow ring (newest-first). Supports all `connections` filter query params + `limit` (default `100`, max `500`). Each entry includes `seq`, `end_time`, and `close_reason` (`normal\|aborted\|reload\|shutdown`). |
| `GET` | `/api/v1/traffic/summary` | Overlays cumulative closed-flow totals with currently active flows across 8 dimensions (`by_src_ip`, `by_mac`, `by_domain`, `by_rule`, `by_outbound`, `by_dialer`, `by_inbound`, `by_process`). Map cardinality is bounded per dimension; excess entries fold into `"other"`. Query: `top` (default `50`, max `200`). |
| `POST` | `/api/v1/traffic/reset` | Resets cumulative traffic summary counters and records active-flow byte baselines so ongoing connections only contribute post-reset traffic. Emits WS `traffic_reset`. |

### Configuration, Inbounds & Sources

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/inbounds` | Returns `inbounds` list with `origin`, `editable`, runtime state, and `ETag` header (passwords omitted; stat-cached). |
| `PUT` | `/api/v1/inbounds` | Updates `config.dae` `inbound {}` section atomically with reload + rollback. Honors optional `If-Match` header (`412 precondition_failed`). |
| `GET` | `/api/v1/config` | Returns `{"config","routing"}` with `admin_secret` redacted (`***`) and `node` URIs stripped, plus `ETag` (stat-cached). |
| `PUT` | `/api/v1/config` | Updates `global`/`routing` in `config.dae` and/or `routing.dae` atomically; auto-rolls back `.admin-last-good` if validation, reload queueing, or async reload fails. Honors optional `If-Match` (`412`). |
| `GET` | `/api/v1/config/effective` | Read-only merged running config (`?format=text` for plain text, default JSON). |
| `GET` | `/api/v1/sources` | Returns `{"mihomo","geodata","rule_providers","sync_warning"}`. |
| `POST` | `/api/v1/sources/refresh` | Refreshes remote rule providers, Mihomo sources, and GeoData caches; queues reload if changed. Returns `409 refresh_in_progress` on concurrent calls. |

### Logs & Diagnostics

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/logs` | Reads the in-memory `1024`-entry structured ring buffer (no disk log file reads; credentials/URIs scrubbed). Query: `limit` (default `200`, max `500`), `level` (`error\|warn\|info\|debug\|trace`), `after_seq`. Returns `{"entries": [...], "latest_seq": N}`. |
| `GET` | `/api/v1/debug/quality` | Dialer quality status + `recovery_diagnostics`. Query: `group`, `host`. |
| `GET` | `/api/v1/debug/capture` | Observation capture snapshot. Query: `after`. |
| `GET` | `/api/v1/debug/evidence` | Observation evidence snapshot. Query: `after`. |
| `GET` | `/api/v1/debug/udp-recovery` | UDP recovery diagnostics snapshot. Query: `after`, `process`. |

---

## 4. Multiplexed WebSocket (`/api/v1/ws`)

One authenticated WebSocket multiplexes all live topics. Idle efficiency is enforced:
- Max `16` concurrent clients (`503` when exceeded).
- `Origin` header (when present) must match `admin_cors_origins` (`403` otherwise).
- Each client has a bounded `64`-frame outbound queue; slow consumers drop frames rather than stalling samplers or the datapath.
- **Zero idle overhead**: topic sampler goroutines start only when total subscribers transition `0 -> 1` and exit immediately on `1 -> 0`.

### Handshake & First-Frame Auth

1. Connect to `ws://<admin_listen>/api/v1/ws` (or `wss://...` through a reverse proxy).
2. Within **3 seconds**, send the auth frame (never pass secret in the URL):
   ```json
   {"type": "auth", "token": "<admin_secret>"}
   ```
3. Server responds with either:
   - `{"type": "auth_ok", "version": "v1"}`
   - `{"type": "auth_error", "code": "unauthorized", "message": "..."}` (or `"rate_limited"`) followed by close `4001`.

### Client Frames

- **Subscribe**:
  ```json
  {"type": "sub", "topic": "metrics", "interval_ms": 1000}
  ```
  Supported `topic` values:
  - `metrics` (`interval_ms`: default `1000`, clamped `500..10000`)
  - `connections` (`interval_ms`: default `1000`, clamped `500..10000`; optional `filter`, `limit`, `sort`, `order`)
  - `groups` (`interval_ms`: default `5000`, clamped `1000..30000`)
  - `logs` (event-driven; optional `level`: `error|warn|info|debug|trace`)
  - `flows` (event-driven closed flows; optional `filter`)
  - `events` (event-driven control-plane events)
- **Unsubscribe**: `{"type": "unsub", "topic": "connections"}`
- **Heartbeat**: `{"type": "ping", "id": "1"}` -> `{"type": "pong", "id": "1", "ts": ...}`

### Server Frames

- **Topic Data**: `{"type": "data", "topic": "metrics", "ts": 1763517600000, "seq": 12, "data": {...}}`
- **Event Push** (`topic: "events"`): `{"type": "event", "topic": "events", "ts": ..., "seq": ..., "event": "<name>", "data": {...}}`
  - Events emitted: `reload_started`, `reload_succeeded`, `reload_failed`, `group_selection_changed`, `log_level_changed`, `config_updated`, `inbounds_updated`, `sources_refreshed`, `connections_closed`, `traffic_reset`.
- **Frame Error**: `{"type": "error", "code": "<code>", "message": "<msg>"}`
