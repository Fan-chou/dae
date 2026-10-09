#!/usr/bin/env node
// A stand-in for fdae's admin API (/v1) with believable data, for developing
// and screenshotting the dashboard without a router. Shapes follow
// src/fdae/types.ts and cmd/admin_server.go. No dependencies.
//
//   node scripts/mock-admin.mjs            # listens on 0.0.0.0:2025
//   MOCK_PORT=2026 MOCK_SECRET=secret node scripts/mock-admin.mjs
//
// Connect the dashboard to host:port with the secret (default "mock").
import http from 'node:http'

const port = Number(process.env.MOCK_PORT || 2025)
const secret = process.env.MOCK_SECRET || 'mock'
const startedAt = Date.now()

const nodes = [
  ['HK_HK_01', '🇭🇰 香港 01 | IEPL', 38],
  ['HK_HK_02', '🇭🇰 香港 02 | IEPL', 41],
  ['JP_01', '🇯🇵 日本 01', 72],
  ['JP_02', '🇯🇵 日本 02', 80],
  ['US_LAX', '🇺🇸 洛杉矶 Hysteria2', 152],
  ['SG_01', '🇸🇬 新加坡 01', 66],
  ['TW_01', '🇹🇼 台湾 01', null],
]
const alive = (latency) => latency !== null
const member = (n) => ({
  name: n[0],
  alive: alive(n[2]),
  latency_ms: n[2],
  admission: alive(n[2]) ? (n[2] > 150 ? 'degraded' : 'alive') : 'dead',
  reason: alive(n[2]) ? (n[2] > 150 ? 'rtt' : 'ok') : 'not_alive',
})
const selection = { Rocket_Proxy: 'HK_HK_01', Media: 'US_LAX' }
const groups = () => [
  {
    name: 'Rocket_Proxy',
    selectable: true,
    policy: 'fixed(0)',
    selected: selection.Rocket_Proxy,
    selection_members: ['Auto', 'HK_HK_01', 'HK_HK_02', 'JP_01', 'SG_01', 'direct'],
    members: [
      { name: 'Auto', alive: true, latency_ms: 38, admission: 'alive', reason: 'ok' },
      ...nodes.slice(0, 4).map(member),
      member(nodes[5]),
      { name: 'direct', alive: true, latency_ms: null },
    ],
  },
  {
    name: 'Auto',
    selectable: false,
    policy: 'url_test',
    selected: 'HK_HK_01',
    selection_members: [],
    members: nodes.map(member),
  },
  {
    name: 'Media',
    selectable: true,
    policy: 'fixed(0)',
    selected: selection.Media,
    selection_members: ['US_LAX', 'JP_01', 'JP_02', 'HK_HK_01'],
    members: [nodes[4], nodes[2], nodes[3], nodes[0]].map(member),
  },
  {
    name: 'Fallback',
    selectable: false,
    policy: 'fallback',
    selected: 'HK_HK_01',
    selection_members: [],
    members: nodes.slice(0, 3).map(member),
  },
  {
    name: 'node_TW_01',
    selectable: true,
    policy: 'fixed(0)',
    selected: 'TW_01',
    selection_members: ['TW_01'],
    members: [member(nodes[6])],
  },
]

let total = { up: 812_345_678, down: 14_562_345_678 }
const status = () => {
  const t = (Date.now() - startedAt) / 1000
  const down = Math.max(0, 1_800_000 + 1_400_000 * Math.sin(t / 6) + Math.random() * 300_000)
  const up = Math.max(0, 260_000 + 180_000 * Math.sin(t / 9 + 1) + Math.random() * 60_000)
  total = { up: total.up + up * 2, down: total.down + down * 2 }
  const samples = []
  for (let i = 59; i >= 0; i--) {
    const s = t - i * 2
    samples.push({
      ts: Date.now() - i * 2000,
      up: Math.round(Math.max(0, 260_000 + 180_000 * Math.sin(s / 9 + 1))),
      down: Math.round(Math.max(0, 1_800_000 + 1_400_000 * Math.sin(s / 6))),
    })
  }
  return {
    version: 'unstable-20261009.r1292.b938e6a6',
    running: true,
    lan_interface: ['br-lan'],
    wan_interface: ['eth1'],
    upload_rate: Math.round(up),
    download_rate: Math.round(down),
    upload_total: Math.round(total.up),
    download_total: Math.round(total.down),
    active_connections: 184 + Math.round(10 * Math.sin(t / 4)),
    udp_sessions: 37,
    rss_bytes: 96_468_992,
    fd_count: 412,
    traffic_samples: samples,
  }
}

const domains = ['www.google.com', 'github.com', 'api.openai.com', 'i.ytimg.com', 'cdn.jsdelivr.net', 'push.apple.com', 'www.bilibili.com', 'static.xx.fbcdn.net', 'registry.npmjs.org', 'music.163.com']
const connections = () => {
  const list = []
  for (let i = 0; i < 60; i++) {
    const d = domains[i % domains.length]
    const out = i % 7 === 0 ? 'direct' : i % 5 === 0 ? 'Media' : 'Rocket_Proxy'
    list.push({
      id: 'c' + i,
      network: i % 4 === 0 ? 'udp' : 'tcp',
      src: `192.168.124.${130 + (i % 12)}:${40000 + i * 13}`,
      dst: `${104 + (i % 40)}.${16 + (i % 200)}.${i % 250}.${(i * 7) % 250}:${i % 4 === 0 ? 443 : 443}`,
      domain: i % 9 === 0 ? '' : d,
      mac: `aa:bb:cc:00:00:${(i % 12).toString(16).padStart(2, '0')}`,
      outbound: out,
      dialer: out === 'direct' ? 'direct' : nodes[i % 4][0],
      policy: out === 'Rocket_Proxy' ? 'fixed(0)' : out === 'Media' ? 'fixed(0)' : 'direct',
      start: new Date(Date.now() - (i + 1) * 9000).toISOString(),
      upload: 1200 + i * 5100,
      download: 38000 + i * 91000,
    })
  }
  return { scope: 'active', total: 184, truncated: false, connections: list }
}

const logLines = () =>
  [
    'time="2026-10-09T22:41:03+08:00" level=info msg="[Mihomo] routing source loaded" nodes=7 groups=5 rules=412',
    'time="2026-10-09T22:41:04+08:00" level=warning msg="skip Mihomo rule at index 17 line 59 (\\"GEOIP,CN,DIRECT\\"): unsupported Mihomo atom \\"GEOIP\\""',
    'time="2026-10-09T22:41:08+08:00" level=info msg="Group alive" group=Rocket_Proxy node=HK_HK_01 latency=38ms',
    'time="2026-10-09T22:42:11+08:00" level=warning msg="node became degraded" group=Auto node=US_LAX reason=rtt',
    'time="2026-10-09T22:43:50+08:00" level=error msg="dial failed" node=TW_01 err="i/o timeout"',
    'time="2026-10-09T22:44:02+08:00" level=info msg="[RuleProvider] refreshed" name=ads changed=false',
  ].concat(Array.from({ length: 40 }, (_, i) => `time="2026-10-09T22:${45 + (i % 14)}:${String(i).padStart(2, '0')}+08:00" level=info msg="connection established" src=192.168.124.13${i % 9} dst=${domains[i % domains.length]}:443 outbound=Rocket_Proxy`))

let configFiles = {
  config: `global {
    log_level: info
    tproxy_port: 12345
    wan_interface: eth1
    lan_interface: br-lan
    admin_listen: '0.0.0.0:2025'
}

mihomo {
    routing_subscription: 'https://example.invalid/sub'
    interval: 1h
}
`,
  routing: `routing {
    dip(224.0.0.0/3, 'ff00::/8') -> must_direct
    fallback: direct
}
`,
}

const effective = () => ({
  loaded_at: new Date().toISOString(),
  mihomo: {
    enabled: true,
    source: 'https://example.invalid/sub',
    checked_at: new Date().toISOString(),
    used_last_good: false,
    nodes: 7,
    groups: 5,
    rules: 412,
    providers: 6,
    skipped_rules: [
      { kind: 'skip', index: 17, line: 59, rule: 'GEOIP,CN,DIRECT', reason: 'unsupported Mihomo atom "GEOIP"' },
      { kind: 'ignore', index: 22, line: 64, rule: 'IN-PORT,7890,PROXY', reason: 'atom "IN-PORT"' },
    ],
    unused_providers: ['spare'],
    ignored_fields: ['mixed-port', 'dns'],
  },
  subscriptions: 0,
  nodes: nodes.map((n, i) =>
    i === 0 && false
      ? null
      : { tag: n[0], display_name: n[1], endpoint: `${['ss', 'ss', 'hysteria2', 'anytls', 'hysteria2', 'ss', 'socks5'][i]} ${n[0].toLowerCase()}.example.com:${8388 + i}`, origin: 'mihomo' },
  ).concat([{ tag: 'mine', endpoint: 'socks5 192.168.124.222:1080', origin: 'config' }]),
  groups: [
    { name: 'hand', policy: 'min_moving_avg', members: ['name(mine)'], origin: 'config' },
    { name: 'Rocket_Proxy', display_name: '🚀 节点选择', policy: 'fixed(0)', members: ['group(Auto)', 'name(HK_HK_01)', 'name(HK_HK_02)', 'group(direct)'], origin: 'mihomo' },
    { name: 'Auto', display_name: '♻️ 自动选择', policy: 'url_test', members: nodes.map((n) => `name(${n[0]})`), options: ['url=http://www.gstatic.com/generate_204', 'interval=5m0s'], origin: 'mihomo' },
    { name: 'node_TW_01', display_name: '🇹🇼 台湾 01', policy: 'fixed(0)', members: ['name(TW_01)'], wrapper: true, origin: 'mihomo' },
  ],
  rule_providers: [
    { name: 'ads', type: 'http', behavior: 'domain', source: 'https://example.invalid/ads.yaml', interval: '1h0m0s', origin: 'mihomo' },
    { name: 'cn_ip', type: 'http', behavior: 'ipcidr', source: 'https://example.invalid/cn.yaml', interval: '24h0m0s', origin: 'mihomo' },
  ],
  rules: [
    { index: 1, text: 'dip(224.0.0.0/3, ff00::/8) -> direct(must)', origin: 'config' },
    { index: 2, text: 'ruleset(ads) -> block', origin: 'mihomo' },
    { index: 3, text: 'domain(suffix: openai.com, suffix: anthropic.com) -> Media', origin: 'mihomo' },
    { index: 4, text: '(ip_no_resolve(10.0.0.0/8) && dport(443)) -> Rocket_Proxy', origin: 'mihomo' },
    { index: 5, text: 'ruleset(cn_ip) -> direct', origin: 'mihomo' },
  ],
  fallback: { outbound: 'Rocket_Proxy', origin: 'mihomo' },
})
const effectiveText = (e) => `mock effective config\n\nnodes (${e.nodes.length})\n` + e.nodes.map((n) => `  [${n.origin}] ${n.tag}  ${n.endpoint}`).join('\n') + '\n'

const send = (res, code, body, type = 'application/json') => {
  res.writeHead(code, {
    'Content-Type': type + (type.startsWith('text') ? '; charset=utf-8' : ''),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, X-Kdae-Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
  })
  res.end(typeof body === 'string' ? body : JSON.stringify(body))
}

http
  .createServer((req, res) => {
    const url = new URL(req.url, 'http://x')
    if (req.method === 'OPTIONS') return send(res, 204, '')
    const auth = req.headers.authorization || req.headers['x-kdae-authorization'] || ''
    if (auth !== 'Bearer ' + secret) return send(res, 401, { error: 'unauthorized' })
    const p = url.pathname
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      if (p === '/v1/status') return send(res, 200, { ...status(), generation: 'generation-2106476694' })
      if (p === '/v1/groups') return send(res, 200, { groups: groups() })
      const g = p.match(/^\/v1\/groups\/([^/]+)(\/delay)?$/)
      if (g) {
        const name = decodeURIComponent(g[1])
        if (g[2]) return send(res, 202, { queued: true })
        if (req.method === 'PUT') {
          try { selection[name] = JSON.parse(body).member } catch { return send(res, 400, { error: 'invalid json' }) }
          return send(res, 200, { ok: true })
        }
      }
      if (p === '/v1/connections') return send(res, 200, connections())
      if (p === '/v1/logs') return send(res, 200, { lines: logLines() })
      if (p === '/v1/config') {
        if (req.method === 'PUT') {
          try { configFiles = { ...configFiles, ...JSON.parse(body) } } catch { return send(res, 400, { error: 'invalid json' }) }
          return send(res, 200, { queued: true })
        }
        return send(res, 200, configFiles)
      }
      if (p === '/v1/config/effective') {
        const e = effective()
        return url.searchParams.get('format') === 'text' ? send(res, 200, effectiveText(e), 'text/plain') : send(res, 200, e)
      }
      if (p === '/v1/reload') return send(res, 202, { queued: true })
      return send(res, 404, { error: 'not found' })
    })
  })
  .listen(port, '0.0.0.0', () => console.log(`mock fdae admin on :${port} (secret "${secret}")`))
