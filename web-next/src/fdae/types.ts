export type AdminStatus = {
  version?: string
  running?: boolean
  lan_interface?: string[]
  wan_interface?: string[]
  generation?: string
  sync_warning?: string
  mihomo?: EffectiveConfig['mihomo']
  upload_rate?: number
  download_rate?: number
  upload_total?: number
  download_total?: number
  active_connections?: number
  udp_sessions?: number
  rss_bytes?: number
  fd_count?: number
  traffic_samples?: { ts: number; up: number; down: number }[]
}

export type AdminGroupMember = {
  name: string
  alive: boolean
  latency_ms?: number | null
  admission?: 'alive' | 'degraded' | 'dead' | string
  reason?: string
}

export type AdminGroup = {
  name: string
  selectable: boolean
  policy: string
  selected: string
  selection_members: string[]
  members: AdminGroupMember[]
}

export type AdminLogs = {
  lines: string[]
}

export type AdminReload = {
  queued: boolean
}

export type AdminConnection = {
  id: string
  network: string
  src: string
  dst: string
  domain?: string
  mac?: string
  outbound: string
  dialer?: string
  policy?: string
  start?: string
  upload: number
  download: number
}

export type AdminConnectionsSnapshot = {
  scope?: string
  total: number
  truncated: boolean
  connections: AdminConnection[]
  // Server-side read time of the byte counters and process-wide totals read
  // at that same moment. Absent on older backends.
  snapshot_at_ms?: number
  upload_total?: number
  download_total?: number
}

export type ConnectionFilter = {
  outbound?: string
  src?: string
  mac?: string
  limit?: number
}

export type AdminConfig = {
  config: string
  routing: string
}

export type AdminError = {
  error?: string
}

export type EffectiveOrigin = 'config' | 'mihomo'
export type EffectiveConfig = {
  loaded_at: string
  mihomo: {
    enabled: boolean
    source?: string
    checked_at?: string
    used_last_good: boolean
    degraded?: boolean
    error?: string
    nodes: number
    groups: number
    rules: number
    providers: number
    skipped_rules?: {
      kind: string
      index: number
      line: number
      rule: string
      reason: string
    }[]
    unused_providers?: string[]
    ignored_fields?: string[]
  }
  subscriptions: number
  nodes: {
    tag: string
    display_name?: string
    endpoint: string
    origin: EffectiveOrigin
  }[]
  groups: {
    name: string
    display_name?: string
    policy: string
    members: string[]
    options?: string[]
    wrapper?: boolean
    origin: EffectiveOrigin
  }[]
  rule_providers: {
    name: string
    type: string
    behavior: string
    source: string
    interval?: string
    origin: EffectiveOrigin
  }[]
  rules: { index: number; text: string; origin: EffectiveOrigin }[]
  fallback: { outbound: string; origin: EffectiveOrigin }
}

export type AdminKernelConnection = {
  id: string
  network: string
  src: string
  dst: string
  domain?: string
  state?: string
  upload: number
  download: number
  upload_packets?: number
  download_packets?: number
  ttl: number
  offloaded?: boolean
  unreplied?: boolean
}

export type AdminKernelConnectionsSnapshot = {
  available: boolean
  error?: string
  accounting: boolean
  total: number
  truncated: boolean
  excluded: { userspace: number; dae: number; inactive: number; local: number }
  connections: AdminKernelConnection[]
  snapshot_at_ms?: number
  scan_ms?: number
}
