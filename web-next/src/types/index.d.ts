// 只剩 Clash REST/WS 一种后端。字段保留是为了让旧记录的迁移与 URL 参数解析
// 有个明确的落点,不必在每处都写字面量。
export type BackendType = 'fdae'

export type Backend = {
  type: BackendType
  protocol: string
  host: string
  port: string
  secondaryPath: string
  password: string // Clash secret
  uuid: string
  label?: string
  disableUpgradeCore?: boolean
  disableTunMode?: boolean
}

export type Config = {
  port: number
  'socks-port': number
  'redir-port': number
  'tproxy-port': number
  'mixed-port': number
  'allow-lan': boolean
  'bind-address': string
  mode: string
  'mode-list': string[]
  modes: string[]
  'log-level': string
  ipv6: boolean
  tun: {
    enable: boolean
  }
}

export type History = {
  time: string
  delay: number
}[]

export type Proxy = {
  fdaePolicy?: string
  fdaeAutomatic?: boolean
  fdaeAdmission?: string
  fdaeReason?: string
  name: string
  type: string
  history: History
  extra: Record<
    string,
    {
      alive: boolean
      history: History
    }
  >
  all?: string[]
  udp?: boolean
  xudp?: boolean
  now: string
  fixed?: string
  icon: string
  hidden?: boolean
  selectable?: boolean
  testUrl?: string
  'dialer-proxy'?: string
  'provider-name'?: string
}

export type SubscriptionInfo = {
  Download?: number
  Upload?: number
  Total?: number
  Expire?: number
}

export type ProxyProvider = {
  subscriptionInfo?: SubscriptionInfo
  name: string
  proxies: Proxy[]
  testUrl: string
  updatedAt: string
  vehicleType: string
}

export type Rule = {
  type: string
  payload: string
  proxy: string
  size: number
  uuid: string
  // sing-box-reFind
  disabled?: boolean
  // mihomo
  index: number
  extra?: {
    disabled: false
    hitAt: string
    hitCount: number
    missAt: string
    missCount: number
  }
}

export type RuleProvider = {
  behavior: string
  format: string
  name: string
  ruleCount: number
  type: string
  updatedAt: string
  vehicleType: string
}

export type ClashConnectionRawMessage = {
  id: string
  download: number
  upload: number
  chains: string[]
  rule: string
  rulePayload: string
  start: string | number
  metadata: {
    destinationGeoIP: string
    destinationIP: string
    destinationIPASN: string
    destinationPort: string
    dnsMode: string
    dscp: number
    host: string
    inboundIP: string
    inboundName: string
    inboundPort: string
    inboundUser: string
    network: string
    process: string
    processPath: string
    remoteDestination: string
    sniffHost: string
    sourceGeoIP: string
    sourceIP: string
    sourceIPASN: string
    sourcePort: string
    specialProxy: string
    specialRules: string
    type: string
    uid: number
    smartBlock: string
  }
}

export type ConnectionRawMessage = ClashConnectionRawMessage

export type Connection = ConnectionRawMessage & {
  fdae?: import('../fdae/types').AdminConnection
  rateKnown?: boolean
  downloadSpeed: number
  uploadSpeed: number
}

export type Log = {
  sourceTime?: string
  type: LOG_LEVEL
  payload: string
}

export type LogWithSeq = Log & { seq: number; time: string }

export type DNSQuery = {
  AD: boolean
  CD: boolean
  RA: boolean
  RD: boolean
  TC: boolean
  status: number
  Question: {
    Name: string
    Qtype: number
    Qclass: number
  }[]
  Answer?: {
    TTL: number
    data: string
    name: string
    type: number
  }[]
}

export type SourceIPLabel = {
  key: string
  label: string
  id: string
  scope?: string[]
}

// smart core
export interface NodeRank {
  Name: string
  Rank: string
  Weight: number
}

// honk core —— GET /stats 的用户态运行时快照。
// 该端点还会返回就绪池 / warm 资源 / TCP / Score / UDP-NFQUEUE 等内部计量
// (完整 schema 见 honk 仓库 doc/en/reference/api.md 的「GET /stats」一节),
// 面板只取其中的出站统计,故这里只声明用得到的部分。
export type HonkStats = {
  outbounds: {
    name: string
    totalConns: number
    activeConns: number
    upload: number
    download: number
    errors: number
  }[]
}
