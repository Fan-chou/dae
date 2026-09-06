import type { Connection } from '@/types'
import type { AdminConnection } from './types'
import type { ConnectionsSnapshot } from '@/assembly/connections/accessor'
import { activeBackend } from '@/store/setup'
import { sourceIPFilter } from '@/store/connections'
import {
  fetchConnections,
  fetchStatus,
  polling,
  state,
  stateRevision,
} from './client'
export function endpoint(value: string) {
  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(value || '')
  const pair = /^([^:]+):(\d+)$/.exec(value || '')
  const parsed = bracket || pair
  const match =
    parsed && (!parsed[2] || Number(parsed[2]) <= 65535) ? parsed : null
  return match
    ? { host: match[1]!, port: match[2] || '' }
    : { host: value === 'invalid AddrPort' ? '' : value || '', port: '' }
}
export function mapConnection(row: AdminConnection, scope: string): Connection {
  const src = endpoint(row.src),
    dst = endpoint(row.dst)
  return {
    id: scope + ':' + row.id + ':' + (row.start || ''),
    upload: row.upload,
    download: row.download,
    chains: [row.dialer, row.outbound].filter(Boolean) as string[],
    rule: row.policy || '',
    rulePayload: '',
    start: row.start || '',
    downloadSpeed: 0,
    uploadSpeed: 0,
    fdae: row,
    rateKnown: false,
    metadata: {
      destinationGeoIP: '',
      destinationIP: dst.host,
      destinationIPASN: '',
      destinationPort: dst.port,
      dnsMode: '',
      dscp: 0,
      host: dst.host,
      inboundIP: '',
      inboundName: '',
      inboundPort: '',
      inboundUser: '',
      network: row.network.startsWith('tcp') ? 'tcp' : 'udp',
      process: '',
      processPath: '',
      remoteDestination: '',
      sniffHost: row.domain || '',
      sourceGeoIP: '',
      sourceIP: src.host,
      sourceIPASN: '',
      sourcePort: src.port,
      specialProxy: '',
      specialRules: '',
      type: row.network,
      uid: 0,
      smartBlock: '',
    },
  }
}
export function subscribeConnections() {
  const revision = stateRevision
  let previous = new Map<string, Connection>()
  let previousContext = '',
    previousAt = 0
  return polling<ConnectionsSnapshot>(async (backend) => {
    const source =
      sourceIPFilter.value?.length === 1 ? sourceIPFilter.value[0]! : ''
    const query = new URLSearchParams({ limit: String(state.filter.limit) })
    if (source) query.set('src', source)
    if (state.filter.outbound) query.set('outbound', state.filter.outbound)
    if (state.filter.mac) query.set('mac', state.filter.mac)
    const context = query.toString()
    try {
      const [snapshot, status] = await Promise.all([
        fetchConnections(query, backend),
        fetchStatus(backend),
      ])
      if (revision !== stateRevision || backend !== activeBackend.value)
        throw new Error('后端已切换')
      const currentSource =
        sourceIPFilter.value?.length === 1 ? sourceIPFilter.value[0]! : ''
      if (
        source !== currentSource ||
        query.get('outbound') !== (state.filter.outbound || null) ||
        query.get('mac') !== (state.filter.mac || null) ||
        query.get('limit') !== String(state.filter.limit)
      )
        throw new Error('筛选条件已更新，等待下一次快照')
      const scope = snapshot.scope || status.generation || ''
      const nextContext = context + ':' + scope
      const resetHistory = previousContext !== nextContext
      if (resetHistory) {
        previous.clear()
        previousAt = 0
      }
      const now = Date.now(),
        elapsed = (now - previousAt) / 1000
      const active = (snapshot.connections || []).map((row) => {
        const result = mapConnection(row, scope),
          old = previous.get(result.id)
        if (
          old &&
          previousAt &&
          elapsed > 0 &&
          result.upload >= old.upload &&
          result.download >= old.download
        ) {
          result.downloadSpeed = (result.download - old.download) / elapsed
          result.uploadSpeed = (result.upload - old.upload) / elapsed
          result.rateKnown = true
        }
        return result
      })
      const ids = new Set(active.map((row) => row.id))
      const closed = snapshot.truncated
        ? []
        : [...previous.values()].filter((row) => !ids.has(row.id))
      previous = new Map(active.map((row) => [row.id, row]))
      previousAt = now
      previousContext = nextContext
      // Preserve discovered pairs while narrowing the list, but never cross runtime scopes.
      const unfiltered = !source && !query.has('mac') && !query.has('outbound')
      const pairs = new Map<string, { ip: string; mac: string }>()
      if (!unfiltered && scope === state.scope) {
        for (const pair of state.devicePairs)
          pairs.set(JSON.stringify(pair), pair)
      }
      for (const row of active) {
        const ip = row.metadata.sourceIP
        const mac = row.fdae?.mac?.toLowerCase() || ''
        if (!ip) continue
        const pair = { ip, mac: mac === '00:00:00:00:00:00' ? '' : mac }
        pairs.set(JSON.stringify(pair), pair)
      }
      state.devicePairs = [...pairs.values()].slice(-2048)
      Object.assign(state, {
        connectionsAt: now,
        connectionsError: '',
        total: snapshot.total,
        loaded: active.length,
        truncated: !!snapshot.truncated,
        scope,
      })
      return {
        active,
        closed,
        resetHistory,
        uploadTotal: status.upload_total,
        downloadTotal: status.download_total,
      }
    } catch (error) {
      if (revision === stateRevision && backend === activeBackend.value)
        state.connectionsError = String((error as Error).message)
      throw error
    }
  })
}
