import type { Connection } from '@/types'
import type { AdminConnection } from './types'
import type { ConnectionsSnapshot } from '@/assembly/connections/accessor'
import { activeBackend } from '@/store/setup'
import { sourceIPFilter } from '@/store/connections'
import {
  fetchConnections,
  fetchKernelConnections,
  fetchStatus,
  polling,
  state,
  stateRevision,
} from './client'
import {
  includeKernel,
  kernelState,
  mapKernelConnection,
  summarizeKernel,
  withKernelRates,
  type KernelRow,
} from './kernelConnections'
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
      inboundName: row.inbound || '',
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
  // Kernel flows are tracked on their own: they never become "closed"
  // connections (a flow leaving the top-N or conntrack is not a close).
  let kernelPrev = new Map<string, { upload: number; download: number }>()
  let kernelAt = 0,
    kernelKey = '',
    kernelConnections: Connection[] = []
  let kernelSums = { upSpeed: 0, downSpeed: 0, upBytes: 0, downBytes: 0 }
  return polling<ConnectionsSnapshot>(async (backend) => {
    const source =
      sourceIPFilter.value?.length === 1 ? sourceIPFilter.value[0]! : ''
    const query = new URLSearchParams({ limit: String(state.filter.limit) })
    if (source) query.set('src', source)
    if (state.filter.outbound) query.set('outbound', state.filter.outbound)
    if (state.filter.mac) query.set('mac', state.filter.mac)
    if (state.filter.inbound) query.set('inbound', state.filter.inbound)
    const context = query.toString()
    // Kernel flows are all "direct" and never come in through an inbound, so
    // any other outbound filter or an inbound filter excludes them; the source
    // and MAC filters are applied by the server.
    const wantKernel =
      includeKernel.value &&
      !state.filter.inbound &&
      (!state.filter.outbound || state.filter.outbound === 'direct')
    const kernelQuery = new URLSearchParams({
      limit: String(state.filter.limit),
    })
    if (source) kernelQuery.set('src', source)
    if (state.filter.mac) kernelQuery.set('mac', state.filter.mac)
    const kernelClosed: Connection[] = []
    try {
      const kernelRequest = wantKernel
        ? fetchKernelConnections(kernelQuery, backend).then(
            (value) => ({ value }),
            (error: Error) => ({ error }),
          )
        : undefined
      const [snapshot, status] = await Promise.all([
        fetchConnections(query, backend),
        fetchStatus(backend),
      ])
      const kernelResult = await kernelRequest
      if (revision !== stateRevision || backend !== activeBackend.value)
        throw new Error('后端已切换')
      const currentSource =
        sourceIPFilter.value?.length === 1 ? sourceIPFilter.value[0]! : ''
      if (
        source !== currentSource ||
        query.get('outbound') !== (state.filter.outbound || null) ||
        query.get('mac') !== (state.filter.mac || null) ||
        query.get('inbound') !== (state.filter.inbound || null) ||
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
      // Rates use the time the server read the counters, not when the
      // response arrived, so network and queueing jitter do not skew them.
      // Older backends send no timestamp; fall back to the receive time.
      const now = snapshot.snapshot_at_ms ?? Date.now(),
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
      const unfiltered =
        !source &&
        !query.has('mac') &&
        !query.has('outbound') &&
        !query.has('inbound')
      const pairs = new Map<string, { ip: string; mac: string }>()
      if (!unfiltered && scope === state.scope) {
        for (const pair of state.devicePairs)
          pairs.set(JSON.stringify(pair), pair)
      }
      if (!wantKernel) {
        kernelPrev = new Map()
        kernelAt = 0
        kernelKey = ''
        kernelConnections = []
        kernelSums = { upSpeed: 0, downSpeed: 0, upBytes: 0, downBytes: 0 }
        kernelState.at = 0
        kernelState.error = ''
      } else if (kernelResult && 'error' in kernelResult) {
        // A failing conntrack read must not take the proxy list down with it.
        kernelState.error = String(kernelResult.error.message)
        kernelConnections = []
        kernelSums = { upSpeed: 0, downSpeed: 0, upBytes: 0, downBytes: 0 }
        kernelAt = 0
      } else if (kernelResult) {
        const ks = kernelResult.value
        const key = kernelQuery.toString() + ':' + scope
        if (key !== kernelKey) {
          kernelPrev = new Map()
          kernelAt = 0
          kernelConnections = []
          kernelKey = key
        }
        const at = ks.snapshot_at_ms ?? Date.now()
        Object.assign(kernelState, {
          error: ks.error || '',
          available: ks.available,
          accounting: ks.accounting,
          total: ks.total,
          truncated: ks.truncated,
          scanMs: ks.scan_ms ?? 0,
          excluded: ks.excluded,
        })
        // The server shares one scan between requests: an unchanged
        // timestamp means no new data, so keep the rows and their rates.
        if (at !== kernelAt) {
          const rows: KernelRow[] = withKernelRates(
            ks.connections || [],
            kernelPrev,
            kernelAt,
            at,
          )
          kernelPrev = new Map(
            rows.map((r) => [r.id, { upload: r.upload, download: r.download }]),
          )
          kernelAt = at
          const next = rows.map((row) =>
            mapKernelConnection(row, ks.accounting, (item) =>
              mapConnection(item, scope),
            ),
          )
          // A flow that left a complete (untruncated) snapshot has ended or
          // gone idle; one that fell off a truncated list may still be live.
          if (!ks.truncated) {
            const alive = new Set(next.map((row) => row.id))
            for (const old of kernelConnections) {
              if (alive.has(old.id)) continue
              // The same tuple can come back later; keep the closed copy's
              // id distinct so it does not mark the new flow as closed.
              kernelClosed.push({
                ...old,
                id: old.id + '#' + at,
                downloadSpeed: 0,
                uploadSpeed: 0,
              })
            }
          }
          kernelConnections = next
          kernelSums = summarizeKernel(rows, ks.accounting)
        }
        kernelState.loaded = kernelConnections.length
        kernelState.at = Date.now()
      }
      // Overview numbers are global, so they only take the kernel side
      // when the kernel query was not narrowed by a source or MAC filter.
      Object.assign(kernelState, kernelSums, {
        global: wantKernel && !!kernelState.at && !source && !state.filter.mac,
      })
      for (const row of active.concat(kernelConnections)) {
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
        active: kernelConnections.length
          ? active.concat(kernelConnections)
          : active,
        closed: kernelClosed.length ? closed.concat(kernelClosed) : closed,
        resetHistory,
        // Prefer the totals read together with the flow list; /v1/status is a
        // separate request taken at a slightly different moment.
        uploadTotal: snapshot.upload_total ?? status.upload_total,
        downloadTotal: snapshot.download_total ?? status.download_total,
      }
    } catch (error) {
      if (revision === stateRevision && backend === activeBackend.value)
        state.connectionsError = String((error as Error).message)
      throw error
    }
  })
}
