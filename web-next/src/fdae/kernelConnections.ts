// 内核转发视图 · 数据层。
// 这里的流量由内核直接转发（direct 快速路径），不经过 fdae 用户态，数据来自
// 服务端读取的 conntrack 表：字节数是 IP 层（含头部），与连接页的应用层字节
// 不可直接比较，所以视图独立，不与连接页合并。
// 只有内核视图挂载时才会轮询；连接页本身不会触发服务端读 conntrack。
import { reactive } from 'vue'
import type { AdminKernelConnection } from './types'
import { endpoint } from './connections'
import { fetchKernelConnections, polling, stateRevision } from './client'
import { activeBackend } from '@/store/setup'

export type KernelRow = AdminKernelConnection & {
  host: string
  port: string
  uploadSpeed: number
  downloadSpeed: number
  rateKnown: boolean
}

export const kernelState = reactive({
  at: 0,
  error: '',
  available: true,
  accounting: false,
  total: 0,
  loaded: 0,
  truncated: false,
  scanMs: 0,
  excluded: { userspace: 0, dae: 0, inactive: 0, local: 0 },
  filter: { src: '', limit: 256 },
})

type Counters = { upload: number; download: number }

// 用服务端读取计数器的时间算速率；新出现的连接、计数回退（元组复用）或
// 同一快照重复到达时，速率不可知，不显示而不是显示 0。
export function withKernelRates(
  rows: AdminKernelConnection[],
  previous: Map<string, Counters>,
  previousAt: number,
  at: number,
): KernelRow[] {
  const elapsed = (at - previousAt) / 1000
  return rows.map((row) => {
    const { host, port } = endpoint(row.dst)
    const old = previous.get(row.id)
    const known =
      !!old &&
      previousAt > 0 &&
      elapsed > 0 &&
      row.upload >= old.upload &&
      row.download >= old.download
    return {
      ...row,
      host,
      port,
      uploadSpeed: known ? (row.upload - old!.upload) / elapsed : 0,
      downloadSpeed: known ? (row.download - old!.download) / elapsed : 0,
      rateKnown: known,
    }
  })
}

export function subscribeKernelConnections() {
  const revision = stateRevision
  let previous = new Map<string, Counters>()
  let previousAt = 0
  let previousKey = ''
  let last: KernelRow[] = []
  return polling<KernelRow[]>(async (backend) => {
    const query = new URLSearchParams({ limit: String(kernelState.filter.limit) })
    const src = kernelState.filter.src.trim()
    if (src) query.set('src', src)
    const key = query.toString()
    try {
      const snapshot = await fetchKernelConnections(query, backend)
      if (revision !== stateRevision || backend !== activeBackend.value)
        throw new Error('后端已切换')
      if (key !== previousKey) {
        previous = new Map()
        previousAt = 0
        last = []
        previousKey = key
      }
      const at = snapshot.snapshot_at_ms ?? Date.now()
      Object.assign(kernelState, {
        error: snapshot.error || '',
        available: snapshot.available,
        accounting: snapshot.accounting,
        total: snapshot.total,
        truncated: snapshot.truncated,
        scanMs: snapshot.scan_ms ?? 0,
        excluded: snapshot.excluded,
      })
      // 服务端在间隔内复用同一次扫描：快照时间没变就没有新数据。
      if (at === previousAt) return last
      const rows = withKernelRates(
        snapshot.connections || [],
        previous,
        previousAt,
        at,
      )
      previous = new Map(
        rows.map((r) => [r.id, { upload: r.upload, download: r.download }]),
      )
      previousAt = at
      last = rows
      kernelState.loaded = rows.length
      kernelState.at = Date.now()
      return rows
    } catch (error) {
      if (revision === stateRevision && backend === activeBackend.value)
        kernelState.error = String((error as Error).message)
      throw error
    }
  }, 3000)
}
