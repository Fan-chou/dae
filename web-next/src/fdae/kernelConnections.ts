// 内核转发数据 · 并入连接列表。
// 这些连接由内核直接转发（direct 快速路径），不经过 fdae 用户态，数据来自服务端
// 读取的 conntrack 表。它们与代理连接放在同一张表里，用「转发方」列区分；字节数是
// IP 层（含头部），比代理连接的应用层字节略大。
// 默认打开；关闭「含内核转发」后不再请求，服务端也不会读 conntrack。
import { reactive } from 'vue'
import { useStorage } from '@/helper/storage'
import type { Connection } from '@/types'
import { state } from './client'
import type { AdminConnection, AdminKernelConnection } from './types'

// useStorage 不写入默认值，所以只有主动改过开关的用户才有存档，其余人随默认值走。
export const includeKernel = useStorage('config/fdae-include-kernel', true)

export type KernelRow = AdminKernelConnection & {
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
  // 概览汇总用：当前内核转发的合计速率，以及内核正在跟踪的这些连接的累计字节。
  // global 为真才表示这些数字是全局的（内核查询没被源 IP / MAC 缩小）。
  global: false,
  upSpeed: 0,
  downSpeed: 0,
  upBytes: 0,
  downBytes: 0,
})

// 已加载行的速率和字节合计。速率只算已采到两次样的行；没开计数时字节全是 0，
// 不是真的没流量，所以字节合计留 0 并由界面按 accounting 隐藏。
export function summarizeKernel(rows: KernelRow[], accounting: boolean) {
  let upSpeed = 0,
    downSpeed = 0,
    upBytes = 0,
    downBytes = 0
  for (const row of rows) {
    if (row.rateKnown) {
      upSpeed += row.uploadSpeed
      downSpeed += row.downloadSpeed
    }
    if (accounting) {
      upBytes += row.upload
      downBytes += row.download
    }
  }
  return { upSpeed, downSpeed, upBytes, downBytes }
}

// 内核转发要并入概览汇总时返回它，否则 null。
export function kernelOverview() {
  return kernelState.global && kernelState.available ? kernelState : null
}

type Counters = { upload: number; download: number }

// 用服务端读取计数器的时间算速率；新出现的连接、计数回退（元组复用）时速率
// 不可知，显示「—」而不是编一个值。
export function withKernelRates(
  rows: AdminKernelConnection[],
  previous: Map<string, Counters>,
  previousAt: number,
  at: number,
): KernelRow[] {
  const elapsed = (at - previousAt) / 1000
  return rows.map((row) => {
    const old = previous.get(row.id)
    const known =
      !!old &&
      previousAt > 0 &&
      elapsed > 0 &&
      row.upload >= old.upload &&
      row.download >= old.download
    return {
      ...row,
      uploadSpeed: known ? (row.upload - old!.upload) / elapsed : 0,
      downloadSpeed: known ? (row.download - old!.download) / elapsed : 0,
      rateKnown: known,
    }
  })
}

// 把内核流映射成与代理连接同一形状的 Connection，复用表格/卡片/排序/筛选。
export function mapKernelConnection(
  row: KernelRow,
  accounting: boolean,
  toConnection: (row: AdminConnection) => Connection,
): Connection {
  const base = toConnection({
    id: row.id,
    network: row.network,
    src: row.src,
    dst: row.dst,
    domain: row.domain,
    mac: row.mac,
    // 内核直接转发的流量没有经过 fdae 的出站选择；conntrack 里这类流量按定义
    // 就是直连，所以统一标成 direct（与用户态直连行一致），而不是留空。
    outbound: 'direct',
    dialer: 'direct',
    upload: row.upload,
    download: row.download,
  })
  return {
    ...base,
    id: 'kernel:' + row.id,
    start: '',
    kernel: row,
    uploadSpeed: row.uploadSpeed,
    downloadSpeed: row.downloadSpeed,
    rateKnown: accounting && row.rateKnown,
    bytesUnavailable: !accounting,
  }
}

// 概览里的连接数：fdae 跟踪的 TCP/UDP 会话加上内核直接转发的连接。
export function totalConnectionCount(): number | null {
  if (!state.status) return null
  return (
    (state.status.active_connections ?? 0) +
    (state.status.udp_sessions ?? 0) +
    (kernelOverview()?.total ?? 0)
  )
}

// 内核正在跟踪的连接的累计字节。它不是自启动以来的总量（conntrack 条目过期后
// 就不再统计），所以单独列出，不并进 fdae 的累计总量。
export function kernelTrackedBytes() {
  const kernel = kernelOverview()
  return kernel && kernel.accounting
    ? { up: kernel.upBytes, down: kernel.downBytes }
    : null
}
