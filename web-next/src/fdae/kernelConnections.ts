// 内核转发数据 · 并入连接列表。
// 这些连接由内核直接转发（direct 快速路径），不经过 fdae 用户态，数据来自服务端
// 读取的 conntrack 表。它们与代理连接放在同一张表里，用「转发方」列区分；字节数是
// IP 层（含头部），比代理连接的应用层字节略大。
// 默认关闭：只有打开「含内核转发」才会请求，服务端不会读 conntrack。
import { reactive } from 'vue'
import { useStorage } from '@/helper/storage'
import type { Connection } from '@/types'
import type { AdminConnection, AdminKernelConnection } from './types'

export const includeKernel = useStorage('config/fdae-include-kernel', false)

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
})

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
