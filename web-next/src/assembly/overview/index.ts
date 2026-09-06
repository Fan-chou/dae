// 组装层 · overview 门面。memory / traffic 统计流统一返回 { data, close } 流;
// honk 的 /stats 没有 WS,走 stats.ts 的轮询。
import { polling, fetchStatus } from '@/fdae/client'

export const fetchMemoryAPI = <T>() =>
  polling<T>(
    async (backend) => ({ inuse: (await fetchStatus(backend)).rss_bytes }) as T,
  )

export const fetchTrafficAPI = <T>() =>
  polling<T>(async (backend) => {
    const status = await fetchStatus(backend)
    return {
      up: status.upload_rate,
      down: status.download_rate,
      upTotal: status.upload_total,
      downTotal: status.download_total,
    } as T
  })

export {
  fetchHonkStats,
  honkStats,
  startHonkStats,
  stopHonkStats,
} from './stats'
