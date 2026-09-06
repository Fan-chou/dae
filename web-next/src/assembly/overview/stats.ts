// 组装层 · honk 的运行时快照(GET /stats)。
//
// 与 memory / traffic 不同,honk 没给 /stats 开 WS,只能轮询。状态与轮询生命周期
// 都收在这里,卡片组件只负责 mount / unmount 时开关。
import { fetchHonkStatsAPI } from '@/api/clash'
import { can } from '@/assembly/backend'
import type { HonkStats } from '@/types'
import { shallowRef } from 'vue'

export const honkStats = shallowRef<HonkStats>()

const POLL_INTERVAL = 5000

let timer: ReturnType<typeof setInterval> | undefined

export const fetchHonkStats = async () => {
  if (!can('runtimeStats')) {
    honkStats.value = undefined
    return
  }

  try {
    const { data } = await fetchHonkStatsAPI()

    honkStats.value = data
  } catch {
    // 拉不到就让卡片自己消失,不必打扰用户 —— 这不是他触发的动作。
    honkStats.value = undefined
  }
}

export const startHonkStats = () => {
  if (timer) return

  fetchHonkStats()
  timer = setInterval(fetchHonkStats, POLL_INTERVAL)
}

export const stopHonkStats = () => {
  if (timer) {
    clearInterval(timer)
    timer = undefined
  }
  honkStats.value = undefined
}
