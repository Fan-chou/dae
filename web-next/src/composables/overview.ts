import type { IPInfo } from '@/api/geoip'
import type { IP_INFO_API } from '@/constant'
import { ref } from 'vue'

export type IPCheckResult = {
  api: IP_INFO_API | null
  ip: string[]
  ipWithPrivacy: string[]
  info: IPInfo | null
}

export const ipCheckPrimaryResult = ref<IPCheckResult>({
  api: null,
  ip: [],
  ipWithPrivacy: [],
  info: null,
})
export const ipCheckSecondaryResult = ref<IPCheckResult>({
  api: null,
  ip: [],
  ipWithPrivacy: [],
  info: null,
})

export const getCachedPublicIPInfo = (api: IP_INFO_API) =>
  [ipCheckPrimaryResult.value, ipCheckSecondaryResult.value].find(
    (result) => result.api === api && result.info,
  )?.info ?? null

// 每个目标保存多次测速的结果(ms;0 表示该次失败),用于概览页柱状图展示。
export const baiduLatency = ref<number[]>([])
export const githubLatency = ref<number[]>([])
export const youtubeLatency = ref<number[]>([])
export const cloudflareLatency = ref<number[]>([])
