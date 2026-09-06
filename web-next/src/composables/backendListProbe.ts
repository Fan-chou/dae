// 后端列表的批量可达性探测。
//
// 切换后端之前就该知道要切过去的那个是不是活的 —— 一个个点过去试,试到第三个
// 才发现都连不上,这个代价本来不必由用户付。所以列表一露面就并发探一轮。
//
// 只在列表可见时探测:关掉面板立刻 abort,不做常驻轮询。
import { probeBackend } from '@/assembly/backend'
import { backendProbe } from '@/assembly/version'
import type { ReachabilityStatus } from '@/composables/backendReachability'
import { backendList } from '@/store/setup'
import { computed, onScopeDispose, ref, watch, type Ref } from 'vue'

const PROBE_TIMEOUT = 8000

export type BackendProbeState = {
  status: ReachabilityStatus
  latency: number
}

export const useBackendListProbe = (enabled: Ref<boolean>) => {
  const results = ref<Record<string, BackendProbeState>>({})

  let controller: AbortController | null = null
  // 世代号:上一轮还在飞的时候面板又开了一次,旧那轮的结论必须丢掉。
  let generation = 0

  const cancel = () => {
    controller?.abort()
    controller = null
  }

  const run = () => {
    cancel()

    const current = ++generation
    controller = new AbortController()
    const signal = controller.signal
    const targets = backendList.value

    results.value = Object.fromEntries(
      targets.map((backend) => [backend.uuid, { status: 'checking' as const, latency: 0 }]),
    )

    // 一个个试太慢,同时打出去,谁先回来先亮谁。
    targets.forEach(async (backend) => {
      const result = await probeBackend(backend, PROBE_TIMEOUT, signal)

      if (current !== generation) return

      results.value[backend.uuid] = result.ok
        ? { status: 'online', latency: result.latency }
        : { status: 'offline', latency: 0 }
    })
  }

  watch(
    enabled,
    (isEnabled) => {
      if (isEnabled) {
        run()
      } else {
        cancel()
        generation++
      }
    },
    { immediate: true },
  )

  onScopeDispose(cancel)

  // 当前后端的结论会话里已经有了(assembly/version 的 backendProbe),直接借用 ——
  // 面板一打开这一行就是确定的,不必陪着别的行一起转圈。
  const stateOf = computed(() => (uuid: string): BackendProbeState => {
    const probe = backendProbe.value

    if (probe?.uuid === uuid) {
      if (probe.status === 'connected') return { status: 'online', latency: probe.latency }
      if (probe.status === 'failed') return { status: 'offline', latency: 0 }
      return { status: 'checking', latency: 0 }
    }

    return results.value[uuid] ?? { status: 'idle', latency: 0 }
  })

  return { stateOf, refresh: run }
}
