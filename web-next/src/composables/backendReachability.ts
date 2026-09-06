// 后端可达性的实时探测。
//
// 填表的时候就该知道这个地址通不通,而不是点了提交、等一个 alert 才知道。
// 连接参数一变就重探(带防抖),失败给出诊断过的原因而不是 "Network Error"。
//
// 只认连接参数:标签、各种开关的变化不该把状态打回「检测中」。
import { probeBackend } from '@/assembly/backend'
import { describeProbeFailure } from '@/helper/connectivity'
import { getBackendProbeUrl } from '@/helper/utils'
import type { Backend } from '@/types'
import { computed, onScopeDispose, ref, watch, type Ref } from 'vue'

export type ReachabilityStatus = 'idle' | 'checking' | 'online' | 'offline'

const DEBOUNCE_DELAY = 400
const PROBE_TIMEOUT = 8000

type ReachabilityTarget = Omit<Backend, 'uuid'> | null | undefined

export const useBackendReachability = (form: Ref<ReachabilityTarget>) => {
  const status = ref<ReachabilityStatus>('idle')
  const latency = ref(0)
  const message = ref('')

  // 地址填不全就没什么可探的,停在 idle,别拿半截地址去打请求。
  const target = computed(() => {
    const value = form.value
    if (!value?.protocol || !value.host || !value.port) return null
    return value
  })

  const identity = computed(() => {
    const backend = target.value
    if (!backend) return ''
    return [
      backend.type,
      backend.protocol,
      backend.host,
      backend.port,
      backend.secondaryPath || '',
      backend.password || '',
    ].join('|')
  })

  let controller: AbortController | null = null
  let debounceTimer = -1
  // 世代号:防抖 + 异步诊断中途参数又变了,旧那轮的结论必须丢掉。
  let generation = 0

  const cancel = () => {
    clearTimeout(debounceTimer)
    controller?.abort()
    controller = null
  }

  const run = async () => {
    const backend = target.value
    if (!backend) return

    const current = ++generation
    controller = new AbortController()
    const signal = controller.signal

    const result = await probeBackend({ uuid: '', ...backend }, PROBE_TIMEOUT, signal)

    if (current !== generation) return

    if (result.ok) {
      status.value = 'online'
      latency.value = result.latency
      message.value = ''
      return
    }

    // 诊断要再打一次探测,期间用户完全可能又改了地址,所以回来还得再对一次世代号。
    const detail = await describeProbeFailure(result, getBackendProbeUrl(backend), signal)

    if (current !== generation) return

    status.value = 'offline'
    latency.value = 0
    message.value = detail
  }

  const schedule = (immediate = false) => {
    cancel()

    if (!target.value) {
      generation++
      status.value = 'idle'
      latency.value = 0
      message.value = ''
      return
    }

    status.value = 'checking'
    message.value = ''
    debounceTimer = setTimeout(run, immediate ? 0 : DEBOUNCE_DELAY)
  }

  watch(identity, () => schedule(), { immediate: false })
  // 首次不防抖:进页面时地址通常已经填好(默认值 / 编辑既有后端),没必要空等。
  schedule(true)

  onScopeDispose(cancel)

  return {
    status,
    latency,
    message,
    // 手动重试:同一份参数再探一遍,不受防抖影响。
    retry: () => schedule(true),
  }
}
