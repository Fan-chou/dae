import { reactive } from 'vue'
import { activeBackend } from '@/store/setup'
import { fetchInbounds, stateRevision } from './client'
import type { AdminInbound } from './types'

// What the backend reports about its inbounds. Shared by the inbound page and
// the connection filter so both read the same snapshot.
export const inboundState = reactive({
  list: [] as AdminInbound[],
  editable: false,
  at: 0,
  error: '',
})

let request: Promise<void> | undefined
let context = ''

export function refreshInbounds(): Promise<void> {
  const backend = activeBackend.value
  const key = JSON.stringify(backend)
  if (request && key === context) return request
  context = key
  const revision = stateRevision
  const current = fetchInbounds(backend)
    .then((body) => {
      if (
        revision !== stateRevision ||
        key !== JSON.stringify(activeBackend.value)
      )
        return
      inboundState.list = body.inbounds || []
      inboundState.editable = !!body.editable
      inboundState.at = Date.now()
      inboundState.error = ''
    })
    .catch((error: Error) => {
      if (key === JSON.stringify(activeBackend.value))
        inboundState.error = String(error.message || error)
    })
    .finally(() => {
      if (request === current) request = undefined
    })
  request = current
  return current
}

export function resetInbounds() {
  Object.assign(inboundState, { list: [], editable: false, at: 0, error: '' })
}

export const inboundStateLabel: Record<string, string> = {
  listening: '监听中',
  pending: '已保存，等待重载',
  failed: '启动失败',
}
export const inboundOriginLabel: Record<string, string> = {
  config: 'config.dae',
  routing: 'routing.dae',
  managed: '其他文件（如 LuCI 生成）',
}
