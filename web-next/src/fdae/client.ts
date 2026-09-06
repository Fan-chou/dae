import { reactive, shallowRef } from 'vue'
import { activeBackend } from '@/store/setup'
import { getUrlFromBackend } from '@/helper/utils'
import type { Backend } from '@/types'
import type {
  AdminStatus,
  AdminGroup,
  AdminConnectionsSnapshot,
  AdminConfig,
} from './types'

export const capabilities = Object.freeze({
  disconnect: false,
  blockConnection: false,
  providers: false,
  tun: false,
  coreUpgrade: false,
  dnsMaintenance: false,
  singleNodeProbe: false,
  groupProbe: true,
  configEditor: true,
  hotReload: true,
  serverSourceFilter: true,
})
export const state = reactive({
  status: null as AdminStatus | null,
  statusAt: 0,
  statusError: '',
  connectionsAt: 0,
  connectionsError: '',
  total: 0,
  loaded: 0,
  truncated: false,
  scope: '',
  devicePairs: [] as { ip: string; mac: string }[],
  filter: { outbound: '', mac: '', limit: 1024 },
  groups: [] as AdminGroup[],
  groupsAt: 0,
  groupsError: '',
  logsAt: 0,
  logsError: '',
})
export async function request<T>(
  path: string,
  init: RequestInit = {},
  backend = activeBackend.value,
): Promise<T> {
  if (!backend) throw new Error('请先连接 fdae')
  const response = await fetch(
    getUrlFromBackend(backend).replace(/\/$/, '') + '/v1' + path,
    {
      ...init,
      signal: init.signal ?? AbortSignal.timeout(12000),
      headers: {
        Authorization: 'Bearer ' + backend.password,
        'X-Kdae-Authorization': 'Bearer ' + backend.password,
        'Content-Type': 'application/json',
        ...init.headers,
      },
    },
  )
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.error || 'HTTP ' + response.status)
  }
  return response.json()
}
export let stateRevision = 0
export function resetState() {
  stateRevision++
  Object.assign(state, {
    status: null,
    statusAt: 0,
    statusError: '',
    connectionsAt: 0,
    connectionsError: '',
    total: 0,
    loaded: 0,
    truncated: false,
    scope: '',
    devicePairs: [],
    groups: [],
    groupsAt: 0,
    groupsError: '',
    logsAt: 0,
    logsError: '',
  })
  statusContext = ''
  statusRequest = undefined
}
let statusRequest: Promise<AdminStatus> | undefined
let statusContext = ''
export function fetchStatus(
  backend = activeBackend.value,
): Promise<AdminStatus> {
  const revision = stateRevision
  const context = JSON.stringify(backend)
  if (context === statusContext && statusRequest) return statusRequest
  if (
    context === statusContext &&
    state.status &&
    Date.now() - state.statusAt < 500
  )
    return Promise.resolve(state.status)
  statusContext = context
  const promise = request<AdminStatus>('/status', {}, backend)
    .then((body) => {
      if (
        revision === stateRevision &&
        JSON.stringify(activeBackend.value) === context
      ) {
        state.status = body
        state.statusAt = Date.now()
        state.statusError = ''
      }
      return body
    })
    .catch((error) => {
      if (
        revision === stateRevision &&
        JSON.stringify(activeBackend.value) === context
      )
        state.statusError = String(error.message || error)
      throw error
    })
    .finally(() => {
      if (statusRequest === promise) statusRequest = undefined
    })
  statusRequest = promise
  return promise
}
export function polling<T>(
  read: (backend: Backend) => Promise<T>,
  interval = 2000,
) {
  const data = shallowRef<T>()
  const backend = activeBackend.value
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  async function poll() {
    if (!backend || stopped) return
    try {
      if (document.visibilityState !== 'hidden') {
        const result = await read(backend)
        if (!stopped) data.value = result
      }
    } catch {
      /* Each domain publishes its own stale/error state. */
    }
    if (!stopped) timer = setTimeout(poll, interval)
  }
  void poll()
  return {
    data,
    close: () => {
      stopped = true
      clearTimeout(timer)
    },
  }
}
export async function fetchGroups() {
  const backend = activeBackend.value,
    revision = stateRevision
  const body = await request<{ groups: AdminGroup[] }>(
    '/groups',
    {},
    backend,
  ).catch((error) => {
    if (revision === stateRevision) state.groupsError = String(error.message)
    throw error
  })
  if (revision !== stateRevision || backend !== activeBackend.value)
    throw new Error('后端已切换')
  state.groups = body.groups || []
  state.groupsAt = Date.now()
  state.groupsError = ''
  return state.groups
}
export const fetchConnections = (query: URLSearchParams, backend?: Backend) =>
  request<AdminConnectionsSnapshot>('/connections?' + query, {}, backend)
export const fetchConfig = () => request<AdminConfig>('/config')
export const saveConfig = (body: AdminConfig) =>
  request<{ queued: boolean }>('/config', {
    method: 'PUT',
    body: JSON.stringify(body),
  })
export const reload = () =>
  request<{ queued: boolean }>('/reload', { method: 'POST' })
export const selectMember = async (group: string, name: string) => {
  const current = state.groups.find((item) => item.name === group)
  if (!current?.selectable)
    throw new Error('此策略由 fdae 自动选择节点，不支持手动切换')
  return request('/groups/' + encodeURIComponent(group), {
    method: 'PUT',
    body: JSON.stringify({ member: name }),
  })
}
export async function probeGroup(group: string) {
  const revision = stateRevision
  await request('/groups/' + encodeURIComponent(group) + '/delay', {
    method: 'POST',
  })
  const deadline = Date.now() + 12000
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1000))
    if (revision !== stateRevision) return
    await fetchGroups()
  }
}
export function unsupported(): never {
  throw new Error('fdae 未提供此操作')
}
