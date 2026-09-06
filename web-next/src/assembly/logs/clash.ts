import { parseLogEntry } from '@/fdae/log-entry'
import { polling, request, state, stateRevision } from '@/fdae/client'
import type { Log } from '@/types'
import { watch } from 'vue'
import { LOG_LEVEL } from '@/constant'
import type { LogsSubscription } from './types'
export const subscribeLogs = (
  _params: Record<string, string>,
  onBatch: (batch: Log[]) => void,
): LogsSubscription => {
  const revision = stateRevision
  let previous: string[] = []
  const stream = polling(async (backend) =>
    request<{ lines: string[] }>('/logs?n=300', {}, backend).catch((error) => {
      if (revision === stateRevision) state.logsError = String(error.message)
      throw error
    }),
  )
  const stop = watch(stream.data, (body) => {
    if (!body) return
    const lines = body.lines || []
    let overlap = Math.min(previous.length, lines.length)
    while (
      overlap &&
      !previous.slice(-overlap).every((line, i) => line === lines[i])
    )
      overlap--
    const fresh = lines.slice(overlap)
    previous = lines
    state.logsAt = Date.now()
    state.logsError = ''

    onBatch(
      fresh.map((payload) => {
        const entry = parseLogEntry(payload)
        const match = entry.level.toLowerCase()
        const type =
          match === 'warn'
            ? LOG_LEVEL.Warning
            : Object.values(LOG_LEVEL).includes(match as LOG_LEVEL)
              ? (match as LOG_LEVEL)
              : LOG_LEVEL.Info
        const time = entry.time
        return { type, payload, sourceTime: time || '—' }
      }),
    )
  })
  return {
    close: () => {
      stop()
      stream.close()
    },
  }
}
