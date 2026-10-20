<template>
  <div
    class="bg-base-150 grid w-full grid-cols-2 gap-x-2 gap-y-2.5 rounded-lg p-3"
  >
    <div
      v-for="stat in statistics"
      :key="stat.label"
      class="flex flex-col items-start gap-0.5"
    >
      <div class="text-base-content/45 text-[11px] leading-tight">
        {{ stat.raw ? stat.label : $t(stat.label) }}
      </div>
      <div class="text-base-content/80 text-sm leading-tight tabular-nums">
        {{ stat.value }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  kernelTrackedBytes,
  totalConnectionCount,
} from '@/fdae/kernelConnections'
import { prettyBytesHelper } from '@/helper/utils'
import {
  activeConnections,
  downloadTotal,
  uploadTotal,
} from '@/store/connections'
import { downloadSpeed, memory, uploadSpeed } from '@/store/overview'
import { computed } from 'vue'

const statistics = computed<
  { label: string; value: string | number; raw?: boolean }[]
>(() => [
  {
    label: 'connections',
    value: totalConnectionCount() ?? '—',
  },
  {
    label: 'memoryUsage',
    value: prettyBytesHelper(memory.value, { binary: true }),
  },
  {
    label: 'download',
    value: prettyBytesHelper(downloadTotal.value),
  },
  {
    label: 'dlSpeed',
    value: `${prettyBytesHelper(downloadSpeed.value)}/s`,
  },
  {
    label: 'upload',
    value: prettyBytesHelper(uploadTotal.value),
  },
  {
    label: 'ulSpeed',
    value: `${prettyBytesHelper(uploadSpeed.value)}/s`,
  },
  ...kernelRows(),
])

// 累计总量只含 fdae；内核转发另列当前正在跟踪的连接的字节。
function kernelRows() {
  const tracked = kernelTrackedBytes()
  return tracked
    ? [
        {
          label: '内核转发下载',
          raw: true,
          value: prettyBytesHelper(tracked.down),
        },
        {
          label: '内核转发上传',
          raw: true,
          value: prettyBytesHelper(tracked.up),
        },
      ]
    : []
}
</script>
