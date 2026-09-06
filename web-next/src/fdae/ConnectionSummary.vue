<template>
  <section class="base-container p-3" aria-label="连接分类汇总">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 class="text-sm font-medium">连接分类汇总</h2>
      <select
        v-model="dimension"
        class="select select-sm"
        aria-label="汇总维度"
      >
        <option value="source">源 IP</option>
        <option value="mac">MAC</option>
        <option value="outbound">出站</option>
        <option value="destination">目标</option>
      </select>
    </div>
    <p class="mt-2 text-xs text-base-content/50">
      当前快照 {{ state.loaded }} /
      {{ state.total }} 条；流量为这些连接的累计值，沿用连接页服务端筛选。{{
        state.truncated ? '快照已截断。' : ''
      }}
    </p>
    <div class="mt-3 max-h-80 overflow-auto">
      <table class="table table-sm w-full">
        <thead>
          <tr>
            <th>分类</th>
            <th class="text-right">连接</th>
            <th class="text-right">上传</th>
            <th class="text-right">下载</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.name">
            <td class="max-w-44 truncate font-mono text-xs" :title="row.name">
              {{ row.name }}
            </td>
            <td class="text-right tabular-nums">{{ row.count }}</td>
            <td class="whitespace-nowrap text-right tabular-nums">
              {{ prettyBytesHelper(row.upload) }}
            </td>
            <td class="whitespace-nowrap text-right tabular-nums">
              {{ prettyBytesHelper(row.download) }}
            </td>
          </tr>
          <tr v-if="!rows.length">
            <td colspan="4" class="text-center text-base-content/50">
              暂无连接
            </td>
          </tr>
        </tbody>
        <tfoot v-if="rows.length">
          <tr>
            <th>快照合计</th>
            <th class="text-right">{{ totals.count }}</th>
            <th class="whitespace-nowrap text-right">
              {{ prettyBytesHelper(totals.upload) }}
            </th>
            <th class="whitespace-nowrap text-right">
              {{ prettyBytesHelper(totals.download) }}
            </th>
          </tr>
        </tfoot>
      </table>
    </div>
  </section>
</template>
<script setup lang="ts">
import { computed, ref } from 'vue'
import { activeConnections } from '@/store/connections'
import { prettyBytesHelper } from '@/helper/utils'
import { state } from './client'
const dimension = ref<'source' | 'mac' | 'outbound' | 'destination'>('source')
const rows = computed(() => {
  const groups = new Map<
    string,
    { name: string; count: number; upload: number; download: number }
  >()
  for (const connection of activeConnections.value) {
    const raw = connection.fdae
    if (!raw) continue
    const name =
      (dimension.value === 'source'
        ? connection.metadata.sourceIP
        : dimension.value === 'mac'
          ? raw.mac
          : dimension.value === 'outbound'
            ? raw.outbound
            : raw.domain || connection.metadata.destinationIP) || '未提供'
    const row = groups.get(name) || { name, count: 0, upload: 0, download: 0 }
    row.count++
    row.upload += raw.upload
    row.download += raw.download
    groups.set(name, row)
  }
  return [...groups.values()].sort(
    (a, b) => b.download - a.download || a.name.localeCompare(b.name),
  )
})
const totals = computed(() =>
  rows.value.reduce(
    (sum, row) => ({
      count: sum.count + row.count,
      upload: sum.upload + row.upload,
      download: sum.download + row.download,
    }),
    { count: 0, upload: 0, download: 0 },
  ),
)
</script>
