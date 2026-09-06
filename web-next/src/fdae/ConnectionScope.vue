<template>
  <div class="border-base-content/10 shrink-0 border-b px-3 py-2 text-xs">
    <div class="grid grid-cols-2 items-center gap-2 md:flex md:flex-wrap">
      <TextInput
        v-model="source"
        class="min-w-0 w-full md:w-52"
        aria-label="源 IP 筛选"
        placeholder="源 IP"
        :menus="sourceOptions"
        :menu-min-width="300"
        dropdown
        clearable
        title="来源于已加载连接；也可手动输入其他源 IP"
      >
        <template #menu="{ item }">
          <span class="block font-mono text-xs">{{ item }}</span>
          <span class="block text-[11px] text-base-content/50">{{
            sourceMacs.get(item)?.join(' · ') || 'MAC 未提供'
          }}</span>
        </template>
      </TextInput>
      <TextInput
        v-model="state.filter.mac"
        class="min-w-0 w-full md:w-56"
        aria-label="MAC 筛选"
        placeholder="MAC"
        :menus="macOptions"
        :menu-min-width="300"
        dropdown
        clearable
        title="来源于已加载连接；也可手动输入其他 MAC"
      >
        <template #menu="{ item }">
          <span class="block font-mono text-xs">{{ item }}</span>
          <span class="block text-[11px] text-base-content/50">{{
            macSources.get(item)?.join(' · ')
          }}</span>
        </template>
      </TextInput>
      <select
        v-model="state.filter.outbound"
        class="select select-sm w-full min-w-0 md:w-32"
        aria-label="出站筛选"
      >
        <option value="">全部出站</option>
        <option
          v-for="group in state.groups"
          :key="group.name"
          :value="group.name"
        >
          {{ group.name }}
        </option>
        <option value="direct">direct</option>
        <option value="block">block</option>
      </select>
      <select
        v-model.number="state.filter.limit"
        class="select select-sm w-full min-w-0 md:w-25"
        aria-label="加载上限"
      >
        <option v-for="n in [256, 512, 1024]" :key="n" :value="n">
          {{ n }} 条
        </option>
      </select>
      <select
        v-model="groupKey"
        class="select select-sm w-full min-w-0 md:w-32"
        aria-label="连接分组"
      >
        <option value="">不分组</option>
        <option
          v-for="key in CONNECTION_GROUPABLE_KEYS"
          :key="key"
          :value="key"
        >
          {{ $t(key) }}
        </option>
      </select>
      <button class="btn btn-ghost btn-sm" @click="clear">清除筛选</button>
    </div>
    <div
      class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-base-content/55"
      aria-live="polite"
    >
      <span>{{
        isPaused
          ? '显示已暂停'
          : state.connectionsAt
            ? '更新于 ' + new Date(state.connectionsAt).toLocaleTimeString()
            : '等待连接快照'
      }}</span>
      <span
        >匹配 {{ state.connectionsAt ? state.total : '—' }} · 已加载
        {{ state.connectionsAt ? state.loaded : '—' }} · 当前视图
        {{ renderConnections.length }}</span
      >
      <span v-if="state.truncated" class="text-warning"
        >列表已截断，可按源 IP、MAC 或出站缩小范围</span
      >
      <span v-if="state.connectionsError || stale" class="text-warning"
        >{{ state.connectionsError || '快照已过期' }} · 保留上次数据</span
      >
    </div>
  </div>
</template>
<script setup lang="ts">
import TextInput from '@/components/common/TextInput.vue'
import { computed } from 'vue'
import { useNow } from '@vueuse/core'
import {
  CONNECTION_GROUPABLE_KEYS,
  type ConnectionGroupableKey,
} from '@/constant'
import {
  sourceIPFilter,
  connectionCardGroupKey,
  connectionFilter,
  quickFilterEnabled,
  renderConnections,
  isPaused,
} from '@/store/connections'
import { isConnectionCard } from '@/store/settings'
import { useStorage } from '@/helper/storage'
import { state } from './client'
const sourceMacs = computed(() => {
  const result = new Map<string, string[]>()
  for (const { ip, mac } of state.devicePairs) {
    const values = result.get(ip) || []
    if (mac && !values.includes(mac)) values.push(mac)
    result.set(ip, values)
  }
  return result
})
const macSources = computed(() => {
  const result = new Map<string, string[]>()
  for (const { ip, mac } of state.devicePairs) {
    if (!mac) continue
    const values = result.get(mac) || []
    if (!values.includes(ip)) values.push(ip)
    result.set(mac, values)
  }
  return result
})
const sourceOptions = computed(() =>
  [...sourceMacs.value.keys()].sort((a, b) =>
    a.localeCompare(b, undefined, { numeric: true }),
  ),
)
const macOptions = computed(() => [...macSources.value.keys()].sort())
const tableGroups = useStorage<string[]>('config/table-grouping', [])
const source = computed({
  get: () => sourceIPFilter.value?.[0] || '',
  set: (value: string) => {
    sourceIPFilter.value = value.trim() ? [value.trim()] : null
  },
})
const groupKey = computed({
  get: () =>
    isConnectionCard.value
      ? connectionCardGroupKey.value || ''
      : tableGroups.value[0] || '',
  set: (value: string) => {
    connectionCardGroupKey.value = (value ||
      null) as ConnectionGroupableKey | null
    tableGroups.value = value ? [value] : []
  },
})
const now = useNow({ interval: 1000 })
const stale = computed(
  () =>
    state.connectionsAt && now.value.getTime() - state.connectionsAt > 10000,
)
function clear() {
  source.value = ''
  state.filter.mac = ''
  state.filter.outbound = ''
  connectionFilter.value = ''
  quickFilterEnabled.value = false
}
</script>
