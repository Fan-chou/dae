<template>
  <div class="base-container px-4 py-3 text-xs text-base-content/60">
    <div class="flex flex-wrap gap-x-5 gap-y-2">
      <span
        >fdae
        {{
          state.status?.running
            ? '运行中'
            : state.status
              ? '未运行'
              : '等待状态'
        }}</span
      >
      <span
        >TCP {{ state.status?.active_connections ?? '—' }} · UDP
        {{ state.status?.udp_sessions ?? '—' }}</span
      >
      <span>文件描述符 {{ state.status?.fd_count ?? '—' }}</span>
      <span
        >LAN {{ state.status?.lan_interface?.join(', ') || '—' }} · WAN
        {{ state.status?.wan_interface?.join(', ') || '—' }}</span
      >
      <span v-if="mihomo?.enabled" :class="mihomoClass"
        >Mihomo 源 · {{ mihomoText }}</span
      >
      <span v-if="state.statusAt">{{
        new Date(state.statusAt).toLocaleTimeString()
      }}</span>
    </div>
    <p class="mt-2">
      全局流量与连接数来自 fdae 运行状态；仅包含 fdae
      跟踪的流量。分类图表基于已加载连接（{{ state.loaded }}/{{
        state.total
      }}），受列表上限、筛选和采样影响。
    </p>
    <p v-if="state.statusError || stale" class="mt-2 text-warning">
      {{ state.statusError || '状态已过期' }} · 以下保留上次数据
    </p>
    <p v-if="detail" class="mt-2 break-all text-warning">{{ detail }}</p>
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useNow } from '@vueuse/core'
import { state } from './client'
const now = useNow({ interval: 1000 })
const mihomo = computed(() => state.status?.mihomo)
const mihomoText = computed(() => {
  const m = mihomo.value
  if (!m) return ''
  if (m.degraded) return '不可用，已不带路由源运行，正在重试'
  if (m.used_last_good) return '使用上一份有效副本'
  return `${m.nodes} 节点 · ${m.rules} 规则`
})
const mihomoClass = computed(() => {
  const m = mihomo.value
  return m?.degraded ? 'text-error' : m?.used_last_good ? 'text-warning' : ''
})
// The Mihomo line above says what happened in the panel's language; this is
// the reason behind it as the daemon reported it.
const detail = computed(() =>
  mihomo.value?.enabled ? mihomo.value.error : state.status?.sync_warning,
)
const stale = computed(
  () => state.statusAt && now.value.getTime() - state.statusAt > 10000,
)
</script>
