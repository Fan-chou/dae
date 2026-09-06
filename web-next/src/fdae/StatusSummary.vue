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
    <p v-if="state.status?.sync_warning" class="mt-2 text-warning">
      {{ state.status.sync_warning }}
    </p>
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useNow } from '@vueuse/core'
import { state } from './client'
const now = useNow({ interval: 1000 })
const stale = computed(
  () => state.statusAt && now.value.getTime() - state.statusAt > 10000,
)
</script>
