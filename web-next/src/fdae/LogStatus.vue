<template>
  <div class="shrink-0 px-3 py-2 text-xs text-base-content/50">
    日志尾部采样，每次最多读取 300 行；高速输出时可能漏过中间行。<span
      v-if="state.logsError || stale"
      class="ml-2 text-warning"
      >{{ state.logsError || '日志已过期' }} · 保留已加载日志</span
    >
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useNow } from '@vueuse/core'
import { state } from './client'
const now = useNow({ interval: 1000 })
const stale = computed(
  () => state.logsAt && now.value.getTime() - state.logsAt > 10000,
)
</script>
