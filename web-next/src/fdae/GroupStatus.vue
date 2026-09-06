<template>
  <div class="mx-3 mt-2 text-xs text-base-content/50">
    <span
      >健康状态由 fdae
      检测；点击组右侧闪电刷新组检测。自动组按策略选路，连接页显示实际节点。</span
    >
    <span v-if="state.groupsError || stale" class="ml-2 text-warning"
      >{{ state.groupsError || '代理组状态已过期' }} · 保留上次数据</span
    >
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useNow } from '@vueuse/core'
import { state } from './client'
const now = useNow({ interval: 1000 })
const stale = computed(
  () => state.groupsAt && now.value.getTime() - state.groupsAt > 15000,
)
</script>
