<template>
  <span class="text-xs text-base-content/45 tabular-nums" :title="title"
    >{{ label }} · {{ count }} 条</span
  >
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useNow } from '@vueuse/core'
import { activeConnections } from '@/store/connections'
import { prettyBytesHelper } from '@/helper/utils'
import { state } from './client'
const props = defineProps<{ name: string }>()
const now = useNow({ interval: 1000 })
const rows = computed(() =>
  activeConnections.value.filter((row) => row.fdae?.outbound === props.name),
)
const count = computed(() => rows.value.length)
const unknown = computed(
  () =>
    !state.connectionsAt ||
    !!state.connectionsError ||
    now.value.getTime() - state.connectionsAt > 10000 ||
    rows.value.some((row) => row.rateKnown === false),
)
const label = computed(() =>
  unknown.value
    ? '速率待采样'
    : '样本 ↓ ' +
      prettyBytesHelper(
        rows.value.reduce((sum, row) => sum + row.downloadSpeed, 0),
      ) +
      '/s',
)
const title =
  '已加载连接按实际出站归属汇总，不包含被截断或筛选掉的连接；嵌套组不重复归账。'
</script>
