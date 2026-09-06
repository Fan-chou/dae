<!--
  列表里表示「这个后端此刻通不通」的一点。
  和 ReachabilityIndicator 是两件事:那个是表单里的整行诊断说明(为什么不通、怎么改),
  这个只在一行里占一个字宽,用来扫视一列后端。
-->
<template>
  <span class="flex flex-none items-center gap-1.5">
    <span
      v-if="status === 'checking'"
      class="loading loading-spinner loading-xs opacity-50"
    ></span>
    <span
      v-else
      class="h-2 w-2 rounded-full"
      :class="dotClass"
    ></span>
    <span
      v-if="showLatency && status === 'online' && latency"
      class="text-base-content/50 text-xs tabular-nums"
    >
      {{ latency }} ms
    </span>
  </span>
</template>

<script setup lang="ts">
import type { ReachabilityStatus } from '@/composables/backendReachability'
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    status: ReachabilityStatus
    latency?: number
    showLatency?: boolean
  }>(),
  {
    latency: 0,
    showLatency: true,
  },
)

const dotClass = computed(() => {
  switch (props.status) {
    case 'online':
      // 用低饱和的 backend-online 而不是 success:这点常驻在列表里,亮绿太吵。
      return 'bg-backend-online'
    case 'offline':
      return 'bg-error'
    default:
      return 'bg-base-content/25'
  }
})
</script>
