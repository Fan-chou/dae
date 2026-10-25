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
      <span
        v-if="inboundState.at && inboundState.list.length"
        :class="inboundClass"
        >入站 {{ inboundSummary }}</span
      >
      <span v-if="mihomo?.enabled" :class="mihomoClass"
        >Mihomo 源 · {{ mihomoText }}</span
      >
      <span v-if="state.statusAt">{{
        new Date(state.statusAt).toLocaleTimeString()
      }}</span>
    </div>
    <p class="mt-2">
      全局连接数与速率 = fdae 运行状态 + 内核转发（读取
      conntrack，开启「含内核转发」时）；累计总量仅含
      fdae，内核转发另列。分类图表基于已加载连接（{{ state.loaded }}/{{
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
import { computed, onBeforeUnmount, onMounted } from 'vue'
import { useNow } from '@vueuse/core'
import { state } from './client'
import { inboundState, refreshInbounds } from './inbounds'
const now = useNow({ interval: 1000 })
const inboundSummary = computed(() => {
  const list = inboundState.list
  const failed = list.filter((i) => i.state === 'failed').length
  const pending = list.filter((i) => i.state === 'pending').length
  const listening = list.filter((i) => i.state === 'listening').length
  return (
    `${listening}/${list.length} 监听中` +
    (pending ? ` · ${pending} 待重载` : '') +
    (failed ? ` · ${failed} 启动失败` : '')
  )
})
const inboundClass = computed(() =>
  inboundState.list.some((i) => i.state === 'failed')
    ? 'text-error'
    : inboundState.list.some((i) => i.state === 'pending')
      ? 'text-warning'
      : '',
)
let inboundTimer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  void refreshInbounds()
  inboundTimer = setInterval(() => {
    if (document.visibilityState !== 'hidden') void refreshInbounds()
  }, 5000)
})
onBeforeUnmount(() => clearInterval(inboundTimer))
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
