<template>
  <div
    class="hover:bg-base-200/40 flex flex-col gap-1 px-3 py-2.5 text-sm transition-colors"
  >
    <div class="flex items-center gap-2">
      <span
        class="text-base-content/40 text-xs tabular-nums"
        :style="{ minWidth: `${(seqWithPadding.length + 1) * 0.62}em` }"
      >
        {{ seqWithPadding }}
      </span>
      <span
        class="text-[11px] tracking-wide uppercase"
        :class="colorMapForType[log.type as keyof typeof colorMapForType]"
      >
        <HighlightText :text="log.type" :filter="logFilter" />
      </span>
      <div class="flex-1"></div>
      <span class="text-base-content/40 text-xs tabular-nums">
        <HighlightText :text="log.time" :filter="logFilter" />
      </span>
    </div>
    <div class="w-full leading-snug break-words">
      <HighlightText :text="entry.message" :filter="logFilter" ansi />
    </div>
    <details class="mt-1 text-xs">
      <summary class="cursor-pointer text-base-content/45">
        {{
          entry.fields.length
            ? entry.fields.length + ' 个字段 · 原始日志'
            : '原始日志'
        }}
      </summary>
      <dl
        v-if="entry.fields.length"
        class="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1"
      >
        <template v-for="(field, index) in entry.fields" :key="index">
          <dt class="text-base-content/45">{{ field.key }}</dt>
          <dd class="break-all font-mono">
            <HighlightText :text="field.value" :filter="logFilter" />
          </dd>
        </template>
      </dl>
      <button class="btn btn-ghost btn-xs mt-2" @click="copyRaw">
        复制原始日志
      </button>
      <pre
        class="mt-1 whitespace-pre-wrap break-all font-mono text-base-content/55"
        >{{ log.payload }}</pre>
    </details>
  </div>
</template>

<script setup lang="ts">
import { parseLogEntry } from '@/fdae/log-entry'
import { showNotification } from '@/helper/notification'
import HighlightText from '@/components/common/HighlightText.vue'
import { useBounceOnVisible } from '@/composables/bouncein'
import { LOG_LEVEL } from '@/constant'
import { logFilter } from '@/store/logs'
import type { LogWithSeq } from '@/types'
import { computed } from 'vue'

const props = defineProps<{
  log: LogWithSeq
}>()

const entry = computed(() => parseLogEntry(props.log.payload))
async function copyRaw() {
  try {
    await navigator.clipboard.writeText(props.log.payload)
    showNotification({
      content: '已复制原始日志',
      type: 'alert-success',
      timeout: 2000,
    })
  } catch {
    showNotification({
      content: '复制失败，可展开原始日志手动复制',
      type: 'alert-error',
      timeout: 3000,
    })
  }
}

const seqWithPadding = computed(() => {
  return props.log.seq.toString().padStart(2, '0')
})

const colorMapForType = {
  [LOG_LEVEL.Trace]: 'text-success',
  [LOG_LEVEL.Debug]: 'text-accent',
  [LOG_LEVEL.Info]: 'text-info',
  [LOG_LEVEL.Warning]: 'text-warning',
  [LOG_LEVEL.Error]: 'text-error',
  [LOG_LEVEL.Fatal]: 'text-error',
  [LOG_LEVEL.Panic]: 'text-error',
}

useBounceOnVisible()
</script>
