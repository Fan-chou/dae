<template>
  <div
    class="relative flex size-full flex-col overflow-hidden"
    :style="isMiddleScreen ? { paddingBottom: dockTop + 'px' } : undefined"
  >
    <LogsCtrl />
    <LogStatus />
    <LogsTable v-if="isLogTable" :logs="renderLogs" />
    <VirtualScroller
      v-else
      :data="renderLogs"
      :size="80"
      :reserve-controls="false"
    >
      <template v-slot="{ item }: { item: LogWithSeq }">
        <LogsCard :log="item" />
      </template>
    </VirtualScroller>
  </div>
</template>

<script setup lang="ts">
import LogStatus from '@/fdae/LogStatus.vue'
import VirtualScroller from '@/components/common/VirtualScroller.vue'
import LogsCtrl from '@/components/controls/LogsCtrl.tsx'
import LogsCard from '@/components/logs/LogsCard.vue'
import LogsTable from '@/components/logs/LogsTable.vue'
import { dockTop } from '@/composables/paddingViews'
import { isMiddleScreen } from '@/helper/utils'
import { LIST_DISPLAY_STYLE } from '@/constant'
import { toSearchRegex } from '@/helper/search'
import {
  logFilter,
  logFilterEnabled,
  logFilterRegex,
  logTypeFilter,
  logs,
} from '@/store/logs'
import { logDisplayStyle } from '@/store/settings'
import type { LogWithSeq } from '@/types'
import { computed } from 'vue'

const isLogTable = computed(
  () => logDisplayStyle.value === LIST_DISPLAY_STYLE.TABLE,
)
const renderLogs = computed(() => {
  let renderLogs = logs.value
  const searchRegex = toSearchRegex(logFilter.value)

  if (logFilter.value || logTypeFilter.value) {
    renderLogs = logs.value.filter((log) => {
      if (
        searchRegex &&
        !searchRegex.testAny([log.payload, log.time, log.type])
      ) {
        return false
      }

      if (
        logTypeFilter.value &&
        !(
          log.payload.includes(logTypeFilter.value) ||
          log.type === logTypeFilter.value
        )
      ) {
        return false
      }

      return true
    })
  }

  if (logFilterEnabled.value && logFilterRegex.value) {
    const hideRegex = toSearchRegex(logFilterRegex.value)

    if (hideRegex) {
      renderLogs = renderLogs.filter((log) => {
        return !hideRegex.testAny([log.payload, log.time, log.type])
      })
    }
  }

  return renderLogs
})
</script>
