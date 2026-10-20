<template>
  <div
    class="relative flex size-full flex-col overflow-hidden"
    :style="isMiddleScreen ? { paddingBottom: dockTop + 'px' } : undefined"
  >
    <div class="border-base-content/10 flex shrink-0 gap-1 border-b px-3 py-1">
      <button
        class="btn btn-sm"
        :class="kernelView ? 'btn-ghost' : 'btn-primary'"
        @click="kernelView = false"
      >
        代理连接
      </button>
      <button
        class="btn btn-sm"
        :class="kernelView ? 'btn-primary' : 'btn-ghost'"
        title="由内核直接转发、不经过 fdae 用户态的连接"
        @click="kernelView = true"
      >
        内核转发
      </button>
    </div>
    <KernelConnections v-if="kernelView" />
    <template v-else>
      <ConnectionCtrl />
      <ConnectionScope />
      <template v-if="isConnectionCard">
        <ConnectionCardList />
      </template>
      <template v-else>
        <ConnectionTable />
      </template>
      <ConnectionDetails />
    </template>
  </div>
</template>

<script setup lang="ts">
import ConnectionScope from '@/fdae/ConnectionScope.vue'
import KernelConnections from '@/fdae/KernelConnections.vue'
import { setConnectionGeoIPEnabled } from '@/api/connectionGeoip'
import ConnectionCardList from '@/components/connections/ConnectionCardList.vue'
import ConnectionDetails from '@/components/connections/ConnectionDetails.vue'
import ConnectionTable from '@/components/connections/ConnectionTable.vue'
import ConnectionCtrl from '@/components/controls/ConnectionCtrl.tsx'
import { dockTop } from '@/composables/paddingViews'
import { isMiddleScreen } from '@/helper/utils'
import { CONNECTIONS_TABLE_ACCESSOR_KEY } from '@/constant'
import { connectionCardGroupKey } from '@/store/connections'
import {
  connectionCardLines,
  connectionTableColumns,
  isConnectionCard,
} from '@/store/settings'
import { computed, onScopeDispose, ref, watch } from 'vue'

// 内核转发视图每次进入才挂载、才会轮询 conntrack；默认进入连接页不触发。
const kernelView = ref(false)

const isGeoIPVisible = computed(() =>
  isConnectionCard.value
    ? connectionCardLines.value.some((line) =>
        line.includes(CONNECTIONS_TABLE_ACCESSOR_KEY.GeoIP),
      )
    : connectionTableColumns.value.includes(
        CONNECTIONS_TABLE_ACCESSOR_KEY.GeoIP,
      ),
)

watch(isGeoIPVisible, setConnectionGeoIPEnabled, { immediate: true })
onScopeDispose(() => setConnectionGeoIPEnabled(false))
</script>

<style>
.vjs-tree {
  font-family:
    NotoEmoji,
    Monaco,
    Menlo,
    Consolas,
    Bitstream Vera Sans Mono,
    monospace;
}
.vjs-tree-node.is-highlight,
.vjs-tree-node:hover {
  background-color: var(--color-base-200);
}
</style>
