<template>
  <div
    class="relative flex size-full flex-col overflow-hidden"
    :style="isMiddleScreen ? { paddingBottom: dockTop + 'px' } : undefined"
  >
    <ConnectionCtrl />
    <ConnectionScope />
    <template v-if="isConnectionCard">
      <ConnectionCardList />
    </template>
    <template v-else>
      <ConnectionTable />
    </template>
    <ConnectionDetails />
  </div>
</template>

<script setup lang="ts">
import ConnectionScope from '@/fdae/ConnectionScope.vue'
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
import { computed, onScopeDispose, watch } from 'vue'

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
