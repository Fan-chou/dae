<template>
  <div class="flex shrink-0 items-center">
    <ProxyIcon
      v-if="icon"
      :icon="icon"
      :margin="iconMargin"
      :size="iconSize"
    />
    <HighlightText
      v-if="filter"
      :text="shown"
      :filter="filter"
    />
    <template v-else>{{ shown }}</template>
    <template v-if="dialerProxy"> ({{ dialerProxy }}) </template>
  </div>
</template>

<script setup lang="ts">
import HighlightText from '@/components/common/HighlightText.vue'
import { proxyMap } from '@/assembly/proxies'
import { computed } from 'vue'
import ProxyIcon from './ProxyIcon.vue'

const props = withDefaults(
  defineProps<{
    name: string
    iconSize?: number
    iconMargin?: number
    filter?: string
  }>(),
  {
    iconSize: 16,
    iconMargin: 4,
    filter: '',
  },
)

import { displayName } from '@/fdae/client'
const shown = computed(() => displayName(props.name))
const node = computed(() => proxyMap.value[props.name])
const icon = computed(() => {
  return node.value?.icon
})
const dialerProxy = computed(() => {
  return node.value?.['dialer-proxy']
})
</script>
