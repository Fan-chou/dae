<template>
  <input
    v-model.trim="source"
    class="input input-sm"
    aria-label="源 IP"
    placeholder="源 IP（全量筛选）"
  />
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { sourceIPFilter } from '@/store/connections'
const source = computed({
  get: () => sourceIPFilter.value?.[0] || '',
  set: (value: string) => {
    sourceIPFilter.value = value ? [value] : null
  },
})
</script>
