<template>
  <div
    class="bg-base-100 top-0 right-0 left-0 z-30 shrink-0 shadow-xs backdrop-blur-xl"
    :class="[
      inline ? 'relative' : isMiddleScreen ? 'fixed' : 'sticky',
      { 'md:bg-base-100/50': !solid },
    ]"
    ref="ctrlsBarRef"
  >
    <slot></slot>
  </div>
</template>
<script lang="ts" setup>
import { ctrlsBottom } from '@/composables/paddingViews'
import { isMiddleScreen } from '@/helper/utils'
import { useElementBounding } from '@vueuse/core'
import { onUnmounted, ref, watch } from 'vue'

const props = defineProps<{
  solid?: boolean
  inline?: boolean
}>()

const ctrlsBarRef = ref<HTMLDivElement | null>(null)
const { bottom: ctrlsBarBottom } = useElementBounding(ctrlsBarRef)

watch(
  ctrlsBarBottom,
  () => {
    if (!props.inline) ctrlsBottom.value = ctrlsBarBottom.value
  },
  { immediate: true },
)

onUnmounted(() => {
  if (!props.inline) ctrlsBottom.value = 0
})
</script>
