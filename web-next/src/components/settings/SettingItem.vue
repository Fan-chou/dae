<template>
  <div
    v-if="shouldRender"
    class="setting-item"
    :id="`setting-${anchorKey || settingKey}`"
    :data-setting-key="settingKey"
    tabindex="-1"
  >
    <slot />
  </div>
</template>

<script setup lang="ts">
import { registerRenderedSetting, useIsSettingVisible } from '@/composables/settings'
import { computed, onUnmounted, toRef, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    /** 该设置项在显隐配置中的 key */
    settingKey: string
    /** 额外的前置条件，为 false 时该项始终不渲染（如依赖于其他开关） */
    when?: boolean
    /** 同一个显隐 key 对应多行时，用独立锚点精确定位，不改变原有显隐语义。 */
    anchorKey?: string
  }>(),
  { when: true },
)

const visible = useIsSettingVisible(toRef(props, 'settingKey'))
const shouldRender = computed(() => props.when && visible.value)

let unregister: (() => void) | undefined
watch(
  shouldRender,
  (rendered) => {
    unregister?.()
    unregister = rendered ? registerRenderedSetting(props.anchorKey || props.settingKey) : undefined
  },
  { immediate: true },
)
onUnmounted(() => unregister?.())
</script>
