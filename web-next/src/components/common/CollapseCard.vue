<template>
  <div
    ref="placeholderRef"
    class="collapse-motion-placeholder"
  >
    <div
      ref="cardRef"
      class="group collapse-motion collapse"
      :class="expanded && 'collapse-motion-open'"
    >
      <div
        ref="headerRef"
        class="collapse-motion-header relative cursor-pointer px-4 pt-4"
        @click="showCollapse = !showCollapse"
      >
        <slot name="title" />
      </div>
      <div
        ref="bodyRef"
        class="collapse-motion-body"
        :class="transitioning && 'collapse-motion-body-transitioning'"
        :style="bodyHeight === null ? undefined : { height: `${bodyHeight}px` }"
        @transitionend="handlerTransitionEnd"
      >
        <div
          v-if="showPreview"
          ref="previewRef"
          class="collapse-motion-preview px-4 pb-4"
        >
          <slot name="preview" />
        </div>
        <div
          v-if="showContent"
          ref="contentRef"
          class="collapse-motion-content mt-2 max-h-108 overflow-y-auto p-4 pt-0"
          :class="PROXIES_PARENT_CLASS"
        >
          <slot name="content" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { provideCollapseTransition } from '@/composables/collapseTransition'
import { useVirtualRowShift } from '@/composables/virtualRowShift'
import { PROXIES_PARENT_CLASS } from '@/helper/utils'
import { collapseGroupMap } from '@/store/settings'
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'

const props = defineProps<{
  name: string
  forceOpen?: boolean
}>()

const FLOATING_CLASS = 'collapse-motion-floating'

const placeholderRef = ref<HTMLDivElement>()
const cardRef = ref<HTMLDivElement>()
const headerRef = ref<HTMLDivElement>()
const bodyRef = ref<HTMLDivElement>()
const previewRef = ref<HTMLDivElement>()
const contentRef = ref<HTMLDivElement>()

const showCollapse = computed({
  get() {
    return props.forceOpen || collapseGroupMap.value[props.name]
  },
  set(value) {
    if (!props.forceOpen) {
      collapseGroupMap.value[props.name] = value
    }
  },
})

// 视觉上的展开态,等目标内容挂载、布局稳定后再更新
const expanded = ref(showCollapse.value)
const showContent = ref(showCollapse.value)
const showPreview = ref(!showCollapse.value)
const transitioning = ref(false)
const bodyHeight = ref<number | null>(null)

provideCollapseTransition(transitioning)

const rowShift = useVirtualRowShift()

let shiftRow: HTMLElement | null = null
let shiftBaseHeight = 0
let openFrameId = 0
let openToken = 0
let transitionTimer = 0

const TRANSITION_FALLBACK_DELAY = 400

/*
 * 动画期间把卡片浮起来、占位高度钉死在动画开始时的值,让 virtualizer 全程不动;
 * 后面的行一次性 transform 到终点,插值交给 CSS,每帧只有卡片自己的布局。
 * 终点高度在 DOM 更新后量一次(展开量 content、收起量 preview)。
 */
const beginShift = (targetBodyHeight: number) => {
  const placeholder = placeholderRef.value
  const card = cardRef.value
  const row = placeholder?.parentElement

  if (!rowShift || !placeholder || !card || !row) return

  // 上一程还没跑完就被点回去了(连点)：基准还是第一次钉下的那个高度，只要把终点重算一遍
  if (!shiftRow) {
    shiftBaseHeight = card.offsetHeight
    placeholder.style.height = `${shiftBaseHeight}px`
    placeholder.classList.add(FLOATING_CLASS)
    shiftRow = row
    rowShift.begin(row, () => releaseShift(row))
  }

  const header = headerRef.value

  if (header) {
    rowShift.update(row, header.offsetHeight + targetBodyHeight - shiftBaseHeight)
  }
}

const releaseShift = (row: HTMLElement | null) => {
  const placeholder = placeholderRef.value

  if (placeholder) {
    placeholder.classList.remove(FLOATING_CLASS)
    placeholder.style.height = ''
  }

  if (shiftRow === row) {
    shiftRow = null
  }
}

// 同列所有动画结束后一起交还占位和高度，避免中途重排打断其他卡片。
const endShift = () => {
  const row = shiftRow

  if (!rowShift || !row) {
    releaseShift(row)

    return
  }

  rowShift.end(row)
}

// nextTick 的回调撤不掉,换成对暗号:令牌一变,还没跑到的那一节自己作废
const cancelPendingOpen = () => {
  openToken++
  cancelAnimationFrame(openFrameId)
  openFrameId = 0
  window.clearTimeout(transitionTimer)
  transitionTimer = 0
}

const finishTransition = () => {
  if (!transitioning.value) return

  window.clearTimeout(transitionTimer)
  transitionTimer = 0

  showContent.value = expanded.value
  showPreview.value = !expanded.value
  bodyHeight.value = null
  transitioning.value = false
  endShift()
}

const settleWithoutTransition = (value: boolean) => {
  expanded.value = value
  showContent.value = value
  showPreview.value = !value
  bodyHeight.value = null
  transitioning.value = false
  endShift()
}

const startHeightTransition = (value: boolean, targetHeight: number) => {
  const body = bodyRef.value

  if (!body) {
    settleWithoutTransition(value)

    return
  }

  expanded.value = value
  beginShift(targetHeight)
  bodyHeight.value = targetHeight

  transitionTimer = window.setTimeout(finishTransition, TRANSITION_FALLBACK_DELAY)
}

/*
 * 展开分两步:先挂内容,等布局落定,再起高度动画 —— 别让首屏几十张卡片的挂载长任务
 * 掉在动画开头那几帧上。展开用双 rAF(虚拟列表要两拍才稳:先挂 ProxiesContent,
 * 它 onMounted 才拿到滚动容器算行范围,第二拍才渲行);收起只等 preview 挂载,一帧够。
 */
watch(showCollapse, (value) => {
  cancelPendingOpen()

  const token = openToken
  const body = bodyRef.value

  // 连点又切回了当前画面:不用补动画,把上一程预挂的内容清掉即可
  if (value === expanded.value) {
    settleWithoutTransition(value)

    return
  }

  transitioning.value = true
  bodyHeight.value = body?.getBoundingClientRect().height ?? 0

  if (!value) {
    showPreview.value = true
    nextTick(() => {
      if (token !== openToken) return

      openFrameId = requestAnimationFrame(() => {
        openFrameId = 0
        startHeightTransition(false, previewRef.value?.offsetHeight ?? 0)
      })
    })

    return
  }

  showContent.value = true
  nextTick(() => {
    if (token !== openToken) return

    openFrameId = requestAnimationFrame(() => {
      openFrameId = requestAnimationFrame(() => {
        openFrameId = 0
        startHeightTransition(true, (contentRef.value?.offsetHeight ?? 0) + 8)
      })
    })
  })
})

// 只认 body 自己的 height 过渡,滤掉 preview/content 冒泡上来的透明度事件
const handlerTransitionEnd = (e: TransitionEvent) => {
  if (e.target !== bodyRef.value || e.propertyName !== 'height') return

  finishTransition()
}

onBeforeUnmount(() => {
  cancelPendingOpen()

  const row = shiftRow

  if (rowShift && row) {
    rowShift.cancel(row)
  } else {
    releaseShift(row)
  }
})
</script>
