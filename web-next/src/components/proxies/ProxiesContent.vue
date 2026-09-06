<script setup lang="ts">
/*
 * 节点网格按「行」虚拟化,只渲染视口附近的几行。
 * 代价:放弃了跨行的 TransitionGroup 重排动画,和虚拟化没法共存。
 */
import { handlerProxySelect } from '@/assembly/proxies'
import { PROXY_CARD_SIZE } from '@/constant'
import { useCollapseTransition } from '@/composables/collapseTransition'
import { scrollNodeIntoViewKey } from '@/composables/proxiesScroll'
import { PROXIES_PARENT_CLASS } from '@/helper/utils'
import { minProxyCardWidth, proxyCardSize } from '@/store/settings'
import { useVirtualizer } from '@tanstack/vue-virtual'
import { useElementSize, useResizeObserver } from '@vueuse/core'
import { computed, nextTick, onMounted, provide, ref } from 'vue'
import ProxyNodeCard from './ProxyNodeCard.vue'

// 行距做在行自己的 pb 上,算进量到的行高里;最后一行多出来的 pb 由根节点的 -mb-2 抵掉。
const GAP = 8

const props = defineProps<{
  name?: string
  now?: string
  renderProxies: string[]
}>()

const rootRef = ref<HTMLElement | null>(null)
const scrollEl = ref<HTMLElement | null>(null)
const scrollMargin = ref(0)
const { width } = useElementSize(rootRef)

// 和原来 grid 的 repeat(auto-fill, minmax(minProxyCardWidth, 1fr)) 是同一个算法
const columns = computed(() =>
  width.value ? Math.max(1, Math.floor((width.value + GAP) / (minProxyCardWidth.value + GAP))) : 1,
)
const rowCount = computed(() => Math.ceil(props.renderProxies.length / columns.value))
const estimatedRowHeight = computed(
  () => (proxyCardSize.value === PROXY_CARD_SIZE.SMALL ? 48 : 60) + GAP,
)

// 入场 / 高亮动画会给卡片挂 transform,只能用不受 transform 影响的布局尺寸来量。
const measureRowHeight = (element: Element, entry: ResizeObserverEntry | undefined) => {
  const box = entry?.borderBoxSize?.[0]

  return box ? Math.round(box.blockSize) : (element as HTMLElement).offsetHeight
}

// 展开动画期间 overscan 归零,只渲一屏,屏外的行等 transitionend 之后再补。
const collapseTransitioning = useCollapseTransition()
const overscan = computed(() => (collapseTransitioning?.value ? 0 : 3))

const rowVirtualizer = useVirtualizer(
  computed(() => ({
    count: rowCount.value,
    getScrollElement: () => scrollEl.value,
    estimateSize: () => estimatedRowHeight.value,
    measureElement: measureRowHeight,
    scrollMargin: scrollMargin.value,
    overscan: overscan.value,
  })),
)

const virtualRows = computed(() => rowVirtualizer.value.getVirtualItems())
const totalSize = computed(() => rowVirtualizer.value.getTotalSize())
const topSpacer = computed(() => {
  const first = virtualRows.value[0]

  return first ? first.start - scrollMargin.value : 0
})
const bottomSpacer = computed(() => {
  const last = virtualRows.value[virtualRows.value.length - 1]

  /*
   * 一行都没渲染时占位块要顶起全部高度:滚动容器高度全靠内容撑,
   * 这里返回 0 就会「容器 0 高 → 算不出可视区 → 渲不出行」死锁。
   */
  return Math.max(0, totalSize.value - (last ? last.end - scrollMargin.value : 0))
})

const rowNodes = (rowIndex: number) =>
  props.renderProxies.slice(rowIndex * columns.value, (rowIndex + 1) * columns.value)

// 每个元素只交给 virtualizer 量一次;之后的高度变化由它自己的 ResizeObserver 报回来。
const measuredRows = new WeakSet<Element>()
const measureRow = (el: Element | null) => {
  if (!el || measuredRows.has(el)) return

  measuredRows.add(el)
  nextTick(() => {
    if (el.isConnected) {
      rowVirtualizer.value.measureElement(el)
    }
  })
}

// 滚动容器不一定紧挨着自己,位置差用 rect 算,不依赖 offsetParent 是谁。
const syncScrollMargin = () => {
  const root = rootRef.value
  const scroller = scrollEl.value

  if (!root || !scroller) return

  scrollMargin.value =
    root.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop
}

// 目标节点可能没挂载,由行 virtualizer 负责定位;已经完整可见就不动。
const scrollNodeIntoView = (name: string, behavior: ScrollBehavior) => {
  const index = props.renderProxies.indexOf(name)

  if (index < 0 || !scrollEl.value) return

  const rowIndex = Math.floor(index / columns.value)
  const row = virtualRows.value.find((item) => item.index === rowIndex)
  const viewportStart = scrollEl.value.scrollTop
  const viewportEnd = viewportStart + scrollEl.value.clientHeight

  if (row && row.start >= viewportStart && row.end <= viewportEnd) return

  rowVirtualizer.value.scrollToIndex(rowIndex, {
    align: 'center',
    behavior,
  })
}

// 测速重排后卡片可能已经不在渲染窗口里,由列表负责滚过去(见 ProxyNodeCard)
provide(scrollNodeIntoViewKey, scrollNodeIntoView)

// 按订阅分段时会有多个实例共用一个滚动容器,前面的段变高之后要由 ProxiesByProvider 叫醒
defineExpose({ syncScrollMargin })

useResizeObserver(scrollEl, syncScrollMargin)

onMounted(() => {
  scrollEl.value = rootRef.value?.closest(`.${PROXIES_PARENT_CLASS}`) as HTMLElement | null

  nextTick(syncScrollMargin)
})
</script>

<template>
  <div
    ref="rootRef"
    class="-mb-2 min-w-0"
  >
    <div :style="{ height: `${topSpacer}px` }" />
    <div
      v-for="row in virtualRows"
      :key="row.key.toString()"
      :data-index="row.index"
      :ref="(el) => measureRow(el as Element | null)"
      class="grid min-w-0 gap-2 pb-2"
      :style="{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }"
    >
      <ProxyNodeCard
        v-for="node in rowNodes(row.index)"
        :key="node"
        :name="node"
        :group-name="name"
        :active="node === now"
        @click.stop="name && handlerProxySelect(name, node)"
      />
    </div>
    <div :style="{ height: `${bottomSpacer}px` }" />
  </div>
</template>
