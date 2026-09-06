<!--
  纯粹的后端切换器。以前它是「切换 + 编辑 + 新增」三合一,而且那个齿轮图标按钮
  实际做的是「清空 activeUuid 再跳 setup 页」—— 想加一个后端得先把自己登出。
  现在增删改统一进 BackendManager,这里只管选一个后端。

  用弹出列表而不是原生 select:每一项要带上「此刻通不通、多少延迟」,
  切过去之前就知道结果,而不是切完看着空页面才发现。

  列表 teleport 到 #app-content 并按触发器的位置定位,而不是用 CSS 下拉:
  两个挂载点(侧边栏底部、设置面板)都在滚动容器里,绝对定位的菜单会被裁掉 ——
  原生 select 不会,是因为它画在浏览器的顶层。这里靠 teleport 补回这一点,
  空间不够时向上翻。
-->
<template>
  <div :class="compact ? 'flex-none' : 'w-full'">
    <!--
      折叠的侧边栏只剩一列图标,状态就不在这儿表了:一列小按钮里再挤进一个状态点
      (或者给图标上色)只是噪声,想知道通不通展开列表就有。这里只保留入口和名字。
    -->
    <button
      v-if="compact"
      ref="triggerRef"
      class="btn btn-circle btn-sm"
      :aria-label="$t('backend')"
      @click="toggle"
      @mouseenter="showLabelTip"
    >
      <ServerIcon class="h-5 w-5" />
    </button>

    <button
      v-else
      ref="triggerRef"
      class="btn btn-sm w-full flex-nowrap justify-between font-normal"
      @click="toggle"
    >
      <template v-if="activeBackend">
        <BackendStatusDot
          :status="activeState.status"
          :show-latency="false"
        />
        <span class="min-w-0 flex-1 truncate text-left">
          {{ getLabelFromBackend(activeBackend) }}
        </span>
      </template>
      <span
        v-else
        class="min-w-0 flex-1 truncate text-left"
      >
        {{ $t('noBackendYet') }}
      </span>
      <ChevronUpDownIcon class="h-4 w-4 flex-none opacity-50" />
    </button>

    <Teleport
      to="#app-content"
      v-if="isReady"
    >
      <Transition name="backend-switch">
        <div
          v-if="isOpen"
          ref="panelRef"
          class="border-base-border bg-base-100 fixed z-[998] flex flex-col gap-1 overflow-hidden rounded-lg border p-1 shadow-lg"
          :style="panelStyle"
        >
          <div
            v-if="backendList.length"
            class="flex min-h-0 flex-col gap-1 overflow-y-auto"
            @mouseenter="closeActions"
          >
            <button
              v-for="backend in backendList"
              :key="backend.uuid"
              class="flex items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors"
              :class="backend.uuid === activeUuid ? 'bg-primary/10' : 'hover:bg-base-200'"
              @click="switchTo(backend.uuid)"
            >
              <BackendStatusDot
                :status="stateOf(backend.uuid).status"
                :show-latency="false"
              />
              <span class="min-w-0 flex-1 truncate text-sm">
                {{ getLabelFromBackend(backend) }}
              </span>
              <span
                v-if="stateOf(backend.uuid).status === 'online'"
                class="text-base-content/50 flex-none text-xs tabular-nums"
              >
                {{ stateOf(backend.uuid).latency }} ms
              </span>
            </button>
          </div>

          <div
            v-if="backendList.length"
            class="bg-base-content/10 mx-1 h-px flex-none"
          ></div>

          <button
            v-if="menuActions.length"
            ref="actionsTriggerRef"
            class="flex flex-none items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors"
            :class="isActionsOpen ? 'bg-base-200' : 'hover:bg-base-200'"
            :aria-expanded="isActionsOpen"
            @click="toggleActions"
            @pointerenter="hoverOpenActions"
          >
            <WrenchScrewdriverIcon class="h-4 w-4 flex-none opacity-60" />
            <span class="min-w-0 flex-1 truncate">{{ $t('actions') }}</span>
            <ChevronRightIcon class="h-4 w-4 flex-none opacity-50" />
          </button>

          <button
            class="hover:bg-base-200 flex flex-none items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors"
            @click="manage"
            @mouseenter="closeActions"
          >
            <Cog6ToothIcon class="h-4 w-4 flex-none opacity-60" />
            {{ backendList.length ? $t('manageBackends') : $t('addBackend') }}
          </button>
        </div>
      </Transition>

      <!--
        二级菜单单独 teleport 一层,而不是塞进一级面板里:一级面板自己是 fixed
        且带 overflow,嵌在里面的横向展开会被它自己裁掉。
      -->
      <Transition name="backend-switch">
        <div
          v-if="isOpen && isActionsOpen"
          ref="actionsPanelRef"
          class="border-base-border bg-base-100 fixed z-[998] flex flex-col gap-1 overflow-y-auto rounded-lg border p-1 shadow-lg"
          :style="actionsPanelStyle"
        >
          <button
            v-for="action in menuActions"
            :key="action.key"
            class="hover:bg-base-200 flex items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors disabled:opacity-50"
            :disabled="action.running"
            @click="runAction(action)"
          >
            <span
              v-if="action.running"
              class="loading loading-spinner h-4 w-4 flex-none"
            ></span>
            <component
              v-else
              :is="action.icon"
              class="h-4 w-4 flex-none opacity-60"
            />
            <span class="whitespace-nowrap">{{ $t(action.label) }}</span>
          </button>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import BackendStatusDot from '@/components/common/BackendStatusDot.vue'
import { menuBackendActions, type BackendAction } from '@/composables/backendActions'
import { useBackendListProbe } from '@/composables/backendListProbe'
import { useTooltip } from '@/helper/tooltip'
import { getLabelFromBackend } from '@/helper/utils'
import {
  activeBackend,
  activeUuid,
  backendList,
  openBackendManager,
  setActiveBackend,
} from '@/store/setup'
import {
  ChevronRightIcon,
  ChevronUpDownIcon,
  Cog6ToothIcon,
  ServerIcon,
  WrenchScrewdriverIcon,
} from '@heroicons/vue/24/outline'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, type CSSProperties } from 'vue'

const GAP = 4
const MIN_WIDTH = 224
const ACTIONS_MIN_WIDTH = 176
const VIEWPORT_PADDING = 8

const props = withDefaults(
  defineProps<{
    compact?: boolean
    /** 设置页里这些动作本来就成排摆着,菜单里不必再来一遍 */
    showActions?: boolean
  }>(),
  { compact: false, showActions: true },
)

const triggerRef = ref<HTMLButtonElement>()
const panelRef = ref<HTMLDivElement>()
const isOpen = ref(false)
const panelStyle = ref<CSSProperties>({})

const actionsTriggerRef = ref<HTMLButtonElement>()
const actionsPanelRef = ref<HTMLDivElement>()
const isActionsOpen = ref(false)
const actionsPanelStyle = ref<CSSProperties>({})

const menuActions = computed(() => (props.showActions ? menuBackendActions.value : []))

// Teleport 的目标是挂载本组件的 #app-content,首帧还不在 DOM 里。
const isReady = ref(false)

// 只在展开时探测,收起就停 —— 侧边栏常驻,不该一直在后台打请求。
const { stateOf } = useBackendListProbe(isOpen)

// 当前后端的状态不依赖展开:stateOf 会优先用会话自己的探测结果(backendProbe),
// 所以展开态那个点一亮出来就是准的,不用等这一轮探测跑完。
const activeState = computed(() => stateOf.value(activeUuid.value || ''))

const { showTip } = useTooltip()

const showLabelTip = (event: MouseEvent) => {
  if (!activeBackend.value) return
  showTip(event, getLabelFromBackend(activeBackend.value), { placement: 'right' })
}

const updatePosition = () => {
  const trigger = triggerRef.value

  if (!trigger) return

  const rect = trigger.getBoundingClientRect()
  const width = Math.max(rect.width, MIN_WIDTH)
  const left = Math.min(
    Math.max(rect.left, VIEWPORT_PADDING),
    window.innerWidth - width - VIEWPORT_PADDING,
  )
  const spaceBelow = window.innerHeight - rect.bottom - GAP - VIEWPORT_PADDING
  const spaceAbove = rect.top - GAP - VIEWPORT_PADDING

  // 侧边栏里的切换器贴着底边,向下几乎没有空间 —— 哪边宽敞往哪边开。
  const dropUp = spaceBelow < 160 && spaceAbove > spaceBelow

  panelStyle.value = {
    left: `${left}px`,
    width: `${width}px`,
    maxHeight: `${Math.max(dropUp ? spaceAbove : spaceBelow, 120)}px`,
    ...(dropUp
      ? { bottom: `${window.innerHeight - rect.top + GAP}px` }
      : { top: `${rect.bottom + GAP}px` }),
  }
}

// 二级菜单挂在触发行的右侧(右边挤不下就翻到左边),纵向跟触发行齐平并夹在视口内。
const updateActionsPosition = () => {
  const anchor = actionsTriggerRef.value

  if (!anchor) return

  const rect = anchor.getBoundingClientRect()
  const panelRect = actionsPanelRef.value?.getBoundingClientRect()
  const width = Math.max(panelRect?.width ?? 0, ACTIONS_MIN_WIDTH)
  const spaceRight = window.innerWidth - rect.right - GAP - VIEWPORT_PADDING
  const spaceLeft = rect.left - GAP - VIEWPORT_PADDING
  const flipLeft = spaceRight < width && spaceLeft > spaceRight
  const left = flipLeft
    ? Math.max(rect.left - GAP - width, VIEWPORT_PADDING)
    : Math.min(
        rect.right + GAP,
        Math.max(window.innerWidth - width - VIEWPORT_PADDING, VIEWPORT_PADDING),
      )
  const maxHeight = window.innerHeight - VIEWPORT_PADDING * 2
  const height = Math.min(panelRect?.height ?? 0, maxHeight)

  actionsPanelStyle.value = {
    left: `${left}px`,
    top: `${Math.min(
      Math.max(rect.top - VIEWPORT_PADDING / 2, VIEWPORT_PADDING),
      Math.max(window.innerHeight - VIEWPORT_PADDING - height, VIEWPORT_PADDING),
    )}px`,
    minWidth: `${ACTIONS_MIN_WIDTH}px`,
    maxHeight: `${maxHeight}px`,
  }
}

// 一级面板的位置一变,挂在它上面的二级菜单也得跟着走 —— 但要等这一帧渲染完,
// 触发行的新坐标才量得到。
const updatePositions = () => {
  updatePosition()
  if (isActionsOpen.value) nextTick(updateActionsPosition)
}

const closeActions = () => {
  isActionsOpen.value = false
}

const openActions = () => {
  if (!menuActions.value.length || isActionsOpen.value) return

  // 首帧还量不到面板自己的宽高,先按下限摆一次,渲染完再按实际尺寸收边。
  updateActionsPosition()
  isActionsOpen.value = true
  nextTick(updateActionsPosition)
}

const toggleActions = () => (isActionsOpen.value ? closeActions() : openActions())

// 触屏上点一下会先补一发 pointerenter 再来 click:两个都当成切换,菜单会刚展开就被收回去。
// 悬停展开只对鼠标生效,触屏走 click。
const hoverOpenActions = (event: PointerEvent) => {
  if (event.pointerType !== 'mouse') return
  openActions()
}

const runAction = (action: BackendAction) => {
  if (action.running) return

  action.run()
  // 要填参数的动作交给弹窗,菜单让位;就地执行的留着 —— 转圈看得见,也能接着点下一个。
  if (action.opensModal) close()
}

const handlePointerDown = (event: PointerEvent) => {
  const target = event.target as Node | null

  if (!target) return
  if (
    triggerRef.value?.contains(target) ||
    panelRef.value?.contains(target) ||
    actionsPanelRef.value?.contains(target)
  )
    return

  close()
}

const handleKeydown = (event: KeyboardEvent) => {
  if (event.key === 'Escape') close()
}

// 滚动的是外层容器而不是面板自己,所以用捕获阶段听,跟着触发器走。
const listen = (add: boolean) => {
  const fn = add ? window.addEventListener : window.removeEventListener

  fn('scroll', updatePositions, true)
  fn('resize', updatePositions)
  fn('pointerdown', handlePointerDown as EventListener, true)
  fn('keydown', handleKeydown as EventListener)
}

function close() {
  if (!isOpen.value) return

  isOpen.value = false
  closeActions()
  listen(false)
}

const open = () => {
  updatePosition()
  isOpen.value = true
  listen(true)
}

const toggle = () => (isOpen.value ? close() : open())

const switchTo = (uuid: string) => {
  setActiveBackend(uuid)
  close()
}

const manage = () => {
  openBackendManager(backendList.value.length ? { mode: 'list' } : { mode: 'create' })
  close()
}

onMounted(() => {
  isReady.value = true
})

onBeforeUnmount(() => listen(false))
</script>

<style scoped>
.backend-switch-enter-active,
.backend-switch-leave-active {
  transition:
    opacity 0.15s ease,
    transform 0.15s cubic-bezier(0.32, 0.72, 0, 1);
}

.backend-switch-enter-from,
.backend-switch-leave-to {
  opacity: 0;
  transform: scale(0.97);
}

@media (prefers-reduced-motion: reduce) {
  .backend-switch-enter-active,
  .backend-switch-leave-active {
    transition: opacity 0.15s ease;
  }

  .backend-switch-enter-from,
  .backend-switch-leave-to {
    transform: none;
  }
}
</style>
