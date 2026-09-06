import { proxiesTabShow, proxyProviederList } from '@/assembly/proxies'
import { ruleProviderList, rulesTabShow } from '@/assembly/rules'
import { openDialogCount } from '@/composables/dialog'
import { useSettingsSection } from '@/composables/settingsSection'
import { CONNECTION_TAB_TYPE, PROXY_TAB_TYPE, ROUTE_NAME, RULE_TAB_TYPE } from '@/constant'
import { renderRoutes } from '@/helper'
import { isMiddleScreen } from '@/helper/utils'
import { connectionTabShow } from '@/store/connections'
import { swipeInPages, swipeInTabs } from '@/store/settings'
import { useEventListener } from '@vueuse/core'
import { flatten } from 'lodash'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const DIRECTION_LOCK_DISTANCE = 12
const HORIZONTAL_SWIPE_THRESHOLD = 90
const HORIZONTAL_DOMINANCE_RATIO = 1.25

// Most conflicts can be identified from native semantics. Custom gesture surfaces
// opt out declaratively so they do not need to coordinate a shared global flag.
const SWIPE_CONFLICT_SELECTOR = [
  'input',
  'textarea',
  'select',
  '[contenteditable]:not([contenteditable="false"])',
  'canvas',
  '.drag-handle',
  '.folder-drag-handle',
  '[data-page-swipe-ignore]',
].join(',')

type GestureState = 'idle' | 'pending' | 'horizontal' | 'vertical' | 'rejected'

const hasTextSelection = () => {
  const selection = window.getSelection()
  return Boolean(selection && !selection.isCollapsed && selection.toString().length)
}

const isTextEditingElement = (element: Element | null) => {
  if (!element) return false
  if (element instanceof HTMLTextAreaElement) return true
  if (element instanceof HTMLElement && element.isContentEditable) return true
  if (!(element instanceof HTMLInputElement)) return false

  return ![
    'button',
    'checkbox',
    'color',
    'file',
    'hidden',
    'image',
    'radio',
    'range',
    'reset',
    'submit',
  ].includes(element.type)
}

const isHorizontallyScrollable = (element: Element) => {
  const { overflowX } = getComputedStyle(element)
  return (
    (overflowX === 'auto' || overflowX === 'scroll') && element.scrollWidth > element.clientWidth
  )
}

const hasSwipeConflict = (event: TouchEvent, root: HTMLElement) => {
  for (const target of event.composedPath()) {
    if (!(target instanceof Element)) continue
    if (target.matches(SWIPE_CONFLICT_SELECTOR) || isHorizontallyScrollable(target)) return true
    if (target === root) break
  }

  return false
}

export const useSwipeRouter = () => {
  const swiperRef = ref<HTMLElement | null>(null)
  const route = useRoute()
  const router = useRouter()
  const { isSettingsSubPage, exitSection } = useSettingsSection()

  const swipeList = computed(() => {
    return flatten(
      renderRoutes.value.map((r) => {
        if (swipeInTabs.value) {
          if (r === ROUTE_NAME.proxies && proxyProviederList.value.length > 0) {
            return Object.values(PROXY_TAB_TYPE).map((tab) => {
              return [
                () => route.name === ROUTE_NAME.proxies && proxiesTabShow.value === tab,
                () => {
                  router.push({ name: ROUTE_NAME.proxies })
                  proxiesTabShow.value = tab
                },
              ]
            })
          } else if (r === ROUTE_NAME.connections) {
            return Object.values(CONNECTION_TAB_TYPE).map((tab) => {
              return [
                () => route.name === ROUTE_NAME.connections && connectionTabShow.value === tab,
                () => {
                  router.push({ name: ROUTE_NAME.connections })
                  connectionTabShow.value = tab
                },
              ]
            })
          } else if (r === ROUTE_NAME.rules && ruleProviderList.value.length > 0) {
            return Object.values(RULE_TAB_TYPE).map((tab) => {
              return [
                () => route.name === ROUTE_NAME.rules && rulesTabShow.value === tab,
                () => {
                  router.push({ name: ROUTE_NAME.rules })
                  rulesTabShow.value = tab
                },
              ]
            })
          }
        }

        return [[() => route.name === r, () => router.push({ name: r })]]
      }),
    )
  })

  const getNextIndexInSwipeList = () => {
    return swipeList.value.findIndex((s) => s[0]())
  }

  const getNextRouteName = () => {
    const routeName = route.name as ROUTE_NAME

    if (routeName === ROUTE_NAME.setup) {
      return router.push({ name: ROUTE_NAME.proxies })
    }

    return swipeList.value[(getNextIndexInSwipeList() + 1) % swipeList.value.length]?.[1]?.()
  }
  const getPrevRouteName = () => {
    const routeName = route.name as ROUTE_NAME

    if (routeName === ROUTE_NAME.setup) {
      return router.push({ name: ROUTE_NAME.proxies })
    }

    return swipeList.value[
      (getNextIndexInSwipeList() - 1 + swipeList.value.length) % swipeList.value.length
    ]?.[1]?.()
  }

  const canSwipeNow = () => {
    return (
      isMiddleScreen.value &&
      swipeInPages.value &&
      openDialogCount.value === 0 &&
      !isTextEditingElement(document.activeElement) &&
      !hasTextSelection()
    )
  }

  let gestureState: GestureState = 'idle'
  let startX = 0
  let startY = 0
  let endX = 0
  let endY = 0

  const resetGesture = () => {
    gestureState = 'idle'
    startX = 0
    startY = 0
    endX = 0
    endY = 0
  }

  const updateEndCoords = (touch: Touch) => {
    endX = touch.clientX
    endY = touch.clientY
  }

  const onTouchStart = (event: TouchEvent) => {
    if (event.touches.length !== 1) {
      gestureState = 'rejected'
      return
    }

    const touch = event.touches[0]
    startX = touch.clientX
    startY = touch.clientY
    updateEndCoords(touch)

    const root = swiperRef.value
    gestureState = root && canSwipeNow() && !hasSwipeConflict(event, root) ? 'pending' : 'rejected'
  }

  const onTouchMove = (event: TouchEvent) => {
    if (gestureState === 'idle' || gestureState === 'rejected') return
    if (event.touches.length !== 1) {
      gestureState = 'rejected'
      return
    }

    updateEndCoords(event.touches[0])
    if (gestureState !== 'pending') return

    const distanceX = Math.abs(endX - startX)
    const distanceY = Math.abs(endY - startY)
    if (Math.max(distanceX, distanceY) < DIRECTION_LOCK_DISTANCE) return

    // Once an axis wins, keep the gesture in that lane for its entire lifetime.
    if (distanceX >= distanceY * HORIZONTAL_DOMINANCE_RATIO) {
      gestureState = 'horizontal'
    } else if (distanceY >= distanceX * HORIZONTAL_DOMINANCE_RATIO) {
      gestureState = 'vertical'
    }
  }

  const onTouchEnd = (event: TouchEvent) => {
    if (gestureState === 'idle') return

    const touch = event.changedTouches[0]
    if (touch) updateEndCoords(touch)

    const state = gestureState
    const distanceX = Math.abs(endX - startX)
    const distanceY = Math.abs(endY - startY)
    const isHorizontal =
      (state === 'horizontal' || state === 'pending') &&
      distanceX >= HORIZONTAL_SWIPE_THRESHOLD &&
      distanceX >= distanceY * HORIZONTAL_DOMINANCE_RATIO
    const swipeDirection = endX < startX ? 'left' : 'right'

    resetGesture()

    if (!isHorizontal || !canSwipeNow()) return

    // 设置的二级页面盖在分类列表上,这里的手势语义是"返回"而不是换顶级页面。
    // PWA 下没有浏览器自带的边缘返回手势来吞掉这个滑动,不拦就会飞到隔壁页面去。
    if (isSettingsSubPage.value) {
      if (swipeDirection === 'right') exitSection()
      return
    }

    if (swipeDirection === 'right') {
      getPrevRouteName()
    } else {
      getNextRouteName()
    }
  }

  useEventListener(swiperRef, 'touchstart', onTouchStart, { passive: true })
  useEventListener(swiperRef, 'touchmove', onTouchMove, { passive: true })
  useEventListener(swiperRef, 'touchend', onTouchEnd, { passive: true })
  useEventListener(swiperRef, 'touchcancel', resetGesture, { passive: true })

  return {
    swiperRef,
  }
}
