import { ROUTE_NAME } from '@/constant'
import { renderRoutes } from '@/helper'
import { isMiddleScreen } from '@/helper/utils'
import { computed, ref } from 'vue'
import type { RouteLocationNormalized } from 'vue-router'

/**
 * 页面过渡方向的唯一来源。
 *
 * 之前这份状态写在 `to.meta.transition` 上,而 meta 挂在共享的 route record 上:
 * 同名路由(只改 query)不会走到赋值分支,上一次的方向就会残留下来。这里改成显式
 * 状态,每条分支都必须给出结果——包括"没有过渡"。
 */

type SlideDirection = 'slide-left' | 'slide-right' | ''

export type SettingsPaneTransition = 'push' | 'pop' | ''

/**
 * 导航层级。设置页的二级页面是用 `?section=` 表达的而不是子路由,
 * 所以层级只能自己算。
 */
const navigationLevel = (route: RouteLocationNormalized) => {
  return route.name === ROUTE_NAME.settings && route.query.section ? 1 : 0
}

const slideDirection = ref<SlideDirection>('')

/**
 * 设置页一级 <-> 二级的进场动画,由 SettingsPage 内部消费。
 * 只有移动端的一二级才是两个页面,宽屏两栏同屏显示,没有进出可言。
 */
export const settingsPaneTransition = ref<SettingsPaneTransition>('')

/** HomePage 的 `<RouterView>` 过渡名。桌面端只做淡入淡出。 */
export const pageTransitionName = computed(() =>
  isMiddleScreen.value ? slideDirection.value : 'page',
)

/** 桌面端淡入淡出要 out-in,移动端两屏需要同时在场做位移。 */
export const pageTransitionMode = computed(() =>
  isMiddleScreen.value ? undefined : ('out-in' as const),
)

const resolveSlideDirection = (
  to: RouteLocationNormalized,
  from: RouteLocationNormalized,
): SlideDirection => {
  const routes = renderRoutes.value
  const toIndex = routes.findIndex((item) => item === to.name)
  const fromIndex = routes.findIndex((item) => item === from.name)

  // 首次进入,或进出 setup 这类不在 dock 里的页面:没有可比较的位置关系。
  if (toIndex === -1 || fromIndex === -1) return ''

  const lastIndex = routes.length - 1

  // 首尾之间的环绕要顺着滑动方向走,否则会整屏倒着飞回去。
  if (toIndex === 0 && fromIndex === lastIndex) return 'slide-left'
  if (toIndex === lastIndex && fromIndex === 0) return 'slide-right'

  return toIndex < fromIndex ? 'slide-right' : 'slide-left'
}

/** 由 router.beforeEach 调用:过渡名必须在渲染之前就位。 */
export const resolvePageTransition = (
  to: RouteLocationNormalized,
  from: RouteLocationNormalized,
) => {
  // 顶级页面之间的切换优先于层级变化:从设置二级页直接点 dock 去别的页,
  // 该走的是横向滑动而不是 pop。
  if (to.name !== from.name) {
    slideDirection.value = resolveSlideDirection(to, from)
    settingsPaneTransition.value = ''
    return
  }

  const levelDelta = isMiddleScreen.value ? navigationLevel(to) - navigationLevel(from) : 0

  slideDirection.value = ''
  settingsPaneTransition.value = levelDelta > 0 ? 'push' : levelDelta < 0 ? 'pop' : ''
}
