import { MIN_PROXY_CARD_WIDTH, PROXY_CARD_SIZE } from '@/constant'
import type { Backend, BackendType } from '@/types'
import { useMediaQuery } from '@vueuse/core'
import dayjs from 'dayjs'
import prettyBytes, { type Options } from 'pretty-bytes'

export const isPreferredDark = useMediaQuery('(prefers-color-scheme: dark)')
export const isMiddleScreen = useMediaQuery('(max-width: 768px)')
export const isPWA = (() => {
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    navigator.standalone
  )
})()

export const prettyBytesHelper = (bytes: number, opts?: Options) => {
  // prettyBytes 对 NaN / Infinity 是抛错的。格式化函数几乎全在渲染函数里调用,
  // 一个脏字段抛出去就会毁掉整棵 vnode 树(而不只是这一格),故就地兜住。
  return prettyBytes(Number.isFinite(bytes) ? bytes : 0, {
    binary: false,
    ...opts,
  })
}

export const fromNow = (timestamp: string | number) => {
  return dayjs(timestamp).fromNow()
}

export const getDashboardSettingsFromStorage = () => {
  const settings: Record<string, string> = {}

  for (const key in localStorage) {
    if (key.startsWith('config/')) {
      settings[key] = localStorage.getItem(key) as string
    }
  }

  return settings
}

export const applyDashboardSettingsToStorage = (
  settings: Record<string, unknown>,
) => {
  for (const key in settings) {
    if (key.startsWith('config/')) {
      localStorage.setItem(key, settings[key] as string)
    }
  }
}

export const exportSettings = () => {
  const settings = getDashboardSettingsFromStorage()
  const blob = new Blob([JSON.stringify(settings, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'zashboard-settings'
  a.click()
  URL.revokeObjectURL(url)
}

export const resetSettings = () => {
  const keysToReset = Object.keys(localStorage).filter((key) => {
    return key.startsWith('config/')
  })

  keysToReset.forEach((key) => localStorage.removeItem(key))
  window.location.reload()
}

export const getUrlFromBackend = (end: {
  protocol: string
  host: string
  port: string
  secondaryPath?: string
}) => {
  return `${end.protocol}://${end.host}:${end.port}${end.secondaryPath || ''}`
}

// 探测 / 诊断打的那个地址:Clash REST 根路径。
export const getBackendProbeUrl = (end: Omit<Backend, 'uuid'>) =>
  getUrlFromBackend(end)

export const getLabelFromBackend = (end: Omit<Backend, 'uuid'>) => {
  return end.label || `${end.host}:${end.port}`
}

export const getMinCardWidth = (size: PROXY_CARD_SIZE) => {
  return size === PROXY_CARD_SIZE.LARGE
    ? MIN_PROXY_CARD_WIDTH.LARGE
    : MIN_PROXY_CARD_WIDTH.SMALL
}

export const PROXIES_PARENT_CLASS = 'proxies-scrollable-parent'

const getLayoutTop = (el: HTMLElement) => {
  let top = 0
  let current: HTMLElement | null = el

  while (current) {
    top += current.offsetTop
    current = current.offsetParent as HTMLElement | null
  }

  return top
}

export const scrollIntoCenter = (
  el: HTMLElement,
  behavior: ScrollBehavior = 'smooth',
) => {
  const scrollableParent = findScrollableParent(el)

  if (!scrollableParent) return

  const parentTop = getLayoutTop(scrollableParent)
  const childTop = getLayoutTop(el)

  // 判断可见性只能用布局位置(offsetTop 链),不能用 getBoundingClientRect:
  // 列表重排时 TransitionGroup 的 FLIP 会给卡片挂 transform,rect 停在动画起点(旧位置,
  // 通常还在视口内),会被误判成"已经可见"而跳过滚动。把整条 offsetParent 链相减,
  // 也能覆盖按 provider 分段后卡片与滚动容器不再共用 offsetParent 的结构。
  const relativeTop = childTop - parentTop - scrollableParent.scrollTop

  if (
    relativeTop >= 0 &&
    relativeTop + el.clientHeight <= scrollableParent.clientHeight
  )
    return

  const centerOffset =
    childTop -
    parentTop -
    scrollableParent.clientHeight / 2 +
    el.clientHeight / 2

  if (behavior === 'smooth') {
    scrollableParent.scrollTo({
      top: centerOffset,
      behavior,
    })
  } else {
    // 直接赋值不会继承容器可能存在的 CSS scroll-behavior,用于展开后的瞬时定位。
    scrollableParent.scrollTop = centerOffset
  }
}

export const findScrollableParent = (
  el: HTMLElement | null,
): HTMLElement | null => {
  const parent = el?.parentElement

  if (
    parent?.classList.contains(PROXIES_PARENT_CLASS) &&
    parent.scrollHeight > parent.clientHeight
  ) {
    return parent
  }

  return parent ? findScrollableParent(parent) : null
}

// 新格式 protocol=http/https 优先,旧格式 http / https 标记参数仍保留兼容,最后兜底当前页面协议。
const getProtocolFromQuery = (query: URLSearchParams) => {
  const protocol = query.get('protocol')

  if (protocol === 'http' || protocol === 'https') {
    return protocol
  }
  if (query.get('http')) {
    return 'http'
  }
  if (query.get('https')) {
    return 'https'
  }

  return window.location.protocol.replace(':', '')
}

export const getBackendFromUrl = () => {
  const query = new URLSearchParams(
    window.location.search ||
      location.hash.match(/\?.*$/)?.[0]?.replace('?', ''),
  )

  if (query.has('hostname')) {
    return {
      type: 'fdae' as BackendType,
      protocol: getProtocolFromQuery(query),
      secondaryPath: query.get('secondaryPath') || '',
      host: query.get('hostname') as string,
      port: query.get('port') as string,
      password: query.get('secret') || '',
      label: query.get('label') || '',
      disableUpgradeCore:
        query.get('disableUpgradeCore') === '1' ||
        query.get('disableUpgradeCore') === 'core',
      disableTunMode:
        query.get('disableTunMode') === '1' ||
        query.get('disableTunMode') === 'tun',
    }
  }
  return null
}
