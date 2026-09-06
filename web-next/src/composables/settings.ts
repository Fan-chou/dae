const unsupportedSettings = new Set([
  'upgradeCore',
  'restartCore',
  'updateConfigs',
  'updateGeoDatabase',
  'flushDNSCache',
  'flushFakeIP',
  'flushSmartWeights',
  'dnsQuery',
  'ports',
  'tunMode',
  'allowLan',
  'checkCoreUpgrade',
  'autoUpgradeCore',
  'speedtestMode',
  'speedtestUrl',
  'speedtestTimeout',
  'ipv6Test',
  'independentLatencyTest',
  'groupTestUrls',
  'automaticDisconnection',
  'autoDisconnectIdleUDP',
  'autoDisconnectIdleUDPTime',
  'resolveClientHostname',
  'disconnectOnRuleDisable',
  'displayAllFeatures',
  'autoUpgradeDashboard',
  'checkUpgradeDashboard',
  'provider',
  'IPInfoAPI',
  'groupProxiesByProvider',
  'useSmartGroupSort',
  'speedtestConcurrency',
  'displayGlobalByMode',
  'geoipCountryDatabaseURL',
  'geoipASNDatabaseURL',
  'autoIPCheckWhenStart',
  'autoConnectionCheckWhenStart',
])
export const isSettingSupported = (key: string) => {
  const name = key.split('.').at(-1) || key
  return (
    !unsupportedSettings.has(name) && !(name === 'fonts' && __FONT__ === 'none')
  )
}
import {
  DEFAULT_SETTINGS_MENU_ORDER,
  getAllSettingKeys,
} from '@/config/settingsItems'
import { SETTINGS_MENU_KEY } from '@/constant'
import { hiddenSettingsItems, settingsMenuOrder } from '@/store/settings'
import type { MaybeRef } from 'vue'
import { computed, ref, unref } from 'vue'

/** 当前实际渲染且可操作的设置项。搜索据此排除平台、能力和依赖条件不满足的项目。 */
const renderedSettingCounts = ref<Record<string, number>>({})

export function registerRenderedSetting(key: string): () => void {
  renderedSettingCounts.value = {
    ...renderedSettingCounts.value,
    [key]: (renderedSettingCounts.value[key] ?? 0) + 1,
  }

  return () => {
    const next = { ...renderedSettingCounts.value }
    const count = (next[key] ?? 1) - 1
    if (count > 0) next[key] = count
    else delete next[key]
    renderedSettingCounts.value = next
  }
}

export function isSettingRendered(key: string): boolean {
  return !!renderedSettingCounts.value[key]
}

/**
 * Returns true when the setting item with the given key is visible.
 * Use inside computed() for reactivity. For templates, use useIsSettingVisible(key) instead.
 */
export function isSettingVisible(key: string): boolean {
  return isSettingSupported(key) && !hiddenSettingsItems.value[key]
}

/**
 * Returns the raw hidden state of a setting key.
 */
export function isSettingHidden(key: string): boolean {
  return !isSettingSupported(key) || !!hiddenSettingsItems.value[key]
}

/** Toggle the hidden state of a setting key. */
export function toggleSettingHidden(key: string): void {
  hiddenSettingsItems.value = {
    ...hiddenSettingsItems.value,
    [key]: !hiddenSettingsItems.value[key],
  }
}

/**
 * Returns a computed that is true when the setting item with the given key is visible.
 * Use in templates for reactive visibility checks.
 */
export function useIsSettingVisible(key: MaybeRef<string>) {
  return computed(() => isSettingVisible(unref(key)))
}

/**
 * Returns a computed that is true when at least one of the given setting keys is visible.
 * Use for "has any visible item" in a settings section.
 */
export function useHasAnyVisibleSetting(keys: MaybeRef<string[]>) {
  return computed(() => unref(keys).some(isSettingVisible))
}

/** 应用「全部显示」预设 */
export function applyShowAllPreset(): void {
  hiddenSettingsItems.value = {}
  settingsMenuOrder.value = [...DEFAULT_SETTINGS_MENU_ORDER]
}

/** 应用「精简显示」预设 */
export function applyMinimalPreset(): void {
  const allKeys = getAllSettingKeys()
  const minimalHiddenKeys: string[] = [
    SETTINGS_MENU_KEY.proxies,
    SETTINGS_MENU_KEY.connections,
  ]

  for (const key of allKeys) {
    if (key.includes('emoji') || key.includes('language')) {
      minimalHiddenKeys.push(key)
    } else if (
      key.includes('autoDisconnectIdleUDP') ||
      key.includes('autoDisconnectIdleUDPTime')
    ) {
      minimalHiddenKeys.push(key)
    } else if (
      key.includes('scrollAnimationEffect') ||
      key.includes('swipeInPages') ||
      key.includes('swipeInTabs') ||
      key.includes('disablePullToRefresh')
    ) {
      minimalHiddenKeys.push(key)
    } else if (
      key.includes('displayAllFeatures') ||
      key.includes('IPInfoAPI') ||
      key.includes('numberOfChartsInSidebar') ||
      key.includes('proxyGroupIconSize') ||
      key.includes('proxyGroupIconMargin') ||
      key.includes('proxyPreviewType') ||
      key.includes('proxyCardSize') ||
      key.includes('twoColumnProxyGroup')
    ) {
      minimalHiddenKeys.push(key)
    }
  }

  const newHiddenItems: Record<string, boolean> = {}
  for (const key of minimalHiddenKeys) {
    newHiddenItems[key] = true
  }
  hiddenSettingsItems.value = newHiddenItems
  settingsMenuOrder.value = [...DEFAULT_SETTINGS_MENU_ORDER]
}

/** 调整大类在设置菜单中的顺序。 */
export function moveSettingsCategory(
  key: SETTINGS_MENU_KEY,
  direction: -1 | 1,
): void {
  const order = [
    ...settingsMenuOrder.value,
    ...DEFAULT_SETTINGS_MENU_ORDER.filter(
      (item) => !settingsMenuOrder.value.includes(item),
    ),
  ]
  const from = order.indexOf(key)
  if (from === -1) return
  const to = from + direction
  if (to < 0 || to >= order.length) return
  ;[order[from], order[to]] = [order[to], order[from]]
  settingsMenuOrder.value = order
}
