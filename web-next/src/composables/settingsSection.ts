import { isSettingVisible } from '@/composables/settings'
import { DEFAULT_SETTINGS_MENU_ORDER, SETTINGS_CATEGORIES } from '@/config/settingsItems'
import { SETTINGS_MENU_KEY } from '@/constant'
import { isMiddleScreen } from '@/helper/utils'
import { settingsMenuOrder } from '@/store/settings'
import { computed, ref } from 'vue'
import { useRoute, useRouter, type LocationQueryValue } from 'vue-router'

/**
 * 设置页的二级页面(分类详情)状态。
 *
 * 二级页面是用 `?section=` 表达的而不是子路由,SettingsPage 之外的地方(手势)
 * 没法从路由本身看出来自己正处在二级页,所以这份判断和进出动作放在这里共享。
 */

type SettingsQuery = Record<string, LocationQueryValue | LocationQueryValue[] | undefined>

/**
 * 进入二级页时是否留下了一条 history 记录。留了就用 back() 退回去,
 * 让系统返回键和返回按钮走同一条路径;没留就只能 replace 掉 query。
 */
const enteredFromMobileIndex = ref(false)

/** 按用户排序、且未被隐藏的分类。 */
export const visibleSectionKeys = computed(() => {
  const order = [
    ...settingsMenuOrder.value,
    ...DEFAULT_SETTINGS_MENU_ORDER.filter((key) => !settingsMenuOrder.value.includes(key)),
  ]

  return order.filter(
    (key) => SETTINGS_CATEGORIES.some((category) => category.key === key) && isSettingVisible(key),
  )
})

export const useSettingsSection = () => {
  const route = useRoute()
  const router = useRouter()

  const sectionKey = computed(() => {
    const value = route.query.section
    if (typeof value !== 'string') return undefined
    return visibleSectionKeys.value.find((key) => key === value)
  })

  /** 移动端的一级分类列表是否被二级页盖住了。 */
  const isSettingsSubPage = computed(() => isMiddleScreen.value && Boolean(sectionKey.value))

  const enterSection = async (key: SETTINGS_MENU_KEY, settingKey?: string) => {
    const fromMobileIndex = isMiddleScreen.value && !sectionKey.value
    const query: SettingsQuery = { ...route.query, section: key }

    delete query.scrollTo
    if (settingKey) query.setting = settingKey
    else delete query.setting

    if (!isMiddleScreen.value) {
      enteredFromMobileIndex.value = false
      await router.replace({ query })
      return
    }

    await router.push({ query })
    if (fromMobileIndex) enteredFromMobileIndex.value = true
  }

  const exitSection = async () => {
    if (enteredFromMobileIndex.value) {
      enteredFromMobileIndex.value = false
      router.back()
      return
    }

    const query: SettingsQuery = { ...route.query }

    delete query.section
    delete query.setting
    delete query.scrollTo
    await router.replace({ query })
  }

  return {
    sectionKey,
    isSettingsSubPage,
    enterSection,
    exitSection,
    /** 二级页被别的途径(系统返回键)关掉时,由 SettingsPage 负责复位。 */
    enteredFromMobileIndex,
  }
}
