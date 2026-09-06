import { blurIntensity, dashboardTransparent } from '@/store/settings'
import { watchEffect } from 'vue'

/**
 * 把「背景不透明度 / 毛玻璃强度」两个设置发布成 CSS 变量,供
 * assets/styles/utilities/appearance.css 里的规则读取。
 *
 * 写在 documentElement 而不是 #app-content:拓扑图全屏时会 Teleport 到 body,
 * 挂在 #app-content 上的变量传不过去。
 */
export const useAppearanceVars = () => {
  watchEffect(() => {
    const root = document.documentElement

    root.style.setProperty('--app-surface-alpha', `${dashboardTransparent.value}%`)
    // 强度为 0 时直接给 none:blur(0px) 一样会让每个面板多一个合成层,是白付的 GPU 开销。
    root.style.setProperty(
      '--app-glass',
      Number(blurIntensity.value) > 0 ? `blur(${blurIntensity.value}px)` : 'none',
    )
  })
}
