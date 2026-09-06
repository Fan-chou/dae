import { theme } from '@/store/settings'
import { computed } from 'vue'

export type ThemeColorScheme = 'dark' | 'light'

export const themeColorScheme = computed<ThemeColorScheme>(() => {
  // Establish the reactive dependency; daisyUI supplies the actual light/dark
  // value through the active theme's color-scheme property.
  void theme.value
  const colorScheme = getComputedStyle(document.body).getPropertyValue('color-scheme').trim()

  return colorScheme.split(/\s+/).includes('dark') ? 'dark' : 'light'
})
