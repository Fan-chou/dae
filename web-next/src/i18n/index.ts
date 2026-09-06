import { LANG } from '@/constant'
import { language } from '@/store/settings'
import { createI18n } from 'vue-i18n'
import en from './en'
import ru from './ru'
import zh from './zh'
import zhTW from './zh-tw'

export const i18n = createI18n({
  legacy: false,
  locale: language.value,
  fallbackLocale: LANG.EN_US,
  messages: {
    [LANG.EN_US]: {
      ...en,
      rules: 'Configuration',
      dialer: 'Node',
      destinationPort: 'Destination port',
      mac: 'Source MAC',
      host: 'Destination host',
    },
    [LANG.ZH_CN]: {
      ...zh,
      reloadConfigsSuccess: '热重载已入队，等待运行代次更新',
      rules: '配置',
      destinationPort: '目标端口',
      mac: '源 MAC',
      host: '目标域名',
      destination: '目标 IP',
      outbound: '出站',
      dialer: '节点',
      rule: '策略',
      memoryUsage: '进程 RSS',
    },
    [LANG.ZH_TW]: {
      ...zhTW,
      reloadConfigsSuccess: '热重载已入队，等待运行代次更新',
      rules: '配置',
      destinationPort: '目標連接埠',
      mac: '來源 MAC',
    },
    [LANG.RU_RU]: ru,
  },
})
