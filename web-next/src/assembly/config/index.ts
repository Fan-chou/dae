// 组装层 · config 门面。持有统一的 configs 状态,转交 clash 实现。
import type { Config } from '@/types'
import { ref } from 'vue'
import * as clash from './clash'

export const defaultConfig: Config = {
  port: 0,
  'socks-port': 0,
  'redir-port': 0,
  'tproxy-port': 0,
  'mixed-port': 0,
  'allow-lan': false,
  'bind-address': '',
  mode: '',
  'mode-list': [],
  modes: [],
  'log-level': '',
  ipv6: false,
  tun: {
    enable: false,
  },
}

export const configs = ref<Config>({ ...defaultConfig })

export const fetchConfigs = () => clash.fetchConfigs()

export const updateConfigs = (cfg: Record<string, string | boolean | object | number>) =>
  clash.updateConfigs(cfg)

// 配置 / 缓存 / DNS 维护动作(Clash 专属),经 config 域门面暴露给 view。
export {
  flushDNSCacheAPI,
  flushFakeIPAPI,
  queryDNSAPI,
  reloadConfigsAPI,
  updateConfigsAPI,
  updateGeoDataAPI,
} from '@/api/clash'
