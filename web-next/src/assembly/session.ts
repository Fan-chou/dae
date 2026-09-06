// 组装层 · 后端会话。
//
// 一次会话 = 面板为某个后端建立起来的整套运行时状态:内核探测 + 首屏数据 +
// 三条常驻流(connections / logs / traffic)。切后端、改当前后端的连接参数、
// 用户手动重连,本质都是「结束旧会话、开一条新的」,所以共用 startBackendSession——
// 重连不需要额外的响应式开关,再调一次就是了。

import { PROXY_TAB_TYPE, RULE_TAB_TYPE } from '@/constant'
import { initConnections, stopConnections } from '@/store/connections'
import { initSatistic, stopSatistic } from '@/store/overview'
import { activeBackend } from '@/store/setup'
import { watch } from 'vue'
import { resetState } from '@/fdae/client'
import { initLogs, stopLogs } from './logs'
import {
  fetchProxies,
  proxiesTabShow,
  proxyMap,
  proxyGroupList,
  proxyProviederList,
} from './proxies'
import { rulesTabShow } from './rules'
import { probeActiveBackend } from './version'

let groupTimer: ReturnType<typeof setTimeout> | undefined
let sessionRevision = 0
export const startBackendSession = () => {
  clearTimeout(groupTimer)
  const revision = ++sessionRevision
  // 探测不 await:连通性提示要的正是「正在连接」这个中间态,数据流也不必等它。
  resetState()
  proxyMap.value = {}
  proxyGroupList.value = []
  proxyProviederList.value = []
  probeActiveBackend()
  // 三条常驻流连同各自的数据在这里先丢掉,不能留到下面重建时再清 ——
  // 上一个后端的日志与统计会安静地冒充新后端的数据。
  stopConnections()
  stopLogs()
  stopSatistic()

  // 后端被清空(登出 / 401 / 新增后端)时就停在这:常驻流上面已经关掉,
  // 否则它们会以无主状态留在 Setup 页继续运行并无限重连。
  if (!activeBackend.value) return

  rulesTabShow.value = RULE_TAB_TYPE.RULES
  proxiesTabShow.value = PROXY_TAB_TYPE.PROXIES
  async function refreshGroups() {
    if (revision !== sessionRevision) return
    try {
      if (document.visibilityState !== 'hidden') await fetchProxies()
    } catch {}
    if (revision === sessionRevision)
      groupTimer = setTimeout(refreshGroups, 5000)
  }
  void refreshGroups()
  initConnections()
  initLogs()
  initSatistic()
}

// 会话跟着 activeBackend 走:换后端要重建,把当前后端的地址 / 密码改掉同样要重建。
watch(activeBackend, startBackendSession, { immediate: true })
