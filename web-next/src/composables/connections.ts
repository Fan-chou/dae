import { activeBackend } from '@/store/setup'
import type { Connection } from '@/types'
import { nextTick, ref, watch } from 'vue'

const infoConn = ref<Connection | null>(null)
const connectionDetailModalShow = ref(false)

// 详情框持有的是某个后端的原始连接对象,换后端后它会被新后端的访问器读取而抛错
// (同 store/connections 的注释),所以切换时连同弹窗一起丢弃。
watch(activeBackend, () => {
  connectionDetailModalShow.value = false
  infoConn.value = null
})

export const useConnections = () => {
  const handlerInfo = async (conn: Connection) => {
    infoConn.value = null
    await nextTick()
    infoConn.value = conn
    connectionDetailModalShow.value = true
  }

  return {
    infoConn,
    connectionDetailModalShow,
    handlerInfo,
  }
}
