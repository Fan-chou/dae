// api 层 · axios 实例的全局拦截器。
// 这是 api 层唯一允许依赖 store/setup 的地方:请求需要从 activeBackend 取得
// 当前连接目标(baseURL / 鉴权)。其余 api 文件不得依赖上层。
import { showNotification } from '@/helper/notification'
import { getUrlFromBackend } from '@/helper/utils'
import {
  activeBackend,
  activeUuid,
  backendManagerView,
  openBackendManager,
} from '@/store/setup'
import axios, { AxiosError } from 'axios'
import { nextTick } from 'vue'

axios.interceptors.request.use((config) => {
  if (config.url && !config.url.startsWith('/v1/'))
    throw new Error('fdae 不支持此接口')
  if (activeBackend.value) {
    config.baseURL = getUrlFromBackend(activeBackend.value)
    config.headers['Authorization'] = 'Bearer ' + activeBackend.value.password
  }
  return config
})

// 响应拦截器只做「401 → 把这个后端的编辑框摆到用户面前」这一件事:任何请求打到
// 401 都必须如此,不是「要不要提示用户」的问题。密码过期要改的就是密码,所以直接
// 打开编辑态 —— 以前是清空 activeUuid 再跳 setup 页带 query 把弹窗绕回来,
// 一次密码失效就把人整个登出了,而他要做的只是改一个字段。
//
// 其余错误一律原样抛出,不在这里弹提示 —— 提示该由发起请求的业务层用 try-catch
// 决定(见 helper/requestError.ts):只有用户手动触发的动作才打扰用户,后台
// 自动拉取失败保持静默。以前靠 url 黑名单区分二者,加一个端点就得改一次名单,
// 而且拦截器根本不知道这次请求是谁发的、为什么发。
axios.interceptors.response.use(
  null,
  (
    error: AxiosError<{
      message: string
    }>,
  ) => {
    if (error.status === 401 && activeUuid.value) {
      const uuid = activeUuid.value
      const alreadyEditing =
        backendManagerView.value?.mode === 'edit' &&
        backendManagerView.value.uuid === uuid

      if (!alreadyEditing) {
        openBackendManager({ mode: 'edit', uuid })
        nextTick(() => {
          showNotification({ content: 'unauthorizedTip' })
        })
      }
    }

    return Promise.reject(error)
  },
)
