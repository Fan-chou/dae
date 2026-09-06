import { readonly, ref } from 'vue'

export type ConfirmDialogOptions = {
  title?: string
  message: string
  /** 在正文下方显示的可选说明链接 */
  link?: {
    text: string
    url: string
  }
  confirmText?: string
  cancelText?: string
  confirmButtonClass?: string
  /** 传入后在对话框内显示一个复选框，其勾选状态随结果一起返回 */
  checkboxText?: string
}

export type ConfirmDialogResult = {
  confirmed: boolean
  checked: boolean
  action: ConfirmDialogAction
}

export type ConfirmDialogAction = 'confirm' | 'cancel' | 'dismiss'

type ConfirmDialogRequest = ConfirmDialogOptions & {
  resolve: (value: ConfirmDialogResult) => void
}

const activeConfirmDialog = ref<ConfirmDialogRequest>()
const confirmDialogQueue: ConfirmDialogRequest[] = []

const showNextConfirmDialog = () => {
  if (activeConfirmDialog.value || confirmDialogQueue.length === 0) return

  activeConfirmDialog.value = confirmDialogQueue.shift()
}

export const confirmDialogState = readonly(activeConfirmDialog)

export const showConfirmDialog = (options: ConfirmDialogOptions) => {
  return new Promise<ConfirmDialogResult>((resolve) => {
    confirmDialogQueue.push({
      ...options,
      resolve,
    })
    showNextConfirmDialog()
  })
}

export const resolveConfirmDialog = (action: ConfirmDialogAction, checked = false) => {
  const currentConfirmDialog = activeConfirmDialog.value
  if (!currentConfirmDialog) return

  activeConfirmDialog.value = undefined
  currentConfirmDialog.resolve({ confirmed: action === 'confirm', checked, action })
  showNextConfirmDialog()
}
