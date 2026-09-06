<template>
  <div class="relative min-h-0 w-full flex-1 overflow-hidden">
    <div
      v-if="loading"
      class="absolute inset-0 flex items-center justify-center text-sm text-base-content/50"
    >
      正在加载编辑器…
    </div>
    <div v-if="failure" class="flex h-full flex-col gap-2 p-2">
      <p class="text-xs text-warning">编辑器加载失败，已切换为纯文本编辑。</p>
      <textarea
        class="textarea min-h-0 w-full flex-1 font-mono"
        :value="files[file]"
        :readonly="readonly"
        :aria-label="file + '.dae'"
        @input="
          emit('change', file, ($event.target as HTMLTextAreaElement).value)
        "
      />
    </div>
    <div ref="host" v-show="!failure" class="h-full w-full" data-fdae-editor />
  </div>
</template>
<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { theme } from '@/store/settings'
import type {
  editor,
  IDisposable,
} from 'monaco-editor/esm/vs/editor/editor.api'
import { loadEditor } from './editor'
type FileKey = 'config' | 'routing'
const props = defineProps<{
  files: Record<FileKey, string>
  file: FileKey
  readonly: boolean
}>()
const emit = defineEmits<{ change: [file: FileKey, value: string]; save: [] }>()
const host = ref<HTMLElement>(),
  loading = ref(true),
  failure = ref(false)
let instance: editor.IStandaloneCodeEditor | undefined
let monaco: Awaited<ReturnType<typeof loadEditor>> | undefined
let disposed = false,
  syncing = false,
  current: FileKey = props.file
const models = {} as Record<FileKey, editor.ITextModel>
const views: Partial<Record<FileKey, editor.ICodeEditorViewState | null>> = {}
const subscriptions: IDisposable[] = []
function setTheme() {
  if (monaco && host.value)
    monaco.editor.setTheme(
      getComputedStyle(host.value).colorScheme.includes('dark')
        ? 'vs-dark'
        : 'vs',
    )
}
watch(theme, async () => {
  await nextTick()
  setTheme()
})
watch(
  () => props.readonly,
  (value) => instance?.updateOptions({ readOnly: value }),
)
watch(
  () => props.files,
  (files) => {
    for (const key of ['config', 'routing'] as const) {
      if (models[key] && models[key].getValue() !== files[key]) {
        syncing = true
        models[key].setValue(files[key])
        syncing = false
      }
    }
  },
  { deep: true },
)
watch(
  () => props.file,
  (key) => {
    if (!instance) return
    views[current] = instance.saveViewState()
    current = key
    instance.setModel(models[key])
    instance.updateOptions({ ariaLabel: key + '.dae' })
    if (views[key]) instance.restoreViewState(views[key]!)
    instance.focus()
  },
)
onMounted(async () => {
  try {
    monaco = await loadEditor()
    if (disposed || !host.value) return
    for (const key of ['config', 'routing'] as const) {
      models[key] = monaco.editor.createModel(props.files[key], 'fdae')
      models[key].updateOptions({ tabSize: 2, insertSpaces: true })
      subscriptions.push(
        models[key].onDidChangeContent(() => {
          if (!syncing) emit('change', key, models[key].getValue())
        }),
      )
    }
    current = props.file
    instance = monaco.editor.create(host.value, {
      model: models[current],
      automaticLayout: true,
      readOnly: props.readonly,
      ariaLabel: current + '.dae',
      fontSize: 14,
      lineHeight: 22,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      minimap: { enabled: false },
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      wordWrap: 'on',
      folding: true,
      tabSize: 2,
      insertSpaces: true,
      renderWhitespace: 'selection',
      padding: { top: 12, bottom: 12 },
      fixedOverflowWidgets: true,
      bracketPairColorization: { enabled: true },
      stickyScroll: { enabled: false },
    })
    subscriptions.push(
      instance.addAction({
        id: 'fdae.save',
        label: '保存全部配置并热重载',
        keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS],
        run: () => {
          if (!props.readonly) emit('save')
        },
      }),
    )
    setTheme()
  } catch {
    if (!disposed) failure.value = true
  } finally {
    loading.value = false
  }
})
onBeforeUnmount(() => {
  disposed = true
  subscriptions.forEach((item) => item.dispose())
  instance?.dispose()
  Object.values(models).forEach((model) => model.dispose())
})
</script>
