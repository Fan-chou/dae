<template>
  <div
    class="flex h-full min-h-0 w-full flex-col overflow-hidden"
    :style="isMiddleScreen ? { paddingBottom: dockTop + 'px' } : undefined"
  >
    <div
      class="flex shrink-0 flex-wrap items-center gap-2 border-b border-base-content/10 px-3 py-2"
    >
      <h1 class="mr-auto text-base font-semibold">fdae 配置</h1>
      <button
        class="btn btn-ghost btn-sm"
        :disabled="busy || dirty"
        @click="read"
      >
        重新读取
      </button>
      <button
        class="btn btn-sm"
        :disabled="busy || !loaded"
        @click="applyReload"
      >
        热重载
      </button>
      <button
        class="btn btn-primary btn-sm"
        :disabled="busy || !loaded || !dirty"
        @click="save"
      >
        保存全部并热重载
      </button>
    </div>
    <div
      class="flex shrink-0 border-b border-base-content/10 px-3"
      role="tablist"
      aria-label="配置文件"
    >
      <button
        v-for="file in ['config', 'routing'] as const"
        :id="'tab-' + file"
        :key="file"
        type="button"
        role="tab"
        :aria-selected="activeFile === file"
        aria-controls="config-editor-panel"
        :tabindex="activeFile === file ? 0 : -1"
        class="flex items-center gap-2 border-b-2 px-4 py-3 font-mono text-sm transition-colors"
        :class="
          activeFile === file
            ? 'border-primary text-primary'
            : 'border-transparent text-base-content/55 hover:text-base-content'
        "
        @click="activeFile = file"
        @keydown.right.prevent="
          activeFile = activeFile === 'config' ? 'routing' : 'config'
        "
        @keydown.left.prevent="
          activeFile = activeFile === 'config' ? 'routing' : 'config'
        "
      >
        {{ file }}.dae
        <span
          v-if="dirtyFile(file)"
          class="h-1.5 w-1.5 rounded-full bg-warning"
          aria-label="有未保存修改"
        />
      </button>
    </div>
    <div class="shrink-0 px-3 py-2 text-xs text-base-content/55">
      {{
        activeFile === 'config'
          ? '仅编辑 global / routing 配置段，其他配置段由后端保留。'
          : '编辑独立 routing.dae 文件。'
      }}
      <span class="ml-2">保存会提交两个文件并请求热重载。</span>
    </div>
    <p v-if="error" class="shrink-0 px-3 pb-2 text-sm text-error" role="alert">
      {{ error }}
    </p>
    <div
      id="config-editor-panel"
      role="tabpanel"
      :aria-labelledby="'tab-' + activeFile"
      class="flex min-h-0 flex-1 border-y border-base-content/10"
    >
      <ConfigEditor
        :key="revisionKey"
        :files="draft"
        :file="activeFile"
        :readonly="!loaded || busy"
        @change="setFile"
        @save="saveIfDirty"
      />
    </div>
    <div
      class="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 text-xs text-base-content/50"
    >
      <span>{{
        !loaded
          ? busy
            ? '正在读取配置'
            : '未读取到配置'
          : dirty
            ? '有未保存修改'
            : '与读取内容一致'
      }}</span>
      <span>{{ draft[activeFile].split('\n').length }} 行</span>
      <span>Ctrl/Cmd+S 保存 · Ctrl/Cmd+F 查找</span>
      <span v-if="state.status?.generation"
        >运行代次：{{ state.status.generation }}</span
      >
      <span v-if="state.status?.sync_warning" class="text-warning">{{
        state.status.sync_warning
      }}</span>
    </div>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, reactive, ref, watch } from 'vue'
import ConfigEditor from './ConfigEditor.vue'
import { isMiddleScreen } from '@/helper/utils'
import { dockTop } from '@/composables/paddingViews'
import { onBeforeRouteLeave } from 'vue-router'
import { activeBackend } from '@/store/setup'
import { showNotification } from '@/helper/notification'
import { fetchConfig, saveConfig, reload, state } from './client'
const draft = reactive({ config: '', routing: '' }),
  baseline = ref(''),
  loaded = ref(false),
  busy = ref(false),
  error = ref('')
const dirty = computed(
  () => loaded.value && JSON.stringify(draft) !== baseline.value,
)
const activeFile = ref<'config' | 'routing'>('config')
const revisionKey = ref(0)
const dirtyFile = (key: 'config' | 'routing') =>
  loaded.value && draft[key] !== JSON.parse(baseline.value || '{}')[key]
function setFile(key: 'config' | 'routing', value: string) {
  draft[key] = value
}
function saveIfDirty() {
  if (!busy.value && loaded.value && dirty.value) void save()
}
let revision = 0
async function read() {
  const rev = ++revision
  busy.value = true
  error.value = ''
  try {
    const body = await fetchConfig()
    if (rev !== revision) return
    Object.assign(draft, body)
    baseline.value = JSON.stringify(draft)
    loaded.value = true
  } catch (e) {
    if (rev === revision) error.value = String((e as Error).message)
  } finally {
    if (rev === revision) busy.value = false
  }
}
async function save() {
  if (!loaded.value || busy.value || !dirty.value) return
  const rev = revision
  busy.value = true
  try {
    const sent = { ...draft }
    const result = await saveConfig(sent)
    if (rev !== revision) return
    baseline.value = JSON.stringify(sent)
    showNotification({
      content: result.queued
        ? '已保存并排队热重载'
        : '已保存，热重载未入队，可稍后重试',
      type: result.queued ? 'alert-success' : 'alert-warning',
      timeout: 5000,
    })
  } catch (e) {
    showNotification({
      content: String((e as Error).message),
      type: 'alert-error',
      timeout: 8000,
    })
  } finally {
    if (rev === revision) busy.value = false
  }
}
async function applyReload() {
  busy.value = true
  try {
    const result = await reload()
    showNotification({
      content: result.queued
        ? '热重载已入队，等待运行代次更新'
        : '热重载忙，请稍后重试',
      type: 'alert-info',
      timeout: 5000,
    })
  } catch (e) {
    showNotification({
      content: String((e as Error).message),
      type: 'alert-error',
      timeout: 8000,
    })
  } finally {
    busy.value = false
  }
}
const guard = () =>
  !dirty.value || window.confirm('配置有未保存修改，是否离开？')
const unload = (event: BeforeUnloadEvent) => {
  if (dirty.value) {
    event.preventDefault()
    event.returnValue = ''
  }
}
onBeforeRouteLeave(guard)
watch(activeBackend, () => {
  revisionKey.value++
  loaded.value = false
  draft.config = ''
  draft.routing = ''
  void read()
})
onMounted(() => {
  void read()
  window.addEventListener('beforeunload', unload)
})
onBeforeUnmount(() => {
  revision++
  window.removeEventListener('beforeunload', unload)
})
</script>
