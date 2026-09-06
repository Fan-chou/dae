<!--
  后端管理的唯一去处:列表、切换、新增、编辑、删除、排序全在这里。
  以前这些散在 Setup 页、侧边栏切换器、连接失败页三处,同一件事有三种做法;
  更糟的是「新增一个后端」得先把自己登出(清 activeUuid)再跳路由才能进到表单。

  列表态和表单态是同一个弹窗的两个视图,不是两个弹窗 —— 从列表点编辑、保存后
  退回列表,中间不该有开合闪烁。
-->
<template>
  <!--
    DialogWrapper 会 teleport 到 #app-content,而那正是挂载本组件的 App 根节点 ——
    首帧它还没进 DOM。等挂载完再渲染,与同处 App 根下的 ConfirmDialogHost 一致。
  -->
  <DialogWrapper
    v-if="isReady"
    v-model="isOpen"
    :title="title"
    box-class="max-w-md"
    @enter="handleEnter"
  >
    <!-- 列表态 -->
    <div v-if="view?.mode === 'list'" class="flex flex-col gap-3">
      <div
        v-if="!backendList.length"
        class="text-base-content/50 py-6 text-center text-sm"
      >
        {{ $t('noBackendYet') }}
      </div>

      <Draggable
        v-else
        class="-mr-2 flex max-h-[50dvh] flex-col gap-1 overflow-y-auto pr-2"
        v-model="backendList"
        group="backendList"
        handle=".drag-handle"
        :animation="150"
        :item-key="'uuid'"
      >
        <template #item="{ element }">
          <div
            :key="element.uuid"
            class="group flex items-center gap-1 rounded-lg pr-1 transition-colors"
            :class="
              element.uuid === activeUuid
                ? 'bg-primary/10'
                : 'hover:bg-base-200'
            "
          >
            <ChevronUpDownIcon
              class="drag-handle text-base-content/30 ml-1 h-4 w-4 flex-none cursor-grab"
            />
            <button
              class="flex min-w-0 flex-1 items-center gap-2 py-2 text-left"
              @click="switchTo(element.uuid)"
            >
              <BackendStatusDot
                :status="stateOf(element.uuid).status"
                :show-latency="false"
              />
              <span class="flex min-w-0 flex-1 flex-col">
                <span class="w-full truncate text-sm">{{
                  getLabelFromBackend(element)
                }}</span>
                <span
                  v-if="element.label"
                  class="text-base-content/50 w-full truncate text-xs"
                >
                  {{ element.host }}:{{ element.port }}
                </span>
              </span>
              <span
                v-if="stateOf(element.uuid).status === 'online'"
                class="text-base-content/50 flex-none text-xs tabular-nums"
              >
                {{ stateOf(element.uuid).latency }} ms
              </span>
            </button>
            <button
              class="btn btn-circle btn-ghost btn-xs text-base-content/40 hover:text-base-content"
              :aria-label="$t('editBackend')"
              @click="openEdit(element.uuid)"
            >
              <PencilSquareIcon class="h-4 w-4" />
            </button>
            <button
              class="btn btn-circle btn-ghost btn-xs text-base-content/40 hover:text-error"
              :aria-label="$t('delete')"
              @click="removeBackend(element.uuid)"
            >
              <TrashIcon class="h-4 w-4" />
            </button>
          </div>
        </template>
      </Draggable>

      <button
        class="btn btn-primary btn-sm w-full"
        @click="openBackendManager({ mode: 'create' })"
      >
        <PlusIcon class="h-4 w-4" />
        {{ $t('addBackend') }}
      </button>
    </div>

    <!-- 表单态:新增与编辑共用 -->
    <div v-else-if="editForm" class="flex flex-col gap-4">
      <BackendForm v-model="editForm" />

      <ReachabilityIndicator
        class="min-h-5"
        :status="reachability.status.value"
        :latency="reachability.latency.value"
        :message="reachability.message.value"
        @retry="reachability.retry"
      />

      <div class="flex justify-end gap-2">
        <button class="btn btn-sm" :disabled="isSaving" @click="handleCancel">
          {{ $t('cancel') }}
        </button>
        <button
          class="btn btn-primary btn-sm"
          :disabled="!canSave"
          @click="handleSave"
        >
          <span
            v-if="isSaving"
            class="loading loading-spinner loading-xs"
          ></span>
          {{ isSaving ? $t('checking') : $t('save') }}
        </button>
      </div>
    </div>
  </DialogWrapper>
</template>

<script setup lang="ts">
import { probeBackend } from '@/assembly/backend'
import BackendStatusDot from '@/components/common/BackendStatusDot.vue'
import DialogWrapper from '@/components/common/DialogWrapper.vue'
import ReachabilityIndicator from '@/components/common/ReachabilityIndicator.vue'
import { useBackendListProbe } from '@/composables/backendListProbe'
import { useBackendReachability } from '@/composables/backendReachability'
import { ROUTE_NAME } from '@/constant'
import { showNotification } from '@/helper/notification'
import { getLabelFromBackend } from '@/helper/utils'
import router from '@/router'
import {
  activeUuid,
  addBackend,
  backendList,
  backendManagerView,
  closeBackendManager,
  openBackendManager,
  removeBackend,
  setActiveBackend,
  updateBackend,
} from '@/store/setup'
import type { Backend, BackendType } from '@/types'
import {
  ChevronUpDownIcon,
  PencilSquareIcon,
  PlusIcon,
  TrashIcon,
} from '@heroicons/vue/24/outline'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Draggable from 'vuedraggable'
import BackendForm from './BackendForm.vue'

const { t } = useI18n()

const isReady = ref(false)
onMounted(() => {
  isReady.value = true
})

const view = computed(() => backendManagerView.value)

const isOpen = computed({
  get: () => view.value !== null,
  set: (value) => {
    if (!value) closeBackendManager()
  },
})

const title = computed(() => {
  switch (view.value?.mode) {
    case 'create':
      return t('addBackend')
    case 'edit':
      return t('editBackendTitle')
    default:
      return t('backend')
  }
})

// 列表露面时才探测,收起立刻停。
const isListVisible = computed(() => view.value?.mode === 'list')
const { stateOf } = useBackendListProbe(isListVisible)

const emptyForm = (): Omit<Backend, 'uuid'> => ({
  type: 'fdae' as BackendType,
  protocol: 'http',
  host: '127.0.0.1',
  port: '9090',
  secondaryPath: '',
  password: '',
  label: '',
  disableUpgradeCore: false,
  disableTunMode: false,
})

const editForm = ref<Omit<Backend, 'uuid'> | null>(null)
const isSaving = ref(false)

// 编辑期间实时探测:地址 / 密码改成什么样才通,改的时候就看得见。
const reachability = useBackendReachability(editForm)
const canSave = computed(
  () => reachability.status.value === 'online' && !isSaving.value,
)

// 视图切进表单态时装填一次表单。用 mode + uuid 做键,免得列表态的每次探测回填
// 都把用户正在改的表单重置掉。
watch(
  () =>
    view.value?.mode === 'edit'
      ? `edit:${view.value.uuid}`
      : (view.value?.mode ?? ''),
  () => {
    const current = view.value

    if (!current || current.mode === 'list') {
      editForm.value = null
      return
    }

    if (current.mode === 'create') {
      editForm.value = emptyForm()
      return
    }

    const backend = backendList.value.find((item) => item.uuid === current.uuid)

    if (!backend) {
      // 要编辑的后端已经不在了(比如别处删掉),退回列表而不是留一个空表单。
      openBackendManager({ mode: 'list' })
      return
    }

    editForm.value = {
      type: backend.type,
      protocol: backend.protocol,
      host: backend.host,
      port: backend.port,
      secondaryPath: backend.secondaryPath,
      password: backend.password,
      label: backend.label || '',
      disableUpgradeCore: backend.disableUpgradeCore || false,
      disableTunMode: backend.disableTunMode || false,
    }
  },
  { immediate: true },
)

// 路由守卫只把「没有后端」的人赶去 setup 页,没有反向的那一条:选中一个后端后
// 不会自己离开。所以在这里补上 —— 否则从 setup 页的管理面板里点一个后端,
// 状态其实已经切好了,人却还留在登录页上,看着像是没登进去。
const leaveSetupPage = () => {
  if (router.currentRoute.value.name === ROUTE_NAME.setup) {
    router.push({ name: ROUTE_NAME.proxies })
  }
}

const switchTo = (uuid: string) => {
  setActiveBackend(uuid)
  closeBackendManager()
  leaveSetupPage()
}

const openEdit = (uuid: string) => openBackendManager({ mode: 'edit', uuid })

// 从列表点进来的退回列表;被 401 之类直接推到编辑态的,取消就是关掉。
const cameFromList = ref(false)

watch(
  () => view.value?.mode,
  (mode, previous) => {
    if (mode === 'list') cameFromList.value = true
    else if (!previous) cameFromList.value = false
  },
  { immediate: true },
)

const handleCancel = () => {
  if (cameFromList.value) {
    openBackendManager({ mode: 'list' })
  } else {
    closeBackendManager()
  }
}

// 保存前再确认一次连通性。改错地址就存下去,下次打开面板才发现连不上,
// 那时已经离开这个表单了 —— 所以拦在这里,原因由上面的指示器给出。
const handleSave = async () => {
  const current = view.value
  const form = editForm.value

  if (!form || !current || current.mode === 'list') return

  isSaving.value = true

  try {
    const composed: Omit<Backend, 'uuid'> = { ...form }
    const result = await probeBackend({
      uuid: current.mode === 'edit' ? current.uuid : '',
      ...composed,
    })

    if (!result.ok) {
      // 失败的原因已经由指示器呈现,让它重探一轮拿到最新结论即可。
      reachability.retry()
      return
    }

    if (current.mode === 'create') {
      addBackend(composed)
      closeBackendManager()
      leaveSetupPage()
    } else {
      updateBackend(current.uuid, composed)
      showNotification({
        content: t('backendConfigSaved'),
        type: 'alert-success',
      })
      handleCancel()
    }
  } catch (error) {
    showNotification({
      content: `${t('saveFailed')}: ${error}`,
      type: 'alert-error',
    })
  } finally {
    isSaving.value = false
  }
}

const handleEnter = () => {
  if (view.value?.mode !== 'list' && canSave.value) handleSave()
}
</script>
