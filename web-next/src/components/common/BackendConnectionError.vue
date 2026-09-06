<template>
  <!-- 连不上后端时,面板上的每一页都是空的 —— 与其让用户对着空页面猜,
       不如直接把「哪个后端、为什么、怎么办」摆在最前面。 -->
  <Transition name="connection-error">
    <div
      v-if="visible && activeBackend"
      class="bg-base-200/80 fixed inset-0 z-[100000] flex items-center justify-center overflow-auto p-4 backdrop-blur-sm"
    >
      <div
        class="border-base-border bg-base-100 flex w-96 max-w-full flex-col gap-3 rounded-xl border px-6 py-5 shadow-lg"
      >
        <div class="flex items-start gap-3">
          <span
            class="bg-error/10 text-error flex h-10 w-10 flex-none items-center justify-center rounded-lg"
          >
            <ExclamationTriangleIcon class="h-5 w-5" />
          </span>
          <div class="min-w-0 flex-1">
            <h1 class="text-base font-medium">{{ $t('backendUnreachable') }}</h1>
            <div class="text-base-content/60 truncate text-sm">{{ label }}</div>
            <div
              v-if="url !== label"
              class="text-base-content/40 truncate text-xs"
            >
              {{ url }}
            </div>
          </div>
        </div>

        <div class="bg-error/10 text-error rounded-lg px-3 py-2 text-xs leading-5 break-all">
          {{ detail || $t('backendConnectionFailed') }}
        </div>

        <div class="flex gap-2">
          <button
            class="btn btn-primary btn-sm flex-1"
            :disabled="isRetrying"
            @click="retry"
          >
            <span
              v-if="isRetrying"
              class="loading loading-spinner loading-xs"
            ></span>
            {{ isRetrying ? $t('backendConnecting') : $t('retry') }}
          </button>
          <button
            class="btn btn-sm flex-1"
            @click="editActiveBackend"
          >
            {{ $t('editBackendTitle') }}
          </button>
        </div>

        <template v-if="otherBackends.length">
          <div class="divider my-0 text-xs">{{ $t('switchToAnotherBackend') }}</div>
          <div class="-mr-2 flex max-h-48 flex-col gap-1 overflow-y-auto pr-2">
            <button
              v-for="backend in otherBackends"
              :key="backend.uuid"
              class="hover:bg-base-200 flex items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors"
              @click="setActiveBackend(backend.uuid)"
            >
              <ServerIcon class="text-base-content/40 h-4 w-4 flex-none" />
              <span class="min-w-0 flex-1 truncate text-sm">
                {{ getLabelFromBackend(backend) }}
              </span>
              <ChevronRightIcon class="text-base-content/30 h-4 w-4 flex-none" />
            </button>
          </div>
          <button
            class="btn btn-ghost btn-sm"
            :disabled="isSwitching"
            @click="switchToReachableBackend"
          >
            <span
              v-if="isSwitching"
              class="loading loading-spinner loading-sm"
            ></span>
            {{ $t('autoSwitchBackend') }}
          </button>
        </template>

        <button
          class="btn btn-ghost btn-sm"
          @click="openBackendManager()"
        >
          {{ $t('manageBackends') }}
        </button>
      </div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { probeBackend } from '@/assembly/backend'
import { startBackendSession } from '@/assembly/session'
import { backendProbe } from '@/assembly/version'
import { ROUTE_NAME } from '@/constant'
import { describeConnectionError } from '@/helper/connectivity'
import { showNotification } from '@/helper/notification'
import { getBackendProbeUrl, getLabelFromBackend } from '@/helper/utils'
import {
  activeBackend,
  activeUuid,
  backendList,
  backendManagerView,
  openBackendManager,
  setActiveBackend,
} from '@/store/setup'
import { ChevronRightIcon, ExclamationTriangleIcon, ServerIcon } from '@heroicons/vue/24/outline'
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

const AUTO_SWITCH_TIMEOUT = 8000

const isSwitching = ref(false)
const detail = ref('')

// 探测结果属于上一个后端时不认,免得刚切走就弹一个旧后端的失败。
const probe = computed(() =>
  backendProbe.value?.uuid === activeUuid.value ? backendProbe.value : undefined,
)
const isRetrying = computed(() => probe.value?.status === 'probing')

// 失败一次就一直摆着,直到真的连上或换了后端 —— 点重试的瞬间探测状态会回到
// probing,若跟着它走,页面会先整个消失再弹回来,像是自己好了。
const failed = ref(false)

watch(
  () => probe.value?.status,
  (status) => {
    if (status === 'failed') failed.value = true
    if (status === 'connected' || status === undefined) failed.value = false
  },
  { immediate: true },
)

// 管理面板自己会实时探测,盖在它上面只会挡路;
// Setup 页本来就是登录后端的地方,不必再盖一层。
const route = useRoute()
const visible = computed(
  () => failed.value && backendManagerView.value === null && route.name !== ROUTE_NAME.setup,
)

const label = computed(() => (activeBackend.value ? getLabelFromBackend(activeBackend.value) : ''))
const url = computed(() => (activeBackend.value ? getBackendProbeUrl(activeBackend.value) : ''))

const otherBackends = computed(() =>
  backendList.value.filter((backend) => backend.uuid !== activeUuid.value),
)

// 会话探测拿到的是 axios / gRPC 的原始 message,"Network Error" 这类不透明说法
// 要再诊断一次才有信息量(CORS?混合内容?服务没起?)。
watch(
  probe,
  async (value) => {
    // 重试期间(probing)留着上一轮的原因不动:清空只会让横幅退回一句废话,
    // 而这一轮多半还是同一个原因。
    if (!value || value.status === 'connected') {
      detail.value = ''
      return
    }
    if (value.status !== 'failed') return

    const target = value.uuid
    const described = await describeConnectionError(value.message, url.value)

    if (activeUuid.value === target) {
      detail.value = described
    }
  },
  { immediate: true },
)

const retry = () => startBackendSession()

const editActiveBackend = () => {
  if (!activeUuid.value) return
  openBackendManager({ mode: 'edit', uuid: activeUuid.value })
}

// 一个个试太慢,同时打出去,谁先通用谁。
const switchToReachableBackend = async () => {
  if (isSwitching.value) return
  isSwitching.value = true

  try {
    const reachable = await Promise.any(
      otherBackends.value.map(async (backend) => {
        const result = await probeBackend(backend, AUTO_SWITCH_TIMEOUT)
        if (!result.ok) throw new Error(backend.uuid)
        return backend
      }),
    ).catch(() => null)

    if (reachable) {
      setActiveBackend(reachable.uuid)
    } else {
      showNotification({ content: 'noReachableBackend', type: 'alert-error' })
    }
  } finally {
    isSwitching.value = false
  }
}
</script>

<style scoped>
.connection-error-enter-active,
.connection-error-leave-active {
  transition: opacity 0.2s ease;
}

.connection-error-enter-from,
.connection-error-leave-to {
  opacity: 0;
}
</style>
