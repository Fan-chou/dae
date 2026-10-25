<template>
  <div
    class="flex h-full min-h-0 w-full flex-col overflow-hidden"
    :style="isMiddleScreen ? { paddingBottom: dockTop + 'px' } : undefined"
  >
    <div
      class="flex shrink-0 flex-wrap items-center gap-2 border-b border-base-content/10 px-3 py-2"
    >
      <h1 class="mr-auto text-base font-semibold">入站</h1>
      <button
        class="btn btn-ghost btn-sm"
        :disabled="busy"
        @click="() => void refreshInbounds()"
      >
        刷新
      </button>
      <button
        class="btn btn-primary btn-sm"
        :disabled="busy || !inboundState.editable || !!form"
        @click="startAdd"
      >
        添加入站
      </button>
    </div>
    <div class="shrink-0 px-3 py-2 text-xs text-base-content/55">
      SOCKS5 监听（TCP CONNECT 与 UDP
      ASSOCIATE），流量与透明代理走同一套路由。要让规则匹配某个入站，在「规则」页写
      <code>inbound(名称)</code>，例如
      <code>inbound(s1) -> my_group</code>。这里只能修改写在 config.dae
      里的入站；其他文件里的入站只读。
    </div>
    <p
      v-if="inboundState.error"
      class="shrink-0 px-3 pb-2 text-sm text-warning"
    >
      {{ inboundState.error }}
      <span v-if="inboundState.at"> · 保留上次数据</span>
    </p>
    <p
      v-if="inboundState.at && !inboundState.editable"
      class="shrink-0 px-3 pb-2 text-xs text-warning"
    >
      config.dae 不可写，当前只能查看。
    </p>

    <form
      v-if="form"
      class="mx-3 mb-3 shrink-0 rounded-box border border-base-content/10 p-3"
      aria-label="入站设置"
      @submit.prevent="submit"
    >
      <h2 class="mb-2 text-sm font-semibold">
        {{ form.isNew ? '添加入站' : '编辑入站 ' + form.name }}
      </h2>
      <div class="grid grid-cols-1 gap-x-4 gap-y-2 text-xs md:grid-cols-2">
        <label class="flex flex-col gap-1">
          <span>名称</span>
          <input
            v-model.trim="form.name"
            class="input input-sm font-mono"
            :disabled="!form.isNew"
            placeholder="s1"
            maxlength="32"
            required
          />
          <span class="text-base-content/50"
            >1–32 位字母、数字、_ 或 -；规则里写 inbound(名称)</span
          >
        </label>
        <label class="flex flex-col gap-1">
          <span>监听地址</span>
          <input
            v-model.trim="form.listen"
            class="input input-sm font-mono"
            placeholder="127.0.0.1:1080"
            required
          />
          <span class="text-base-content/50"
            >IP:端口，IPv6 写成 [地址]:端口。监听 0.0.0.0、[::]
            或公网地址必须设置用户名和密码</span
          >
        </label>
        <label class="flex flex-col gap-1">
          <span>用户名</span>
          <input
            v-model="form.username"
            class="input input-sm"
            autocomplete="off"
            placeholder="留空则不认证"
          />
        </label>
        <label class="flex flex-col gap-1">
          <span>密码</span>
          <input
            v-model="form.password"
            class="input input-sm"
            type="password"
            autocomplete="new-password"
            :placeholder="
              form.hadPassword ? '留空保持不变' : '与用户名同时填写'
            "
          />
          <span v-if="form.hadPassword && !form.username" class="text-warning"
            >用户名为空会同时清除已保存的密码</span
          >
        </label>
        <label class="flex flex-col gap-1">
          <span>嗅探</span>
          <select v-model="form.sniff" class="select select-sm">
            <option value="auto">
              自动：对 IP 目标先应答再嗅探 TLS SNI / HTTP Host
            </option>
            <option value="off">关闭：先拨号，SOCKS5 错误码更精确</option>
          </select>
        </label>
        <label class="flex flex-col gap-1">
          <span>域名解析</span>
          <select v-model="form.resolve" class="select select-sm">
            <option value="local">本地：先解析再路由</option>
            <option value="deferred">
              延后：先按域名路由，走代理的域名由节点解析
            </option>
          </select>
        </label>
        <label class="flex items-center gap-2">
          <input
            v-model="form.udp"
            type="checkbox"
            class="checkbox checkbox-sm"
          />
          <span>允许 UDP（UDP ASSOCIATE）</span>
        </label>
        <label class="flex flex-col gap-1">
          <span>UDP 中继地址（可选）</span>
          <input
            v-model.trim="form.udpAdvertise"
            class="input input-sm font-mono"
            placeholder="自动"
          />
          <span class="text-base-content/50"
            >dae 在 NAT 或端口转发之后时，告诉客户端的 UDP 地址</span
          >
        </label>
      </div>
      <p v-if="formError" class="mt-2 text-sm text-error" role="alert">
        {{ formError }}
      </p>
      <div class="mt-3 flex gap-2">
        <button class="btn btn-primary btn-sm" type="submit" :disabled="busy">
          保存并热重载
        </button>
        <button
          class="btn btn-ghost btn-sm"
          type="button"
          :disabled="busy"
          @click="form = null"
        >
          取消
        </button>
      </div>
    </form>

    <div class="min-h-0 flex-1 overflow-auto px-3 pb-3">
      <table v-if="inboundState.list.length" class="table table-sm">
        <thead>
          <tr>
            <th>名称</th>
            <th>监听</th>
            <th>认证</th>
            <th>协议 · 嗅探 · 解析</th>
            <th>状态</th>
            <th class="text-right">连接</th>
            <th>来源</th>
            <th class="text-right">操作</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="inbound in inboundState.list" :key="inbound.name">
            <tr>
              <td class="font-mono font-semibold">{{ inbound.name }}</td>
              <td class="font-mono">{{ inbound.listen }}</td>
              <td>
                {{
                  inbound.username
                    ? inbound.username + (inbound.has_password ? ' / ••••' : '')
                    : '无'
                }}
              </td>
              <td class="whitespace-nowrap text-base-content/70">
                {{ inbound.udp ? 'TCP+UDP' : 'TCP' }} · {{ inbound.sniff }} ·
                {{ inbound.resolve }}
              </td>
              <td>
                <span
                  class="badge badge-sm"
                  :class="stateClass(inbound.state)"
                  >{{ inboundStateLabel[inbound.state] || inbound.state }}</span
                >
              </td>
              <td class="whitespace-nowrap text-right">
                {{ inbound.conns }}
                <span class="text-base-content/50"
                  >· UDP {{ inbound.udp_sessions }} · 累计
                  {{ inbound.accepted }}</span
                >
              </td>
              <td class="text-base-content/70">
                {{ inboundOriginLabel[inbound.origin] || inbound.origin }}
              </td>
              <td class="whitespace-nowrap text-right">
                <router-link
                  v-if="inbound.state !== 'pending' || inbound.conns"
                  class="btn btn-ghost btn-xs"
                  :to="{ name: ROUTE_NAME.connections }"
                  @click="state.filter.inbound = inbound.name"
                  >连接</router-link
                >
                <button
                  v-if="inbound.editable"
                  class="btn btn-ghost btn-xs"
                  :disabled="busy || !!form"
                  @click="startEdit(inbound)"
                >
                  编辑
                </button>
                <button
                  v-if="inbound.editable"
                  class="btn btn-ghost btn-xs text-error"
                  :disabled="busy || !!form"
                  @click="remove(inbound)"
                >
                  删除
                </button>
              </td>
            </tr>
            <tr v-if="inbound.error">
              <td colspan="8" class="break-all text-xs text-error">
                {{ inbound.error }}
              </td>
            </tr>
          </template>
        </tbody>
      </table>
      <p v-else class="py-6 text-center text-sm text-base-content/55">
        {{
          inboundState.at
            ? '没有入站。点「添加入站」创建一个。'
            : '正在读取入站'
        }}
      </p>
    </div>
  </div>
</template>
<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { isMiddleScreen } from '@/helper/utils'
import { dockTop } from '@/composables/paddingViews'
import { ROUTE_NAME } from '@/constant'
import { activeBackend } from '@/store/setup'
import { showNotification } from '@/helper/notification'
import { saveInbounds, state } from './client'
import {
  inboundOriginLabel,
  inboundState,
  inboundStateLabel,
  refreshInbounds,
  resetInbounds,
} from './inbounds'
import type { AdminInbound, AdminInboundInput } from './types'

type Form = {
  isNew: boolean
  name: string
  listen: string
  username: string
  password: string
  hadPassword: boolean
  udp: boolean
  udpAdvertise: string
  sniff: string
  resolve: string
}

const busy = ref(false)
const form = ref<Form | null>(null)
const formError = ref('')

const NAME = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$/

function stateClass(value: string) {
  return value === 'listening'
    ? 'badge-success'
    : value === 'failed'
      ? 'badge-error'
      : 'badge-warning'
}

function startAdd() {
  formError.value = ''
  form.value = {
    isNew: true,
    name: '',
    listen: '127.0.0.1:1080',
    username: '',
    password: '',
    hadPassword: false,
    udp: true,
    udpAdvertise: '',
    sniff: 'auto',
    resolve: 'local',
  }
}

function startEdit(inbound: AdminInbound) {
  formError.value = ''
  form.value = {
    isNew: false,
    name: inbound.name,
    listen: inbound.listen,
    username: inbound.username || '',
    password: '',
    hadPassword: inbound.has_password,
    udp: inbound.udp,
    udpAdvertise: inbound.udp_advertise || '',
    sniff: inbound.sniff || 'auto',
    resolve: inbound.resolve || 'local',
  }
}

// The inbounds config.dae owns, as the server should keep them. An edited
// entry carries a password only when one was typed; the others are sent
// without one so the saved password stays.
function currentInputs(): AdminInboundInput[] {
  return inboundState.list
    .filter((item) => item.editable)
    .map((item) => ({
      name: item.name,
      listen: item.listen,
      username: item.username || '',
      udp: item.udp,
      udp_advertise: item.udp_advertise || '',
      sniff: item.sniff,
      resolve: item.resolve,
    }))
}

function validate(f: Form): string {
  if (!NAME.test(f.name)) return '名称要 1–32 位字母、数字、_ 或 -'
  if (f.isNew && inboundState.list.some((item) => item.name === f.name))
    return '名称已被使用'
  const listen =
    /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\]):(\d{1,5})$/.exec(f.listen)
  if (!listen || Number(listen[1]) < 1 || Number(listen[1]) > 65535)
    return '监听地址写成 IP:端口，IPv6 写成 [地址]:端口'
  if (f.username && !f.password && !f.hadPassword)
    return '用户名和密码要同时填写'
  if (!f.username && f.password) return '用户名和密码要同时填写'
  return ''
}

async function send(list: AdminInboundInput[], done: string) {
  busy.value = true
  try {
    const result = await saveInbounds(list)
    showNotification({
      content: result.queued
        ? done + '，已排队热重载'
        : done + '，热重载未入队，可稍后重试',
      type: result.queued ? 'alert-success' : 'alert-warning',
      timeout: 5000,
    })
    form.value = null
    await refreshInbounds()
    return true
  } catch (e) {
    const message = String((e as Error).message)
    if (form.value) formError.value = message
    else
      showNotification({
        content: message,
        type: 'alert-error',
        timeout: 8000,
      })
    return false
  } finally {
    busy.value = false
  }
}

async function submit() {
  const f = form.value
  if (!f) return
  formError.value = validate(f)
  if (formError.value) return
  const entry: AdminInboundInput = {
    name: f.name,
    listen: f.listen,
    username: f.username,
    udp: f.udp,
    udp_advertise: f.udpAdvertise,
    sniff: f.sniff,
    resolve: f.resolve,
  }
  // Only a typed password is sent; otherwise the server keeps the saved one.
  if (f.password) entry.password = f.password
  const list = currentInputs()
  const at = list.findIndex((item) => item.name === f.name)
  if (at >= 0) list[at] = entry
  else list.push(entry)
  await send(list, '已保存')
}

async function remove(inbound: AdminInbound) {
  if (
    !window.confirm(
      '删除入站 ' +
        inbound.name +
        '？使用它的连接会断开，引用它的规则需要先改掉。',
    )
  )
    return
  await send(
    currentInputs().filter((item) => item.name !== inbound.name),
    '已删除 ' + inbound.name,
  )
}

let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  void refreshInbounds()
  timer = setInterval(() => {
    if (document.visibilityState !== 'hidden' && !busy.value)
      void refreshInbounds()
  }, 3000)
})
onBeforeUnmount(() => clearInterval(timer))
watch(activeBackend, () => {
  form.value = null
  resetInbounds()
  void refreshInbounds()
})
</script>
