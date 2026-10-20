<template>
  <div class="flex min-h-0 flex-1 flex-col text-xs">
    <div
      class="border-base-content/10 flex shrink-0 flex-wrap items-center gap-2 border-b px-3 py-2"
    >
      <input
        v-model.trim="kernelState.filter.src"
        class="input input-sm w-full min-w-0 md:w-52"
        aria-label="源 IP 筛选"
        placeholder="源 IP"
      />
      <select
        v-model.number="kernelState.filter.limit"
        class="select select-sm w-full min-w-0 md:w-25"
        aria-label="加载上限"
      >
        <option v-for="n in [256, 512, 1024]" :key="n" :value="n">
          {{ n }} 条
        </option>
      </select>
      <select
        v-model="sortKey"
        class="select select-sm w-full min-w-0 md:w-32"
        aria-label="排序"
      >
        <option value="speed">按速度</option>
        <option value="total">按总流量</option>
      </select>
    </div>
    <div class="text-base-content/55 shrink-0 space-y-1 px-3 py-2" aria-live="polite">
      <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span>{{
          kernelState.at
            ? '更新于 ' + new Date(kernelState.at).toLocaleTimeString()
            : '等待快照'
        }}</span>
        <span
          >匹配 {{ kernelState.at ? kernelState.total : '—' }} · 已加载
          {{ kernelState.at ? kernelState.loaded : '—' }}</span
        >
        <span v-if="kernelState.at"
          >已排除：fdae 转发 {{ kernelState.excluded.userspace }} · fdae
          自身连接 {{ kernelState.excluded.dae }} · 已结束
          {{ kernelState.excluded.inactive }}</span
        >
        <span v-if="kernelState.truncated" class="text-warning"
          >列表已截断（按流量取前 {{ kernelState.filter.limit }} 条）</span
        >
        <span v-if="kernelState.error" class="text-warning"
          >{{ kernelState.error }} · 保留上次数据</span
        >
      </div>
      <div v-if="kernelState.at && !kernelState.available" class="text-warning">
        无法读取内核连接表（conntrack）。
      </div>
      <div v-else-if="kernelState.at && !kernelState.accounting" class="text-warning">
        内核未启用流量计数，只能显示连接，没有流量与速度。开启：
        <code>sysctl -w net.netfilter.nf_conntrack_acct=1</code>
        （只对之后新建的连接生效；会让 conntrack 每个包多更新一次计数）。
      </div>
      <div class="text-base-content/40">
        这些连接由内核直接转发，不经过 fdae 用户态。流量为 IP
        层字节（含头部），比连接页的应用层字节略大；域名来自 DNS
        缓存反查，可能不准（CDN 共用 IP，或客户端自行解析）。
      </div>
    </div>
    <div class="min-h-0 flex-1 overflow-auto px-3 pb-3">
      <table class="table table-xs table-pin-rows">
        <thead>
          <tr>
            <th>源</th>
            <th>目的</th>
            <th>协议</th>
            <th>状态</th>
            <th class="text-right">上传</th>
            <th class="text-right">下载</th>
            <th class="text-right">↑ 速度</th>
            <th class="text-right">↓ 速度</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in sorted" :key="row.id" class="hover:bg-base-200">
            <td class="font-mono">{{ row.src }}</td>
            <td class="font-mono" :title="row.dst">
              {{ row.domain || row.host }}<span v-if="row.port">:{{ row.port }}</span>
              <span v-if="row.domain" class="text-base-content/40"> · {{ row.host }}</span>
            </td>
            <td>{{ row.network }}</td>
            <td>
              {{ row.state || (row.unreplied ? '无回包' : '') }}
              <span v-if="row.offloaded" class="badge badge-ghost badge-xs ml-1">offload</span>
            </td>
            <td class="text-right">{{ bytes(row.upload) }}</td>
            <td class="text-right">{{ bytes(row.download) }}</td>
            <td class="text-right">{{ speed(row, row.uploadSpeed) }}</td>
            <td class="text-right">{{ speed(row, row.downloadSpeed) }}</td>
          </tr>
          <tr v-if="kernelState.at && !sorted.length">
            <td colspan="8" class="text-base-content/50 py-6 text-center">
              当前没有仅由内核转发的连接
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
<script setup lang="ts">
import { computed, onScopeDispose, ref, watch } from 'vue'
import { prettyBytesHelper } from '@/helper/utils'
import {
  kernelState,
  subscribeKernelConnections,
  type KernelRow,
} from './kernelConnections'

const sortKey = ref<'speed' | 'total'>('speed')
const rows = ref<KernelRow[]>([])

// 只在本组件挂载期间轮询；筛选条件变化后下一拍自然带上新参数。
const feed = subscribeKernelConnections()
const stop = watch(feed.data, (value) => {
  rows.value = value || []
})
onScopeDispose(() => {
  stop()
  feed.close()
})

const sorted = computed(() =>
  [...rows.value].sort((a, b) => {
    const total = b.upload + b.download - (a.upload + a.download)
    if (sortKey.value === 'total') return total
    const rate = b.uploadSpeed + b.downloadSpeed - (a.uploadSpeed + a.downloadSpeed)
    return rate || total
  }),
)
const bytes = (n: number) => (kernelState.accounting ? prettyBytesHelper(n) : '—')
const speed = (row: KernelRow, n: number) =>
  !kernelState.accounting || !row.rateKnown ? '—' : prettyBytesHelper(n) + '/s'
</script>
