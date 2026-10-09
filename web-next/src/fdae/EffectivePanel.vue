<template>
  <div class="flex min-h-0 flex-1 flex-col overflow-auto p-3 text-sm">
    <p v-if="error" class="text-error" role="alert">{{ error }}</p>
    <p v-else-if="!data" class="text-base-content/55">正在读取生效配置…</p>
    <template v-else>
      <section class="mb-4 flex flex-wrap items-center gap-x-4 gap-y-1">
        <span class="text-base-content/55"
          >生效于 {{ new Date(data.loaded_at).toLocaleString() }}</span
        >
        <template v-if="data.mihomo.enabled">
          <span class="badge badge-sm badge-soft">Mihomo 源</span>
          <span class="truncate text-base-content/55">{{
            data.mihomo.source
          }}</span>
          <span
            v-if="data.mihomo.used_last_good"
            class="badge badge-warning badge-sm"
            >使用上一份有效副本</span
          >
          <span v-if="data.mihomo.error" class="text-warning">{{
            data.mihomo.error
          }}</span>
        </template>
        <span class="ml-auto text-xs text-base-content/45"
          >只读 · 不含节点链接与凭据</span
        >
      </section>
      <details
        v-if="notices.length"
        class="mb-4 rounded-box bg-base-200/50 p-3"
        open
      >
        <summary class="cursor-pointer font-medium">
          转换提示（{{ notices.length }}）
        </summary>
        <ul class="mt-2 space-y-1 font-mono text-xs">
          <li v-for="(n, i) in notices" :key="i">{{ n }}</li>
        </ul>
      </details>
      <div
        class="mb-3 flex flex-wrap items-center gap-2"
        role="tablist"
        aria-label="生效配置分区"
      >
        <button
          v-for="s in sections"
          :key="s.key"
          type="button"
          role="tab"
          :aria-selected="section === s.key"
          class="btn btn-sm"
          :class="section === s.key ? 'btn-primary' : 'btn-ghost'"
          @click="section = s.key"
        >
          {{ s.label }} <span class="opacity-60">{{ s.count }}</span>
        </button>
        <input
          v-model="filter"
          type="search"
          class="input input-sm ml-auto w-48"
          placeholder="过滤…"
          aria-label="过滤"
        />
      </div>
      <div class="overflow-x-auto">
        <table class="table table-sm table-zebra">
          <thead>
            <tr>
              <th v-for="h in head" :key="h">{{ h }}</th>
              <th>来源</th>
            </tr>
          </thead>
          <tbody class="font-mono text-xs">
            <tr v-for="(row, i) in rows" :key="i">
              <td
                v-for="(cell, j) in row.cells"
                :key="j"
                class="max-w-[28rem] break-all"
              >
                {{ cell }}
              </td>
              <td>
                <span
                  class="badge badge-xs"
                  :class="
                    row.origin === 'mihomo' ? 'badge-info' : 'badge-neutral'
                  "
                  >{{ row.origin }}</span
                >
              </td>
            </tr>
            <tr v-if="!rows.length">
              <td :colspan="head.length + 1" class="text-base-content/50">
                无匹配项
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="section === 'rules'" class="mt-2 text-xs text-base-content/50">
        兜底出口：{{ data.fallback.outbound }}（{{ data.fallback.origin }}）。
        规则集以 ruleset(名称) 表示，不展开条目。
      </p>
    </template>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { activeBackend } from '@/store/setup'
import { fetchEffective } from './client'
import type { EffectiveConfig } from './types'

const data = ref<EffectiveConfig>()
const error = ref('')
const section = ref<'rules' | 'groups' | 'nodes' | 'providers'>('rules')
const filter = ref('')

async function load() {
  data.value = undefined
  error.value = ''
  try {
    data.value = await fetchEffective()
  } catch (e) {
    error.value = String((e as Error).message)
  }
}
const notices = computed(() => {
  const m = data.value?.mihomo
  if (!m) return []
  return [
    ...(m.skipped_rules ?? []).map(
      (r) => `[${r.kind}] 第 ${r.line} 行 ${r.rule} — ${r.reason}`,
    ),
    ...(m.unused_providers ?? []).map((p) => `[unused] rule-provider ${p}`),
    ...(m.ignored_fields ?? []).map((f) => `[ignored] 顶层字段 ${f}`),
  ]
})
const sections = computed(() => [
  { key: 'rules' as const, label: '规则', count: data.value?.rules.length },
  { key: 'groups' as const, label: '策略组', count: data.value?.groups.length },
  { key: 'nodes' as const, label: '节点', count: data.value?.nodes.length },
  {
    key: 'providers' as const,
    label: '规则集',
    count: data.value?.rule_providers.length,
  },
])
const head = computed(
  () =>
    ({
      rules: ['#', '规则'],
      groups: ['名称', '策略', '成员'],
      nodes: ['标识', '显示名', '端点'],
      providers: ['名称', '类型', '行为', '地址', '间隔'],
    })[section.value],
)
type Row = { cells: string[]; origin: string }
const rows = computed<Row[]>(() => {
  const d = data.value
  if (!d) return []
  let all: Row[]
  switch (section.value) {
    case 'rules':
      all = d.rules.map((r) => ({
        cells: [String(r.index), r.text],
        origin: r.origin,
      }))
      break
    case 'groups':
      all = d.groups.map((g) => ({
        cells: [
          g.display_name && g.display_name !== g.name
            ? `${g.display_name} (${g.name})`
            : g.name,
          [g.policy, ...(g.options ?? [])].join(' '),
          g.members.join(', '),
        ],
        origin: g.origin,
      }))
      break
    case 'nodes':
      all = d.nodes.map((n) => ({
        cells: [n.tag, n.display_name ?? '', n.endpoint],
        origin: n.origin,
      }))
      break
    default:
      all = d.rule_providers.map((p) => ({
        cells: [p.name, p.type, p.behavior, p.source, p.interval ?? ''],
        origin: p.origin,
      }))
  }
  const q = filter.value.trim().toLowerCase()
  return q
    ? all.filter((r) => r.cells.join(' ').toLowerCase().includes(q))
    : all
})
watch(activeBackend, load)
onMounted(load)
</script>
