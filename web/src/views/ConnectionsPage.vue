<script setup lang="ts">
import {
  FlexRender,
  createColumnHelper,
  getCoreRowModel,
  getExpandedRowModel,
  getGroupedRowModel,
  getSortedRowModel,
  useVueTable,
  type ColumnOrderState,
  type ExpandedState,
  type GroupingState,
  type Row,
  type SortingState,
  type Updater,
  type VisibilityState,
} from "@tanstack/vue-table";
import { useDocumentVisibility, useIntervalFn } from "@vueuse/core";
import prettyBytes from "pretty-bytes";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { persistPrefs, refresh, refreshConnections, ui } from "@/store/session";
import {
  applyConnectionFilters,
  connectionAge,
  connectionAgeMs,
  connectionMacOptions,
  connectionSrcOptions,
  displayEndpoint,
  formatTimeShort,
  lookupCachedMac,
  uniqueDialers,
  uniqueNetworks,
  uniqueOutbounds,
  type ConnectionView,
} from "@/lib/format";
import { effectiveConnView, useCompactLayout } from "@/lib/layout";
import type { ConnViewMode } from "@/api/prefs";

const compact = useCompactLayout();
const search = ref("");
const tab = ref<"active" | "closed" | "all">("active");
const network = ref("");
const dialer = ref("");
const sorting = ref<SortingState>([{ id: "age", desc: false }]);
const grouping = ref<GroupingState>([]);
const rowExpanded = ref<ExpandedState>({});
const columnOrder = ref<ColumnOrderState>([]);
const dragging = ref("");
const detailId = ref("");
const nowMs = ref(Date.now());

const helper = createColumnHelper<ConnectionView>();

function bytesCell(value: number): string {
  return prettyBytes(value || 0);
}

function rateCell(value: number): string {
  return prettyBytes(value || 0) + "/s";
}

const columnMeta: { id: string; label: string }[] = [
  { id: "mac", label: "MAC" },
  { id: "src", label: "源IP" },
  { id: "dst", label: "目标" },
  { id: "host", label: "主机" },
  { id: "domain", label: "域名" },
  { id: "network", label: "协议" },
  { id: "outbound", label: "出站" },
  { id: "dialer", label: "节点" },
  { id: "policy", label: "策略" },
  { id: "age", label: "时长" },
  { id: "uploadRate", label: "上行速度" },
  { id: "downloadRate", label: "下行速度" },
  { id: "upload", label: "上行流量" },
  { id: "download", label: "下行流量" },
  { id: "start", label: "开始" },
];

function macCell(row: ConnectionView): string {
  return row.mac || lookupCachedMac(ui.srcMacHints, row.src) || "—";
}

const columns = [
  helper.accessor((row) => row.mac || lookupCachedMac(ui.srcMacHints, row.src), {
    id: "mac",
    header: "MAC",
    cell: (ctx) => ctx.getValue() || "—",
  }),
  helper.accessor("src", { header: "源IP", cell: (ctx) => displayEndpoint(ctx.getValue()) || "—" }),
  helper.accessor((row) => displayEndpoint(row.dst), { id: "dst", header: "目标", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor((row) => row.domain || displayEndpoint(row.dst), { id: "host", header: "主机", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("domain", { header: "域名", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("network", { header: "协议", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("outbound", { header: "出站", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("dialer", { header: "节点", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("policy", { header: "策略", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor((row) => connectionAgeMs(row.start || "", nowMs.value), {
    id: "age",
    header: "时长",
    enableGrouping: false,
    cell: (ctx) => connectionAge(ctx.row.original.start || "", nowMs.value),
  }),
  helper.accessor("uploadRate", { header: "上行速度", enableGrouping: false, cell: (ctx) => rateCell(ctx.getValue()) }),
  helper.accessor("downloadRate", { header: "下行速度", enableGrouping: false, cell: (ctx) => rateCell(ctx.getValue()) }),
  helper.accessor("upload", { header: "上行流量", enableGrouping: false, cell: (ctx) => bytesCell(ctx.getValue()) }),
  helper.accessor("download", { header: "下行流量", enableGrouping: false, cell: (ctx) => bytesCell(ctx.getValue()) }),
  helper.accessor("start", {
    header: "开始",
    enableGrouping: false,
    cell: (ctx) => formatTimeShort(ctx.getValue() || "") || "—",
  }),
];

function applyUpdater<T>(updater: Updater<T>, current: T): T {
  return typeof updater === "function" ? (updater as (old: T) => T)(current) : updater;
}

const filteredRows = computed(() =>
  applyConnectionFilters(ui.connectionViews, {
    src: ui.connectionFilter.src || "",
    mac: ui.connectionFilter.mac || "",
    network: network.value,
    dialer: dialer.value,
    closed: tab.value,
    search: search.value,
    exclude: ui.prefs.connExclude,
    excludeOn: ui.prefs.connExcludeOn,
  }),
);
const outboundOptions = computed(() => uniqueOutbounds(ui.groups, ui.connectionViews));
const srcOptions = computed(() => connectionSrcOptions(ui.srcMacHints));
const macOptions = computed(() => connectionMacOptions(ui.srcMacHints));
const dialerOptions = computed(() => uniqueDialers(ui.connectionViews));
const networkOptions = computed(() => uniqueNetworks(ui.connectionViews));
const columnVisibility = computed<VisibilityState>(() => {
  const vis: VisibilityState = {};
  for (const col of columnMeta) vis[col.id] = !ui.prefs.connHiddenCols.includes(col.id);
  return vis;
});

const table = useVueTable({
  get data() {
    return filteredRows.value;
  },
  columns,
  getRowId: (row) => row.id,
  autoResetExpanded: false,
  getCoreRowModel: getCoreRowModel(),
  getSortedRowModel: getSortedRowModel(),
  getGroupedRowModel: getGroupedRowModel(),
  getExpandedRowModel: getExpandedRowModel(),
  state: {
    get sorting() {
      return sorting.value;
    },
    get grouping() {
      return grouping.value;
    },
    get expanded() {
      return rowExpanded.value;
    },
    get columnOrder() {
      return columnOrder.value;
    },
    get columnVisibility() {
      return columnVisibility.value;
    },
  },
  onSortingChange: (updater) => {
    sorting.value = applyUpdater(updater, sorting.value);
  },
  onGroupingChange: (updater) => {
    grouping.value = applyUpdater(updater, grouping.value);
  },
  onExpandedChange: (updater) => {
    rowExpanded.value = applyUpdater(updater, rowExpanded.value);
  },
  onColumnOrderChange: (updater) => {
    columnOrder.value = applyUpdater(updater, columnOrder.value);
  },
});

const tableRows = computed(() => table.getRowModel().rows);

function onRowClick(row: Row<ConnectionView>): void {
  if (row.getIsGrouped()) {
    row.getToggleExpandedHandler()?.();
    return;
  }
  detailId.value = detailId.value === row.original.id ? "" : row.original.id;
}

async function poll(silent = true): Promise<void> {
  nowMs.value = Date.now();
  await refreshConnections({ silent });
}

const visibility = useDocumentVisibility();
const { pause, resume } = useIntervalFn(
  () => {
    void poll(true);
  },
  () => ui.prefs.connInterval,
  { immediate: false },
);

watch(visibility, (state) => {
  if (state === "hidden") pause();
  else resume();
});

onMounted(() => {
  void refresh("groups");
  void poll(false);
  if (visibility.value !== "hidden") resume();
});
onUnmounted(() => {
  pause();
});

function onOutboundChange(): void {
  ui.connectionFilter.src = "";
  ui.connectionFilter.mac = "";
  dialer.value = "";
  void poll(false);
}

function onHeaderDragStart(id: string): void {
  dragging.value = id;
}

function onHeaderDrop(id: string): void {
  if (!dragging.value || dragging.value === id) return;
  const order = (columnOrder.value.length ? columnOrder.value : columns.map((col) => col.id || "")).filter(Boolean);
  const from = order.indexOf(dragging.value);
  const to = order.indexOf(id);
  if (from < 0 || to < 0) return;
  const next = order.slice();
  next.splice(from, 1);
  next.splice(to, 0, dragging.value);
  columnOrder.value = next;
  dragging.value = "";
}

function toggleCol(id: string): void {
  const hidden = ui.prefs.connHiddenCols.slice();
  const index = hidden.indexOf(id);
  if (index >= 0) hidden.splice(index, 1);
  else hidden.push(id);
  persistPrefs({ connHiddenCols: hidden });
}

function onExcludeToggle(event: Event): void {
  persistPrefs({ connExcludeOn: (event.target as HTMLInputElement).checked });
}

function onExcludeChange(event: Event): void {
  persistPrefs({ connExclude: (event.target as HTMLInputElement).value });
}

function onIntervalChange(event: Event): void {
  persistPrefs({ connInterval: Number((event.target as HTMLSelectElement).value) });
}

function hostOf(row: ConnectionView): string {
  return row.domain || displayEndpoint(row.dst) || "—";
}

const showCards = computed(() => effectiveConnView(ui.prefs.connView, compact.value) === "card");

function setConnView(mode: ConnViewMode): void {
  persistPrefs({ connView: mode });
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <div class="flex flex-wrap items-center gap-2">
      <div class="join">
        <button class="btn btn-sm join-item min-h-10" :class="{ 'btn-active': tab === 'active' }" type="button" @click="tab = 'active'">活动</button>
        <button class="btn btn-sm join-item min-h-10" :class="{ 'btn-active': tab === 'closed' }" type="button" @click="tab = 'closed'">刚断开</button>
        <button class="btn btn-sm join-item min-h-10" :class="{ 'btn-active': tab === 'all' }" type="button" @click="tab = 'all'">全部</button>
      </div>
      <span class="text-sm opacity-70">{{ filteredRows.length }} / {{ ui.connectionsTotal }}{{ ui.connectionsTruncated ? "（截断）" : "" }}</span>
    </div>

    <details class="rounded-box border border-base-300 bg-base-100 p-3 md:hidden">
      <summary class="cursor-pointer text-sm font-medium">筛选 · {{ filteredRows.length }} 条</summary>
      <div class="mt-3 flex flex-col gap-2">
        <select v-model="ui.connectionFilter.outbound" class="select select-bordered select-sm w-full" @change="onOutboundChange">
          <option value="">全部出站</option>
          <option v-for="name in outboundOptions" :key="'m-ob-' + name" :value="name">{{ name }}</option>
        </select>
        <select v-model="ui.connectionFilter.src" class="select select-bordered select-sm w-full">
          <option value="">全部源</option>
          <option v-for="opt in srcOptions" :key="'m-src-' + opt.value" :value="opt.value">{{ opt.label }}</option>
        </select>
        <select v-model="ui.connectionFilter.mac" class="select select-bordered select-sm w-full">
          <option value="">全部 MAC</option>
          <option v-for="opt in macOptions" :key="'m-mac-' + opt.value" :value="opt.value">{{ opt.label }}</option>
        </select>
        <select v-model="network" class="select select-bordered select-sm w-full">
          <option value="">协议</option>
          <option v-for="name in networkOptions" :key="'m-net-' + name" :value="name">{{ name }}</option>
        </select>
        <select v-model="dialer" class="select select-bordered select-sm w-full">
          <option value="">全部节点</option>
          <option v-for="name in dialerOptions" :key="'m-d-' + name" :value="name">{{ name }}</option>
        </select>
        <input v-model="search" class="input input-bordered input-sm w-full" placeholder="空格分隔，同时匹配主机/源/出站/节点" />
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" class="checkbox checkbox-sm" :checked="ui.prefs.connExcludeOn" @change="onExcludeToggle" />
          排除
        </label>
        <input
          class="input input-bordered input-sm w-full"
          :value="ui.prefs.connExclude"
          placeholder="正则，匹配则隐藏（如 stun|ntp）"
          @change="onExcludeChange"
        />
        <select class="select select-bordered select-sm w-full" :value="String(ui.prefs.connInterval)" @change="onIntervalChange">
          <option value="1000">1s</option>
          <option value="2000">2s</option>
          <option value="5000">5s</option>
        </select>
        <div class="join w-full">
          <button class="btn btn-sm join-item flex-1" :class="{ 'btn-active': ui.prefs.connView === 'auto' }" type="button" @click="setConnView('auto')">自动</button>
          <button class="btn btn-sm join-item flex-1" :class="{ 'btn-active': ui.prefs.connView === 'table' }" type="button" @click="setConnView('table')">表格</button>
          <button class="btn btn-sm join-item flex-1" :class="{ 'btn-active': ui.prefs.connView === 'card' }" type="button" @click="setConnView('card')">卡片</button>
        </div>
      </div>
    </details>

    <div class="hidden flex-wrap items-center gap-2 md:flex">
      <select v-model="ui.connectionFilter.outbound" class="select select-bordered select-sm max-w-56" @change="onOutboundChange">
        <option value="">全部出站</option>
        <option v-for="name in outboundOptions" :key="name" :value="name">{{ name }}</option>
      </select>
      <select v-model="ui.connectionFilter.src" class="select select-bordered select-sm max-w-72">
        <option value="">全部源</option>
        <option v-for="opt in srcOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
      </select>
      <select v-model="ui.connectionFilter.mac" class="select select-bordered select-sm max-w-80">
        <option value="">全部 MAC</option>
        <option v-for="opt in macOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
      </select>
      <select v-model="network" class="select select-bordered select-sm w-28">
        <option value="">协议</option>
        <option v-for="name in networkOptions" :key="name" :value="name">{{ name }}</option>
      </select>
      <select v-model="dialer" class="select select-bordered select-sm max-w-56">
        <option value="">全部节点</option>
        <option v-for="name in dialerOptions" :key="name" :value="name">{{ name }}</option>
      </select>
      <input v-model="search" class="input input-bordered input-sm min-w-48 flex-1" placeholder="空格分隔，同时匹配主机/源/出站/节点" />
    </div>
    <div class="hidden flex-wrap items-center gap-2 md:flex">
      <label class="flex items-center gap-1 text-sm">
        <input type="checkbox" class="checkbox checkbox-xs" :checked="ui.prefs.connExcludeOn" @change="onExcludeToggle" />
        排除
      </label>
      <input
        class="input input-bordered input-sm min-w-40 flex-1"
        :value="ui.prefs.connExclude"
        placeholder="正则，匹配则隐藏（如 stun|ntp）"
        @change="onExcludeChange"
      />
      <select class="select select-bordered select-sm w-28" :value="String(ui.prefs.connInterval)" @change="onIntervalChange">
        <option value="1000">1s</option>
        <option value="2000">2s</option>
        <option value="5000">5s</option>
      </select>
      <div class="join">
        <button class="btn btn-sm join-item min-h-10" :class="{ 'btn-active': ui.prefs.connView === 'auto' }" type="button" @click="setConnView('auto')">自动</button>
        <button class="btn btn-sm join-item min-h-10" :class="{ 'btn-active': ui.prefs.connView === 'table' }" type="button" @click="setConnView('table')">表格</button>
        <button class="btn btn-sm join-item min-h-10" :class="{ 'btn-active': ui.prefs.connView === 'card' }" type="button" @click="setConnView('card')">卡片</button>
      </div>
      <details class="dropdown">
        <summary class="btn btn-sm min-h-10">列</summary>
        <div class="menu dropdown-content z-20 rounded-box bg-base-100 p-2 shadow">
          <label v-for="col in columnMeta" :key="col.id" class="flex cursor-pointer items-center gap-2 px-2 py-1 text-sm">
            <input type="checkbox" class="checkbox checkbox-xs" :checked="!ui.prefs.connHiddenCols.includes(col.id)" @change="toggleCol(col.id)" />
            {{ col.label }}
          </label>
        </div>
      </details>
    </div>
    <p class="text-sm opacity-70">开始是 kdae 开始跟踪这条流的时间；时长由开始时间推算。这是 tproxy 抓住的流，不是整机 conntrack。</p>

    <div v-if="showCards" class="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
      <button
        v-for="row in filteredRows"
        :key="row.id"
        type="button"
        class="min-h-16 rounded-box border border-base-300 bg-base-100 p-3 text-left shadow"
        :class="{ 'opacity-40': row.closed }"
        @click="detailId = detailId === row.id ? '' : row.id"
      >
        <div class="flex items-start justify-between gap-2">
          <div class="min-w-0 break-all text-base font-semibold leading-snug">{{ hostOf(row) }}</div>
          <span v-if="row.closed" class="badge badge-ghost badge-sm shrink-0">断开</span>
        </div>
        <div class="mt-1 break-all font-mono text-sm font-medium text-primary">{{ displayEndpoint(row.src) || "—" }}</div>
        <div class="mt-2 flex flex-wrap items-center gap-1.5">
          <span class="badge badge-primary badge-sm font-semibold">{{ row.outbound || "—" }}</span>
          <span class="text-sm font-semibold text-secondary">{{ row.dialer || "—" }}</span>
        </div>
        <div class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          <span class="font-semibold text-success">↓ {{ prettyBytes(row.downloadRate) }}/s</span>
          <span class="font-medium text-info">↑ {{ prettyBytes(row.uploadRate) }}/s</span>
          <span class="opacity-70">{{ connectionAge(row.start || "", nowMs) }}</span>
          <span class="opacity-70">{{ row.network }}</span>
          <span v-if="macCell(row) !== '—'" class="font-mono opacity-70">{{ macCell(row) }}</span>
        </div>
        <div v-if="detailId === row.id" class="mt-2 grid grid-cols-1 gap-1 font-mono text-xs sm:grid-cols-2">
          <div class="break-all">目标 {{ displayEndpoint(row.dst) || "—" }}</div>
          <div class="break-all">MAC {{ macCell(row) }}</div>
          <div>开始 {{ formatTimeShort(row.start || "") || "—" }}</div>
          <div>上行 {{ prettyBytes(row.upload) }} · 下行 {{ prettyBytes(row.download) }}</div>
        </div>
      </button>
      <div v-if="!filteredRows.length" class="col-span-full py-8 text-center opacity-60">暂无 kdae 抓住的流。</div>
    </div>

    <div v-else class="overflow-x-auto rounded-box border border-base-300 bg-base-100">
      <table class="table table-sm kdae-zebra">
        <thead>
          <tr v-for="headerGroup in table.getHeaderGroups()" :key="headerGroup.id">
            <th
              v-for="header in headerGroup.headers"
              :key="header.id"
              draggable="true"
              class="cursor-pointer select-none bg-base-100"
              @click="header.column.getToggleSortingHandler()?.($event)"
              @dragstart="onHeaderDragStart(header.column.id)"
              @drop="onHeaderDrop(header.column.id)"
              @dragover.prevent
            >
              <div class="flex items-center gap-1">
                <FlexRender :render="header.column.columnDef.header" :props="header.getContext()" />
                <button
                  v-if="header.column.getCanGroup()"
                  class="btn btn-ghost btn-sm h-8 min-h-8 px-2"
                  type="button"
                  :title="header.column.getIsGrouped() ? '取消分组' : '按此列分组'"
                  @click.stop="header.column.getToggleGroupingHandler()?.()"
                >
                  {{ header.column.getIsGrouped() ? "−" : "+" }}
                </button>
                <span v-if="header.column.getIsSorted() === 'asc'">↑</span>
                <span v-else-if="header.column.getIsSorted() === 'desc'">↓</span>
              </div>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!tableRows.length">
            <td :colspan="columns.length" class="text-center opacity-60">暂无 kdae 抓住的流。must_direct 未劫持、block 静默丢、DNS 不在此表。</td>
          </tr>
          <tr
            v-for="row in tableRows"
            :key="row.id"
            :class="{ 'opacity-40': !row.getIsGrouped() && row.original.closed, 'font-semibold': row.getIsGrouped() }"
            @click="onRowClick(row)"
          >
            <td v-for="cell in row.getVisibleCells()" :key="cell.id" class="font-mono whitespace-nowrap">
              <div class="flex items-center gap-1">
                <template v-if="cell.getIsGrouped()">
                  <button class="btn btn-ghost btn-sm h-8 min-h-8 px-2" type="button" @click.stop="row.getToggleExpandedHandler()?.()">
                    {{ row.getIsExpanded() ? "−" : "+" }}
                  </button>
                  <FlexRender :render="cell.column.columnDef.cell" :props="cell.getContext()" />
                  <span>({{ row.subRows.length }})</span>
                </template>
                <template v-else-if="cell.getIsAggregated() || cell.getIsPlaceholder()" />
                <template v-else>
                  <FlexRender :render="cell.column.columnDef.cell" :props="cell.getContext()" />
                  <span v-if="cell.column.id === 'src' && row.original.closed" class="badge badge-ghost badge-xs ml-1">断开</span>
                </template>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

