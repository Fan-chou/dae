<script setup lang="ts">
import {
  FlexRender,
  createColumnHelper,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useVueTable,
  type ColumnOrderState,
  type SortingState,
  type Updater,
} from "@tanstack/vue-table";
import { useDocumentVisibility, useIntervalFn } from "@vueuse/core";
import prettyBytes from "pretty-bytes";
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { refreshConnections, ui } from "@/store/session";
import { formatTimeShort, mergeConnectionSnapshots, type ConnectionView } from "@/lib/format";

const { t } = useI18n();
const search = ref("");
const sorting = ref<SortingState>([{ id: "upload", desc: true }]);
const columnOrder = ref<ColumnOrderState>([]);
const rows = ref<ConnectionView[]>([]);
const lastPollAt = ref(0);
const dragging = ref("");

const helper = createColumnHelper<ConnectionView>();

function bytesCell(value: number): string {
  return prettyBytes(value || 0);
}

function rateCell(value: number): string {
  return prettyBytes(value || 0) + "/s";
}

const columns = [
  helper.accessor("src", { header: "src", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("dst", { header: "dst", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("domain", { header: "domain", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("mac", { header: "mac", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("network", { header: "net", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("outbound", { header: "outbound", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("dialer", { header: "dialer", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("policy", { header: "policy", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("start", {
    header: "start",
    cell: (ctx) => formatTimeShort(ctx.getValue() || "") || "—",
  }),
  helper.accessor("upload", { header: "↑", cell: (ctx) => bytesCell(ctx.getValue()) }),
  helper.accessor("uploadRate", { header: "↑/s", cell: (ctx) => rateCell(ctx.getValue()) }),
  helper.accessor("download", { header: "↓", cell: (ctx) => bytesCell(ctx.getValue()) }),
  helper.accessor("downloadRate", { header: "↓/s", cell: (ctx) => rateCell(ctx.getValue()) }),
];

function applyUpdater<T>(updater: Updater<T>, current: T): T {
  return typeof updater === "function" ? (updater as (old: T) => T)(current) : updater;
}

const table = useVueTable({
  get data() {
    return rows.value;
  },
  columns,
  getCoreRowModel: getCoreRowModel(),
  getSortedRowModel: getSortedRowModel(),
  getFilteredRowModel: getFilteredRowModel(),
  globalFilterFn: (row, _columnId, filterValue) => {
    const q = String(filterValue || "")
      .trim()
      .toLowerCase();
    if (!q) return true;
    const item = row.original;
    return [item.src, item.dst, item.domain, item.mac, item.outbound, item.dialer, item.network, item.policy]
      .join(" ")
      .toLowerCase()
      .includes(q);
  },
  state: {
    get sorting() {
      return sorting.value;
    },
    get globalFilter() {
      return search.value;
    },
    get columnOrder() {
      return columnOrder.value;
    },
  },
  onSortingChange: (updater) => {
    sorting.value = applyUpdater(updater, sorting.value);
  },
  onGlobalFilterChange: (updater) => {
    search.value = applyUpdater(updater, search.value);
  },
  onColumnOrderChange: (updater) => {
    columnOrder.value = applyUpdater(updater, columnOrder.value);
  },
});

const visibleRows = computed(() => table.getRowModel().rows);
const truncated = computed(() => ui.connectionsTruncated);
const liveCount = computed(() => ui.connectionsTotal);

function applySnapshot(): void {
  const now = Date.now();
  const elapsed = lastPollAt.value ? now - lastPollAt.value : 0;
  rows.value = mergeConnectionSnapshots(rows.value, ui.connections, elapsed);
  lastPollAt.value = now;
}

async function poll(silent = true): Promise<void> {
  await refreshConnections({ silent });
  applySnapshot();
}

const visibility = useDocumentVisibility();
const { pause, resume } = useIntervalFn(
  () => {
    void poll(true);
  },
  2000,
  { immediate: false },
);

watch(visibility, (state) => {
  if (state === "hidden") pause();
  else resume();
});

onMounted(() => {
  void poll(false);
  if (visibility.value !== "hidden") resume();
});

function setOutbound(name: string): void {
  ui.connectionFilter.outbound = name;
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
</script>

<template>
  <div class="flex flex-col gap-3">
    <div class="flex flex-wrap items-center gap-2">
      <button class="btn btn-xs" :class="{ 'btn-active': ui.connectionFilter.outbound === 'AI' }" type="button" @click="setOutbound('AI')">
        outbound=AI
      </button>
      <button class="btn btn-xs" :class="{ 'btn-active': !ui.connectionFilter.outbound }" type="button" @click="setOutbound('')">
        全部
      </button>
      <input v-model="ui.connectionFilter.src" class="input input-bordered input-sm w-40" placeholder="src" @change="poll(false)" />
      <input v-model="ui.connectionFilter.mac" class="input input-bordered input-sm w-40" placeholder="mac" @change="poll(false)" />
      <input v-model="search" class="input input-bordered input-sm flex-1 min-w-48" placeholder="搜索 src / dst / domain / dialer" />
      <span class="text-sm opacity-70">{{ visibleRows.length }} / {{ liveCount }}{{ truncated ? "（截断）" : "" }}</span>
    </div>
    <p class="text-sm opacity-70">{{ t("connections.note") }}</p>
    <div class="overflow-x-auto rounded-box border border-base-300">
      <table class="table table-zebra table-sm">
        <thead>
          <tr v-for="headerGroup in table.getHeaderGroups()" :key="headerGroup.id">
            <th
              v-for="header in headerGroup.headers"
              :key="header.id"
              draggable="true"
              class="cursor-pointer select-none"
              @click="header.column.getToggleSortingHandler()?.($event)"
              @dragstart="onHeaderDragStart(header.column.id)"
              @dragover.prevent
              @drop="onHeaderDrop(header.column.id)"
            >
              <FlexRender :render="header.column.columnDef.header" :props="header.getContext()" />
              <span v-if="header.column.getIsSorted() === 'asc'"> ↑</span>
              <span v-else-if="header.column.getIsSorted() === 'desc'"> ↓</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!visibleRows.length">
            <td :colspan="columns.length" class="text-center opacity-60">{{ t("connections.empty") }}</td>
          </tr>
          <tr v-for="row in visibleRows" :key="row.id" :class="{ 'opacity-40': row.original.closed }">
            <td v-for="cell in row.getVisibleCells()" :key="cell.id" class="font-mono whitespace-nowrap">
              <FlexRender :render="cell.column.columnDef.cell" :props="cell.getContext()" />
              <span v-if="cell.column.id === 'src' && row.original.closed" class="badge badge-ghost badge-xs ml-1">断开</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
