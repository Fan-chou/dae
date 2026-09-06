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
import { useDocumentVisibility, useIntervalFn, useEventListener, onClickOutside } from "@vueuse/core";
import prettyBytes from "pretty-bytes";
import UiIcon from "@/components/UiIcon.vue";
import SegmentControl from "@/components/SegmentControl.vue";
import ConnectionDetails from "@/components/ConnectionDetails.vue";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { persistPrefs, refresh, refreshConnections, ui } from "@/store/session";
import {
  applyConnectionFilters,
  splitEndpoint,
  connectionAge,
  connectionAgeMs,
  connectionMacOptions,
  connectionSrcOptions,
  formatTimeShort,
  lookupCachedMac,
  uniqueDialers,
  uniqueNetworks,
  uniqueOutbounds,
  type ConnectionView,
} from "@/lib/format";
import { effectiveConnView, useCompactLayout } from "@/lib/layout";
import type { ConnViewMode } from "@/api/prefs";

const optionsPanel = ref<HTMLDetailsElement | null>(null);
onClickOutside(optionsPanel, () => optionsPanel.value?.removeAttribute("open"));
const paused = ref(false);
const page = ref(0);
const tabs = [{value:"active",label:"活动"},{value:"closed",label:"刚断开"},{value:"all",label:"全部"}] as const;
const compact = useCompactLayout();
const searchInput = ref<HTMLInputElement | null>(null);
const search = ref("");
const tab = ref<"active" | "closed" | "all">("active");
const network = ref("");
const dialer = ref("");
const sorting = ref<SortingState>([{ id: "age", desc: false }]);
const grouping = ref<GroupingState>([]);
const rowExpanded = ref<ExpandedState>({});
const columnOrder = ref<ColumnOrderState>(["domain","src","srcPort","dst","dstPort","network","route","downloadRate","uploadRate","age","outbound","dialer","mac","host","policy","upload","download","start"]);
const dragging = ref("");
const detailId = ref("");
const nowMs = ref(Date.now());
useEventListener("keydown", event => {
  const target = event.target as HTMLElement | null;
  if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey && !detailId.value && !target?.closest("input,textarea,select,[contenteditable=true]")) {
    event.preventDefault(); searchInput.value?.focus();
  }
 if (event.key === "Escape") { detailId.value = ""; optionsPanel.value?.removeAttribute("open"); } });

const helper = createColumnHelper<ConnectionView>();

function bytesCell(value: number): string {
  return prettyBytes(value || 0);
}

function rateCell(value: number): string {
  return prettyBytes(value || 0) + "/s";
}

const columnMeta: { id: string; label: string }[] = [
  { id: "mac", label: "MAC" },
  { id: "src", label: "源 IP" },
  { id: "srcPort", label: "源端口" },
  { id: "dst", label: "目标 IP / 域名" },
  { id: "dstPort", label: "目标端口" },
  { id: "host", label: "主机" },
  { id: "domain", label: "域名" },
  { id: "network", label: "协议" },
  { id: "route", label: "出站 / 节点" },
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
  return row.mac || (lookupCachedMac(ui.srcMacHints, row.src) ? lookupCachedMac(ui.srcMacHints, row.src) + "（缓存）" : "—");
}

const columns = [
  helper.accessor((row) => macCell(row), {
    id: "mac",
    header: "MAC",
    cell: (ctx) => ctx.getValue() || "—",
  }),
  helper.accessor((row) => splitEndpoint(row.src).host, { id: "src", header: "源 IP", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor((row) => splitEndpoint(row.src).port ? Number(splitEndpoint(row.src).port) : undefined, { id: "srcPort", header: "源端口", cell: (ctx) => ctx.getValue() ?? "—" }),
  helper.accessor((row) => splitEndpoint(row.dst).host, { id: "dst", header: "目标 IP / 域名", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor((row) => splitEndpoint(row.dst).port ? Number(splitEndpoint(row.dst).port) : undefined, { id: "dstPort", header: "目标端口", cell: (ctx) => ctx.getValue() ?? "—" }),
  helper.accessor((row) => row.domain || splitEndpoint(row.dst).host, { id: "host", header: "主机", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("domain", { header: "域名", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor(row => [row.outbound, row.dialer].filter(Boolean).join(" › "), { id: "route", header: "出站 / 节点", cell: ctx => ctx.getValue() || "—" }),
  helper.accessor("network", { header: "协议", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("outbound", { header: "出站", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("dialer", { header: "节点", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor("policy", { header: "策略", cell: (ctx) => ctx.getValue() || "—" }),
  helper.accessor((row) => connectionAgeMs(row.start || "", row.closedAt || nowMs.value), {
    id: "age",
    header: "时长",
    enableGrouping: false,
    cell: (ctx) => connectionAge(ctx.row.original.start || "", ctx.row.original.closedAt || nowMs.value),
  }),
  helper.accessor("uploadRate", { header: "上行速度", enableGrouping: false, cell: (ctx) => ctx.row.original.rateKnown ? rateCell(ctx.getValue()) : "—" }),
  helper.accessor("downloadRate", { header: "下行速度", enableGrouping: false, cell: (ctx) => ctx.row.original.rateKnown ? rateCell(ctx.getValue()) : "—" }),
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

const showCards = computed(() => effectiveConnView(ui.prefs.connView, compact.value) === "card");
const allTableRows = computed(() => table.getRowModel().rows);
const tableRows = computed(() => allTableRows.value.slice(page.value * 50, (page.value + 1) * 50));
const cardRows = computed(() => filteredRows.value.slice(page.value * 50, (page.value + 1) * 50));
const pageCount = computed(() => Math.max(1, Math.ceil((showCards.value ? filteredRows.value.length : allTableRows.value.length) / 50)));
const selectedRow = computed(() => ui.connectionViews.find(row => row.id === detailId.value));
const activeFilters = computed(() => {
  const result: { key: string; label: string; clear: () => void }[] = [];
  for (const [key, name] of [["outbound","出站"],["src","源 IP"],["mac","MAC"]] as const) {
    if (ui.connectionFilter[key]) result.push({key, label:name + " · " + ui.connectionFilter[key], clear:() => {ui.connectionFilter[key] = "";}});
  }
  if (network.value) result.push({key:"network",label:"协议 · " + network.value,clear:() => {network.value = "";}});
  if (dialer.value) result.push({key:"dialer",label:"节点 · " + dialer.value,clear:() => {dialer.value = "";}});
  if (search.value) result.push({key:"search",label:"搜索 · " + search.value,clear:() => {search.value = "";}});
  if (ui.prefs.connExcludeOn && ui.prefs.connExclude) result.push({key:"exclude",label:"排除 · " + ui.prefs.connExclude,clear:() => persistPrefs({connExcludeOn:false})});
  return result;
});
async function copyDetails(): Promise<void> {
  const row = selectedRow.value;
  if (!row) return;
  ui.notice = ""; ui.error = "";
  try {
    await navigator.clipboard.writeText([
      "源 IP: " + splitEndpoint(row.src).host, "源端口: " + splitEndpoint(row.src).port,
      "目标: " + splitEndpoint(row.dst).host, "目标端口: " + splitEndpoint(row.dst).port,
      "域名: " + (row.domain || "—"), "出站: " + row.outbound, "节点: " + (row.dialer || "—"),
    ].join("\n"));
    ui.notice = "已复制连接信息";
  } catch { ui.error = "无法访问剪贴板，请手动选择详情中的文字复制"; }
}

watch(pageCount, count => { page.value = Math.min(page.value, count - 1); });
watch([search, network, dialer, tab, sorting, grouping], () => { page.value = 0; });
watch(() => [ui.connectionFilter.outbound, ui.connectionFilter.src, ui.connectionFilter.mac, ui.prefs.connLimit], () => { page.value = 0; detailId.value = ""; void poll(false); });
function clearFilters() { ui.connectionFilter = {outbound:"",src:"",mac:""}; search.value=""; network.value=""; dialer.value=""; persistPrefs({connExcludeOn:false}); }

function onRowClick(row: Row<ConnectionView>): void {
  if (row.getIsGrouped()) {
    row.getToggleExpandedHandler()?.();
    return;
  }
  detailId.value = detailId.value === row.original.id ? "" : row.original.id;
}

let refreshingStatus = false;
async function pollStatus(silent: boolean): Promise<void> {
  if (refreshingStatus) return;
  refreshingStatus = true;
  try { await refresh(undefined, { silent }); } finally { refreshingStatus = false; }
}
async function poll(silent = true): Promise<void> {
  nowMs.value = Date.now();
  await Promise.all([refreshConnections({ silent }), pollStatus(silent)]);
}

const visibility = useDocumentVisibility();
const { pause, resume } = useIntervalFn(
  () => {
    if (!paused.value) void poll(true);
  },
  () => ui.prefs.connInterval,
  { immediate: false },
);

watch([visibility, paused], ([state, stopped]) => {
  if (state === "hidden" || stopped) pause();
  else { resume(); void poll(true); }
});

onMounted(() => {
  void refresh("groups");
  void poll(false);
  if (visibility.value !== "hidden") resume();
});
onUnmounted(() => {
  pause();
});

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
  return row.domain || splitEndpoint(row.dst).host || "—";
}



function setConnView(mode: ConnViewMode): void {
  persistPrefs({ connView: mode });
}
</script>

<template>
  <div class="connection-page">
    <section class="connection-toolbar">
      <div class="connection-command">
        <SegmentControl :model-value="tab" :options="tabs.map(item => ({...item, count: tab === item.value ? filteredRows.length : undefined}))" label="连接状态" @update:model-value="tab = $event as typeof tab" />
        <label class="source-filter"><span class="sr-only">源 IP</span><select v-model="ui.connectionFilter.src" class="select select-sm"><option value="">全部来源</option><option v-for="opt in srcOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</option></select></label>
        <label class="search-field"><UiIcon name="search" /><input ref="searchInput" v-model="search" class="input input-sm" placeholder="搜索 IP、域名、节点…" aria-label="搜索已加载连接" /><button v-if="search" class="search-clear" aria-label="清空搜索" @click.prevent="search = ''"><UiIcon name="close" /></button><kbd v-else>/</kbd></label>
      <select class="select select-sm connection-group-select" aria-label="连接分组" :value="grouping.length > 1 ? '__multiple' : grouping[0] || ''" @change="grouping = ($event.target as HTMLSelectElement).value ? [($event.target as HTMLSelectElement).value] : []">
        <option value="">不分组</option>
        <option v-if="grouping.length > 1" value="__multiple" disabled>多字段分组</option>
        <template v-for="col in columnMeta" :key="col.id"><option v-if="table.getColumn(col.id)?.getCanGroup()" :value="col.id">按{{ col.label }}分组</option></template>
      </select>
      <details ref="optionsPanel" class="advanced-filters"><summary aria-label="显示与筛选" title="显示与筛选"><UiIcon name="filter" /><span class="sr-only">显示与筛选</span></summary>
        <div class="connection-options">
        <div class="options-heading">显示与筛选<button class="btn btn-sm btn-ghost" aria-label="关闭显示选项" @click="optionsPanel?.removeAttribute('open')">×</button></div>
      <div class="filter-grid">
        <label>出站<select v-model="ui.connectionFilter.outbound" class="select select-sm"><option value="">全部出站</option><option v-for="name in outboundOptions" :key="name">{{ name }}</option></select></label>
        <label>协议<select v-model="network" class="select select-sm"><option value="">全部协议</option><option v-for="name in networkOptions" :key="name">{{ name }}</option></select></label>
        <label>节点<select v-model="dialer" class="select select-sm"><option value="">全部节点</option><option v-for="name in dialerOptions" :key="name">{{ name }}</option></select></label>
      </div>
        <div class="filter-grid mt-3">
          <label>MAC<select v-model="ui.connectionFilter.mac" class="select select-sm"><option value="">全部 MAC</option><option v-for="opt in macOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</option></select></label>
          <label>刷新间隔<select class="select select-sm" :value="ui.prefs.connInterval" @change="onIntervalChange"><option :value="1000">1 秒</option><option :value="2000">2 秒</option><option :value="5000">5 秒</option></select></label>
          <label>加载上限<select class="select select-sm" :value="ui.prefs.connLimit" @change="persistPrefs({connLimit: Number(($event.target as HTMLSelectElement).value)})"><option :value="256">256 条</option><option :value="512">512 条</option><option :value="1024">1024 条</option></select></label>
          <label>视图<select class="select select-sm" :value="ui.prefs.connView" @change="setConnView(($event.target as HTMLSelectElement).value as ConnViewMode)"><option value="auto">自动</option><option value="table">表格</option><option value="card">卡片</option></select></label>
        </div>
        <div class="flex flex-wrap items-center gap-3 mt-3"><label class="flex items-center gap-2"><input type="checkbox" class="checkbox checkbox-sm" :checked="ui.prefs.connExcludeOn" @change="onExcludeToggle" />排除匹配</label><input class="input input-sm flex-1" aria-label="排除正则表达式" :value="ui.prefs.connExclude" placeholder="例如 stun|ntp" @change="onExcludeChange" /></div>
        <p class="options-label">分组</p>
        <div class="column-options"><template v-for="col in columnMeta" :key="col.id"><label v-if="table.getColumn(col.id)?.getCanGroup()"><input type="checkbox" class="checkbox checkbox-xs" :checked="grouping.includes(col.id)" @change="table.getColumn(col.id)?.toggleGrouping()" />{{ col.label }}</label></template></div>
        <p class="options-label">可见列 · 拖动表头调整顺序</p>
        <div class="column-options"><label v-for="col in columnMeta" :key="col.id"><input type="checkbox" class="checkbox checkbox-xs" :checked="!ui.prefs.connHiddenCols.includes(col.id)" @change="toggleCol(col.id)" />{{ col.label }}</label></div>
      </div></details>
        <div class="refresh-controls">
          <button class="btn btn-sm btn-ghost icon-button" :aria-label="paused ? '继续刷新' : '暂停刷新'" :title="paused ? '继续刷新' : '暂停刷新'" :aria-pressed="paused" @click="paused = !paused"><UiIcon :name="paused ? 'play' : 'pause'" /></button>
          <button class="btn btn-sm btn-ghost icon-button" aria-label="刷新" title="刷新" :disabled="ui.connectionsPending" @click="poll(false)"><UiIcon name="refresh" /></button>
        </div>
      </div>
      <div v-if="activeFilters.length" class="filter-chips"><button @click="clearFilters">清除筛选</button><button v-for="filter in activeFilters" :key="filter.key" :aria-label="'移除' + filter.label" @click="filter.clear()"><span>{{ filter.label }}</span><UiIcon name="close" /></button></div>
    </section>
    <div v-if="ui.connectionsError" role="alert" class="data-note">{{ ui.connectionsError }} · 以下保留上次成功结果</div>

    <p v-if="ui.connectionsTruncated" class="data-note" role="status">结果超过加载上限。搜索、节点与协议筛选仅覆盖已加载连接；可先按出站、源 IP 或 MAC 缩小范围。未返回的连接不会被判定为断开。</p>
    <div v-if="showCards" class="connection-cards">
      <button v-for="row in cardRows" :key="row.id" class="connection-card" :class="{'is-closed': row.closed}" @click="detailId = detailId === row.id ? '' : row.id">
        <div class="card-heading"><strong>{{ hostOf(row) }}</strong><span class="badge badge-sm">{{ row.closed ? '刚断开' : row.network }}</span></div>
        <div class="endpoint-line"><span>源 IP</span><code>{{ splitEndpoint(row.src).host || '—' }}</code><span>端口 <b>{{ splitEndpoint(row.src).port || '—' }}</b></span></div>
        <div class="endpoint-line"><span>目标</span><code>{{ splitEndpoint(row.dst).host || '—' }}</code><span>端口 <b>{{ splitEndpoint(row.dst).port || '—' }}</b></span></div>
        <div class="card-route"><span>{{ row.outbound || '—' }}</span><span>→</span><span>{{ row.dialer || '—' }}</span></div>
        <div class="card-rates"><span>↓ {{ row.rateKnown ? rateCell(row.downloadRate) : "—" }}</span><span>↑ {{ row.rateKnown ? rateCell(row.uploadRate) : "—" }}</span><span>{{ connectionAge(row.start || '', row.closedAt || nowMs) }}</span></div>
      </button>
      <div v-if="!cardRows.length" class="empty-state">{{ search || network || dialer ? '没有符合筛选条件的连接' : '当前没有连接记录' }}</div>
    </div>
    <div v-else class="connection-table-wrap">
      <table class="table kdae-zebra connection-table">
        <thead>
          <tr v-for="headerGroup in table.getHeaderGroups()" :key="headerGroup.id">
            <th
              v-for="header in headerGroup.headers"
              :key="header.id"
              :data-column="header.column.id"
              :aria-sort="header.column.getIsSorted() === 'asc' ? 'ascending' : header.column.getIsSorted() === 'desc' ? 'descending' : 'none'"
              tabindex="0"
              @keydown.enter.prevent="header.column.getToggleSortingHandler()?.($event)"
              @keydown.space.prevent="header.column.getToggleSortingHandler()?.($event)"
              draggable="true"
              class="cursor-pointer select-none bg-base-100"
              @click="header.column.getToggleSortingHandler()?.($event)"
              @dragstart="onHeaderDragStart(header.column.id)"
              @drop="onHeaderDrop(header.column.id)"
              @dragover.prevent
            >
              <div class="flex items-center gap-1">
                <FlexRender :render="header.column.columnDef.header" :props="header.getContext()" />
                <UiIcon v-if="header.column.getIsSorted()" :name="header.column.getIsSorted() === 'asc' ? 'up' : 'down'" />
              </div>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!tableRows.length">
            <td :colspan="table.getVisibleLeafColumns().length" class="connection-empty"><UiIcon name="search" /><strong>{{ ui.connectionsPending ? "正在获取连接" : "没有符合条件的连接" }}</strong><span>{{ activeFilters.length ? "尝试移除筛选条件，或检查加载范围。" : "此处显示 fdae 跟踪的连接。" }}</span></td>
          </tr>
          <tr
            v-for="row in tableRows"
            :key="row.id"
            :class="{ 'opacity-40': !row.getIsGrouped() && row.original.closed, 'font-semibold': row.getIsGrouped(), 'is-selected': !row.getIsGrouped() && row.original.id === detailId }"
            tabindex="0"
            @keydown.enter="onRowClick(row)"
            @keydown.space.prevent="onRowClick(row)"
            @click="onRowClick(row)"
          >
            <td v-for="cell in row.getVisibleCells()" :key="cell.id" :data-column="cell.column.id" class="whitespace-nowrap">
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

    <footer class="connection-footer"><div class="connection-summary"><span>匹配 {{ ui.connectionsLastPollAt ? ui.connectionsTotal : "—" }} · 已加载 {{ ui.connections.length }} · 当前 {{ filteredRows.length }}</span><span class="refresh-status">{{ ui.connectionsPending ? '刷新中…' : paused ? '已暂停' : ui.connectionsLastPollAt ? '更新于 ' + formatTimeShort(new Date(ui.connectionsLastPollAt).toISOString()) : '等待连接' }}</span><span title="仅包含 fdae 跟踪的连接；每页 50 条；速率 — 表示等待两次可比较的采样。" tabindex="0" class="table-help" aria-label="仅包含 fdae 跟踪的连接；每页 50 条；速率未知时显示横线。">ⓘ</span></div><div class="join"><button class="btn btn-sm join-item" :disabled="page === 0" @click="page--">上一页</button><span class="btn btn-sm join-item pointer-events-none">{{ page + 1 }} / {{ pageCount }}</span><button class="btn btn-sm join-item" :disabled="page + 1 >= pageCount" @click="page++">下一页</button></div></footer>
    <ConnectionDetails v-if="selectedRow" :row="selectedRow" :mac="macCell(selectedRow)" @close="detailId = ''" @copy="copyDetails" />
  </div>
</template>
