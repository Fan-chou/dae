<script setup lang="ts">
import prettyBytes from "pretty-bytes";
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { useDocumentVisibility, useIntervalFn, usePreferredDark } from "@vueuse/core";
import { generation, refresh, refreshConnections, ui } from "@/store/session";
import { rateScale, srcHost, summarizeConnections, type TrafficBucket } from "@/lib/format";
import { resolveTheme } from "@/lib/theme";

type ChartHandle = {
  setOption: (opt: Record<string, unknown>, notMerge?: boolean) => void;
  resize: () => void;
  dispose: () => void;
};
const chartEl = ref<HTMLDivElement | null>(null);
let chart: ChartHandle | null = null;

function onResize(): void {
  chart?.resize();
}

const summary = computed(() => summarizeConnections(ui.connectionViews, 12));
const rateUp = computed(() => prettyBytes(summary.value.uploadRate || 0) + "/s");
const rateDown = computed(() => prettyBytes(summary.value.downloadRate || 0) + "/s");
const totalUp = computed(() => prettyBytes(summary.value.upload || 0));
const totalDown = computed(() => prettyBytes(summary.value.download || 0));
const rss = computed(() => prettyBytes(ui.status?.rss_bytes || 0));

function macsForSrc(host: string): string {
  const macs = new Set<string>();
  for (const hint of ui.srcMacHints) {
    if (srcHost(hint.src) === host && hint.mac) macs.add(hint.mac);
  }
  return [...macs].join(", ");
}

function srcsForMac(mac: string): string {
  const srcs = new Set<string>();
  for (const hint of ui.srcMacHints) {
    if (hint.mac === mac) srcs.add(srcHost(hint.src) || hint.src);
  }
  return [...srcs].join(", ");
}

function bucketLine(item: TrafficBucket): string {
  return (
    item.count +
    " 条 · 累计 ↑ " +
    prettyBytes(item.upload) +
    " ↓ " +
    prettyBytes(item.download) +
    " · ↑ " +
    prettyBytes(item.uploadRate) +
    "/s ↓ " +
    prettyBytes(item.downloadRate) +
    "/s"
  );
}

async function renderChart(): Promise<void> {
  const samples = ui.trafficSamples;
  if (!chartEl.value || samples.length < 2) return;
  const echarts = await import("echarts");
  const theme = resolveTheme(ui.prefs.theme);
  if (chart && (chart as ChartHandle & { __kdaeTheme?: string }).__kdaeTheme !== theme) {
    chart.dispose();
    chart = null;
  }
  if (!chart) {
    chart = echarts.init(chartEl.value, theme === "dark" ? "dark" : undefined) as unknown as ChartHandle;
    (chart as ChartHandle & { __kdaeTheme?: string }).__kdaeTheme = theme;
  }
  const instance = chart;
  if (!instance) return;
  const scale = rateScale(samples.flatMap((sample) => [sample.up || 0, sample.down || 0]));
  instance.setOption(
    {
      backgroundColor: "transparent",
      animationDuration: 300,
      tooltip: {
        trigger: "axis",
        formatter: (items: { dataIndex: number; axisValue: string }[]) => {
          const index = items[0]?.dataIndex ?? 0;
          const sample = samples[index];
          if (!sample) return "";
          return (
            new Date(sample.ts).toLocaleTimeString() +
            "<br/>上行 " +
            prettyBytes(sample.up || 0) +
            "/s<br/>下行 " +
            prettyBytes(sample.down || 0) +
            "/s"
          );
        },
      },
      legend: { data: ["上行", "下行"] },
      xAxis: {
        type: "time",
        min: samples[0]?.ts,
        max: samples[samples.length - 1]?.ts,
      },
      yAxis: { type: "value", name: scale.unit, min: 0, max: scale.niceMax },
      series: [
        {
          name: "上行",
          type: "line",
          showSymbol: false,
          data: samples.map((sample) => [sample.ts, Number(((sample.up || 0) / scale.divisor).toFixed(2))]),
        },
        {
          name: "下行",
          type: "line",
          showSymbol: false,
          data: samples.map((sample) => [sample.ts, Number(((sample.down || 0) / scale.divisor).toFixed(2))]),
        },
      ],
    },
    true,
  );
  instance.resize();
}

async function poll(silent = true): Promise<void> {
  await refresh("overview", { silent });
  await refreshConnections({ silent, outbound: "" });
  await nextTick();
  await renderChart();
}

const visibility = useDocumentVisibility();
const prefersDark = usePreferredDark();
const { pause, resume } = useIntervalFn(
  () => {
    void poll(true);
  },
  2000,
  { immediate: false },
);

onMounted(() => {
  void poll(false);
  window.addEventListener("resize", onResize);
  if (visibility.value !== "hidden") resume();
});
onUnmounted(() => {
  window.removeEventListener("resize", onResize);
  pause();
  chart?.dispose();
  chart = null;
});
watch(visibility, (state) => {
  if (state === "hidden") pause();
  else resume();
});
watch(
  () => ui.trafficSamples.at(-1)?.ts,
  () => {
    void renderChart();
  },
);
watch(
  [() => ui.prefs.theme, prefersDark],
  () => {
    void renderChart();
  },
);
</script>

<template>
  <div class="grid grid-cols-2 gap-4 lg:grid-cols-4">
    <div class="stat rounded-box bg-base-100 shadow">
      <div class="stat-title">版本</div>
      <div class="stat-value text-lg">{{ ui.status?.version || "—" }}</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow">
      <div class="stat-title">运行</div>
      <div class="stat-value text-lg">{{ ui.status?.running ? "运行中" : "未连接" }}</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow">
      <div class="stat-title">generation</div>
      <div class="stat-value text-lg">{{ generation }}</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow">
      <div class="stat-title">RSS / fd</div>
      <div class="stat-value text-lg">{{ rss }} / {{ ui.status?.fd_count ?? "—" }}</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow">
      <div class="stat-title">当前会话</div>
      <div class="stat-value text-lg">{{ summary.live }}</div>
      <div class="stat-desc">kdae 抓住的活动连接</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow">
      <div class="stat-title">上行（当前会话）</div>
      <div class="stat-value text-lg">{{ rateUp }}</div>
      <div class="stat-desc">累计 {{ totalUp }}</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow">
      <div class="stat-title">下行（当前会话）</div>
      <div class="stat-value text-lg">{{ rateDown }}</div>
      <div class="stat-desc">累计 {{ totalDown }}</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow">
      <div class="stat-title">TCP / UDP</div>
      <div class="stat-value text-lg">{{ ui.status?.active_connections ?? "—" }} / {{ ui.status?.udp_sessions ?? "—" }}</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow sm:col-span-2">
      <div class="stat-title">LAN</div>
      <div class="stat-value text-lg">{{ (ui.status?.lan_interface || []).join(", ") || "—" }}</div>
    </div>
    <div class="stat rounded-box bg-base-100 shadow sm:col-span-2">
      <div class="stat-title">WAN</div>
      <div class="stat-value text-lg">{{ (ui.status?.wan_interface || []).join(", ") || "（空，不劫持本机）" }}</div>
    </div>
  </div>
  <div class="mt-4 rounded-box bg-base-100 p-4 shadow">
    <h2 class="mb-2 text-base font-semibold">速率（当前会话）</h2>
    <p class="mb-2 text-sm opacity-70">按连接快照差分，约 2 秒一点，最多保留 5 分钟。第一次刷新速率为 0 是正常的。</p>
    <div v-if="ui.trafficSamples.length < 2" class="py-10 text-center text-sm opacity-60">采集中，请稍候…</div>
    <div v-show="ui.trafficSamples.length >= 2" ref="chartEl" class="h-44 w-full md:h-56" />
  </div>
  <div class="mt-4 grid gap-4 lg:grid-cols-2">
    <section class="rounded-box bg-base-100 p-4 shadow">
      <h2 class="mb-2 text-base font-semibold">来源 IP</h2>
      <p class="mb-2 text-sm opacity-70">当前 {{ summary.live }} 条活动连接</p>
      <div v-if="!summary.bySrc.length" class="text-sm opacity-60">暂无连接</div>
      <div v-for="item in summary.bySrc" :key="'src-' + item.name" class="border-t border-base-300 py-2 text-sm first:border-t-0">
        <div class="truncate font-mono font-medium">{{ item.name }}</div>
        <div v-if="macsForSrc(item.name)" class="truncate text-xs opacity-70">MAC {{ macsForSrc(item.name) }}</div>
        <div class="text-xs leading-relaxed break-words opacity-80">{{ bucketLine(item) }}</div>
      </div>
    </section>
    <section class="rounded-box bg-base-100 p-4 shadow">
      <h2 class="mb-2 text-base font-semibold">MAC</h2>
      <div v-if="!summary.byMac.length" class="text-sm opacity-60">暂无 MAC</div>
      <div v-for="item in summary.byMac" :key="'mac-' + item.name" class="border-t border-base-300 py-2 text-sm first:border-t-0">
        <div class="truncate font-mono font-medium">{{ item.name }}</div>
        <div v-if="srcsForMac(item.name)" class="truncate text-xs opacity-70">源 {{ srcsForMac(item.name) }}</div>
        <div class="text-xs leading-relaxed break-words opacity-80">{{ bucketLine(item) }}</div>
      </div>
    </section>
    <section class="rounded-box bg-base-100 p-4 shadow">
      <h2 class="mb-2 text-base font-semibold">出站</h2>
      <div v-if="!summary.byOutbound.length" class="text-sm opacity-60">暂无连接</div>
      <div v-for="item in summary.byOutbound" :key="'ob-' + item.name" class="border-t border-base-300 py-2 text-sm first:border-t-0">
        <div class="truncate font-medium">{{ item.name }}</div>
        <div class="text-xs leading-relaxed break-words opacity-80">{{ bucketLine(item) }}</div>
      </div>
    </section>
    <section class="rounded-box bg-base-100 p-4 shadow">
      <h2 class="mb-2 text-base font-semibold">节点</h2>
      <div v-if="!summary.byDialer.length" class="text-sm opacity-60">暂无连接</div>
      <div v-for="item in summary.byDialer" :key="'d-' + item.name" class="border-t border-base-300 py-2 text-sm first:border-t-0">
        <div class="truncate font-medium">{{ item.name }}</div>
        <div class="text-xs leading-relaxed break-words opacity-80">{{ bucketLine(item) }}</div>
      </div>
    </section>
    <section class="rounded-box bg-base-100 p-4 shadow lg:col-span-2">
      <h2 class="mb-2 text-base font-semibold">域名</h2>
      <div v-if="!summary.byDomain.length" class="text-sm opacity-60">暂无 sniff 域名</div>
      <div class="grid gap-2 md:grid-cols-2">
        <div v-for="item in summary.byDomain" :key="'dom-' + item.name" class="border-t border-base-300 py-2 text-sm first:border-t-0">
          <div class="truncate font-mono font-medium">{{ item.name }}</div>
          <div class="text-xs leading-relaxed break-words opacity-80">{{ bucketLine(item) }}</div>
        </div>
      </div>
    </section>
  </div>
</template>
