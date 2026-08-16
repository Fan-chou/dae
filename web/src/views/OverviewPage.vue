<script setup lang="ts">
import prettyBytes from "pretty-bytes";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { generation, refresh, ui } from "@/store/session";

const chartEl = ref<HTMLDivElement | null>(null);
let chart: { setOption: (opt: unknown) => void; resize: () => void; dispose: () => void } | null = null;

function onResize(): void {
  chart?.resize();
}

const rateUp = computed(() => prettyBytes(ui.status?.upload_rate || 0) + "/s");
const rateDown = computed(() => prettyBytes(ui.status?.download_rate || 0) + "/s");
const totalUp = computed(() => prettyBytes(ui.status?.upload_total || 0));
const totalDown = computed(() => prettyBytes(ui.status?.download_total || 0));
const rss = computed(() => prettyBytes(ui.status?.rss_bytes || 0));

async function renderChart(): Promise<void> {
  const samples = ui.status?.traffic_samples || [];
  if (!chartEl.value || samples.length === 0) {
    return;
  }
  const echarts = await import("echarts");
  if (!chart) {
    chart = echarts.init(chartEl.value, "dark");
  }
  chart.setOption({
    backgroundColor: "transparent",
    tooltip: { trigger: "axis" },
    legend: { data: ["上行", "下行"] },
    xAxis: {
      type: "category",
      data: samples.map((s) => new Date(s.ts).toLocaleTimeString()),
    },
    yAxis: { type: "value", name: "B/s" },
    series: [
      { name: "上行", type: "line", showSymbol: false, data: samples.map((s) => s.up) },
      { name: "下行", type: "line", showSymbol: false, data: samples.map((s) => s.down) },
    ],
  });
}

onMounted(() => {
  void refresh("overview").then(() => renderChart());
  window.addEventListener("resize", onResize);
});
onUnmounted(() => {
  window.removeEventListener("resize", onResize);
  chart?.dispose();
  chart = null;
});
watch(
  () => ui.status?.traffic_samples,
  () => {
    void renderChart();
  },
);
</script>

<template>
  <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">版本</div>
      <div class="stat-value text-lg">{{ ui.status?.version || "—" }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">运行</div>
      <div class="stat-value text-lg">{{ ui.status?.running ? "运行中" : "未连接" }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">generation</div>
      <div class="stat-value text-lg">{{ generation }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">RSS / fd</div>
      <div class="stat-value text-lg">{{ rss }} / {{ ui.status?.fd_count ?? "—" }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">上行</div>
      <div class="stat-value text-lg">{{ rateUp }}</div>
      <div class="stat-desc">累计 {{ totalUp }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">下行</div>
      <div class="stat-value text-lg">{{ rateDown }}</div>
      <div class="stat-desc">累计 {{ totalDown }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">TCP 会话</div>
      <div class="stat-value text-lg">{{ ui.status?.active_connections ?? "—" }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">UDP 会话</div>
      <div class="stat-value text-lg">{{ ui.status?.udp_sessions ?? "—" }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box sm:col-span-2">
      <div class="stat-title">LAN</div>
      <div class="stat-value text-lg">{{ (ui.status?.lan_interface || []).join(", ") || "—" }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box sm:col-span-2">
      <div class="stat-title">WAN</div>
      <div class="stat-value text-lg">{{ (ui.status?.wan_interface || []).join(", ") || "（空，不劫持本机）" }}</div>
    </div>
  </div>
  <div class="card bg-base-200 mt-4">
    <div class="card-body">
      <h2 class="card-title text-base">速率</h2>
      <div ref="chartEl" class="h-56 w-full" />
    </div>
  </div>
</template>
