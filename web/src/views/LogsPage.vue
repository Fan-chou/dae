<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { refresh, ui } from "@/store/session";

const logFilter = ref("");
const logLevel = ref("");
const logKind = ref("");

onMounted(() => {
  void refresh("logs");
});

const filteredLogs = computed(() => {
  const q = logFilter.value.trim().toLowerCase();
  return ui.logs.filter((entry) => {
    if (logLevel.value && entry.level !== logLevel.value) return false;
    if (logKind.value && entry.kind !== logKind.value) return false;
    if (!q) return true;
    return entry.raw.toLowerCase().indexOf(q) !== -1;
  });
});

function togglePause(): void {
  ui.logPaused = !ui.logPaused;
  if (!ui.logPaused) void refresh("logs");
}

function clearLogs(): void {
  ui.logs = [];
  ui.logPaused = true;
}

function downloadLogs(): void {
  const lines = filteredLogs.value.map((entry) => {
    return [entry.seqLabel, entry.timeShort || "-", entry.level.padEnd(7, " "), entry.msg].join("  ");
  });
  const blob = new Blob([lines.join("\n") + "\n"], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "kdae-logs.txt";
  a.click();
  URL.revokeObjectURL(url);
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <div class="flex flex-wrap items-center gap-2">
      <select v-model="logLevel" class="select select-bordered select-sm">
        <option value="">级别</option>
        <option value="trace">trace</option>
        <option value="debug">debug</option>
        <option value="info">info</option>
        <option value="warning">warning</option>
        <option value="error">error</option>
      </select>
      <select v-model="logKind" class="select select-bordered select-sm">
        <option value="">全部类型</option>
        <option value="conn">连接</option>
        <option value="dns">DNS</option>
        <option value="sys">系统</option>
      </select>
      <input v-model="logFilter" class="input input-bordered input-sm flex-1 min-w-48" placeholder="搜索 payload / outbound / dialer" />
      <button class="btn btn-sm" :class="{ 'btn-active': ui.logPaused }" type="button" @click="togglePause">
        {{ ui.logPaused ? "继续" : "暂停" }}
      </button>
      <button class="btn btn-sm" type="button" @click="clearLogs">清空</button>
      <button class="btn btn-sm" type="button" @click="downloadLogs">下载</button>
      <span class="text-sm opacity-60">{{ filteredLogs.length }} / {{ ui.logs.length }}</span>
    </div>
    <p class="text-sm opacity-70">
      这里的级别是<strong>前端筛选已采集日志</strong>，不会改 dae 的 <code>log_level</code>。配置写成
      <code>info</code> 时进程根本不会写出 debug/trace，把筛选改成 debug 只会得到空列表。
    </p>
    <div v-if="!filteredLogs.length" class="alert">暂无日志</div>
    <article
      v-for="(entry, index) in filteredLogs"
      :key="entry.seq"
      class="rounded-box border border-base-300 p-3"
      :class="index % 2 ? 'kdae-log-even' : 'kdae-log-odd'"
    >
      <div class="flex flex-wrap gap-2 text-xs opacity-80">
        <span>{{ entry.seqLabel }}</span>
        <span v-if="entry.timeShort">{{ entry.timeShort }}</span>
        <span class="badge badge-outline">{{ entry.level }}</span>
        <span class="badge">{{ entry.kindLabel }}</span>
        <span v-if="entry.match" class="badge badge-info">{{ entry.match }}</span>
      </div>
      <div v-if="entry.conn" class="font-mono text-sm">{{ entry.conn.from }} ↔ {{ entry.conn.to }}</div>
      <div v-else class="text-sm">{{ entry.msg }}</div>
      <div v-if="entry.chips.length" class="mt-1 flex flex-wrap gap-1">
        <span v-for="chip in entry.chips" :key="chip.k" class="badge badge-ghost badge-sm">
          <b class="mr-1">{{ chip.k }}</b>{{ chip.v }}
        </span>
      </div>
    </article>
  </div>
</template>
