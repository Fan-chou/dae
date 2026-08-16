<script setup lang="ts">
import { onMounted } from "vue";
import { generation, refresh, ui } from "@/store/session";

onMounted(() => {
  void refresh("overview");
});
</script>

<template>
  <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
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
      <div class="stat-title">LAN</div>
      <div class="stat-value text-lg">{{ (ui.status?.lan_interface || []).join(", ") || "—" }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">WAN</div>
      <div class="stat-value text-lg">{{ (ui.status?.wan_interface || []).join(", ") || "（空，不劫持本机）" }}</div>
    </div>
    <div class="stat bg-base-200 rounded-box">
      <div class="stat-title">组</div>
      <div class="stat-value text-lg">{{ ui.groups.length }}</div>
    </div>
  </div>
</template>
