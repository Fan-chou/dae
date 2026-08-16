<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { lintDae } from "@/lib/dae-lint";
import { refresh, saveConfig, ui } from "@/store/session";

const DaeEditor = defineAsyncComponent(() => import("@/views/DaeEditor.vue"));
const { t } = useI18n();
const tab = ref<"config" | "routing">("config");

onMounted(() => {
  void refresh("config");
});

const currentText = computed(() => (tab.value === "config" ? ui.config.config : ui.config.routing));
const currentIssues = computed(() => lintDae(currentText.value, tab.value));
const errorCount = computed(() => currentIssues.value.filter((issue) => issue.severity === "error").length);
const warningCount = computed(() => currentIssues.value.filter((issue) => issue.severity === "warning").length);
</script>

<template>
  <div class="flex min-h-[80vh] flex-col gap-3">
    <p class="text-sm opacity-70">{{ t("config.note") }}</p>
    <div class="flex flex-wrap items-center gap-2">
      <div class="tabs tabs-box">
        <button class="tab" :class="{ 'tab-active': tab === 'config' }" type="button" @click="tab = 'config'">config.dae</button>
        <button class="tab" :class="{ 'tab-active': tab === 'routing' }" type="button" @click="tab = 'routing'">routing.dae</button>
      </div>
      <span class="text-sm opacity-70">{{ errorCount }} 个错误 · {{ warningCount }} 个警告</span>
      <div class="ml-auto flex gap-2">
        <button class="btn btn-primary btn-sm" type="button" :disabled="errorCount > 0" @click="saveConfig">保存并热重载</button>
        <button class="btn btn-ghost btn-sm" type="button" @click="refresh('config')">重新加载</button>
      </div>
    </div>
    <DaeEditor v-if="tab === 'config'" v-model="ui.config.config" kind="config" />
    <DaeEditor v-else v-model="ui.config.routing" kind="routing" />
    <ul v-if="currentIssues.length" class="max-h-40 overflow-auto rounded-box border border-base-300 bg-base-100 p-3 text-sm">
      <li v-for="(issue, index) in currentIssues" :key="index" :class="issue.severity === 'error' ? 'text-error' : 'text-warning'">
        L{{ issue.line }}:{{ issue.column }} {{ issue.message }}
      </li>
    </ul>
  </div>
</template>
