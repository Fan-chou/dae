<script setup lang="ts">
import { onMounted } from "vue";
import { useI18n } from "vue-i18n";
import { refresh, saveConfig, ui } from "@/store/session";

const { t } = useI18n();

onMounted(() => {
  void refresh("config");
});
</script>

<template>
  <div class="flex flex-col gap-4">
    <p class="text-sm opacity-70">{{ t("config.note") }}</p>
    <div class="card bg-base-200">
      <div class="card-body p-4 gap-2">
        <h2 class="card-title text-base">config.dae（global + routing）</h2>
        <textarea v-model="ui.config.config" class="textarea textarea-bordered font-mono text-xs min-h-64" spellcheck="false" />
      </div>
    </div>
    <div class="card bg-base-200">
      <div class="card-body p-4 gap-2">
        <h2 class="card-title text-base">routing.dae</h2>
        <textarea v-model="ui.config.routing" class="textarea textarea-bordered font-mono text-xs min-h-64" spellcheck="false" />
      </div>
    </div>
    <div class="flex gap-2">
      <button class="btn btn-primary btn-sm" type="button" @click="saveConfig">保存并热重载</button>
      <button class="btn btn-ghost btn-sm" type="button" @click="refresh('config')">重新加载</button>
    </div>
  </div>
</template>
