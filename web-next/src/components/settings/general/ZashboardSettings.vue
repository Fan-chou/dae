<template>
  <div class="relative flex flex-col text-sm">
    <StyleSettings />
    <GeneralSettings />
    <p class="mt-6 px-1 text-xs text-base-content/40">
      fdae · 基于
      <a
        href="https://github.com/Zephyruso/zashboard"
        target="_blank"
        rel="noreferrer"
        class="link link-hover"
        >zashboard {{ zashboardVersion }}</a
      >
    </p>
  </div>
</template>
<script setup lang="ts">
import { zashboardVersion } from '@/assembly/version'
import GeneralSettings from './GeneralSettings.vue'
import StyleSettings from './StyleSettings.vue'
</script>
