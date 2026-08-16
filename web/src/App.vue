<script setup lang="ts">
import { computed } from "vue";
import { RouterLink, RouterView, useRoute } from "vue-router";
import { reloadPlane, ui } from "@/store/session";

const route = useRoute();
const links = [
  { to: "/overview", key: "overview" },
  { to: "/groups", key: "groups" },
  { to: "/connections", key: "connections" },
  { to: "/logs", key: "logs" },
  { to: "/config", key: "config" },
  { to: "/settings", key: "settings" },
];

const labels: Record<string, string> = {
  overview: "概览",
  groups: "组",
  connections: "连接",
  logs: "日志",
  config: "配置",
  settings: "设置",
};

const active = computed(() => route.path);
</script>

<template>
  <div class="navbar bg-base-200 border-b border-base-300">
    <div class="navbar-start">
      <RouterLink class="btn btn-ghost text-xl" to="/overview">kdae</RouterLink>
    </div>
    <div class="navbar-center hidden lg:flex">
      <ul class="menu menu-horizontal gap-1">
        <li v-for="link in links" :key="link.to">
          <RouterLink :to="link.to" :class="{ 'menu-active': active === link.to }">{{ labels[link.key] }}</RouterLink>
        </li>
      </ul>
    </div>
    <div class="navbar-end gap-2">
      <span v-if="ui.loading" class="loading loading-spinner loading-sm" />
      <button class="btn btn-sm btn-outline" type="button" @click="reloadPlane">热重载</button>
    </div>
  </div>
  <div class="lg:hidden px-3 py-2 overflow-x-auto">
    <ul class="menu menu-horizontal gap-1">
      <li v-for="link in links" :key="'m' + link.to">
        <RouterLink :to="link.to" :class="{ 'menu-active': active === link.to }">{{ labels[link.key] }}</RouterLink>
      </li>
    </ul>
  </div>
  <div v-if="ui.error" class="alert alert-error mx-4 mt-4 w-auto">{{ ui.error }}</div>
  <div v-if="ui.notice" class="alert alert-success mx-4 mt-4 w-auto">{{ ui.notice }}</div>
  <div v-if="ui.status?.sync_warning" class="alert alert-warning mx-4 mt-4 w-auto">{{ ui.status.sync_warning }}</div>
  <main class="p-4">
    <RouterView />
  </main>
</template>
