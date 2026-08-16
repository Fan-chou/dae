<script setup lang="ts">
import { computed, onMounted, onUnmounted, watch } from "vue";
import { usePreferredDark } from "@vueuse/core";
import { RouterLink, RouterView, useRoute } from "vue-router";
import { applyTheme } from "@/lib/theme";
import { reloadPlane, ui } from "@/store/session";

const route = useRoute();
const links = [
  { to: "/overview", key: "overview", short: "概览", d: "M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z" },
  { to: "/groups", key: "groups", short: "组", d: "M4 7a3 3 0 1 0 6 0 3 3 0 0 0-6 0m10 0a3 3 0 1 0 6 0 3 3 0 0 0-6 0M2 19a5 5 0 0 1 10 0m10 0a5 5 0 0 0-8-4" },
  { to: "/connections", key: "connections", short: "连接", d: "M8 12h8M7 8H5a3 3 0 0 0 0 8h2m10-8h2a3 3 0 0 1 0 8h-2" },
  { to: "/logs", key: "logs", short: "日志", d: "M6 4h9l3 3v13H6zm3 6h6M9 14h6M9 18h4" },
  { to: "/config", key: "config", short: "配置", d: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6m7.4-3.4-.9 1.6 1.2 1.4-1.7 1.7-1.6-.6-1.4 1.1v2h-2.4v-2l-1.4-1.1-1.6.6-1.7-1.7 1.2-1.4-.9-1.6-2-.4V9.8l2-.4.9-1.6-1.2-1.4 1.7-1.7 1.6.6 1.4-1.1V2.2h2.4v2l1.4 1.1 1.6-.6 1.7 1.7-1.2 1.4.9 1.6 2 .4v2.4z" },
  { to: "/settings", key: "settings", short: "设置", d: "M5 7h14M5 12h14M5 17h14" },
];

const labels: Record<string, string> = {
  overview: "概览",
  groups: "代理组",
  connections: "连接",
  logs: "日志",
  config: "配置",
  settings: "设置",
};

const active = computed(() => route.path);
const prefersDark = usePreferredDark();
const resolvedTheme = computed(() => {
  if (ui.prefs.theme === "light" || ui.prefs.theme === "dark") return ui.prefs.theme;
  return prefersDark.value ? "dark" : "light";
});

let media: MediaQueryList | null = null;
function onSystemTheme(): void {
  if (ui.prefs.theme === "system") applyTheme("system");
}

onMounted(() => {
  applyTheme(ui.prefs.theme);
  media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", onSystemTheme);
});
onUnmounted(() => {
  media?.removeEventListener("change", onSystemTheme);
});
watch(
  () => ui.prefs.theme,
  (pref) => {
    applyTheme(pref);
  },
);
</script>

<template>
  <div class="navbar sticky top-0 z-30 border-b border-base-300 bg-base-100 pt-[env(safe-area-inset-top)]">
    <div class="navbar-start">
      <RouterLink class="btn btn-ghost min-h-10 text-xl" to="/overview">kdae</RouterLink>
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
      <button class="btn btn-sm btn-outline min-h-10" type="button" @click="reloadPlane">热重载</button>
    </div>
  </div>
  <div class="hidden overflow-x-auto px-3 py-2 md:block lg:hidden">
    <ul class="menu menu-horizontal gap-1">
      <li v-for="link in links" :key="'m' + link.to">
        <RouterLink class="min-h-10" :to="link.to" :class="{ 'menu-active': active === link.to }">{{ labels[link.key] }}</RouterLink>
      </li>
    </ul>
  </div>
  <div v-if="ui.error" class="alert alert-error mx-4 mt-4 w-auto">{{ ui.error }}</div>
  <div v-if="ui.notice" class="alert alert-success mx-4 mt-4 w-auto">{{ ui.notice }}</div>
  <div v-if="ui.status?.sync_warning" class="alert alert-warning mx-4 mt-4 w-auto">{{ ui.status.sync_warning }}</div>
  <main class="p-4 pb-[calc(4.75rem+env(safe-area-inset-bottom))] md:pb-4" :data-resolved-theme="resolvedTheme">
    <RouterView />
  </main>
  <nav
    class="fixed inset-x-0 bottom-0 z-40 grid grid-cols-6 border-t border-base-300 bg-base-100 pb-[env(safe-area-inset-bottom)] md:hidden"
    aria-label="主导航"
  >
    <RouterLink
      v-for="link in links"
      :key="'b' + link.to"
      :to="link.to"
      class="flex min-h-12 flex-col items-center justify-center gap-0.5 py-1 text-[11px] leading-none"
      :class="active === link.to ? 'text-primary' : 'opacity-70'"
    >
      <svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path :d="link.d" />
      </svg>
      {{ link.short }}
    </RouterLink>
  </nav>
</template>
