<script setup lang="ts">
import { computed, onMounted, onUnmounted, watch } from "vue";
import prettyBytes from "pretty-bytes";
import UiIcon from "@/components/UiIcon.vue";
import { useNow, usePreferredDark } from "@vueuse/core";
import { RouterLink, RouterView, useRoute } from "vue-router";
import { applyTheme } from "@/lib/theme";
import { persistPrefs, reloadPlane, ui } from "@/store/session";

const route = useRoute();
const links = [
  { to: "/overview", key: "overview", short: "概览" },
  { to: "/groups", key: "groups", short: "组" },
  { to: "/connections", key: "connections", short: "连接" },
  { to: "/logs", key: "logs", short: "日志" },
  { to: "/config", key: "config", short: "配置" },
  { to: "/settings", key: "settings", short: "设置" },
] as const;

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

const clock = useNow({ interval: 1000 });
const stale = computed(() => !ui.statusLastSuccessAt || !!ui.statusError || clock.value.getTime() - ui.statusLastSuccessAt > 10000);
function toggleTheme(): void { persistPrefs({ theme: resolvedTheme.value === "dark" ? "light" : "dark" }); }
function sidebarRate(value?: number): string { return stale.value || value == null ? "—" : prettyBytes(value) + "/s"; }
let media: MediaQueryList | null = null;
let errorTimer: ReturnType<typeof setTimeout> | undefined;
watch(() => ui.error, (message) => {
  clearTimeout(errorTimer);
  if (message) errorTimer = setTimeout(() => { ui.error = ""; }, 8000);
});
onUnmounted(() => clearTimeout(errorTimer));
let noticeTimer: ReturnType<typeof setTimeout> | undefined;
watch(() => ui.notice, (message) => {
  clearTimeout(noticeTimer);
  if (message) noticeTimer = setTimeout(() => { ui.notice = ""; }, 4500);
});
onUnmounted(() => clearTimeout(noticeTimer));
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
  <aside class="app-sidebar" :class="{ collapsed: ui.prefs.sidebarCollapsed }">
    <RouterLink class="app-brand" to="/overview"><span class="brand-mark">f</span><span class="brand-name">fdae</span></RouterLink>
    <nav class="sidebar-nav" aria-label="桌面主导航">
      <RouterLink v-for="link in links" :key="link.to" :to="link.to" :title="labels[link.key]" :class="{ 'is-active': active === link.to }">
        <UiIcon :name="link.key" /><span class="nav-label">{{ labels[link.key] }}</span>
      </RouterLink>
    </nav>
    <button class="sidebar-collapse" :aria-label="ui.prefs.sidebarCollapsed ? '展开侧栏' : '收起侧栏'" :title="ui.prefs.sidebarCollapsed ? '展开侧栏' : '收起侧栏'" @click="persistPrefs({ sidebarCollapsed: !ui.prefs.sidebarCollapsed })"><UiIcon name="chevron" :class="{ 'points-left': !ui.prefs.sidebarCollapsed }" /></button>
    <div class="sidebar-bottom">
      <div class="sidebar-traffic"><span>上传</span><strong>{{ sidebarRate(ui.status?.upload_rate) }}</strong><span>下载</span><strong>{{ sidebarRate(ui.status?.download_rate) }}</strong><span>内存</span><strong>{{ stale || ui.status?.rss_bytes == null ? '—' : prettyBytes(ui.status.rss_bytes) }}</strong></div>
      <div class="sidebar-state"><i :class="{ 'is-live': !stale && ui.status?.running }" />{{ stale ? '等待状态更新' : ui.status?.running ? '运行中' : '已停止' }}</div>
      <div class="sidebar-actions"><button class="btn btn-sm btn-ghost" :aria-label="resolvedTheme === 'dark' ? '浅色' : '深色'" :title="resolvedTheme === 'dark' ? '浅色' : '深色'" @click="toggleTheme"><UiIcon :name="resolvedTheme === 'dark' ? 'sun' : 'moon'" /><span class="action-label">{{ resolvedTheme === 'dark' ? '浅色' : '深色' }}</span></button><button class="btn btn-sm btn-ghost" aria-label="热重载" title="热重载" @click="reloadPlane"><UiIcon name="refresh" /><span class="action-label">热重载</span></button></div>
    </div>
  </aside>
  <header class="mobile-header"><RouterLink class="app-brand" to="/overview"><span class="brand-mark">f</span><span class="brand-name">fdae</span></RouterLink><div class="flex gap-1"><button class="btn btn-sm btn-ghost" @click="toggleTheme">{{ resolvedTheme === 'dark' ? '浅色' : '深色' }}</button><button class="btn btn-sm btn-ghost" @click="reloadPlane">热重载</button></div></header>
  <div class="toast-stack">
    <div v-if="ui.refreshError" class="toast-message toast-error" role="alert"><span>刷新失败：{{ ui.refreshError }}</span><button aria-label="关闭刷新提示" @click="ui.refreshError = ''">×</button></div>
    <div v-if="ui.error" class="toast-message toast-error" role="alert"><span>{{ ui.error }}</span><button aria-label="关闭错误提示" @click="ui.error = ''">×</button></div>
    <div v-if="ui.notice" class="toast-message" role="status"><span>{{ ui.notice }}</span><button aria-label="关闭操作提示" @click="ui.notice = ''">×</button></div>
  </div>
  <main class="app-main" :class="{ 'sidebar-collapsed': ui.prefs.sidebarCollapsed }" :data-resolved-theme="resolvedTheme">
    <div v-if="ui.status?.sync_warning" class="alert alert-warning mb-3">{{ ui.status.sync_warning }}</div>
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
      <UiIcon :name="link.key" />
      {{ link.short }}
    </RouterLink>
  </nav>
</template>
