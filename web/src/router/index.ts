import { createRouter, createWebHashHistory } from "vue-router";

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", redirect: "/overview" },
    { path: "/overview", name: "overview", component: () => import("@/views/OverviewPage.vue") },
    { path: "/groups", name: "groups", component: () => import("@/views/GroupsPage.vue") },
    { path: "/connections", name: "connections", component: () => import("@/views/ConnectionsPage.vue") },
    { path: "/logs", name: "logs", component: () => import("@/views/LogsPage.vue") },
    { path: "/config", name: "config", component: () => import("@/views/ConfigPage.vue") },
    { path: "/settings", name: "settings", component: () => import("@/views/SettingsPage.vue") },
  ],
});
