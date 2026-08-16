<script setup lang="ts">
import prettyBytes from "pretty-bytes";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useDocumentVisibility, useIntervalFn } from "@vueuse/core";
import type { AdminGroup, AdminGroupMember } from "@/api/types";
import { persistPrefs } from "@/store/session";
import { displayedSelected, latencyClass, latencyText, policyLabel, trafficForName } from "@/lib/format";
import { checkGroupDelay, refresh, refreshConnections, selectMember, ui } from "@/store/session";

const search = ref("");
const visibility = useDocumentVisibility();
const { pause, resume } = useIntervalFn(
  () => {
    void refreshConnections({ silent: true, outbound: "" });
  },
  2000,
  { immediate: false },
);

onMounted(() => {
  void refresh("groups");
  void refreshConnections({ silent: true, outbound: "" });
  if (visibility.value !== "hidden") resume();
});
onUnmounted(() => {
  pause();
});
watch(visibility, (state) => {
  if (state === "hidden") pause();
  else resume();
});

const groups = computed(() => {
  const q = search.value.trim().toLowerCase();
  if (!q) return ui.groups;
  return ui.groups.filter((group) => {
    if (group.name.toLowerCase().includes(q)) return true;
    return (group.members || []).some((member) => member.name.toLowerCase().includes(q));
  });
});

function membersOf(group: AdminGroup): AdminGroupMember[] {
  const members = (group.members || []).slice();
  if (ui.prefs.groupSort === "latency") {
    members.sort((a, b) => (a.latency_ms ?? 1e9) - (b.latency_ms ?? 1e9));
  } else if (ui.prefs.groupSort === "traffic") {
    members.sort((a, b) => trafficForName(ui.connectionViews, b.name).downloadRate - trafficForName(ui.connectionViews, a.name).downloadRate);
  }
  return members;
}

function isCurrent(group: AdminGroup, member: AdminGroupMember): boolean {
  return member.name === displayedSelected(group);
}

function onSelect(group: AdminGroup, member: AdminGroupMember): void {
  if (!group.selectable) return;
  void selectMember(group, member.name);
}

function groupTraffic(group: AdminGroup) {
  return trafficForName(ui.connectionViews, group.name);
}

function memberTraffic(member: AdminGroupMember) {
  return trafficForName(ui.connectionViews, member.name);
}

function onGroupSort(event: Event): void {
  const value = (event.target as HTMLSelectElement).value;
  if (value === "default" || value === "latency" || value === "traffic") persistPrefs({ groupSort: value });
}
</script>

<template>
  <div class="mb-3 flex flex-wrap items-center gap-2">
    <input v-model="search" class="input input-bordered input-sm min-w-48 flex-1" placeholder="搜索组或节点" />
    <select class="select select-bordered select-sm" :value="ui.prefs.groupSort" @change="onGroupSort">
      <option value="default">默认顺序</option>
      <option value="latency">按延迟</option>
      <option value="traffic">按下行速率</option>
    </select>
  </div>
  <div class="flex flex-col gap-4">
    <section v-for="group in groups" :key="group.name" class="rounded-box border border-base-300 bg-base-100 p-4 shadow">
      <div class="mb-3 flex flex-wrap items-start justify-between gap-2">
        <div class="min-w-0">
          <h2 class="text-base font-semibold">{{ group.name }}</h2>
          <div class="text-sm opacity-70">
            {{ policyLabel(group.policy) }} · 当前
            <span class="font-semibold text-success">{{ displayedSelected(group) }}</span>
            · {{ groupTraffic(group).count }} 连接
            · ↓ {{ prettyBytes(groupTraffic(group).downloadRate) }}/s
          </div>
        </div>
        <button class="btn btn-xs btn-outline shrink-0" type="button" :disabled="!!ui.checkingGroups[group.name]" @click="checkGroupDelay(group.name)">
          <span v-if="ui.checkingGroups[group.name]" class="loading loading-spinner loading-xs" />
          {{ ui.checkingGroups[group.name] ? "测速中" : "测延迟" }}
        </button>
      </div>
      <div class="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
        <button
          v-for="member in membersOf(group)"
          :key="member.name"
          type="button"
          class="rounded-box border bg-base-200 p-3 text-left transition"
          :class="isCurrent(group, member) ? 'border-success bg-base-100' : 'border-base-300 hover:border-base-content/40'"
          @click="onSelect(group, member)"
        >
          <div class="truncate text-sm font-medium" :title="member.name">{{ member.name }}</div>
          <div class="mt-1 flex items-center justify-between gap-1 text-xs">
            <span :class="latencyClass(member.alive, member.latency_ms)">{{ latencyText(member.alive, member.latency_ms) }}</span>
            <span class="opacity-70">{{ memberTraffic(member).count }}</span>
          </div>
          <div class="mt-0.5 text-xs opacity-70">↓ {{ prettyBytes(memberTraffic(member).downloadRate) }}/s</div>
        </button>
      </div>
    </section>
  </div>
</template>
