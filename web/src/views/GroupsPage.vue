<script setup lang="ts">
import prettyBytes from "pretty-bytes";
import UiIcon from "@/components/UiIcon.vue";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useDocumentVisibility, useIntervalFn } from "@vueuse/core";
import type { AdminGroup, AdminGroupMember } from "@/api/types";
import { persistPrefs } from "@/store/session";
import {
  admissionBadgeClass,
  admissionCounts,
  admissionLabel,
  admissionTitle,
  displayedSelected,
  latencyClass,
  latencyText,
  memberAdmission,
  memberCardClass,
  policyLabel,
  siteLocalSelectionPolicy,
  trafficForName,
  bucketRateText,
} from "@/lib/format";
import { checkGroupDelay, refresh, refreshConnections, selectMember, ui } from "@/store/session";

const search = ref("");
const collapsed = ref<Record<string, boolean>>({});
const anyExpanded = computed(() => ui.groups.some(group => !collapsed.value[group.name]));
function toggleAll(): void {
  const shouldCollapse = anyExpanded.value;
  collapsed.value = Object.fromEntries(ui.groups.map(group => [group.name, shouldCollapse]));
}
const visibility = useDocumentVisibility();
const { pause, resume } = useIntervalFn(
  () => {
    void refreshConnections({ silent: true, outbound: "" });
    void refresh("groups", { silent: true });
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
  if (siteLocalSelectionPolicy(group.policy) && !group.selected) return false;
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

function cardClass(group: AdminGroup, member: AdminGroupMember): string {
  return memberCardClass(isCurrent(group, member), memberAdmission(member));
}

function groupAdmission(group: AdminGroup) {
  return admissionCounts(group.members);
}
</script>

<template>
  <header class="page-heading"><div class="heading-title"><h1>代理组</h1><span class="count-pill">{{ ui.groups.length }}</span></div><button class="btn btn-sm btn-ghost" @click="toggleAll">{{ anyExpanded ? '全部收起' : '全部展开' }}</button></header>
  <p v-if="ui.connectionsTruncated || ui.connectionsError" class="data-note mb-4">节点流量仅基于已加载连接{{ ui.connectionsError ? "，当前刷新失败" : "，列表有截断" }}，不代表全部流量。</p>
  <div class="mb-3 flex flex-wrap items-center gap-2">
    <input v-model="search" class="input input-bordered input-sm min-h-10 min-w-0 flex-1" placeholder="搜索组或节点" />
    <select class="select select-bordered select-sm min-h-10" :value="ui.prefs.groupSort" @change="onGroupSort">
      <option value="default">默认顺序</option>
      <option value="latency">按延迟</option>
      <option value="traffic">按下行速率</option>
    </select>
  </div>
  <div class="proxy-groups">
    <section v-for="group in groups" :key="group.name" class="proxy-group">
      <div class="proxy-group-header">
        <button class="proxy-group-toggle" :aria-label="(collapsed[group.name] ? '展开 ' : '收起 ') + group.name" :aria-expanded="!collapsed[group.name]" @click="collapsed[group.name] = !collapsed[group.name]">
          <span class="proxy-group-name">{{ group.name }}<span class="group-member-count">{{ (group.members || []).length }}</span></span>
          <span class="group-health" :title="'健康 ' + groupAdmission(group).alive + ' · 变差 ' + groupAdmission(group).degraded + ' · 死亡 ' + groupAdmission(group).dead"><i />{{ groupAdmission(group).alive }}/{{ (group.members || []).length }}</span>
          <span class="proxy-group-selected" :title="displayedSelected(group)">{{ displayedSelected(group) }}<small v-if="siteLocalSelectionPolicy(group.policy)"> · 组默认</small></span>
          <UiIcon name="chevron" class="group-chevron" :class="{ expanded: !collapsed[group.name] }" />
        </button>
        <button class="btn btn-sm btn-ghost group-delay" type="button" :disabled="!!ui.checkingGroups[group.name]" :aria-label="'测延迟 ' + group.name" @click="checkGroupDelay(group.name)">
          <span v-if="ui.checkingGroups[group.name]" class="loading loading-spinner loading-xs" />
          <UiIcon v-else name="refresh" />{{ ui.checkingGroups[group.name] ? "测速中" : "测延迟" }}
        </button>
      </div>
      <div v-show="!collapsed[group.name]" class="proxy-group-content">
        <div class="proxy-group-meta"><span>{{ policyLabel(group.policy) }}</span><span>{{ groupTraffic(group).count }} 连接 · ↓ {{ ui.connectionsLastPollAt ? bucketRateText(groupTraffic(group), "download", prettyBytes) : "—" }}</span></div>
        <p v-if="siteLocalSelectionPolicy(group.policy)" class="group-policy-note">按站点选择，实际使用的节点可能不同。</p>
      <div v-show="!collapsed[group.name]" class="proxy-members">
        <button
          v-for="member in membersOf(group)"
          :key="member.name"
          type="button"
          class="proxy-member"
          :class="[cardClass(group, member), { 'is-selected': isCurrent(group, member) }]"
          @click="onSelect(group, member)"
        >
          <div class="flex items-start justify-between gap-1">
            <div class="truncate text-sm font-medium" :title="member.name">{{ member.name }}</div>
            <span :class="admissionBadgeClass(memberAdmission(member))" :title="admissionTitle(member)">{{
              admissionLabel(memberAdmission(member))
            }}</span>
          </div>
          <div class="mt-1 flex items-center justify-between gap-1 text-xs">
            <span :class="latencyClass(member.alive, member.latency_ms)">{{ latencyText(member.alive, member.latency_ms) }}</span>
            <span class="opacity-70">{{ memberTraffic(member).count }}</span>
          </div>
          <div class="mt-0.5 text-xs opacity-70">↓ {{ ui.connectionsLastPollAt ? bucketRateText(memberTraffic(member), "download", prettyBytes) : "—" }}</div>
        </button>
      </div>
      </div>
    </section>
  </div>
</template>
