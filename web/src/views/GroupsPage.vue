<script setup lang="ts">
import { onMounted } from "vue";
import type { AdminGroup, AdminGroupMember } from "@/api/types";
import { displayedSelected, latencyClass, latencyText, policyLabel } from "@/lib/format";
import { refresh, selectMember, ui } from "@/store/session";

onMounted(() => {
  void refresh("groups");
});

function isCurrent(group: AdminGroup, member: AdminGroupMember): boolean {
  return member.name === displayedSelected(group);
}

function onSelect(group: AdminGroup, member: AdminGroupMember): void {
  if (!group.selectable) return;
  void selectMember(group, member.name);
}
</script>

<template>
  <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
    <div v-for="group in ui.groups" :key="group.name" class="card bg-base-200 shadow">
      <div class="card-body p-4">
        <h2 class="card-title text-base">{{ group.name }}</h2>
        <p class="text-sm opacity-70">
          策略 {{ policyLabel(group.policy) }} · 当前
          <span class="text-success font-semibold">{{ displayedSelected(group) }}</span>
        </p>
        <button
          v-for="member in group.members"
          :key="member.name"
          type="button"
          class="btn btn-sm justify-between font-normal"
          :class="isCurrent(group, member) ? 'btn-outline btn-success' : 'btn-ghost bg-base-100'"
          @click="onSelect(group, member)"
        >
          <span>{{ member.name }}</span>
          <span :class="latencyClass(member.alive, member.latency_ms)">{{ latencyText(member.alive, member.latency_ms) }}</span>
        </button>
      </div>
    </div>
  </div>
</template>
