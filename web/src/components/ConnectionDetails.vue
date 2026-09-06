<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref } from "vue";
import prettyBytes from "pretty-bytes";
import { connectionAge, splitEndpoint, type ConnectionView } from "@/lib/format";
import UiIcon from "./UiIcon.vue";
import { ui } from "@/store/session";
const props = defineProps<{ row: ConnectionView; mac: string }>();
const emit = defineEmits<{ close: []; copy: [] }>();
const dialog = ref<HTMLDialogElement | null>(null);
const tab = ref("overview");
const sections = computed(() => [
  { title: "来源与目标", rows: [
    ["源 IP", splitEndpoint(props.row.src).host], ["源端口", splitEndpoint(props.row.src).port],
    ["目标 IP / 域名", splitEndpoint(props.row.dst).host], ["目标端口", splitEndpoint(props.row.dst).port],
    ["嗅探域名", props.row.domain], ["MAC", props.mac],
  ] },
  { title: "路由", rows: [["协议", props.row.network], ["出站", props.row.outbound], ["节点", props.row.dialer], ["策略", props.row.policy]] },
  { title: "流量与时间", rows: [
    ["上传", prettyBytes(props.row.upload || 0)], ["下载", prettyBytes(props.row.download || 0)],
    ["上行速度", props.row.rateKnown ? prettyBytes(props.row.uploadRate) + "/s" : "—"],
    ["下行速度", props.row.rateKnown ? prettyBytes(props.row.downloadRate) + "/s" : "—"],
    ["开始时间", props.row.start ? new Date(props.row.start).toLocaleString() : "—"],
    ["持续时间", connectionAge(props.row.start || "", props.row.closedAt || Date.now())],
  ] },
]);
onMounted(() => dialog.value?.showModal());
onBeforeUnmount(() => dialog.value?.close());
</script>
<template>
  <dialog ref="dialog" class="connection-detail" aria-labelledby="connection-detail-title" @cancel.prevent="emit('close')" @click="event => { if (event.target === dialog) emit('close'); }">
    <div class="detail-shell">
      <header class="detail-header"><div><h2 id="connection-detail-title">连接详情</h2><p>{{ row.domain || splitEndpoint(row.dst).host }}</p></div><button class="btn btn-sm btn-ghost icon-button" aria-label="关闭连接详情" @click="emit('close')"><UiIcon name="close" /></button></header>
      <div class="detail-tabs"><button :class="{active:tab === 'overview'}" @click="tab = 'overview'">概览</button><button :class="{active:tab === 'record'}" @click="tab = 'record'">当前记录</button></div>
      <div class="detail-body">
        <template v-if="tab === 'overview'"><section v-for="section in sections" :key="section.title" class="detail-section"><h3>{{ section.title }}</h3><dl><template v-for="[label,value] in section.rows" :key="label"><dt>{{ label }}</dt><dd>{{ value || '—' }}</dd></template></dl></section></template>
        <template v-else><p class="record-note">当前界面记录，包含计算速率和观察到的连接状态。</p><pre>{{ JSON.stringify(row, null, 2) }}</pre></template>
      </div>
      <p v-if="ui.notice || ui.error" class="detail-feedback" :role="ui.error ? 'alert' : 'status'">{{ ui.error || ui.notice }}</p>
      <footer class="detail-footer"><span>{{ row.closed ? '已观察到连接结束' : '最后快照中的活动连接' }}</span><button class="btn btn-sm btn-ghost" @click="emit('copy')"><UiIcon name="copy" />复制连接信息</button></footer>
    </div>
  </dialog>
</template>
