<script setup lang="ts">
import { onMounted } from "vue";
import { refresh } from "@/store/session";

onMounted(() => {
  void refresh("overview");
});
</script>

<template>
  <div class="card bg-base-200">
    <div class="card-body">
      <h2 class="card-title">连接</h2>
      <p>这是 kdae 抓住的流，不是整机 conntrack。</p>
      <p class="opacity-70">must_direct 未劫持、block 静默丢、DNS 不在此表。列表 API 下一步接入。</p>
      <div class="overflow-x-auto">
        <table class="table table-zebra">
          <thead>
            <tr>
              <th>src</th>
              <th>dst</th>
              <th>domain</th>
              <th>mac</th>
              <th>outbound</th>
              <th>dialer</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td colspan="6" class="text-center opacity-60">暂无快照</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
