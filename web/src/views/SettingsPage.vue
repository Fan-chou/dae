<script setup lang="ts">
import { reactive } from "vue";
import { persistSettings, refresh, ui } from "@/store/session";

const form = reactive({
  baseUrl: ui.settings.baseUrl,
  secret: ui.settings.secret,
});

function save(): void {
  persistSettings({ baseUrl: form.baseUrl.trim(), secret: form.secret });
  ui.notice = "已保存本地设置";
  void refresh("overview");
}

function testConn(): void {
  persistSettings({ baseUrl: form.baseUrl.trim(), secret: form.secret });
  void refresh("overview");
}
</script>

<template>
  <div class="card bg-base-200 max-w-xl">
    <div class="card-body">
      <p class="opacity-80">
        面板只打 kdae <code>/v1</code>，不是 Clash API。HTTPS 下默认走同源反代。密钥只存在浏览器本地。
      </p>
      <label class="form-control">
        <span class="label-text">admin_listen 地址</span>
        <input v-model="form.baseUrl" class="input input-bordered" placeholder="/cgi-bin/kdae-proxy" />
      </label>
      <label class="form-control">
        <span class="label-text">admin_secret</span>
        <input v-model="form.secret" class="input input-bordered" type="password" placeholder="Bearer token" />
      </label>
      <div class="flex gap-2">
        <button class="btn btn-primary" type="button" @click="save">保存</button>
        <button class="btn" type="button" @click="testConn">测试连接</button>
      </div>
    </div>
  </div>
</template>
