<script setup lang="ts">
import { reactive } from "vue";
import type { ThemePref } from "@/api/prefs";
import { persistPrefs, persistSettings, refresh, ui } from "@/store/session";

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

function onTheme(event: Event): void {
  const value = (event.target as HTMLSelectElement).value;
  if (value === "system" || value === "light" || value === "dark") persistPrefs({ theme: value as ThemePref });
}
</script>

<template>
  <div class="mx-auto max-w-xl pb-[env(safe-area-inset-bottom)]">
    <section class="rounded-box border border-base-300 bg-base-100 p-6 shadow">
      <h1 class="text-lg font-semibold">本地设置</h1>
      <p class="mt-2 text-sm leading-relaxed opacity-70">
        面板只打 kdae <code class="rounded bg-base-200 px-1 py-0.5">/v1</code>，不是 Clash API。HTTPS 下默认走同源反代。密钥只存在浏览器本地。
      </p>

      <div class="mt-6 flex flex-col gap-5">
        <label class="flex flex-col gap-1.5">
          <span class="text-sm font-medium">界面主题</span>
          <select class="select select-bordered w-full" :value="ui.prefs.theme" @change="onTheme">
            <option value="system">跟随系统</option>
            <option value="light">浅色</option>
            <option value="dark">深色</option>
          </select>
        </label>

        <label class="flex flex-col gap-1.5">
          <span class="text-sm font-medium">admin_listen 地址</span>
          <input v-model="form.baseUrl" class="input input-bordered w-full" placeholder="/cgi-bin/kdae-proxy" />
          <span class="text-xs leading-relaxed opacity-60">HTTPS 下可用同源反代 <code>/cgi-bin/kdae-proxy</code>，或填 <code>http://IP:端口</code></span>
        </label>

        <label class="flex flex-col gap-1.5">
          <span class="text-sm font-medium">admin_secret</span>
          <input v-model="form.secret" class="input input-bordered w-full" type="password" placeholder="Bearer token" autocomplete="off" />
        </label>
      </div>

      <div class="mt-6 flex flex-col gap-2 sm:flex-row sm:flex-wrap">
        <button class="btn btn-primary w-full sm:w-auto" type="button" @click="save">保存</button>
        <button class="btn btn-outline w-full sm:w-auto" type="button" @click="testConn">测试连接</button>
      </div>
    </section>
  </div>
</template>
