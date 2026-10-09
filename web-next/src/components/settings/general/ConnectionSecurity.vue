<template>
  <section class="mt-6 rounded-box bg-base-200/50 p-3 text-sm">
    <h3 class="mb-1 font-medium">访问方式与证书</h3>
    <p class="text-base-content/70">
      <template v-if="isSecure">
        当前为受信任的 HTTPS 连接，离线缓存与“添加到主屏幕”可用。
      </template>
      <template v-else-if="isHttps">
        HTTPS 连接尚未被信任（自签名或未安装本地 CA），离线缓存已停用。
      </template>
      <template v-else>
        当前为 HTTP 连接，仅限可信局域网使用；离线缓存与“添加到主屏幕”不可用。
      </template>
    </p>
    <a
      v-if="!isSecure"
      :href="caPage"
      target="_blank"
      rel="noreferrer"
      class="link link-primary mt-1 inline-block"
      >安装路由器的本地证书（Safari / iOS / macOS）</a
    >
  </section>
</template>
<script setup lang="ts">
const isHttps = location.protocol === 'https:'
// An untrusted certificate keeps the page loadable only after a manual
// override, and browsers then refuse service workers.
const isSecure = window.isSecureContext && isHttps
const caPage = new URL('./ca/', location.href.split('#')[0]).href
</script>
