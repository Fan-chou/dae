<template>
  <section class="mt-6 rounded-box bg-base-200/50 p-3 text-sm">
    <h3 class="mb-1 font-medium">访问方式与证书</h3>
    <p class="text-base-content/70">
      <template v-if="!isHttps">
        当前为 HTTP 连接，仅限可信局域网使用；离线缓存与“添加到主屏幕”不可用。
      </template>
      <template v-else-if="offline === 'yes'">
        浏览器没有接受此页面的缓存注册，通常是因为证书未被信任（自签名或未安装本地
        CA）。面板仍可使用，但没有离线缓存。
      </template>
      <template v-else-if="offline === 'unknown'">正在确认证书是否被信任…</template>
      <template v-else>
        当前为受信任的 HTTPS 连接，离线缓存与“添加到主屏幕”可用。
      </template>
    </p>
    <a
      v-if="!isHttps || offline === 'yes'"
      :href="caPage"
      target="_blank"
      rel="noreferrer"
      class="link link-primary mt-1 inline-block"
      >安装路由器的本地证书（Safari / iOS / macOS）</a
    >
  </section>
</template>
<script setup lang="ts">
import { onMounted, ref } from 'vue'

const isHttps = location.protocol === 'https:'
const caPage = new URL('./ca/', location.href.split('#')[0]).href

// A page opened by clicking through a certificate warning is still an HTTPS
// page, and browsers still call it a secure context; what they refuse is the
// service worker. Whether one registered is the honest signal.
const offline = ref<'unknown' | 'yes' | 'no'>(isHttps ? 'unknown' : 'no')
onMounted(async () => {
  if (!isHttps) return
  const sw = navigator.serviceWorker
  if (!sw || !window.isSecureContext) {
    offline.value = 'yes'
    return
  }
  for (let attempt = 0; attempt < 6; attempt++) {
    if (await sw.getRegistration().catch(() => undefined)) {
      offline.value = 'no'
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  offline.value = 'yes'
})
</script>
