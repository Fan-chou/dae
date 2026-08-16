# kdae 管理面板

只请求 kdae 的 `/v1`，不兼容 Clash `/proxies`。

## 开发（Vite）

```bash
cd web
pnpm install
pnpm test
pnpm build
pnpm dev
```

`pnpm dev` 把 `/v1` 反代到 `192.168.124.223:2025`（可用 `KDAE_ADMIN_PROXY` 覆盖）。浏览器打开后在设置里填 `admin_secret`。

## OpenWrt 包（过渡）

当前 ipk 仍安装 [`legacy/`](legacy/) 下的无构建 Vue 单文件，避免未切 dist 时面板空白。S8 会改为安装 `web/dist`。
