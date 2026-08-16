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

## OpenWrt 包

`kdae-ui` ipk 安装 `pnpm build` 产出的 `web/dist`（`/www/kdae-ui/`），CGI 仍只反代 `/v1/*`。打包前需要本机有 pnpm。
