# kdae 管理面板

静态 Vue 3 应用，只请求 kdae 的 `/v1` 管理 API，不兼容 Clash `/proxies`。

构建/打包不需要 npm：OpenWrt 包把本目录安装到 `/www/kdae-ui/`。

首次打开时在「设置」填写 `admin_listen` 的 URL 和 `admin_secret`。
