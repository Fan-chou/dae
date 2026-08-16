# OpenWrt packaging for kdae

This tree is consumed by the independent `openwrt-kdae-feed` repository
and by `openwrt/scripts/build-ipk.sh` when the ImmortalWrt SDK is not
installed.

Packages:

- `kdae` — binary as `/usr/bin/dae`, `PROVIDES`/`CONFLICTS`/`REPLACES` official `dae`
- `kdae-rule-sync` — `/usr/libexec/dae/dae-rule-sync`
- `luci-app-kdae` — start/stop, validate, reload, rule-sync warnings, panel link
- `kdae-ui` — Vite-built Vue panel at `/www/kdae-ui/` (`web/dist`)

Do not enable `DAE_ALLOW_TCP_SOCKMAP` on kernels older than 6.6.94.

ImmortalWrt 24.10 `opkg` still expects **gzipped tar** ipk files (`debian-binary` + `data.tar.gz` + `control.tar.gz`), not Debian `ar` archives. The local feed uses `src/gz kdae file:///www/kdae-feed`.

