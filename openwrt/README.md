# OpenWrt packaging for kdae

This tree is consumed by the independent `openwrt-kdae-feed` repository
and by `openwrt/scripts/build-ipk.sh` when the ImmortalWrt SDK is not
installed.

Packages:

- `kdae` — binary as `/usr/bin/dae`, `PROVIDES`/`CONFLICTS`/`REPLACES` official `dae`
- `luci-app-kdae` — start/stop, validate, reload, Mihomo source status, panel link
- `kdae-ui` — Vite-built Vue panel at `/www/kdae-ui/` (`web-next/dist`, based on zashboard; override with `KDAE_UI_DIR`). Also issues a private CA and a Safari-compliant HTTPS certificate for uhttpd (`kdae-ui-cert`); the CA is offered at `/kdae-ui/ca/`.

Do not enable `DAE_ALLOW_TCP_SOCKMAP` on kernels older than 6.6.94.

ImmortalWrt 24.10 `opkg` still expects **gzipped tar** ipk files (`debian-binary` + `data.tar.gz` + `control.tar.gz`), not Debian `ar` archives. The local feed uses `src/gz kdae file:///www/kdae-feed`.


## Mihomo routing source

`dae` fetches, converts and merges the complete Mihomo YAML itself (the `mihomo {}` section of `local.dae`, written from UCI by `kdae-write-local.sh`). There is no generation directory, no `routing.dae` and no sidecar binary. Moving an existing install over: run `/usr/libexec/dae/kdae-migrate-mihomo.sh` once, then restart the service. `dae mihomo preview -c /etc/dae/config.dae` shows what the source converts to; `dae mihomo status -c ...` asks the running daemon how its last read went.
