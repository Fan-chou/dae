# fdae on OpenWrt

Two packages:

| package | contents |
|---|---|
| `fdae` | `/usr/bin/dae`, `/etc/init.d/dae`, `/etc/config/dae`, `/etc/dae/config.dae`, the panel in `/usr/share/fdae-ui`, helper scripts in `/usr/libexec/fdae` |
| `luci-app-fdae` | LuCI: Services → fdae (settings, config, log) |

The service keeps the name `dae`, so existing UCI settings, logs and habits
carry over. The panel is served by dae itself on its admin address:
`http://<admin_listen>/fdae-ui/`. There is no CGI, uhttpd instance, certificate
or sidecar; the Mihomo source (subscription or local YAML) is read, converted
and merged by dae in-process.

## Layout

```
openwrt/
  build.sh                 ipk + apk for fdae and luci-app-fdae
  fdae/files/              init script, UCI defaults, default config.dae, apply/write-local/recover scripts
  fdae/tests/              shell tests (apply_test.sh)
  luci-app-fdae/           LuCI views, menu, ACL
```

Settings live in UCI (`/etc/config/dae`). `write-local.sh` renders them to
`/etc/dae/local.dae`; `apply.sh` writes, validates (`dae validate`,
`dae mihomo preview`) and only then asks a running dae to reload. A failed
check leaves the running service alone.

## Updating

Installing a package only replaces files. **It never restarts dae.** When the
installed binary differs from the running one, Services → fdae → Settings shows
a "switch to the new version" button (CLI: `/etc/init.d/dae pending`,
`switch`, `switch_state`). The switch:

1. validates the current configuration with the new binary (fails → nothing changes);
2. keeps a copy of the running binary as `/usr/libexec/fdae/dae.prev`;
3. restarts onto the new binary and waits for it to answer;
4. if it does not come up, puts the old binary back and starts it again.

There is a brief interruption during step 3.

## Install

```sh
apk add --allow-untrusted ./fdae-*.apk ./luci-app-fdae-*.apk      # apk (25.12)
opkg install ./fdae_*.ipk ./luci-app-fdae_*.ipk                   # opkg
```

Coming from `kdae` / `kdae-rule-sync`: remove them first without running their
scripts (`apk del --no-scripts kdae kdae-rule-sync`), keep `/etc/config/dae`,
then install. If `/etc/init.d/dae` was left behind, replace it with the one
from the package (`/etc/init.d/dae.apk-new`).

## Build

```sh
make dae                                   # needs clang; see AGENTS.md for the Go cache env
(cd web-next && pnpm install --frozen-lockfile && FONT=none pnpm build)
FDAE_BIN_x86_64=$PWD/dae openwrt/build.sh  # also FDAE_BIN_aarch64, FDAE_UI, FDAE_VERSION
```

apk files are made with `apk mkpkg` in an `alpine:edge` container (apk-tools 3
is what OpenWrt 25.12 uses); `FDAE_NO_APK=1` skips them, `FDAE_DOCKER_ARGS`
passes extra `docker run` arguments. GitHub Actions (`.github/workflows/fdae-build.yml`)
builds the binaries, packages and, for `v*` tags, a release.

## Tests

```sh
sh openwrt/fdae/tests/apply_test.sh
```
