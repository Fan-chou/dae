# 223 切换清单:旧 sidecar → dae 进程内 Mihomo

给执行切换的人(223 由用户自己切)。每步都写了怎么确认成功、失败怎么退。

## 先知道的几件事(2026-10-10 只读查看 223 得到)

- 系统是 ImmortalWrt 25.12,包管理器是 **apk**。仓库里的 `openwrt/scripts/build-ipk.sh` 只产出 opkg 风格的 ipk,**没有 apk 产物**。
- 223 上 `/usr/bin/dae`、`/usr/libexec/dae/*.sh`、luci 视图、`/www/kdae-ui` 都是手工部署的,apk 数据库里只有过期的 `kdae-20260822` 和 `kdae-rule-sync-20260822`,没有 `luci-app-kdae`、`kdae-ui`。所以这次切换是**手工拷文件**,不是装包。切完之前不要对 kdae 相关包跑 `apk upgrade`,它会把二进制换回旧版。
- `/etc/init.d/dae` 比仓库多三行本地设置(`GOMEMLIMIT=256MiB`、`GOMAXPROCS=2`、`KDAE_EVIDENCE_KEY_FILE`),**不要用仓库的 `dae.init` 覆盖它**。这次切换不需要改 init。
- 旧布局:`config.dae` 的 `include {}` 里有 `local.dae`、`current/nodes.dae`、`current/groups.dae`、`routing.dae`;sidecar 由 `/etc/init.d/dae-rule-sync` 和 `/usr/libexec/dae/dae-rule-sync` 提供;UCI 里订阅 `role=routing`、8 条 `mixin`(`resolve_dns`)、`isolate_transport_groups='Fuel_YouTuBe'`、`generation_dir='/etc/dae'`。
- 用 223 的真实订阅在 220 上验证过:转换/合并/加载通过,`Routing match set len: 406/1024`,与旧 sidecar 输出等价。**没有验证的**:真实流量走 lan/wan 数据面(220 没绑网卡,节点在 223 内网 220 够不到)。

## 0. 准备(开发机)

在仓库根目录,按 `AGENTS.md` 用持久化的 Go 缓存:

```bash
export PATH="$PWD/hack/bin:$PATH"; . hack/env.sh
make dae                      # 默认 MAX_MATCH_SET_LEN=1024,当前订阅 406/1024
(cd web-next && npm ci && FONT=none npx vite build)   # 产出 web-next/dist
```

需要拷到 223 的文件:

| 来源 | 目标 |
|---|---|
| `dae` | `/usr/bin/dae`(先改名保留旧的) |
| `openwrt/luci-app-kdae/root/usr/libexec/dae/*.sh` | `/usr/libexec/dae/`(0755) |
| `openwrt/luci-app-kdae/htdocs/luci-static/resources/view/kdae/*.js` | `/www/luci-static/resources/view/kdae/` |
| `openwrt/luci-app-kdae/root/usr/share/luci/menu.d/luci-app-kdae.json`、`.../rpcd/acl.d/luci-app-kdae.json` | 对应目录 |
| `web-next/dist/*` | `/www/kdae-ui/` |
| `openwrt/kdae-ui/files/{kdae-proxy.cgi,kdae-ui-cert,ca-index.html}` | `/www/cgi-bin/kdae-proxy`、`/usr/sbin/kdae-ui-cert` 等(对照 `openwrt/kdae-ui/Makefile` 的 install 段) |

## 1. 备份(223,可回滚的前提)

```sh
d=/root/pre-mihomo-$(date +%Y%m%d%H%M); mkdir -p $d
cp -p /usr/bin/dae $d/dae
cp -rp /usr/libexec/dae $d/libexec-dae
cp -p /etc/config/dae $d/uci-dae
cp -p /etc/init.d/dae $d/init-dae
tar -C /etc -cf $d/etc-dae.tar --exclude=dae/persist.d --exclude=dae/generations dae
tar -C /www -cf $d/www.tar kdae-ui luci-static/resources/view/kdae cgi-bin/kdae-proxy
ls -la $d
```

`persist.d` 里是规则集缓存和 geodata(约 25 MB),`generations` 是旧 sidecar 的历史代,都不需要备份;`current` 要留着(回滚时 sidecar 路径要用)。

## 2. 停掉旧 sidecar

```sh
/etc/init.d/dae-rule-sync stop
/etc/init.d/dae-rule-sync disable
```

**确认**:`pgrep -a dae-rule-sync` 无输出。dae 本身还在跑,此时流量不受影响。

## 3. 部署新文件

按第 0 步的表拷贝。先拷 `dae`:

```sh
mv /usr/bin/dae /usr/bin/dae.old && cp /tmp/dae /usr/bin/dae && chmod 0755 /usr/bin/dae
/usr/bin/dae --version
```

此时**还不要重启 dae**。

## 4. 迁移配置

```sh
/usr/libexec/dae/kdae-migrate-mihomo.sh
```

它会:把 `current/nodes.dae`、`current/groups.dae`、`routing.dae` 从 `include {}` 里去掉(备份为 `config.dae.pre-mihomo.bak`)、删除 `generation_dir` UCI 选项、用 UCI 重写 `local.dae`(带 `mihomo {}`)、再用 `dae mihomo preview` 做校验。

**确认**:脚本退出码 0;`/etc/dae/local.dae` 里有 `mihomo { routing_subscription: ... interval: ... node_resolve_dns {...} }`,以及原来的 `isolate_transport_groups`。**这一步 preview 失败就停在这里**,不要往下走,按第 7 节回滚。

可选:先看一眼结果而不应用:

```sh
dae mihomo preview -c /etc/dae/config.dae | head -40
```

输出里不会出现节点链接或凭据。

## 5. 重启并验证

```sh
/etc/init.d/dae restart
sleep 20
dae mihomo status -c /etc/dae/config.dae
```

逐项确认:

1. `mihomo.nodes`=8、`groups`=39、`rules`=90 左右(订阅更新后会略有变化),`used_last_good` 为 false,`degraded` 不是 true。
2. 日志里有 `Routing match set len: …/1024`,数字远小于 1024,且没有 `fatal`。
3. 管理接口 `/v1/status` 的 `sync_warning` 为空。
4. 一台 LAN 客户端实际上网:国内站点直连、被代理的站点能通,看 `/v1/connections` 里策略和出站符合预期;DNS 正常。
5. 打开面板:概览的 Mihomo 状态行、配置页的"生效配置"标签、连接页的"无域名"显示。

## 6. 观察几天后清理

- 删除 `/etc/dae/current`、`/etc/dae/generations`、`/etc/dae/generation.lock`、`/etc/dae/routing.dae`、`/usr/libexec/dae/dae-rule-sync*`、`/etc/init.d/dae-rule-sync*`。
- `apk del kdae-rule-sync`(包本身没有用了)。
- 为 apk 做一个 `kdae`/`luci-app-kdae`/`kdae-ui` 的正式产物,之后才可以放心 `apk upgrade`(目前仓库没有这条路径,是个待办)。

## 7. 回滚

任何一步之后,想回到旧方案:

```sh
/etc/init.d/dae stop
cp -p $d/dae /usr/bin/dae
cp -p $d/uci-dae /etc/config/dae
cp -p /etc/dae/config.dae.pre-mihomo.bak /etc/dae/config.dae
tar -C /etc -xf $d/etc-dae.tar dae/local.dae dae/routing.dae   # 旧的 local.dae 与 routing.dae
cp -p $d/libexec-dae/* /usr/libexec/dae/
/etc/init.d/dae-rule-sync enable && /etc/init.d/dae-rule-sync start
/etc/init.d/dae start
```

`current/` 没有被动过,旧的 `include` 路径在回滚后立即可用。前端文件按需从 `$d/www.tar` 还原。

## 8. iPhone / Safari 证书(独立于切换,可以分开做)

1. 在 223 上执行 `kdae-ui-cert`(私有 CA + 带 SAN 的 397 天证书),确认 uhttpd 用上新证书。
2. iPhone 上打开 CA 页面(`ca-index.html`),下载描述文件,在"设置 → 已下载描述文件"里安装,再到"设置 → 通用 → 关于本机 → 证书信任设置"里打开完全信任。
3. 用 Safari 打开 `https://<223>/kdae-ui/`,确认无证书警告、面板能连上、"添加到主屏幕"可用。
4. 确认 cron 续期任务存在(`crontab -l`)。

## 已知没验证的

- 真实 lan/wan 数据面流量(见上)。
- 这些 shell 脚本只在 busybox 容器里跑过,没在真实 OpenWrt 上跑过;第一次在 223 上跑时留意 `ash` 与容器里 busybox 的差异。
- Safari/iPhone 证书流程。
