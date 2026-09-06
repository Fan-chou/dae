# fdae dashboard

基于 Zephyruso/zashboard 3.25.0 的原生 Vue 页面与组件，适配 fdae Admin HTTP API。
上游源码：https://github.com/Zephyruso/zashboard （2026-09-06 main 快照）。
原始 MIT 许可保留于 LICENSE；fdae 适配代码见 src/fdae。

## 构建

使用 Node 22.12+ 和 pnpm，执行 `pnpm install --frozen-lockfile`、`pnpm build`。
无字体构建可用 `FONT=none pnpm build`。输出 dist，按站点实际静态目录部署。
OpenWrt 打包默认使用此目录；可通过 KDAE_UI_DIR 指向旧 web/ 构建目录回退。生产服务不会因本地构建而更新。

## 后端语义

- 请求只使用 `/v1/status`、`/v1/connections`、`/v1/groups`、`/v1/logs`、`/v1/config`、`/v1/reload` 及组选择/检测端点。
- 不提供 Clash 模式切换、TUN、连接断开/封锁、订阅管理、单节点检测、内核/面板远程升级。
- 自动组保留 fdae policy，手动选择按 selectable/selection_members，PUT 使用 member；健康信息按组读取，不用同名节点覆盖别组样本。
- 全局流量、TCP/UDP 数量、RSS 使用状态接口；代理组按已加载连接的实际 outbound 归账。分类汇总不是全量，界面明确范围。
- 连接上限 256/512/1024，源 IP、MAC、出站后端筛选；保留原生多列分组、排序、虚拟表格、卡片和详情。切换筛选或运行 scope 时清理比较基线，截断不推断结束。
- 配置 API 仅编辑 global/routing 和独立 routing 文件；保存排队不表示重载已完成。
- 旧版 kdae-ui-settings 的 API 地址与密钥可在本地迁移，原记录保留。

## 界面约定

- 连接表格和卡片分别显示源/目标 IP 与端口；卡片默认包含 MAC，旧布局首次升级时补齐缺失字段，之后保留用户自定义。
- 源 IP 与 MAC 下拉展示已观察到的设备对应关系，支持手动输入；候选项不代表完整设备清单。
- 设置页连续展开支持的分类，桌面左侧用于页内定位，内容使用可用宽度。
- 配置编辑器使用 Monaco，config.dae / routing.dae 独立 Tab 保留草稿与撤销状态；语法高亮参考 daed，许可证见 public/DAED-LICENSE.txt。配置校验仍由 fdae 后端负责。
- 日志卡片拆分消息与附加字段，原文可展开和复制；检索保留完整原始内容。日志为最近 300 行轮询采样，不保证完整历史。

`node_modules/`、`dist/` 和本地构建缓存不纳入版本控制。部署需单独执行，Git 提交不会更新运行中的服务。
