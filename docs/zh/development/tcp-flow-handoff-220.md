# TCP 长连接交接：修改说明与 220 验证

验证日期：2026-11-02～03。源码基线为 `119ab8cf`，已包含 DNS prepared hook 引用链修复。

## 改动与所有权

透明 TCP 的建连函数现在返回 `establishedTCPTask`。accept 启动的建连 goroutine 将任务交给独立的运行 goroutine，然后返回；错误日志和 panic defer 不再伴随长连接保留旧控制面。每条连接只在交接时短暂多出一个 goroutine。

任务保存流、连接/缓冲包装、日志值、capture scope 和可选 offload 租约，不保存控制面或 core。所有依赖旧代的快照在 `adoptTCPFlow` 释放 drain ticket **之前**准备完成。成功后清理责任转给任务；失败时由既有 adoption 逻辑关闭出站，准备阶段释放额外的 capture/offload 资源，避免重复关闭出站。

DNS/TCP 的长期读取循环同样独立。进程级会话不保存旧控制面 fallback，每个查询使用当前活动 DNS 控制器；独立私有 SessionManager 调用者保留原有 fallback 行为。

offload 复用既有按 BPF 对象登记的链接引用计数，新增流租约。每组共享资源只克隆一次三个 map 句柄；最后一个控制面/流租约退出才关闭链接及克隆句柄。这样原始 map 句柄被关闭后，活跃流仍可使用自己的共享句柄。关闭 offload 时走原子状态快速检查，不增加 core 锁操作。

未启用 `MigrateGeneration`，未改变长连接的原始选路或出站。未通过清空旧控制面的字段释放内存，也未增加强制断连的代数上限。

范围是此次定位的透明 TCP 和 DNS/TCP 路径。命名 SOCKS 入站的 `ServeInboundTCP`、UDP 生命周期没有在本次重构中迁移；不能据此声称所有协议的旧代引用都已经消除。

## 测试环境与方法

220（192.168.124.220），Arch Linux，内核 `7.2.11-arch1-1`，x86_64，报告为 Ryzen 7 7840HS、16 个逻辑 CPU 的虚拟化环境，约 10GB 内存。运行 `GOMAXPROCS=2`、`GOMEMLIMIT=512MiB`。

未替换 `/usr/bin/dae` 或修改服务配置。测试开始时没有运行中的 dae，使用临时 veth、网络命名空间、受控 SOCKS5/echo/iperf3 服务。流量通过真实 BPF 透明代理进入 dae，并走用户定义代理组，避免 direct 快速通道绕过待测 handler。

配置含 12,000 个不匹配的域名后缀和固定 SOCKS 出站。该合成配置的每代成本比 223 实际配置小，绝对内存值不能套用于 223。

普通中继交替运行 B→H、H→B、B→H，共各三轮。每轮新建连接+65 字节回显 3,000 次，已建立连接回显 3,000 次，iperf3 单流吞吐 10 秒。随后每代新增并保留 8 条连接，共重载 8 次、保留 64 条；每次重载完成后逐条验证回显并取强制 GC profile。在发信号至退休完成的窗口另采集已有连接 RTT。

offload 交替各两轮，每类延迟 2,000 次，其余相同。每轮重载末尾均从 goroutine 栈确认 **64 个实际运行的 offload session**，不是仅设置开关。

下表的延迟是“各轮 p95 的中位数”，并非把各轮样本合并后重新计算 p95。吞吐也是各轮结果的中位数。测试无 CPU 绑核，Python fixture 与客户端亦运行在 220 上；结果用于发现回归，不能推导公网延迟或宣称统计显著的加速。

## 普通中继结果

| 指标 | 基线 | 修复版 |
|---|---:|---:|
| 新建连接+回显 p95 | 0.666 ms | 0.641 ms |
| 已建立连接回显 p95 | 0.102 ms | 0.091 ms |
| 重载窗口回显 p95 | 0.956 ms | 0.768 ms |
| 单流吞吐 | 15.69 Gbit/s | 16.04 Gbit/s |
| 10 秒吞吐期间 dae CPU 时间 | 1.92 s | 1.99 s |
| 第 8 次重载后存活堆 | 14.43 MB | 8.45 MB |
| 第 1～8 次重载间平均增量/次 | 914 KB | 61 KB |
| 存活连接 / 重载错误 | 64 / 0 | 64 / 0 |

内存使用十进制 MB/KB，来自强制 GC 后的 `HeapAlloc`，不是 RSS。修复版仍有新增 56 条连接及其流状态的成本，因此不能要求增量为零。八次重载后的总存活堆减少约 41%；首次重载之后的增长斜率减少约 93%。

关闭保留连接后，两版存活堆均回落到约 8.13 MB，所有透明 handler/独立 task 栈消失。普通中继两版都保留约 232 个 FD，包含已有 splice pipe 缓存（代码最多缓存 64 根管道），不能把退出后的缓存 FD 直接归为活跃连接泄漏。

基线第三轮新建连接 p95 出现 **10.128 ms** 异常值；另两轮为 0.641/0.666 ms，修复版三轮为 0.621/0.641/0.672 ms。保留全部原始结果，没有剔除异常后宣称加速。重载 p95 的轮间波动也较大：基线 0.846～0.957 ms，修复版 0.642～1.044 ms。

最初 3 秒吞吐预试验曾出现修复版约 6% 的下降；最终 10 秒交替测试没有复现。可支持的结论是本次最终受控测试未发现明确的吞吐回退，仍需生产负载观察。

## offload 结果

| 指标 | 基线 | 修复版 |
|---|---:|---:|
| 新建连接+回显 p95 | 0.625 ms | 0.638 ms |
| 已建立连接回显 p95 | 0.084 ms | 0.090 ms |
| 重载窗口回显 p95 | 0.241 ms | 0.234 ms |
| 单流吞吐 | 14.10 Gbit/s | 14.46 Gbit/s |
| 第 8 次重载后存活堆 | 14.22 MB | 8.24 MB |
| 实际 offload 存活连接 / 重载错误 | 64 / 0 | 64 / 0 |

offload 建连 p95 中位数增加约 13 微秒，已有连接 RTT p95 增加约 6 微秒；样本只有两轮，不据此断言改善或退化。修复版最终多保留 **3 个 map FD**，符合每组共享资源一次克隆的设计，不随连接数线性增加。关闭所有连接后，offload session 栈均消失，两版堆均回落到约 8.00 MB。

## 正确性验证

- `go test ./control ./cmd -count=1` 通过。
- `go vet ./control ./cmd` 通过。
- 新增测试在 race detector 下通过：旧控制面和原始出站组可被回收，同时连接仍双向传输；capture 开/关；登记前取消；登记失败出站只关闭一次；嗅探首包完整；DNS/TCP 旧代回收和后续查询使用新控制器。
- 220 实机执行同组测试通过，包括实际 BPF map 创建：关闭原始句柄和释放控制面引用后，流租约仍能操作 map；最后一个租约释放才关闭克隆句柄和链接。没有跳过该测试。
- 第 8 次重载后的普通中继堆栈：基线有 64 个 `ControlPlane.handleConn`，修复版为 0，同时有 64 个 `establishedTCPTask.run`。
- pprof 差分中，基线继续累积 `newControlPlaneRealDomainRuntime`、trie 和 bitlist；修复版不再显示同样的持续代际累积。
- 测试完成后，220 无测试 dae 进程、临时网络命名空间、veth 或 BPF pin 目录残留。

## 成本与限制

每条连接新增一个任务对象及短暂的交接调度；启用 offload 时增加小型流租约及共享的三个 map FD。原有中继复制路径未改变。新实现把部分生命周期复杂度集中到了任务清理和资源租约上，因此回归测试必须继续覆盖失败、取消和退休竞态。

这不是全进程内存硬上限。活跃 socket、所选代理传输、QUIC pool、其他协议以及新建连接仍有正常内存成本。本次没有在 223 部署，也没有模拟真实订阅变更、删节点或数日长运行。

## 复现与原始材料

测试脚本：`scripts/tcp-handoff-live.py`。只允许在没有已有 dae/BPF 资源的测试机运行；结果目录必须不存在。

```sh
python3 tcp-handoff-live.py \
  --binary baseline=/absolute/dae-flow-baseline \
  --binary handoff=/absolute/dae-flow-handoff \
  --output /absolute/new-results \
  --rounds 3 --samples 3000 --reloads 8 --throughput-seconds 10
# 真实 offload 验证增加 --offload；脚本会检查实际 offload session 栈。
```

本工作区原始材料（gitignored）：

- `tmp/flow-handoff/comparison-final/`：最终普通中继各轮 JSON、daemon 日志、iperf JSON、GC heap profile、goroutine 栈。
- `tmp/flow-handoff/comparison-offload/`：真实 offload 同类材料。
- `tmp/flow-handoff/comparison-initial/`：最初短时预试验。
- `tmp/flow-handoff/tests-final.log`、`race.log`、`race-final.log`、`vet.log`、`live-unit.log`：测试记录。

220 原始文件保留于 `/tmp/kdae-flow-handoff-20261102/`，仅为测试产物。

被测二进制 SHA-256：

- baseline：`544d5539a2bcb3b4559e1c28dc87da0d4ac81c0b19c5798367302e9a4dc7609b`
- handoff：`4628c10ec74de0ca37919d68c9b6e3f543d8b1a6c412d59acb072e019b07dc4b`
