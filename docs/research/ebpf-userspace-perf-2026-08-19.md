# eBPF 用户态热路径：审查、222 实测、不必改（2026-08-19）

> 范围：Go 侧 cilium/ebpf（`domain_routing` 投影、Lookup、janitor、reload LPM），不含 TC 分类器本身。  
> 测量机：222（Debian 13 amd64，2 核 2GB）。Clash TUN `stack: system` + FakeIP `28.0.0.0/8` 在跑，**未进入测试 map**。  
> 223：日常 `conn_state` memlock 约 4.5MB，DNS 走 222:5354（SmartDNS，命中率约 95%）。  
> 相关：[honk-2026-08-19.md](./honk-2026-08-19.md)（不要为对齐去改 LRU / NFQUEUE）、[tcp-sockmap-offload.md](./tcp-sockmap-offload.md)  
> 回归：`control/dns_bpf_update_policy_test.go`、`control/ebpf_userspace_hotpath_measure_test.go`、`control/ebpf_userspace_hotpath_scale_test.go`

**结论：主路径不必改。** 代码结构上确有全局锁、逐条 `BatchUpdate`、LPM `MaxEntries=2_048_000`、60s hash 不变仍强制写、HASH `NO_PREALLOC`。家庭 LAN 和 223 日常离「用户能感到」（约 5ms）差两到三个数量级。优化幅度在微秒；预分配两张主表要先付 **+62MB 空载**。

不要为这些点改锁、合并 worker、预分配 HASH。HASH 不要改 LRU（223 有 overflow 史）。

---

## 1. Clash TUN 有没有污染测量

没有。Clash pid 当时 RSS 约 59MB、CPU 0%、`VmLck` 0，不用 HASH/LPM。系统 BPF memlock 合计约 473KB（systemd cgroup）。测试只 `bpf(2)` 私有 map，不发包进 `utun`。Clash 最多抢 CPU/内存；空闲时若有干扰也是让数字变慢，不会把 93µs 测虚。

kdae 跑在 223，Clash 跑在 222，两边 map 本来就不共享。

---

## 2. 正常负载（会不会打中）

门限：投影 p99/max **5ms** 才当主路径问题。突发只记日志。

| 路径 | 家庭 LAN 实测 | 第一次撞 5ms |
|---|---|---|
| 32 owner / 8 worker 投影 | p50 1.7µs，p99 **93µs** | — |
| 64 路同时投影（突发） | max **144µs** | — |
| 同时投影（同一瞬间抢锁） | 32 路 max 103µs | **约 1024 个不同域名**（max 5.3ms）；512 路仍 1.25ms |
| 顺序 2-IP `BatchUpdate` | 32 条 **23µs** | **约 1.1 万次**（8192≈3.6ms，16384≈7.2ms） |
| janitor `BatchLookup` | 2048 条 135–414µs | 65536 条 9ms；满表 262144 外推 **约 36ms**，5s 一轮，不是每包 |
| 60s 空写 | 10 hit/s × 50 热名 → 预热后 **1.67 次写/秒** | 同一秒命中 **>1024** 热名才挤爆 worker 队列（深 1024） |
| LPM 64 CIDR：上限 64 vs 2M | 差值 **21µs**，×16 张 trie ≈ 341µs | 到不了 5ms |

223 若是更慢的嵌入式 CPU，按 20–50 倍放大，32 路投影仍多半低于一次问 222:5354 的 RTT。SmartDNS 未命中 p95 约 77ms 才是大头。

---

## 3. 空间换时间：内存顶格

预分配按 `max_entries` 在建表时一次锁死，**空表就付全款**。`NO_PREALLOC` 只付桶，条目随占用涨。数字来自 `MapInfo.Memlock()`。

| 对象 | 规格 | NO_PREALLOC 空 | 预分配空 | 满表约 |
|---|---|---|---|---|
| `conn_state` | 262144 × (40+56) | 4.0MB | **40MB** | 40MB |
| `domain_routing` | 131072 × (20+132) | 2.0MB | **28MB** | 28MB |
| janitor scratch 8192 | lookup 缓冲 | — | +2–3MB | +2–3MB |
| tracker 双槽写满 | 2 × 65536 owner | 随占用 | 不预扣 RSS | 估 30–60MB 堆 |

只开两张主表预分配：空载从约 6MB 桶跳到 **68MB（+62MB 常驻）**。占满时两边差不多。若再给 redirect / cookie / handoff 预分配，再加约 30MB。理论顶格（主表+辅表预分配 + tracker 写满 + janitor）大约 **150–170MB**。222 的 2GB 吃得下；223 现在 `conn_state` 约 4.5MB，一预分配就会变成 40MB 常驻——比微秒级 syscall 更可能先碰到内存。

---

## 4. 各修改点：代价 vs 幅度

| 点 | 改不改 | 日常能省 | 何时才值 | 代价 |
|---|---|---|---|---|
| tracker 分片 / 放锁再写 map | **不改** | 32 路 103µs → 估 &lt;80µs | 同一瞬间 ≥1024 个不同域名 | 高：epoch 竞态、双槽一致性 |
| 投影合并成一次 `BatchUpdate` | **不改** | 32 条 23µs vs 合并数 µs | 一次顺序投影 ≥约 1.1 万条 | 中：攒批拖单条；reload 要重写 |
| LPM `MaxEntries` 收到实际 CIDR 数 | **不改**（可顺手） | reload 约 0.3ms | 永远到不了 5ms | 低；建完只读则安全，以后 insert 会 E2BIG |
| 去掉 60s hash 不变仍强制写 | **不改** | 50 热名约少 1.7 次写/秒 | &gt;1024 热名同一秒命中 | 中：漏更新安全网 |
| janitor `BatchLookup` 1024→8192 | **不改** | 5s 一轮里估再削 2–4ms | 满表扫描约 36ms | 低：+2–3MB scratch |
| `redirect_track` 每条 RLock → 快照 | **不改** | 后台可能省百 µs | 能证明 janitor 与 UDP retain 互堵 | 低：多拷 pin 集合 |
| `ReleaseUdpConnStateTuples` 持锁 `BatchDelete` | **不改** | 释放路径少持锁数 µs–ms | UDP 退役风暴且锁争用可见 | 中：先放锁有 TOCTOU |
| `conn_state` / `domain_routing` 预分配 | **不改** | 日常 insert 未测到可感加速 | 低水位仍疯狂 insert 且能证明是分配器 | **高：空载 +62MB** |
| tracker map 预扩到 65536 | **不改** | 少几次 rehash | 从 0 冲到数万 owner | 低，写满才占堆 |
| TCP 2ms Lookup 重试 / DNS 五元组缓存 | **不改** | 未测；稳态第一次 Lookup 就中 | 223 上能看到 miss 重试或 Lookup 占 CPU | 中：竞态 / 脏 pname·mac |

全部做完，稳态也只是少几十到一两百微秒。唯一「便宜」的是 LPM `MaxEntries` 十几行，为的是规格诚实，不是性能；不碰也没问题。

---

## 5. 若以后再动

只有 223 上出现 **DNS 投影 p99 数毫秒** 或 **reload 卡几十毫秒** 才回头。用 `go test`（不要 `dae_stub_ebpf`）跑：

```text
go test ./control/ -run 'TestNeedsBpfUpdate|TestDomainRoutingProjection|TestHotpathScaleFindCrossing|TestHotpathMapMemlockScale'
```

只动被数据打中的那一项，不要顺手改锁和预分配。
