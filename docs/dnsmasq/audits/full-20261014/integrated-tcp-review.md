# 最终组合候选：TCP/hosts rotation 独立验收

冻结候选为 `19bd6162e1b33c92a1e5ea26e864497800c7cfed`，tag
`audit/dnsmasq-full-19bd6162-20261014`。Oracle ELF SHA-256
`fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b`，
2,089,440 B；审计方先复制到自己的目录并重新核验 hash。本页没有独立重编译，
冻结源码与构建来源由总审计另行校验。没有修改产品、访问路由器、合并或推送。

**结论：已知 TCP hosts 复制和 warmed 多地址 rotation 的内存反例在此 ELF 上闭合；
正常快照与 unique-address rolling 用例通过。既有 repeated-address 顺序差异单独保留，
不把资源修复通过写成完整行为一致。** [机器可读结果](integrated-tcp-review.json)
记录每项输入身份、driver/result hash、内存事件和连接结果。

## 独立最小重放

全部通过 `run_isolated.sh` 在 Oracle 的独立 network/mount/PID namespace 执行，
使用精确 OpenWrt 镜像用户空间。C ELF SHA-256 为
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
所有 cgroup 均为整个 daemon 进程树共享预算、swap 禁用。

| 用例 | 精确 C | Rust | 结果 |
| --- | --- | --- | --- |
| 旧 `22fe5dd9`，50k 双 A 记录、父 UDP warmup、32 MiB | 20/20、UDP 正常；peak 14,962,688 B | **第 9 条连接失败、daemon -9、UDP 丢失；oom_kill=1**；peak 33,554,432 B | 旧反例重新复现 |
| 最终候选，相同 50k/32 MiB 输入与 driver | 20/20、UDP 正常；peak 15,118,336 B | 20/20、UDP 正常；peak **21,102,592 B**；OOM 0 | 通过 |
| 最终候选，60k 双 A 记录、warmup、64 MiB | 20/20、UDP 正常；peak 16,986,112 B | 20/20、UDP 正常；peak **27,750,400 B**；OOM 0 | 通过，20 对完整 wire 相同 |
| 最终候选，原 50k 单 A 名字、64 MiB | 20/20、UDP 正常；peak 10,653,696 B | 20/20、UDP 正常；peak **23,601,152 B**；OOM 0 | 通过 |
| 最终候选，60k unique-address records、64 MiB、2,000 rolling 次数 | peak 16,625,664 B；OOM 0 | peak **36,487,168 B**；OOM 0 | **6,020/6,020** raw/relative wire 都相同 |

前两项使用旧审计 `rotations_cgroup.py` 的同一份副本：25,000 个名字各两个 A，
保留 seed TCP，父 UDP 查询全部名字，再逐步保持总共 20 条连接。仅去掉失效的
硬编码 import 路径，改由 `PYTHONPATH` 指向已审读的精确镜像隔离 helper。
旧 ELF SHA-256 为 `0ac4ad216c071ae708af52f5d4d4cd6e4c2130b451655033efc463888bff0834`。
因此旧失败与新成功不是更换 workload 后的比较。

60k 和 rolling 使用已审读的 `hosts_rotation_memory.py`，SHA-256
`66f29e7cf865072124b6773d56f3f63cf064cd629ab7e673f769aa924be4a758`。
rolling 在完成 20 条连接后留下一个旧 TCP，每轮执行父 UDP、新 TCP、旧 TCP 查询，
再关闭旧 TCP。Rust 的 rolling start/end PSS 均为 **35,452 KiB**，本次没有
随 2,000 轮持续上涨。这里只报告该有限 schedule，不外推到任意历史代数。

## 快照与顺序语义

重新执行旧审计扩展快照工具，**98 对完整 wire 和解码结果全部一致**，两端进程存活。
覆盖 IPv4/IPv6 的 A、AAAA、ANY 独立轮转；已有与新建 TCP 的 HUP 前后正反向记录；
host-record 保留；hostsdir 原地替换、删除及其 PTR；父进程、旧孩子、新孩子各自的可见代。
本次没有把旧 DHCP 17 对或其它未重放的大矩阵计入最终候选通过数量。

unique-address rolling 记录每个名字第一次 warmup 答案，并相对各 daemon 的初始
地址排列比较后续轮转；raw wire 同时保留并单独比较。本次两个比较都通过。
此方法没有假设大型 C 表在不同进程启动之间具有固定 raw 顺序，也没有删除 raw mismatch。

源码 `hosts.rs:130-174,207-214` 将轮转状态按稳定 entry ID 划为 64-ID 页，
TCP 分享页、首次修改只复制该页；已有 records/index generation 和接受时顺序仍被保留。
这与新旧资源对照和快照结果相符。**不是绝对 O(1) 连接成本**：接受时复制的页 handle
表仍随最高 entry ID/64 增长，单页内地址向量的大小也随各名字地址数量增长。

## repeated-address 边界的独立核对

没有把修复方报告中的 `188/6,020` 默认为噪声或新的 pass。本轮下载旧原始证据后逐字节检查：

- 188 个差异全部是两个 A 地址的顺序互换；地址集合、TTL、flags 和其余 wire 完全相同。
- 分布为新 TCP 136、父 UDP 26、旧 TCP 26；不是只有新连接一个视图。
- 修复前后 Rust 的 6,020 条输出完全相同；两个 C 运行之间差 3 条。

它没有表现为缺地址、错误地址、查询失败或内存失控；对于优先使用第一条 A 的客户端，
答案顺序仍是可观察行为。以上证据支持“不是此 page 修复新引入”，**不等于证明现有实现
与 C 的 repeated-address 轮转兼容**。跨 C 重启的 raw 次序不能独自判定根因或严重性；
减化且相对于各自初始顺序的重放由另一审计线继续处理。此处保留该边界，资源结论不代替它。

## 证据与清理

新原始证据仅位于 Oracle `/dev/shm/full-audit-resume-20261014/rotation-*/private/`；
driver、两个 ELF 副本和总日志在 `rotation-input/`。电脑备份在
`private/full-audit-20261014/resume/rotation/`，含原始 wire/result、stderr、driver、
ELF、执行脚本与 SHA-256 inventory；生成的 staging rootfs 未打包。
首次调用因 helper 要求路径含 `private` 而在启动 daemon 前退出，已保留 setup 日志，
修正输出路径后才开始以上六个实际重放。

五个 cgroup 用例的两端均记录 `cgroup_removed=true`；最终检查自有进程与宿主挂载均为空。
Oracle 内核为 `6.17.0-1020-oracle`，不是路由器内核；32/64 MiB 是人工预算，不是当前设备
空闲 RAM。本页只验收上述冻结 ELF 和 schedule，没有物理路由器部署结论。
