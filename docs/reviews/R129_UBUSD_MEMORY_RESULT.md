# R129：R124 连接规模驻留内存

精确 C 与 R124 各运行 4 个独立 daemon 窗口，C/R124/R124/C 两轮交错。每个窗口分别新建 daemon，
对 0、1、8、32、64 个 libubus 连接发送并验证一次 PING，然后保持 30 秒；连接回收和 FD 回落也经过检查。
生产始终是 C，8 个窗口清理、boot/config/身份/mounts 全部通过。

| 连接数 | C RssAnon 增量 | R124 RssAnon 增量 | C VmData 增量 | R124 VmData 增量 |
|---:|---:|---:|---:|---:|
| 1 | 0 KiB | 0 KiB | 0 KiB | 0 KiB |
| 8 | 4 KiB | 0 KiB | 4 KiB | 0 KiB |
| 32 | 24 KiB | 12 KiB | 24 KiB | 12 KiB |
| 64 | 48 KiB | 28 KiB | 52 KiB | 28 KiB |

0 连接均无增量。R124 在 64 个空闲连接时比 C 少 20 KiB RssAnon/VmRSS、24 KiB VmData；
这只是本次 `/proc` 快照的驻留差，不是 allocator 峰值、PSS、内核 socket 内存或完整组件内存结论。
PSS 均不可用；每个连接的 RSS 曲线和 raw status 均保留。

本结果与 R124 的事件驻留结果一起表明，目前已测的事件和连接内存开销没有超过 C；
注册单方法仍约慢 3%，16 方法只有约 1% 小幅优势且受反向窗口影响。lookup/invoke 的明显耗时优势见 R127，
仍需把这些不同业务路径作为分项证据，不能合成未经业务权重的总分。
