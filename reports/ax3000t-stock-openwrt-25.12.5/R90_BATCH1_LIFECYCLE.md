# R90：第一批生命周期修复

日期：2026-09-13。代码起点 `39e5d89`，冻结性能基线为 R89 正式构建
`d9c1048` / release-image `34724293710`。仅修改 netifd 与 procd。

本轮状态：**正式候选的离线功能、22 项性能矩阵和 procd 尾延迟复核已完成**。修复提交
`ae51db4` 的正式构建 `34753661051` 已成功；netifd 完整 30 项与 procd
候选功能门通过，离线安装/回退自测 5/5 通过。原版 C 的 busy 对照丢失一条
末尾日志，单独补跑的正式 Rust 候选通过；不将原版失败记录改写为双侧通过。
**未修改物理路由器，实机性能与冷启动验收仍待完成。**

## 1. 范围与源码身份

| 项 | 处理 |
|---|---|
| netifd F2 | DOWN、无载波但持有主设备 claim 的接口，ifdown 释放设备 |
| netifd F3 | UP/DOWN 时的 data-only 更新也合并，变化才发 IUF_DATA/ifupdate |
| netifd F4 | setup_failed 保留 autostart，LINK_LOST → teardown → 重试 |
| netifd F5 | teardown/abort 期间的 renew 不遗留给下一次 setup |
| netifd F10 | 新 helper 清 task_killed，恢复自动 SIGTERM；这是对原版既有问题的有意改进 |
| netifd F11 | 旧协议的 teardown、notify、回收保留旧配置，连续 reload 使用最后的新配置 setup |
| netifd F12 | available 通知驱动完整生命周期，而非仅修改布尔值 |
| procd F3 | state(spawn=false) 不升级强杀；delete 的强杀期限仍生效 |
| 已修项回归 | 接口删除实际调用 teardown、终止 helper；R89 节拍与 hotplug 修复保持 |

R88 的 netifd 审计混用了较新 `netifd-c/proto-ext.c`。本轮改用镜像匹配的
`cbb83a1857407a28a63dc09412a1f209195914ef`，构建机 Git 工作树 clean。
本地 `netifd-ref` 与它的两个文件逐字节一致：

- `interface.c` SHA256 `3404ca8b45b2e9cd638f11852f52f5dc33f338502a0a9e06a88d68f4ebfc1829`
- `proto-shell.c` SHA256 `414456fcddd798f590d6a9c9c196f0645f1d026933d11100c34ea1dc8aa2a668`
- 镜像 `/sbin/netifd` SHA256 `8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90`
- procd 源码提交 `58eb263d5abe03f8c1280bdfa65a3b052614215d`

R88 F10 在精确原版同样存在。测试明确期待原版在 1 秒内不自动 TERM、最终由
5 秒期限清理，候选则要求及时 TERM 和清理；不将这项改进冒充逐字节等价。
netifd 的缺失方法、全局 restart/re-exec、netlink 溢出、日志等不纳入本批。

## 2. 修复边界与性能保护

- procd 只改到期处理对 halt 的判断；R87/R89 的只读请求分类、维护截止时间、
  就绪等待保持原实现，避免重新引入每查询一次维护或节拍饥饿。
- netifd 不修改状态查询、netlink 订阅、热路径扫描或无线编排。
- 旧配置只在 reload 时临时保存，释放旧协议状态时一并释放；连续 reload 不覆盖
  最初的运行配置，也不增加常驻配置副本。
- data 合并去掉临时 Vec 和已有键的名字分配，仅在新增键时排序。
- helper 正常退出不再等待强杀期限，时间记录保存在专项探针 `timing.json`。

## 3. 验证与红证

入口 `tools/r90_lifecycle_probe.py ROOTFS BINS OUTPUT`：每场景各自的 rootfs 副本、
mount/net/PID namespace，实际进程身份与必需断言集合检查，失败和缺失用例均报红。
`tools/r90_netifd_lifecycle.sh` 把 11 个网络场景纳入 netifd_suite；procd 单独一个场景。

开发候选的 12 场景 × 原版/候选两侧全部符合各自合同；同一探针对 R89 正式
二进制的 12 场景有 10 场景报红（renew_abort 和已经修好的 remove 通过）。
场景含无载波释放、数据变化/重复/迟到、失败重连、teardown/abort renew、二次 helper、
普通/连续/切换协议 reload、remove、available、state-stop 后 delete。

`R90_HOTPLUG_PROBE=1 tools/r71_pid1_probe.sh ...` 延迟 ubusd 5 秒，令 coldplug
命令在连接重试期间退出，再发送后续 lo 事件。原版和开发候选通过；R87 正式
procd 被准确判为 hotplug 队列停滞。默认 r71 不挂载 sysfs；专项模式只运行自制
lo 触发器，不运行构建机硬件的 udevtrigger。

测试开发期间的失败输出全部留在 `private/r90` 对应的构建机工作目录：最初 proc
挂载不匹配 PID namespace；随后把 TEARDOWN 的状态布尔值误当完成；无载波用例
的 veth 对端受设备发现影响。已分别改为 namespace proc、清理/回收断言和隔离对端。
这些夹具失败不作为产品缺陷或通过证据。

## 4. 正式产物的功能验收

正式产物身份见 [canonical_build.json](R90_parts/canonical_build.json)：只有 procd、
netifd 改变，其余七个二进制与 R89 逐字节相同。全部产物校验和、manifest 链与
三个核心二进制均已核验。产物和原始日志留在 private，不进入 Git。

构建机 `source/` 中组件、工具与工具链清单的 335 个文件，均与正式构建提交
`ae51db4` 的 Git archive 校验和一致。本次续接没有改动运行时代码或重新构建。
逐门结果、证据文件摘要和场景断言见 [validation.json](R90_parts/validation.json)。

| 验证 | 结果 |
|---|---|
| 单元测试 | netifd 156、procd 74 通过；复用暂停前已经结束的同源码验证 |
| clippy | 两组件通过已有 unsafe 注释检查 |
| netifd 完整套件 | 30/30，无跳过；前三项使用同源码 example 探针，daemon 场景使用正式二进制 |
| R90 生命周期 | 12 场景 × 两侧，各 30 个必需断言，符合各自合同 |
| procd 回归 | tick、busy 候选、r65、r83、r71、r72、r75 通过 |
| hotplug 专项 | 延迟总线连接期间 coldplug 退出及后续队列推进，原版/正式候选通过 |
| 离线安装与回退 | 安装惰性、切换确认、恢复失败、自动回退、无总线救援，5/5 通过 |

二次 helper teardown 专项中，镜像原版清理耗时 5013 ms，正式候选为 72 ms，
候选及时收到 TERM 并完成回收。这是该故障场景的响应改善，不代表常规查询吞吐提升。

原版 C busy 对照在 32 个子进程均回收、退出码均为 19、watchdog 已停止的情况下，
仅收到 31 条末尾日志，故完整门返回失败，候选尚未运行。保留该失败后，用已有
`--sides candidate` 接口补完正式候选：32 条末尾日志完整且归属正确，hotplug
增删通过，fd 从 7 保持为 7。不能将这次结果表述为原版/候选 busy 双侧通过。

暂停时中断的 netifd 套件仍保留 `PAUSED_BY_USER`，不纳入验收。续接使用新的
`raw/acceptance-02`。离线自测首轮因包内 checksum 路径多写了一层 `bins/` 失败；
修正清单后的正式复测通过，原始失败也保留。

性能预检还发现旧测试的 chroot 删除后仍有子进程存活。按隔离根目录和 PID
启动标识核验，清理 127 个历史/已结束测试进程及最后套件留下的 2 个子进程。
测量前确认功能 validator、cargo/rustc、临时 chroot 均已退出。
旧测试脚本的自动清理能力仍值得后续统一补强；本次没有扩大运行时代码修改范围。

## 5. 性能对照

R89 与 R90 正式二进制的 22 项矩阵已完整完成。每侧四轮，顺序为
R89/R90/R90/R89/R90/R89/R89/R90；每项每轮 30,000 次请求，共 5,280,000 次，
全部成功。比较每侧四轮统计量的中位数，c4 的 CPU 使用包含 warm-up 的外层区间。
二进制、冻结客户端、夹具、内核/boot identity、接口集合及 hotplug 子进程回收均通过校验。
完整派生数据见 [performance_build_host.json](R90_parts/performance_build_host.json)，
来源与测量前检查见 [performance_provenance.json](R90_parts/performance_provenance.json)。

下表范围覆盖各组件的所有负载；负值为候选耗时/CPU 更少，正值为更多。

| 组件 | 负载数 | 平均延迟变化 | subject CPU / op 变化 | p99 变化 |
|---|---:|---:|---:|---:|
| netifd | 14 | −1.27%～+2.15% | −2.94%～+3.45% | −7.00%～+4.27% |
| procd | 8 | −1.07%～+4.04% | −2.94%～+1.52% | −3.10%～+7.45% |

常驻 RSS 中位数：procd 两侧均 988 KiB，netifd 两侧均 1212 KiB；匿名 RSS
分别均为 196 / 284 KiB。fd 分别保持 7 / 10，两组件线程数均保持 1。
netifd 的 VmHWM 最大值两侧均为 1312 KiB，但达到该峰值的轮次数不同，不能将
常驻中位数相同表述为每轮所有内存读数完全相同。

procd `system_info_c4` 的平均延迟 +4.04%、p95 +14.99%、p99 +7.45%，
而 subject CPU 中位数不变。进一步限定 CPU 2,3，只复测 procd 八项，仍为
四轮/侧、30,000 次/项，共 1,920,000 次请求，全部成功：该负载的平均延迟
−1.03%、p95 −0.77%、p99 +0.20%，没有复现原来的升高。专项数据单独保存在
[performance_procd_affinity.json](R90_parts/performance_procd_affinity.json)，不覆盖原矩阵。

固定 CPU 下另一负载 `service_list_named_128_c4` 的平均延迟 +4.76%、
p99 +8.25%，subject CPU −4.76%；它在原矩阵中的平均延迟 −0.57%、
p99 −0.86%。差异随调度条件/负载变化，不能据此断言所有尾延迟均无回退，
也不能把单一环境的尾部上升直接归因于本次生命周期修复。
本轮未发现跨环境一致的 subject CPU 或常驻资源退化；保留这些尾延迟差异，
将 AX3000T 实机对照作为最终性能验收。当前证据不支持宣称普通查询有统一提速。

首次完整矩阵尝试 `performance-01` 已完成 procd 八轮及 netifd 第一轮采集，但
汇总脚本误读 `interfaces-*.txt` / `objects-*.txt`，实际文件名为
`interface-names-*.txt` / `interface-objects-*.txt`，因此在 R89 基线 netifd 的
采集后停止。修正两处读取路径后，在 `performance-02` 全量重跑；前次不作为
完整验收。修正仅在独立 `validation-tools/benchmark` 中应用，正式构建的
`source/` 快照、被测二进制、客户端及采集脚本保持原身份。
汇总工具另增加 `--components`，让上述针对性复核只运行相关组件；默认仍为两组件。

## 6. 实机阶段

构建机结果不能替代 AX3000T 实机性能与冷启动验收。部署包仍为
`prepared_not_deployed`，当前备份核验未完成；实机部署需要独立授权及恢复核验。
续接入口见 [R90_RESUME](../../docs/R90_RESUME.md)。
