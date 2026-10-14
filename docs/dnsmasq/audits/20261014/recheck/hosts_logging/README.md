# B1 / B6 独立复核

复核 `aa8f12db`；产品冻结源码 `807db8a1`，真实 SDK 包内 Rust ELF
`0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`。
行为对照均为镜像 C ELF
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
本轮实际新运行结果、原始路径及 SHA 见 [summary.json](summary.json)；
[collect.py](collect.py) 只读收集。所有实验在 Oracle 独立 network/mount/PID
namespace；未操作物理路由器，未修改产品源码。

## 发现 R-H1：B1 原最小复现修好，同类 ENOMEM 仍可使整个 daemon 中止

**P1，已复现的 B1 残余；不是本次新引入的回归。** 原审计的“初始单条
hosts，新增地址空间 1 MiB，HUP 30,000 条”现在 C/Rust 都存活并在解除限制后
恢复，确实修复了原最小用例。但仅把初始 hosts 改成 2,000 条，仍给每侧
各自 `VmSize + 1 MiB` 的相同新增余量，最终包 Rust 在 HUP 后、测试工具停止
进程之前自行 SIGABRT；精确 C 保持存活并恢复。最终包该点已复现 **3/3** 次，
C 对照 **3/3** 次存活。

| 条件 | 精确 C | 最终包 Rust |
| --- | --- | --- |
| 初始 2,000 条，+1 MiB；第一次 | VmSize 1,556 KiB；18,036 次 ENOMEM；存活，解除限制并 HUP 后 UDP/TCP 恢复，exit 0 | VmSize 3,428 KiB；23,848 次 ENOMEM；HUP 后 exit -6 |
| 相同条件第二、三次 | 同样存活、恢复、exit 0 | 同样 SIGABRT，23,848 次 ENOMEM |
| 初始 2,000 条，+256 KiB；两次 | 两次均存活并恢复 | 两次均 SIGABRT，26,638 次 ENOMEM |
| 初始 2,000 条，+512 KiB | 存活并恢复 | 存活并恢复 |
| 初始 1 条，+256/512/1,024 KiB | 全部存活并恢复 | 全部存活并恢复 |
| 旧审计 Rust，初始 2,000 条，+1 MiB | C 仍存活并恢复 | 旧 Rust 同样 SIGABRT，首次 ENOMEM 即中止 |

完整矩阵在 `sweep`；重复在 `sweep_repeat`、`sweep_final`；旧 Rust 负控在
`old_rust_negative`。最终确认使用已提交的
[recheck_hosts_limits.py](../../../../../../tools/dnsmasq/recheck_hosts_limits.py)。
早期工具把不存在的 `rcode` 字段读为 null，最终版已改为 `flags & 15`；
故障注入和生死判定未改变，早期工具原文及散列单独保留在 private，未把
它的 null 当作 DNS rcode 证据。

最后的 syscall 摘录是 `mmap(...32768...) = -1 ENOMEM` 后
`SIGABRT {si_code=SI_TKILL}`；`pressure_exit` 已为 -6，说明不是测试的 TERM
或清理 SIGKILL。诊断未取得分配调用栈，因此不将某个源码行说成唯一根因。
复核代码确认 fallible hosts 表与快照之外仍有不可失败分配，例如
`main.rs:3192-3195` 的 reload 日志路径进入
`logging/startup.rs:4-10` 的 `to_vec`/`format!`；正常 owner/TCP 路径也仍有
分配。它们是故障边界尚不能泛化的源码依据，不是本次崩溃的已定位栈。

实际影响是一个合法 hosts 重载仍能终止共享 DNS/DHCP daemon；守护回退可以
缩短后果，却不能使 B1 成为“已完全排除”。本实验使用合成大 hosts 和显式
地址空间限制，**没有证明当前路由器配置会发生此压力，也不估计现场概率**。
+512 KiB 存活、+1 MiB 失败说明不能将单个 headroom 通过点外推为安全阈值；
本轮没有对分配器布局的非单调现象定位唯一原因。

## B1 正常与已修复边界

- 新跑原 B1：两侧都发生 ENOMEM，仍回答 `ready.test`，解除限制后不重启即可
  HUP 载入 `recovered.test`，正常 exit 0。无压力 30,000 条控制均能查询最后一条。
- 新跑原扩展矩阵：文件/hostsdir × expand 开关 × C/Rust 共 8 组合，每组合两轮
  失败；配置 DNS、租约 DNS、DHCP ACK 与后续 UDP/TCP 恢复全部通过。
- 新跑 generation/cursor：每侧 204 查询，固定顺序和轮转两组；PTR、IPv6、重载、
  TCP 接受快照、字面点、多地址顺序零差异；负向 order/TTL 校准仍拒绝变异。
- 源码审查覆盖 `hosts.rs:145-293`、`hostsdir_runtime.rs:85-172`、
  `main.rs:3180-3223,3673-3788`。索引发布前 reserve、暂存失败释放、旧快照恢复
  与下一 source 更新前恢复措施确实存在；新正常路径未发现可证实的回归。

资源不足时 Rust 的旧快照恢复不是 C 的逐条部分装载。本轮初始单条的压力
实验也观测到 Rust 保留旧记录、C 移除旧记录；这与修复报告披露的一致。连续
复制失败下 owner 本地视图失效的静态路径已审查，但未把未触发的 TCP/DHCP
视图差异另报成已复现故障。

## B6：修复成立；连接持续背压时停止仍会等待

新跑三个场景 × C/Rust 共 6 组全部通过：

- 300 个查询在日志背压期间全部成功，TERM 后继续停读 2.1 秒，恢复 reader 后
  两侧正常退出。
- 内核日志接收队列被 fixture 填满后，query、answer、SIGTERM 三条尾记录在
  延迟 350 ms 排空时内容、顺序、各一次均正确。
- 同样背压后关闭接收端，两侧无需排空即 exit 0。

`main.rs:1980-1992` 删除 100 ms 截止并沿用非阻塞 flush/poll；
`logging.rs:724-729` 的队列空/连接失效出口与匹配 C `src/log.c:457-474`
一致。永久不读且保持连接时，停止可持续等待，这是 C 共同语义；部署层
若需要有界停止，不能仅等待 TERM。该结论针对显式 `log-async=25`、
`log-queries`，不推算默认 logd 的发生概率。此前 329 场景日志族证据已审阅，
本次没有把它算作新跑数量。

## 重现入口与收尾

Oracle 根为 `/home/ubuntu/dnsmasq-recheck-hosts-20261014`。先复制仓库工具到
`source/tools/dnsmasq`；路径必须换成不存在的 private 输出：

```sh
base=/home/ubuntu/dnsmasq-recheck-hosts-20261014
sudo -n sh "$base/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$base/source/tools/dnsmasq/recheck_hosts_limits.py" \
  --image-root /home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity-final/rootfs-check \
  --rust /home/ubuntu/dnsmasq-predeploy-fixes-20261014/root/private/sdk-acquire-02/payload/usr/sbin/dnsmasq \
  --rust-sha256 0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728 \
  --initial-rows 2000 --headroom-kib 1024 \
  --output "$base/private/new-output"
```

其余新跑工具是 `audit_integration_resources.py --kinds memory`（另以
`--memory-headroom-mib 0` 做控制）、`predeploy_hosts_pressure.py`、
`predeploy_logging_shutdown.py`、`predeploy_hosts_generation.py`；输入相同
镜像与包内 ELF。工具身份和 52 个原始证据散列在汇总中。所有运行已退出，
宿主 mount 表没有本任务挂载；原始日志/镜像 overlay/ELF 均只在 Oracle private。
