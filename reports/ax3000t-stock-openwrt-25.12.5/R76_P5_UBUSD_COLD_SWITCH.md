# R76：P5 —— ubusd-rs 冷切换，设备的常驻总线

> 2026-09-09。候选 ubusd-rs md5 `ce2759db907bfba752f529c9b9f4008f`（HEAD e67d8d6 树，
> oracle `~/netifd-r59/components/ubusd`，cargo 1.98.1，aarch64-musl，opt-3/lto/static）。
> **终态：设备总线 = ubusd-rs（ubus 用户，VmRSS 336 kB），回退件 `/sbin/ubusd.c-orig`
> （ba762b66，与 /rom 相同）。**

## 为什么是冷切换

决策 0015 封死的是**热切换**：ubusd 重启后 odhcpd 永久脱离总线、空闲 dnsmasq 不回、
netifd 丢 network.wireless。冷切换（替换 /sbin/ubusd + 重启，procd 的早期 ubus 服务在
下一次启动拉起新二进制）没有任何客户端经历总线重启。0015 当时"开机切换不可行"的理由
（够不着 preinit、0006 禁重启）已被 P3.3/P4 消解：procd-rs 就是 PID 1，且重启窗口有授权。

## 门槛（oracle，全部一次通过，/tmp/p5）

| 门 | 结果 |
|---|---|
| ubusd 单测 + clippy | 18 过 / 0 警告 |
| r36 差分（root） | 85 行转录逐字节相同 |
| r36 差分（DAEMON_USER=ubus，设备的运行身份） | 85 行相同 |
| r22 重跑（C 总线） | 故障面与 0015 表一致：重启后仅 log/network.* 恢复 |
| r22 重跑（ubusd-rs 总线） | **与 C 完全同形**——客户端命运由客户端代码决定，与总线实现无关 |
| r71（procd-rs PID1 + ubusd-rs，全 Rust 启动链，ns） | ok（自判门） |
| r65（双侧沙箱总线换成 ubusd-rs 的监管差分） | 2199 行比较、diff 0、无 expect/ready.err —— 总线对上层透明 |

ubusd 组件源码自 r36–r42 轮（差分/重连/包检/bench/fuzz）以来未变（main.rs md5 同），
bench（无一慢于 C）与 fuzz 结论继续有效。

## 设备窗口（2026-09-09 14:37–14:47）

1. 基线：40 对象、14 running、board md5 0ac54e2d、wifi 双频。
2. `p5_switch.sh stage`：候选在丢弃 socket 上应答 `ubus list` 后才落位；一次原子 rename；
   运行中 ubusd 持旧（已删）inode。
3. **重启 #1**（14:37，2 分 42 秒回）：ubusd-rs 为总线（pid 868，ubus 用户），
   **40 对象与 C 基线逐行相同**，14 running，board 字节同，log/rpcd 应答，0 procd 错误。
4. 3 分钟观察：ubusd/netifd/odhcpd/dnsmasq PID 全程不变（无 crash-loop），对象数/错误数不变。
5. **重启 #2**（14:43，2 分 45 秒回）：与 #1 一致；wifi 客户端 1+4 重新关联。
6. **不回退**。undo = `mv /sbin/ubusd.c-orig /sbin/ubusd` + 重启；failsafe 走 /rom 原件。

## 记录在案

- 设备 procd（a5e5b70e）与 HEAD 重建（0b8d47d2）md5 不同：P4 会话先跑门槛、后改注释再提交，
  行号位移改变 panic 位置字符串。行为等价（改动仅注释/文档），r65/r71/r75 当时全绿。
  教训重申：**构建、门槛、提交要出自同一棵树的同一瞬间**，注释也算改动。
- 设备 busybox `pgrep -x ubusd` 不匹配（p5_switch.sh 已改用 `pgrep ubusd`）。
- /tmp 是 tmpfs：切换脚本重启后消失，undo 前需重传（.c-orig 在 overlay 上持久）。

## 现状

设备控制面：uci、reload-config、logd、httpd、fw4、rpcd、procd（PID 1）、**ubusd** 均为 Rust。
剩 C：netifd（P6 = wireless 半边 + 设备接管）。
