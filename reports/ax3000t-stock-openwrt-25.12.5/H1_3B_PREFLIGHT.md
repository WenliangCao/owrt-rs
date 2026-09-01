# AX3000T stock / OpenWrt 25.12.5：H1.3b RAM boot preflight

> 状态：`authorized_but_blocked_before_device_contact`
> 日期：2026-09-01
> 设备操作：没有连接、重启或修改路由器
> 执行门：`commands_authorized=false`、`router_reboot=false`
> 后续处置：用户固定无拆机边界后，本阶段为 `not_applicable_under_no_disassembly_policy`；
> 本报告保留为历史 fail-closed 证据，不再要求用户准备 UART

## 1. 判定

用户已在 H1.3b 被明确列为下一阶段后要求继续，因此本次记录为 H1.3b 已请求、preflight 已
授权。现场执行仍被 fail-closed：当前 Codex 宿主没有 USB-UART 设备，有线接口 `en2`、`en3`
都没有 link，只有 Wi-Fi 承担现有管理/默认路由，而 H1.3a candidate 明确禁用 Wi-Fi。可控供电、
现场操作者和独立联网设备也尚未确认。

在这种条件下 RAM boot 会同时丢失 console 和管理面，无法证明停止条件，更无法在 boot 失败
时区分 FIT、网口、内核或用户态问题。因此没有向路由器传文件，没有执行 UART/U-Boot 命令，
也没有安排重启。

## 2. 已完成的离线准备

H1.3a candidate 已从服务器复制到 Git 外的本地私有 TFTP staging 目录并设为 mode `0444`：

```text
filename: openwrt-mediatek-filogic-xiaomi_mi-router-ax3000t-initramfs-kernel.bin
size: 8762644 bytes
SHA-256: c9ce88f597dea3e552c05cdcf9ed2d3f9683161731dc12747cc7627783247a5a
```

复制后的 SHA-256 与服务器构建产物、H1.3a manifest 一致。candidate 仍未进入系统 TFTP root，
macOS 的 `tftpd` 保持 disabled，UDP/69 没有 listener，本机网络设置没有改变。

官方 AX3000T 页面、techdata 与 UART 照片已保存到私有 evidence，并记录原始 SHA-256。官方
资料给出的串口条件是 115200、8N1、3.3 V；照片中的四个孔从上到下为 VCC、RX、GND、TX。
正式连接只接 GND、交叉 TX/RX，**不连接 VCC**。参考：[设备页](https://openwrt.org/toh/xiaomi/ax3000t)、
[techdata](https://openwrt.org/toh/hwdata/xiaomi/xiaomi_mi_router_ax3000t)、
[UART 照片](https://openwrt.org/_media/media/xiaomi/xiaomi_ax3000t_uart.jpg)。

## 3. 两个 RAM 地址不是同一概念

官方 recovery 命令把完整 FIT 下载到 `0x46000000`，再对同一地址执行 `bootm`。H1.3a FIT
内部 kernel node 的 load/entry 则是 `0x48000000`：

| 边界 | 值 |
|---|---:|
| TFTP FIT buffer start | `0x46000000` |
| FIT buffer end（exclusive） | `0x4685b514` |
| kernel load / entry | `0x48000000` |
| buffer 与 kernel load 的空隙 | 24,791,788 bytes |

所以 8,762,644-byte FIT buffer 与 kernel load region 不重叠。`0x46000000` 是 `tftpboot`/
`bootm` 看到的 FIT 地址，`0x48000000` 是 FIT 描述的 kernel 解包目标；不能把其中一个机械替换
成另一个。

## 4. 尚未授权的 U-Boot 序列

preflight manifest 固定了 13 条 proposed command，但每条状态都是 `not_authorized`。前七条
只用于在 UART 上识别 stock U-Boot 和查询 `tftpboot`、`bootm`、`iminfo`、`setenv` 的实际
语义；只有它们与预期一致，才可能允许两个 volatile `setenv`、一次 TFTP load、size/FIT
检查和最终 `bootm`。

该集合不含 `saveenv`、`env save`、`nand`、`mtd`、`ubi`、`erase`、`write`、`sysupgrade`
或任何 flash 命令。即便未来执行，`setenv` 也必须先由本机 stock U-Boot 的 `help`/行为确认
为 RAM-only；绝不使用 persistent save。

当前不能把 proposed command 当成操作说明。stock U-Boot identity、command help、TFTP host
interface 和服务启动/停止命令都还没有现场证据，因此 exact command plan 仍为 false。

## 5. 现场 gate

进入任何路由器重启以前，必须同时满足：

1. 一个明确支持 3.3 V logic 的 USB-UART 已连接，并出现新的 `/dev/cu.*`；不接 VCC。
2. 一根网线从 `en2` 或 `en3` 对应适配器直连路由器中间 LAN 口，link 为 active；WAN 断开。
3. 另有不依赖该路由器的联网/通信设备；当前 Mac 的 Wi-Fi 不能同时冒充独立回退通道。
4. 操作者在路由器旁，可立即断电；电源插头或受控插座已明确。
5. candidate hash 再次匹配；TFTP 只在隔离有线接口可达，结束后能立即关闭。
6. 先只捕获 UART bootlog、识别 U-Boot 并查询 help；发现命令/地址/内存/菜单不一致就让原
   OpenWrt 正常启动，不进入 TFTP load。
7. transfer 后 `filesize` 必须精确为 `0x85b514`，FIT 检查通过后才讨论 `bootm`。

其中任一项缺失，`h1_3b_ram_boot`、`recovery_boot_verified` 和 H1.2 backup 都保持 false。

## 6. Gate 结果与证据边界

机器 gate 校验 H1.3a manifest、私有 candidate、三份官方资料、脱敏 host snapshot、地址计算、
proposed command 精确集合、未满足 preconditions 和所有关闭 gate。预期输出包括：

```text
h1_3b_preflight_review=true
h1_3b_ram_boot=false
recovery_boot_verified=false
commands_authorized=false
router_contact=false
router_reboot=false
device_writes=false
firmware_flash=false
```

最终十类负向篡改全部被拒绝：伪造 RAM-boot gate、command authorization、router reboot、删除
blocker、伪造 UART、制造 buffer overlap、塞入 `saveenv`、改成 `ubootmod` candidate、放宽
candidate mode、篡改私有 host snapshot。

本报告只证明 preflight 正确阻断了不具备恢复条件的运行；不证明 UART、stock U-Boot、TFTP、
FIT acceptance、candidate runtime 或 flash 零写入。

## 7. 方法纠正

本阶段保留三项方法纠正：

1. OpenWrt wiki 普通页面被 Anubis 拦截后，没有改用搜索摘要，而是读取同一官方站点的
   DokuWiki `export_raw` 并固定 SHA-256。
2. 官方资料同时出现 `0x46000000` 与 `0x48000000`；最初不能把二者当作一个模糊的“启动
   地址”。复核 FIT 后分别登记为 FIT buffer 与 kernel load/entry，并计算不重叠边界。
3. 第一轮组合负向测试在前八项已经成功拒绝后，最后一项误用了未定义的 filename 变量；
   candidate mode 篡改单独重跑并被正确拒绝，没有把脚本中断当成 gate 成功。

## 8. 证据

- [H1.3b preflight manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-3b-preflight.json)
- [H1.3b preflight gate](../../tools/h1_3b_preflight_gate.py)
- [H1.3a manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-3a-recovery-design.json)
- [H1 runbook](../../docs/H1_RUNBOOK.md)
