# AX3000T stock / OpenWrt 25.12.5：H1 无拆机边界重规划

> 日期：2026-09-01
> 状态：`complete_offline_policy_only`
> 设备操作：无；没有连接、传输、执行、重启、安装、mount 或写入路由器

## 1. 判定

**项目不因用户拒绝拆机而阻塞。** 用户可提供的 Wi-Fi、以太网和现有 OpenWrt SSH 足以完成
R05 的真实设备 tmpfs shadow 验证，也足以在以后单独授权时进行有线、短时、重启即回退的
canary。不能完成的是 raw NAND/UBI/kernel/bootloader 恢复验证，以及任何可能破坏启动或唯一
管理路径的职责替换；这些能力不属于当前 R05 的失败边界。

此前 H1 顺序把 H1.2 raw backup、H1.3b UART RAM boot 和 R05 shadow/canary 串成单链。
H1.2 的 exact-source 预检正确发现了 NMBM 读侧条件写入风险，H1.3b preflight 也正确拒绝在
没有 UART 时启动 recovery candidate；错误发生在**阶段依赖关系**：深层恢复被当成低风险 R05
验证的必经前置，而项目证据已经证明 R05 不触碰那些故障层。

## 2. 证据对齐

| 事实 | 已有证据 | 对新路径的含义 |
|---|---|---|
| R05 唯一持久语义是可重建的 tmpfs baseline | `replacement-boundary.json`，R05 `rust-replace` | H1.4 可完全限制在 `/tmp`，不需要 raw flash 备份 |
| V1 package 默认 disabled | `v1-validation.json` lifecycle gate | 安装不会自动取得 `/sbin/reload_config` 控制权；H1.5 仍需另行授权 |
| 切换是 reboot-volatile bind mount | V1 lifecycle + 决策 0004 | H1.6 的故障层是进程/mount，不是 bootloader/NAND |
| H1.2 读取可能触发 NMBM remap | `h1-2-preflight.json` | raw backup 保持未执行并退出当前路径，不放宽成“只读” |
| H1.3b 需要拆机 UART | `h1-3b-preflight.json` | 保留历史证据，但按用户固定边界标记不适用 |
| R01/R03/R08/R12/R17 是禁止触碰 | `replacement-boundary.json` | 缺少深层恢复继续阻止扩大到启动、无线、总线和升级 |

## 3. 固定的无拆机边界

允许的设备接入只有：

- Ethernet；
- Wi-Fi；
- 已存在的 OpenWrt SSH。

永久排除：拆机、主板测试点、焊接、USB-UART、TFTP/U-Boot、raw NAND 读取、固件刷写。
普通“继续”不能撤销这条边界。

H1.2 和 H1.3b 没有被伪装成完成：两者的 device execution 和 gate 仍是 false，状态变为
`not_applicable_under_no_disassembly_policy`。H1.3a 的 recovery candidate 保留在 Git 外，
不传入或启动。

## 4. 新顺序

```text
H1 无拆机边界重规划（本阶段，已完成）
  → H1.4 preflight：离线冻结 SSH/tmpfs shadow harness（下一阶段）
  → H1.4 run：另行授权后，仅 /tmp + fake ubus
  → H1.5：另行决定是否 disabled install
  → H1.6：另行决定是否五分钟 volatile bind-mount canary
```

H1.4 preflight 不能继承本阶段授权。它要先冻结 exact candidate hash、目标 `/tmp` 布局、命令
白名单、fake ubus、真实状态前后 hash、timeout、清理和停止条件；preflight 本身仍不连接设备。

H1.4 run 的上限是：临时传入已固定 hash 的 candidate，在独立 `/tmp/<run-id>` 中使用配置
副本、baseline 副本和 fake ubus。真实 `/etc/config`、`/var/run/config.md5`、ubus、mount、
服务和网络必须保持不变。失败时终止进程并删除临时目录，不 reboot。

## 5. 仍未授权

- 任何 SSH 命令或文件传输；
- H1.4 device run；
- APK 安装或卸载；
- bind mount、真实事件投递或真实 caller 切换；
- router reboot/power cycle；
- device write 或 firmware flash。

## 6. Gate

`tools/h1_no_disassembly_gate.py` 固定四份历史输入的 SHA-256，核对 R05 与五项禁止触碰职责、
V1 的默认禁用/重启即失语义、H1.2/H1.3b 仍未执行、用户物理边界、空命令集和所有关闭 gate。
正向 gate 通过；8 类负向篡改全部拒绝：伪造 device contact、伪造 H1.4 device run、移除
USB-UART 禁止项、加入 device command、扩大到 R01、伪造 RAM boot 完成、授权 reboot、授权
firmware flash。旧 H1.3b gate 也重新通过并继续输出所有运行态 gate 为 false，证明本次只改变
阶段依赖关系，没有改写历史事实。

它只允许输出：

```text
no_disassembly_policy_review=true
h1_4_offline_preflight_ready=true
h1_4_device_run=false
device_contact=false
device_writes=false
firmware_flash=false
next_stage=H1.4-preflight
```
