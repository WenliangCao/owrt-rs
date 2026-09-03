# R23：开机路径验证（受控重启，2026-09-03）

> 决策 [0016](../../docs/decisions/0016-reboot-verification-and-rescue-boundary.md)。门禁脚本 `tools/r23_reboot_gate.sh`。
> 原始输出 `private/backup/2026-09-03/r23/{pre,post}/`（Git 外）。

## 1. 结论

**通过。** 六个 Rust 组件（uci-rs S00、reload_config_rs S11、rpcd-rs S11、logd-rs S12、fw4-rs S18、httpd-rs S50）
在这台设备上第一次经历真实开机，全部按 boot-enable 接管；重启前后 15 组结构化状态逐文件相同；bootloader
标志按预测变化（仅 `flag_try_sys1_failed` 22→23）；四分钟稳定性探针无 respawn、无异常退出。
REPORT_ROUND2 §4 第一项（开机路径未验证）关闭。

## 2. 前置条件（均在重启前满足）

- 备份：`sysupgrade -b`、`/overlay/upper` 全量、mtd0–mtd7 只读转储（设备端/本地 SHA-256 一致）、`fw_printenv`、
  系统事实 → `private/backup/2026-09-03/`（8.5 MB）。
- 镜像：官方 25.12.5 sysupgrade / initramfs-factory / initramfs-kernel，SHA-256 与官方 `sha256sums` 一致；
  小米 RD03 原厂 1.0.47（官方 CDN）→ `private/images/`（50 MB）。
- bootloader 选槽逻辑核实（见 0016 §设备事实 2）；uci-rs 与 `/rom/sbin/uci` 在 19 个包上的 export/show/get 相同。
- 用户在设备旁；网线接 `lan4`（`carrier=1` 确认，原来插在 lan2，换口后确认）；Mac 网络服务顺序改为
  iPhone 热点优先（`networksetup -ordernetworkservices`），路由器失联时对话不中断。
- 救援手册 [RUNBOOK_AX3000T_RECOVERY](../../docs/RUNBOOK_AX3000T_RECOVERY.md) 已交付用户。

## 3. 过程

| 时间 | 事件 |
|---|---|
| 20:11:50 | `r23 pre` 采集 17 个文件 |
| 20:11:54 | `ssh openwrt 'sync; reboot'` |
| +39 s | SSH 恢复（设备 uptime 21.9 s），cmdline `firmware=0 mtd=ubi`，`owrt-switch status` 六个组件 enabled / boot-enable on，三个 daemon 有 pid |
| uptime 90 s | `r23 post` + diff |
| uptime 240 s | 稳定性探针 |

## 4. 门禁结果（pre → post）

| 文件 | 内容 | 结果 |
|---|---|---|
| ubus-list | 40 个 ubus 对象 | 相同 |
| init-enabled | 31 个 init 脚本的 enabled/disabled | 相同 |
| bind-mounts | `/sbin/uci`、`/sbin/reload_config`、`/sbin/fw4` 三个 bind mount | 相同 |
| owrt-switch-status | 六组件 switch/boot-enable/版本 | 相同（pid 列已掩蔽；首轮脚本未掩蔽，唯一差异即三个 pid） |
| processes | 14 种进程及计数（rpcd-rs/httpd-rs/logd-rs 各 1，无 rpcd/uhttpd/logd） | 相同 |
| nft-ruleset | 152 行规则集（计数掩蔽） | 相同 |
| config-hashes | 19 个 `/etc/config/*` 哈希 | 相同 |
| binary-hashes | 6 个二进制、7 个 switch、6 个 init、6 个 boot-enable 标记 | 相同 |
| links | 9 个接口与标志、br-lan 地址、wan 有地址 | 相同 |
| wireless-status / iwinfo | 两个 radio 的 netifd 无线状态与 iwinfo 摘要 | 相同 |
| uci-export-hash | uci-rs 与 `/rom/sbin/uci` 全量 export 哈希 | 相同（两者一致） |
| jsonrpc | httpd-rs `/ubus` → rpcd-rs 的两个 JSON-RPC 探针 | 相同 |
| ubus-probes | system board、session list、iwinfo devices、rc list | 相同 |

bootloader 标志：`flag_boot_rootfs=0`、`flag_boot_success=1`、`flag_last_success=1`、`flag_try_sys2_failed=8`、
`flag_ota_reboot=0` 不变；`flag_try_sys1_failed` 22→23（bootloader 每次开机 +1，不参与选槽）。

## 5. 稳定性探针（uptime 240 s）

- procd 服务实例：owrt-rpcd/owrt-logd/owrt-httpd/dnsmasq/odhcpd/network/dropbear 各 1，wpad 2；日志无 respawn、
  无 "exited with"、无 segfault。
- WAN 默认路由存在，`ping 1.1.1.1` 2/2，本机 dnsmasq 解析 openwrt.org 成功，NTP 已校时。
- 6 个 DHCP 租约；2.4 GHz 2 个、5 GHz 3 个关联客户端。
- LuCI：`/` 200，`/luci-static/bootstrap/cascade.css` 200（44 042 字节），`/cgi-bin/luci/` 403 且正文为登录页
  （LuCI 对未认证会话返回 403，与 uhttpd 下相同）；HTTPS 同样 403 登录页。
- 内存：已用 67 MB / 239 MB。

## 6. 观察与说明

- `logread` 中开机早期日志时间戳为 2026-09-02 22:35（sysfixtime 用最后写入文件的 mtime），NTP 校时后正常；
  S00/S11 阶段的 switch 消息发生在 logd-rs（S12）之前，日志中只见 S18owrt-fw4 "gate: identical (174 lines)" 与
  bootcount "rd03 model detected, exit"。
- 内核 `mt7530-mdio ... probe failed with error -110`：本机交换芯片是 Airoha AN8855（随后成功绑定），mt7530 探测
  超时是该硬件修订的正常现象，与本项目无关。
- 重启期间 Mac 与设备对话未中断（默认路由走热点）。

## 7. 仍未验证

- 断电上电（power cycle）与 `reboot` 的差别：本次只做了软重启。
- failsafe 进入流程只做了源码核实，没有演练（需要一次故意的 failsafe 重启；不在本次授权内）。
- sysupgrade 路径、rpc-sys 的 upgrade/factory/reboot 方法仍未触碰。
