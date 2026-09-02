# AX3000T stock / OpenWrt 25.12.5：阶段 1 —— R05 Rust dispatcher 转正

> 日期：2026-09-02
> 状态：`complete_live_boot_enabled`
> 设备效果：`owrt-reload-config` 升级到 0.2.0-r1；Rust dispatcher 当前接管 `/sbin/reload_config`，
> 且 `boot-enable` 打开，每次开机由 S11 init 脚本重新接管。原文件未改动，`disable` 或断电即回退。

## 结论

R05 从"实验候选"变为设备默认路径。与 0.1.0 相比，0.2.0 只改两点：trace 默认写 syslog
（`daemon.info`，tag `reload_config`），stderr 与原实现一样静默；新增 `/etc/init.d/owrt-reload-config`
（START=11）和 `boot-enable` 开关。决策见 [0007](../../docs/decisions/0007-r05-boot-enable-and-syslog-trace.md)。

## 离线验证（oracle，精确 rootfs）

| 项 | 结果 |
|---|---|
| 工具链 | rustc 1.94.0，OpenWrt 25.12.5 filogic SDK，`aarch64-unknown-linux-musl`，零第三方 crate |
| 二进制 | 354,723 bytes（预算 512 KiB），SHA-256 `a209dedb…9ec6` |
| R1 harness | 11/11 合同用例，6/6 故障用例，baseline 字节等价，delivery 可观测 |
| V1 harness | package 身份、ABI/hardening、默认无控制权、生命周期（install/enable/upgrade/downgrade/uninstall）、回退路径、只读 I/O、磁盘满、100 次循环全部通过 |
| 新增断言 | init 脚本 0755；安装后 `S11` 链接存在、boot-enable off；`start` 在 off 时不挂载、on 时挂载；卸载后脚本、链接、flag 全部消失 |
| 可重复性 | r1 两次干净构建 APK 字节一致 |

harness 唯一改动是候选调用加 `--trace-stderr`，用例本身不变。

## 设备步骤

| 步骤 | 观察 |
|---|---|
| 升级 0.1.0-r1 → 0.2.0-r1 | apk 本地安装，post-upgrade 输出 `disabled`；候选/switch/init 三文件哈希与离线一致；dispatcher、baseline、配置树哈希不变；`S11` 链接已建立；boot-enable off |
| canary：enable → 3 次稳态 | mount 1，`/sbin/reload_config` 为候选哈希；3 次 compared 19、零事件；baseline 不变；stderr 无输出 |
| canary：synthetic 新建/修改/删除 | 新建静默；修改与删除各恰好一次 `delivery success status 0`；baseline 回到窗口前字节 |
| canary：disable → 原实现一次 | mount 0，原哈希恢复，零事件，baseline 不变 |
| go-live | `boot-enable on`，`/etc/init.d/owrt-reload-config start` → enabled，mount 1；候选执行一次零事件；drift 0 |

trace 全部出现在 `logread -e 'reload_config\['`，共 65 行，`delivery_failures` 全为 0。

## 监测窗口（约 3 分钟，用户要求）

11:17:59Z、11:18:55Z、11:19:50Z 三次只读探针：mount 1、switch `enabled`、baseline SHA-256 不变、
drift 0、`delivery_failures` 非零计数 0、fatal 0。

## 最终状态与退路

- `/sbin/reload_config` 当前解析到候选（SHA-256 `a209dedb…9ec6`），原文件 `f1527a79…4e15` 未改动。
- `/etc/owrt-reload-config.boot-enable` 存在，`S11owrt-reload-config` 在每次启动后重新挂载。
- 退路：`owrt-reload-config-switch boot-enable off && owrt-reload-config-switch disable`；或断电重启后
  不再重新挂载（需先关掉 boot-enable）。
- 尚未观察到的一件事：开机重新挂载本身。本项目不主动重启设备，留待用户下次自然重启后用
  `tools/r05_go_live_device.sh probe` 复核。

机器记录：[r05-go-live.json](../../manifests/ax3000t-stock-openwrt-25.12.5/r05-go-live.json)。
