# AX3000T stock / OpenWrt 25.12.5：阶段 2 —— R15 logd 替换与 Rust ubus 库

> 日期：2026-09-02
> 状态：`complete_live_boot_enabled`
> 设备效果：`owrt-logd` 0.1.0-r1 已安装；`logd-rs` 当前提供 ubus 对象 `log`，开机由 `S12owrt-logd`
> 启动，原 `log` 服务的 rc 链接被替换（文件未改动）。`owrt-logd-switch boot-enable off; disable` 即回退。

## 结论

R15 从"包装"改为完整替换（决策 0008）。`components/ubus` 用纯 Rust 实现 ubus 线协议（blob/blobmsg、
HELLO/LOOKUP/INVOKE/ADD_OBJECT/DATA/STATUS/NOTIFY、SCM_RIGHTS fd 传递），`components/logd` 在其上
实现合同 C2。两者零第三方 crate。

## 离线并排比对（oracle，精确 rootfs，真实 ubusd / logger / ubus / logread）

同一脚本对原 `/sbin/logd` 与 `logd-rs`（静态 musl）分别执行，`-S 1` 强制环形缓冲回绕：

| 输出 | 结果 |
|---|---|
| `ubus -v list log` 签名 | 一致 |
| 回绕前全量 `logread`、回绕后全量 `logread` | 一致（保留集合与顺序相同） |
| `logread -l 5`、`logread -e 正则` | 一致 |
| `ubus call log read` lines 0/3/4（非流式） | 一致 |
| `logread -f -l 0` 流式跟随（logger + ubus write 各一条） | 一致 |
| 18 步执行码 | 一致 |

屏蔽项只有时间戳前缀、`[pid]`、JSON 的 `time`/`id` 与对象 id。过程中复现了两处上游行为：
`log.write` 的内容同样会被剥去 16 字节"syslog 时间戳"（第 16 字节为空格时）；原 `logread` 遇到
1500 字节记录会段错误，用例改为 900 字节。

## 设备步骤

| 步骤 | 观察 |
|---|---|
| 安装 | 三文件哈希与离线一致；原 logd（pid 1267）不受影响；无 rc 链接；switch disabled |
| canary：enable | 原 logd 实例停止，`logd-rs` 注册 `log`；`logger`、`ubus call log write`、`logread -l`、`ubus call log read`、`logread -f` 全部正常 |
| canary：disable | 原 logd 重新启动并服务 `logread` |
| 怪癖复核 | 原 logd 对 `<14>canary via ubus write` 同样只保留 `write` |
| go-live | `boot-enable on` 把 `S12log/K89log` 换成 `S12owrt-logd/K89owrt-logd`；`enable` 后往返再次通过 |

切换瞬间环形缓冲区清空（与原 logd 重启相同）。SSH、网络、`reload_config` bind mount 均不受影响。

## 监测窗口（约 3 分钟）

12:33:14Z、12:34:09Z、12:35:05Z 三次探针：`logd-rs` pid 19348 不变，RSS 约 1 MB，`logread` 行数
12 → 20 → 26 持续增长，每次探针写入的 `logger` 行都能在 `logread -l 1` 读回；switch `enabled`，
boot-enable `on`。

## 最终状态与退路

- ubus `log` 由 `/usr/sbin/logd-rs -S 128` 提供（procd 服务 `owrt-logd`，respawn 5 1 -1）。
- `/etc/rc.d/S12owrt-logd`、`K89owrt-logd` 存在；原 `log` 服务的 rc 链接已移除，文件未改动。
- 退路：`owrt-logd-switch boot-enable off && owrt-logd-switch disable`，原 logd 立即恢复。
- 未观察：开机启动本身；内核消息摄入（窗口内没有新的 kmsg）。

机器记录：[r15-logd.json](../../manifests/ax3000t-stock-openwrt-25.12.5/r15-logd.json)。
