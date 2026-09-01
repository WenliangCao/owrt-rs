# AX3000T stock / OpenWrt 25.12.5：H1.4 tmpfs shadow preflight

> 日期：2026-09-01
> 状态：`passed_offline_ready_for_authorized_device_run`
> 本阶段设备操作：无；没有连接、传输或执行路由器命令

## 判定

H1.4 的真实设备 shadow run 已具备可执行条件。它不是模拟器测试的重复：V1 已证明 candidate
在匹配 rootfs 中实现合同，H1.4 将验证同一精确 binary 在真实 AX3000T CPU、动态链接器、
BusyBox、UCI、当前 baseline 和配置文件名集合下能否保持兼容。

设备操作上限已经冻结为：通过现有 `openwrt` SSH alias 把两个固定 hash 的文件传到三个固定
`/tmp` 路径，在隔离 shadow root 中运行，使用 PATH 优先的 fake `ubus`，最后删除所有临时
文件。它不安装 APK，不改 overlay，不执行 bind mount，不调用真实 ubus，不重启也不刷写。

## 合同序列纠正

最初 runbook 把“新建 synthetic package”写成应产生事件，这与 C-04 及 V1 用例
`c03-new-config-is-silent` 冲突。preflight 已改成三个独立步骤：

1. 对复制的当前 baseline 运行：零事件，baseline 字节不变；
2. 只在 shadow tree 新建 `h1_shadow_probe`：仍然零事件，但 shadow baseline 前进；
3. 再修改该 synthetic package：恰好一个 `h1_shadow_probe` fake-ubus 事件。

这不是优化实现，而是保留原始 `/sbin/reload_config` 的新增静默语义。

## 真实状态隔离

设备 harness 在执行前后分别计算以下对象的 SHA-256 或树摘要：

- `/etc/config`；
- `/var/run/uci`，并区分“不存在”与空目录；
- `/var/run/config.md5`；
- `/sbin/reload_config`；
- `/lib/apk/db/installed`；
- `/sbin/reload_config` 的 mount count。

任何差异都会使 run 非零退出。配置和 baseline 的副本留在设备 tmpfs，只输出 hash、package
名称和候选 JSONL trace；配置内容不复制回工作站，也不进入报告。

## 固定 artifact 与命令边界

候选是 V1 APK 在隔离的 OpenWrt 25.12.5 rootfs 中实际安装出的 346,531-byte binary：

```text
SHA-256 b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75
private mode 0500
remote /tmp/owrt-h1-4-reload-config-rs
```

另两个 remote path 是 `/tmp/owrt-h1-4-shadow.sh` 和
`/tmp/owrt-r05-shadow-20260901`。runner 只接受 SSH alias `openwrt`，启用 strict host-key check，
identity/transfer/execution timeout 分别为 30/60/120 秒。失败和成功都执行固定路径清理，然后
再次通过 SSH 证明三个路径不存在、原 dispatcher 未变、没有 candidate install/switch/mount。

## 离线验证与 gate

`tools/h1_4_shadow_device.sh` 已同时通过本机 shell syntax 和精确 OpenWrt 25.12.5 rootfs 中的
BusyBox `ash -n`；runner 通过 Python compile。机器 gate 固定 contract、V1、无拆机 policy、
candidate、harness 和 runner 的 hash，检查三步合同序列、授权边界、timeout、cleanup、所有
关闭的 device-effect gate 和本报告文字。八类负向篡改均被拒绝：持久写入、伪造 device-run
完成、扩大 cleanup 到整个 `/tmp`、把 creation 改成 event、继承 H1.5 授权、package install、
router reboot，以及删除停止条件。

preflight 的 `h1_4_device_run=false` 只是表示尚未执行，不表示继续逃避实体设备。本轮用户已
明确要求扩大跨度并继续，因此 preflight 通过后可消耗本轮授权执行这一个 H1.4 device run；
授权不延伸到 H1.5 的持久 APK 安装。

## 证据

- [preflight manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-4-preflight.json)
- [device harness](../../tools/h1_4_shadow_device.sh)
- [SSH runner](../../tools/h1_4_run.py)
- [compatibility contract](../../docs/contracts/config-change-dispatch.md)
