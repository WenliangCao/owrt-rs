# AX3000T stock / OpenWrt 25.12.5：H1.4 tmpfs shadow preflight

> 日期：2026-09-01
> 状态：`corrected_ready_for_authorized_device_run`
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
`c03-new-config-is-silent` 冲突。实机 probe 又证明不能假设共享 baseline 当前一定与配置同步。
最终序列改成四个独立步骤：

1. 对复制的固定当前 baseline 运行：恰好观察已发现的 `network` drift，只推进 shadow baseline；
2. 不改变 shadow tree 再运行：零事件，baseline 字节不变；
3. 只在 shadow tree 新建 `h1_shadow_probe`：仍然零事件，但 shadow baseline 前进；
4. 再修改该 synthetic package：恰好一个 `h1_shadow_probe` fake-ubus 事件。

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
candidate、harness 和 runner 的 hash，检查四步合同序列、授权边界、timeout、cleanup、所有
关闭的 device-effect gate 和本报告文字。八类负向篡改均被拒绝：持久写入、伪造 device-run
完成、扩大 cleanup 到整个 `/tmp`、把 creation 改成 event、继承 H1.5 授权、package install、
router reboot，以及删除停止条件。

首次 device-run 尝试在 identity gate 通过后由 transfer gate 正确阻断：本机 OpenSSH `scp`
默认使用 SFTP，而目标 OpenWrt 没有 `/usr/libexec/sftp-server`。runner 随后完成固定路径 emergency
cleanup 和 post-cleanup identity 验证。只读确认目标存在 `/usr/bin/scp` 后，runner 固定使用
OpenSSH `scp -O` 的 legacy SCP protocol；没有安装 SFTP server，也没有扩大设备状态。

第二次尝试完成 legacy transfer 后，harness 在输出合同 trace 前以 1 fail-closed；cleanup 与
post-cleanup identity 再次通过。原 harness 只有退出码，不能定位失败断言。修正后的 trap
只额外输出预先枚举的 `failed_step`（不输出命令、路径内容或配置），使后续失败可诊断而不
放宽动作或读取配置内容。

第三次尝试用该诊断把失败收敛到 `run1-shared-baseline`，但该标签仍同时覆盖 candidate 执行、
零 fake event、两个 JSONL 断言和 baseline byte identity。最终 harness 把这些断言继续拆为固定
子步骤；失败输出仍只有枚举标签，所有清理/身份不变量继续通过。

第四次尝试证明 candidate 本身在实机可以执行，失败点是 run1 的“应为零 fake event”断言。
这意味着复制的当前 baseline 与当前规范化配置可能存在 drift，不能靠放宽断言掩盖。失败
trap 因而增加既有 candidate JSONL 和 fake-ubus argv 的诊断输出；两者只含 package 名称、
状态和计数，不含配置内容。

第五次诊断固定了实际差异：19 个 baseline entry 中只有 `network` 被报告 changed；七个含点
备份文件仍按合同产生空规范化条目。fake ubus 收到且只收到一个 `network` call，真实 ubus
没有被调用，真实 baseline hash 仍为
`b77e0e99672ee504d1ee1183f14b8ba8cfe92f6c546aa585f7efc784d2b0c163`。最终 harness 固定该
baseline 身份，把“观察共享 drift”和“吸收后稳态零事件”拆开，避免把真实 drift 误报为候选
不兼容，也不修改实机 baseline 来制造通过。

preflight manifest 中的 `h1_4_device_run=false` 记录的是执行前边界，不表示继续逃避实体设备。
本轮授权随后已被 H1.4 device run 消耗，最终结果见 `H1_4_SHADOW.md`；该授权没有延伸到
H1.5 的持久 APK 安装，授权不延伸到 H1.5。

## 证据

- [preflight manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-4-preflight.json)
- [device harness](../../tools/h1_4_shadow_device.sh)
- [SSH runner](../../tools/h1_4_run.py)
- [compatibility contract](../../docs/contracts/config-change-dispatch.md)
