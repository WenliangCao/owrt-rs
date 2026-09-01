# H1 物理设备准入与 canary runbook

> 状态：H1.1a 只读准入通过；H1.1b 及后续阶段未授权
> 适用范围：`xiaomi,mi-router-ax3000t` stock layout，OpenWrt 25.12.5
> 不适用：`xiaomi,mi-router-ax3000t-ubootmod`、任何 `.itb`

## 1. 本轮结论

H1 不是“把 APK 装上试试”，而是一组互不继承授权的 gate。H1.1a 已用 11 条只读命令完成
身份、存储、空间和工具观察；没有写入、上传、安装、重启或 mount。对本项目的 R05 canary，
不需要也不允许刷 firmware；候选默认禁用，最终切换是 RAM 中的 bind mount，重启即失。

```text
H1.0 离线准入设计（已完成）
  → H1.1a 只读身份/存储元数据（已完成）
  → H1.1b 白名单 boot flags
  → H1.2 私有备份验收
  → H1.3 恢复演练
  → H1.4 tmpfs shadow
  → H1.5 默认禁用 APK 安装
  → H1.6 短时 bind-mount canary
```

每一箭头都要：上一 gate 通过、报告已审查、用户对下一阶段作出新的明确授权。授权不能从
“继续”外推到多个阶段；没有授权时 gate 必须保持 false。

## 2. 固定身份和禁止项

唯一目标：

| 项目 | 值 |
|---|---|
| board | `xiaomi,mi-router-ax3000t` |
| layout | stock，`ubi_kernel` + `ubi` |
| release | OpenWrt `25.12.5` / `r33051-f5dae5ece4` |
| target / kernel | `mediatek/filogic` / `6.12.94` |
| sysupgrade | `openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin` |
| sysupgrade SHA-256 | `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` |
| original dispatcher SHA-256 | `f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15` |

全 H1 永久禁止：

- `ubootmod` `.itb`、OpenWrt U-Boot conversion、`kmod-mtd-rw`；
- `xiaomi_initial_setup`、`sysupgrade`、`mtd write/erase`、`ubiformat`、`ubiupdatevol`；
- 写 BL2、FIP、Nvram、Bdata、Factory、`ubi_kernel`、`ubi` 或 boot flags；
- factory reset、切换 boot slot、擦 overlay；
- 首次 canary 接管 WAN、LAN 管理路径、默认路由、Wi-Fi、firewall 或任何其他职责。

固件写入只能成为另一个明确命名的阶段；不能用 H1 授权代替。若未来真的讨论刷写，必须
重新验证恢复链和 artifact，当前 runbook 不提供刷写步骤。

## 3. H1.1：只读准入

执行 [H1_READ_ONLY_PLAN.md](H1_READ_ONLY_PLAN.md)。H1.1a 和 H1.1b 分开批准；原始输出留在
私有 evidence。通过条件：

- 实物、运行态、image/source 三方身份闭合；
- 十个 MTD label/size 与 stock DTS 一致；NAND/switch 变体受 25.12 支持；
- UBI/NMBM/overlay 无未解释异常且有足够空间；
- 原 dispatcher hash 正确，无 candidate package 或 mount 遗留；
- H1.1b 只读的 boot flags 能解释当前 stock 双固件 slot 分支，且没有触发写入。

本 gate 失败时设备仍未被修改。不要安装工具来补命令；缺少工具本身就是观察结果。

## 4. H1.2：私有备份验收

H1.2 是新的授权。它允许读取设备专属数据并流式保存到仓库外，不允许写 flash。具体
`/dev/mtdX` 只能由刚观测的 label 动态解析，不能沿用网页、另一台设备或旧 run 的编号。

最低备份集：

- 所有 observed MTD partition 的完整只读 dump，至少特别覆盖 BL2、Nvram、Bdata、Factory、
  FIP、`ubi_kernel`、`ubi`、KF；
- `/etc/config`、Dropbear host keys、已安装 package DB、sysupgrade 配置备份；
- observed `/proc/mtd`、UBI/NMBM 元数据、boot flag 白名单和 exact firmware identity；
- 每个文件的 label、设备节点、observed size、实际 bytes、SHA-256、读取工具/参数和时间。

验收条件：

1. raw 文件从未落入 Git 工作树，也不经聊天传输；
2. 至少两份独立私有副本重新计算 hash 后一致；
3. dump 长度与 observed 逻辑 MTD size 的关系已解释；NMBM/OOB 语义没有被猜测；
4. 设备专属校准/MAC/密钥只来自本机备份，不使用其他 AX3000T 的备份；
5. 恢复映射文档能从 label 追到文件和 hash，但“备份可读”不冒充“恢复已证明”。

exact image inventory 已证明 `/usr/sbin/nanddump` 不存在。H1.0 已从 25.12.5 官方 filogic
feed 的已签名 `packages.adb` 验证 `nand-utils-2.3.0-r1.apk`，在服务器的一次性 root 中不使用
`allow-untrusted` 提取出单一 binary：

```text
nanddump size: 28677 bytes
nanddump SHA-256: 21d7c3daa9e792a9b892af956ce64c59c4588c99eb7084b93ef5ee6f4bd47b92
APK SHA-256: a889a18c410b464dd0ec1538b0595d0566c921a16bd3dbeaf2b7f75a6efbcbca
```

H1.2 如获授权，只把 `nanddump` 放入 `/tmp` 并复算 hash；不安装 APK，也不传输同包中的
`flash_erase`、`nandwrite`、`nandtest` 或 `nandbiterrs`。如果 hash/ABI/依赖不匹配，或还没
冻结 NMBM/OOB 对应的 exact flags，立即停止；不改用未经审查的 `dd`。

## 5. H1.3：恢复演练

恢复能力按故障层分开：

| 层 | 本 canary 的用途 | 证明方式 | 不能证明 |
|---|---|---|---|
| 普通 reboot/power cycle | 清除 reboot-volatile bind mount | 未启用 candidate 时先演练，确认 wired 管理恢复 | kernel/bootloader 损坏恢复 |
| OpenWrt failsafe | 修复 overlay package/config | 有线独立主机进入 failsafe，验证只读 root 和可挂载 overlay；不 reset | broken kernel/UBI/bootloader |
| stock U-Boot + UART/initramfs | 更深层 soft-brick 恢复 | 另行物理授权；只允许 RAM load rehearsal，绝不执行 flash | bootloader 自身损坏 |
| MediaTek UART boot / raw restore | bootloader 损坏 | 仅作为最后恢复设计，当前不演练 | 未经真实恢复验证前不能宣称可用 |

OpenWrt 官方设备页说明：stock bootloader 的 TFTP soft-brick 流程会获取 OEM image 并写入；
因此不能把一次网络连通测试伪装成无写入演练。官方 failsafe 只覆盖配置/overlay 问题，不能
修复 broken kernel。对当前只写 overlay、默认禁用、RAM 切换的 R05 canary，H1.3 的最低
通过线是：独立有线管理、可控供电、未启用 candidate 时的正常 reboot，以及一次不擦除
overlay 的 failsafe 进入/退出。更深恢复保留为禁止升级 blast radius 的边界，不用刷机来
“提前证明”。

恢复演练本身会中断网络并重启，必须预约窗口并得到单独授权。演练期间 WAN 断开，电脑只
通过一根网线直连 LAN；另有独立互联网/通信设备查看资料。

参考资料：

- <https://openwrt.org/toh/xiaomi/ax3000t>
- <https://openwrt.org/docs/guide-user/troubleshooting/failsafe_and_factory_reset>

## 6. H1.4：tmpfs shadow

H1.4 不安装 APK。把 V1 已验证的 candidate binary 临时传到 `/tmp`，先核对
`b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75`，再使用独立
`--root /tmp/<run-id>`：

- 配置副本和 `/var/run/uci` 副本只存在 tmpfs，不离开设备；
- PATH 最前放置 fake `ubus`，只记录参数并返回，绝不调用真实 `service.event`；
- 复制原实现生成的当前 baseline，第一次 candidate run 必须零 event 且 baseline
  byte-identical；
- 只在 shadow tree 新建 synthetic package，第二次必须只产生一个 synthetic event；
- 删除整个 tmpfs run 目录后确认设备配置、baseline、mount 和进程集合未变。

任何真实 ubus delivery、真实 `/var/run/config.md5` 变化、配置 hash 变化或网络状态变化都使
gate 失败。H1.4 的具体 harness 要在 H1.1 的 BusyBox/工具结果后冻结，不能现在假定设备命令
能力。

## 7. H1.5：默认禁用安装

安装前再次核对 APK：

```text
owrt-reload-config-0.1.0-r1.apk
SHA-256 02d0c977d68192c28d0ef537a704435d9814fb8e04763cd67d73e00e41e5d9b1
size 184099 bytes
arch aarch64_cortex-a53
```

安装必须 `--no-network`，并在复制后、安装前于设备上复算 hash。安装窗口内不同时做 package
index update 或其他变更。通过条件：

- lifecycle script 返回成功且 switch status 为 disabled（约定退出码 3）；
- `/sbin/reload_config` hash 仍是 original；
- `/proc/self/mountinfo` 没有 `/sbin/reload_config` bind mount；
- `/etc/config`、网络/无线/firewall 状态和真实 baseline 均未改变；
- 卸载命令与私有备份已经预置但不因“以防万一”提前执行。

本阶段只允许 APK 安装产生的 overlay/package DB 写入。不能 enable candidate。

## 8. H1.6：短时 canary

H1.6 是独立授权，且必须由用户在路由器旁操作。第一次窗口：

- WAN 断开；一台有线管理电脑直连 LAN，另有独立联网/通信设备；
- 先记录 original hash、mount、baseline、核心网络可达性和恢复步骤；
- enable 只建立 `/usr/sbin/reload_config_rs` 到 `/sbin/reload_config` 的 bind mount；
- 只执行一次“配置未变化”的 dispatcher 调用；event 集合必须为空，不创建或修改任何 UCI
  package；synthetic event 已在 H1.4 的 tmpfs + fake ubus 中覆盖；
- 观察 candidate JSONL、零 event、服务存活和 baseline byte-equivalence；
- 最长五分钟，无论成功失败都先 disable，再核对 original hash 和 mount 消失。

第一次 canary 不把 candidate 留到无人值守状态，也不跨 reboot。只有一次完整窗口成功且审查
通过，后续才可另建一次授权，讨论 synthetic event delivery、扩大时间或真实 R05 ownership。

## 9. 通用停止与回退

立即停止并执行当前阶段预先批准的最小回退，如果出现：

- 任何身份/hash/profile/layout 不匹配；
- SSH 或有线管理抖动，WAN/LAN/Wi-Fi/firewall/default route 变化；
- 未计划 reboot、kernel warning、NMBM/UBI/ECC 错误；
- candidate 投递了批准集合外 event，或 baseline 不是 byte-equivalent；
- switch disable 非零、original hash 未恢复、mount 仍存在；
- 操作者不能在设备旁继续，或恢复设备/独立通信不可用。

回退层级严格递增：

1. H1.4：终止进程并删除 tmpfs shadow；
2. H1.5：保持 disabled；必要时按预批准命令卸载 package；
3. H1.6：`owrt-reload-config-switch disable` 并验证 original；
4. 无法 SSH 时才用已演练的 power cycle；bind mount 随 reboot 消失；
5. 配置/overlay 锁死才进入已演练的 failsafe；
6. 不因 canary 失败自动进入 TFTP、UART、sysupgrade 或 raw flash。

## 10. 操作记录

每个阶段的 run 记录必须包含：授权范围、操作者、开始/结束 UTC、artifact hash、设备身份、
逐命令状态、停止条件、回退结果和脱敏说明。报告要明确写 `device_writes`，并区分 tmpfs、
overlay、service state、reboot 和 flash；不能用一个 `true/false` 掩盖写入层级。
