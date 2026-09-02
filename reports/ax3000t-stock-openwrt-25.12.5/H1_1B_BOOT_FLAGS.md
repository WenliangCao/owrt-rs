# AX3000T stock / OpenWrt 25.12.5：H1.1b boot flag 报告

> 阶段状态：带一个受限开放问题通过
> 执行日期：2026-09-01
> 命令结果：H1-RO-11 成功，stderr 为空
> 设备写入：无

## 1. 判定

H1.1b 通过。冻结命令只调用 `fw_printenv` 读取八个白名单变量；八个变量全部存在，没有读取
完整 environment 或白名单外变量。当前 active rootfs 分支与 H1.1a 的 kernel cmdline
`firmware=0` 一致；exact OpenWrt `bootcount` 会命中 early-exit 判断，不会在正常启动时执行
其 `fw_setenv` reset block。

本阶段没有调用 `fw_setenv`，没有读取 raw MTD payload，也没有上传、安装、mount、改变
service/network、重启或刷写。H1.1b 的单次授权已经消费完毕。

## 2. 脱敏观察

| 观察 | 结论 |
|---|---|
| 白名单完整性 | 8/8 存在，顺序与冻结清单一致 |
| 白名单外变量 | 0 |
| `boot_wait` | enabled |
| UART flag | enabled |
| active rootfs | slot 0；与 cmdline 一致 |
| last-success / boot-success | asserted |
| OTA reboot | clear |
| system-2 failure counter | 命中 exact-source early-exit sentinel |
| system-1 failure counter | numeric，但不属于 exact OpenWrt 会写入的 0/8 集合 |

表格只保留存在性、定义域和分支推断。原始值、完整 `fw_printenv` 输出和连接信息均保留在
Git 外私有 evidence。

## 3. Exact-source caller 边界

固定 buildroot commit：`f0a60eee2fe051741c643ea6118718aae1ef17fb`。

| source | SHA-256 | 相关行为 |
|---|---|---|
| `target/linux/mediatek/filogic/base-files/etc/init.d/bootcount` | `fe6e18a37531de608315c592b39f36da1a9c68e9f108aa5f5af152a42e9b27e3` | 只读取 system-2 counter；命中 sentinel 时返回，否则把六个 flag reset 为 0/1 |
| `target/linux/mediatek/filogic/base-files/lib/upgrade/platform.sh` | `72c75ab0ee140e4f543fa0c30becb265f529ec87657961803f981bbf96f3dc7f` | 仅在 initramfs initial-setup 路径把两个 failure counter 初始化为 sentinel |

对 mediatek/filogic exact source 的 caller 全量检索结果：OpenWrt 读取 system-2 counter，写入
system-1/system-2 counter；没有 OpenWrt 代码读取 system-1 counter。因此 system-1 当前值不能
用 OpenWrt source 解释成故障次数、slot 健康度或硬件版本，也不应被“修正”。

## 4. H1-OQ-01

`H1-OQ-01`：system-1 counter 是数字，但超出 exact OpenWrt source 会写入的 0/8 集合。
bootloader 是否拥有该值、何时转换以及具体语义尚无匹配源码或差分运行证据。

范围判定：

- 继续阻断 boot-flag mutation、slot switching 和 firmware upgrade；这些操作本来就不属于 H1。
- 不阻断 H1.2 只读私有备份准备，因为 H1.2 应原样保存环境和分区，而不是解释或修改该值。
- H1.3 若获单独授权，正常 reboot 前后应再次只读比较该 counter，把转换行为作为观察项；
  不以当前值预测 bootloader 行为。

H1.1b 能通过是因为本阶段要裁决的 OpenWrt caller 分支已经闭合，而未知项明确限制在未授权的
bootloader mutation/upgrade 范围内。

## 5. Gate

机器 gate 验证：

- H1.1a manifest、layout gate、source baseline 和 authorization hash；
- H1-RO-11 唯一命令及 SHA-256；
- 单次 collector ID、退出码、stdout/stderr；
- 八个变量的精确白名单、顺序、存在性和允许的派生定义域；
- active rootfs 与 H1.1a cmdline 一致；
- raw 值不会写入脱敏 manifest。

负向测试分别把 authorization 伪造成允许 device write、在输出中加入白名单外变量、改变
early-exit sentinel、篡改 source baseline；四次都被 gate fail-closed 拒绝。

Git 外的本地和服务器副本共含 5 个文件；相对路径 + SHA-256 排序清单在两端得到相同
aggregate：`ea9f9c352e6aae1fbf78dc998c637dded78778611f752891727701504b8ceee7`。这只证明 H1.1b
私有观察副本一致，不冒充 H1.2 的设备分区备份。

机器记录：

- [H1.1b observations](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-1b-observations.json)
- [H1.1b authorization](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-1b-authorization.json)
- [H1.1b gate](../../archive/stage-gates/h1_1b_review.py)
- [冻结命令](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-read-only-commands.json)
