# AX3000T stock / OpenWrt 25.12.5：风险登记

> I0.8 状态：完成
> 日期：2026-08-31

七条风险，全部有 DEP/SRC/RUN 证据支撑，不含推测项。机器记录见
[replacement-boundary.json](../../manifests/ax3000t-stock-openwrt-25.12.5/replacement-boundary.json)
的 `risks`。

## RK-01 配置变更投递失败是静默的

**影响**：R05、R04

`/sbin/reload_config` 漏发 `config.change` 事件时不报错，目标服务继续用旧配置运行，
外部没有任何信号。变更检测的粒度是整个 config 文件，基线存在 tmpfs 中且重启即丢失。

**缓解**：任何替换实现必须**先**让"变更已送达"可观测，再改变检测方式。
这是 R05 进入替换范围的前置条件，不是可选优化。

**证据**：`/sbin/reload_config` 全文（17 行）；whole-file md5 粒度；Q12 观察到的基线。

## RK-02 声明的隔离不等于生效的隔离

**影响**：R01、R08

`/etc/init.d/wpad` 写了 `procd_add_jail hostapd`，但设备上 hostapd 与 wpa_supplicant
工作进程**没有任何独立 namespace**。原因在 `_procd_add_jail`：只传名字、没有 flag、
没有 mount 时，ujail 没有可隔离的内容。它们实际获得的只是 user/group + capabilities +
`no_new_privs`。对照之下 ntpd 与 dnsmasq 都拿到了独立的 ipc/mnt/pid namespace。

**缓解**：在任何设计中把"声明"与"实测 namespace 集合"作为两个独立事实处理。
假设 wpad 运行在 namespace 内的替换设计会在本设备上失配。

**证据**：Q11 namespace inode；`/lib/functions/procd.sh` 的 `_procd_add_jail`。

## RK-03 ACL 会授权不存在的对象

**影响**：R12、R13

两层 ACL 都授权了本部署中没有提供方的对象：ubusd 层的 `udebug`
（`wpad_acl.json` 授权访问并订阅，实测 `Not found`），rpcd 层的 `dsl` 与 `fingerprint`。

**缓解**：**永远不要把 ACL 当作接口清单。** 它是意图声明。

**证据**：Q10 `udebug` Not found；rpcd ACL 覆盖检查（18 个目标中 2 个无提供方）。

## RK-04 设备携带更早工具留下的配置历史

**影响**：R04、R09、R10

`/var/run/config.md5` 跟踪了 `dhcp.bak-codex-*`、`network.bak-codex-*`、
`wireless.bak-codex-*` 以及 `dnsproxy` 残留，时间戳早于当前固件，经 sysupgrade
配置保留延续至今。`/etc/config/dhcp` 与 `/etc/config/firewall` 都已偏离镜像。

**缓解**：**不要把本设备的配置当作出厂配置。** 任何 oracle 用法必须以设备当前配置
为输入。相关审查见 [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md) OQ-07。

**证据**：Q12 `config.md5` 跟踪列表；Q13 配置哈希比对（6 个中 4 个已改）。

## RK-05 静态目录的完整性只针对已观察的那一种配置

**影响**：R07、R08、R15

ubus 目录与运行态双向闭合，但那是**针对一种配置**验证的。配置一个 STA 接口会产生
`wpa_supplicant.<ifname>` 实例（本设备为空），设置 `log_file` 会让 `log` 从 1 个实例
变成 2 个（声明 3 个）。

**缓解**：任何完整性主张必须同时声明其配置范围。

**证据**：`wpa_supplicant.<ifname>` 规则无实例；`log` 声明 3 实际 1。

## RK-06 远程代码执行路径是设计内可达的

**影响**：R13、R14

`rc.init` 与 `file.exec` 执行任意程序，唯一约束是 rpcd 会话 ACL；而镜像自带的
`login` 段读写范围都是 `*`，即认证成功后不再受 ACL 组限制。uhttpd 以 root 运行，
在 v4/v6 的 :80 与 :443 上监听，`no_ubusauth` 未设置（默认要求鉴权）。

**缓解**：任何包装层必须**保持或收紧** ACL 判定，绝不放宽。这是 R13 被分类为
`Rust 接入或包装`而非`优先用 Rust 替换`的直接原因。

**证据**：Q05 方法签名；Q13 rpcd login 范围与 uhttpd 监听配置。

## RK-07 启动证据不被保留

**影响**：R03、R15

默认日志缓冲区容量不足以保留一次启动记录（实测覆盖约 93 分钟）。这意味着**启动顺序
的回归在事后无法被发现**。

**缓解**：任何涉及启动路径的工作都需要事先安排串口控制台或加大缓冲区。

**证据**：Q02 缓冲区覆盖范围；`log_buffer_size` 默认 64。

## 风险与分类的对应

| 风险 | 直接影响的分类决定 |
|---|---|
| RK-01 | R05 进入替换范围的前置条件 |
| RK-02 | R08 列入禁止触碰的支撑理由之一 |
| RK-03 | R12、R13 的接口边界定义方式 |
| RK-04 | 本设备作为 C1 oracle 的使用前提 |
| RK-05 | 所有完整性主张的范围声明 |
| RK-06 | R13 选择包装而非替换的直接原因 |
| RK-07 | R15 选择包装而非替换的直接原因 |
