# 第二轮收官（阶段 6–9，2026-09-02）

> 计划 §11（v5）。本轮四个阶段全部有结论：三个上线，一个经前置检验判定不做。原始输出在
> `private/stage6/`、`private/stage7/`、`private/stage8/`、`private/stage9/`（不入库）。

## 1. 结果一览

| 阶段 | 结论 | 证据 |
|---|---|---|
| §11.0 自检 | 20 处行为差异修复并重验，9 处记录待收口 | [AUDIT_ROUND1](AUDIT_ROUND1.md) |
| 6：uci 库 + `/sbin/uci` | uci-rs 接管 `/sbin/uci`（bind mount，S00）；上游 112/112，rootfs 差分 175/175，设备门禁相同 | [R16_UCI](R16_UCI.md)、决策 0012、合同 C6 |
| 7：rpcd 核心对象 | rpcd-rs 接管 `session`/`uci`/`rc`（`uci` 对象基于阶段 6 库）；沙箱 272/272，设备门禁 51 项相同 | [R17_RPCD_CORE](R17_RPCD_CORE.md)、决策 0013、合同 C7 |
| 8：rpcd 余下对象 + netlink 读侧 | rpcd-rs 接管 `rpc-sys`/`network.rrdns`/`luci-rpc`/`iwinfo`（纯 Rust rtnetlink 与 libiwinfo nl80211 复刻）；沙箱 74/74 + 11/11，设备门禁 49 项相同；**原 rpcd 进程停止，S12 移除** | [R18_RPCD_PLUGINS](R18_RPCD_PLUGINS.md)、决策 0014、合同 C8 |
| 9：ubusd（有条件） | **不执行**：ubusd 重启后 odhcpd 永不恢复、dnsmasq 空闲不恢复、netifd 丢 `network.wireless`，补救触及禁区 | [决策 0015](../../docs/decisions/0015-ubusd-replacement-not-executed.md)、`tools/r22_ubus_clients_reconnect.sh` |
| §11.6 收口 | rpcd 与 fw4 的内嵌 UCI 解析器均改为 `components/uci`（fw4 r2 上线，门禁 203 行相同）；logd-rs 补 ubus 重连（沙箱验证，设备仍为 r1） | [R09 补记](R09_FW4.md)、`tools/r21_logd_reconnect_check.sh` |

## 2. 设备现状（2026-09-02 20:40 UTC）

| 组件 | 实现 | 包 | 接管方式 | 开机 |
|---|---|---|---|---|
| `/sbin/uci` | uci-rs | owrt-uci 0.1.0-r2 | bind mount | S00 |
| `/sbin/reload_config` | reload-config-rs | owrt-reload-config 0.2.0-r1 | bind mount | on |
| logd | logd-rs | owrt-logd 0.1.0-r1 | 服务替换 | on |
| uhttpd | httpd-rs | owrt-httpd 0.1.1-r1 | 服务替换 | on |
| `/sbin/fw4` | fw4-rs | owrt-fw4 0.1.0-r2 | bind mount | S18 |
| rpcd（9 个 ubus 对象） | rpcd-rs | owrt-rpcd 0.1.0-r4 | 唯一 rpcd，原 rpcd 已 disable | S11 |

仍为 C：procd、ubusd、netifd、hostapd/wpa_supplicant、dnsmasq、odhcpd、odhcp6c、dropbear、内核与
驱动；`libuci.so` 及其库使用者（netifd、odhcpd、ucode、libiwinfo、ujail）。

## 3. 代码规模（本轮新增，零外部 crate）

`components/uci` 约 2.3k 行；`components/rpcd` 新增约 9.5k 行（其中 nl80211 后端 5.8k、luci-rpc/rtnetlink 1.1k、
session/uci/rc 1.7k、rpc-sys/rrdns 0.6k）；harness：r16（175 步）、r17（272）、r18（74）、r19（11 对）、
r21、r22；设备脚本 r16/r17/r20/r09b。

## 4. 未验证 / 待办

- **开机路径**：阶段 6–8 与 fw4 r2 的 boot-enable 均未经重启验证（决策 0006 不重启）；下次自然重启后按
  `owrt-switch status` 与各 `probe` 步骤核对。S11 `owrt-rpcd` 现在是系统唯一 rpcd，若它开机失败，LuCI 不可用
  但 SSH 不受影响，`owrt-rpcd-switch disable` 可恢复原 rpcd。
- logd-rs 的 ubus 重连已在沙箱验证但设备仍运行 r1；升级需一次 logd 重启（丢失内存日志环），留待下一次窗口。
- `rpc-sys` 的 upgrade_start/factory/reboot、`uci apply` 的真实 procd 事件路径、LuCI 用用户口令登录：未在任何
  验证中触发。
- fw4 r2 的 enable 步骤沿用阶段 4 校验，经挂载做了一次 `fw4 reload`（规则集与状态文件哈希前后不变）；报告已记。
- 沙箱历史缺陷：2026-09-02 晚之前 oracle 上的 rootfs 副本 acl.d 属主非 root，ubusd 未加载 ACL；发现后所有
  harness 改为 chown 并重跑（结果不变）。
- 阶段 9 的解除条件见决策 0015。

## 5. 与迁移规则相关的新经验

- 只读对象若读的是主机实时状态，用"同一沙箱、测试对象名并排"的差分（r19，`OWRT_RPCD_LUCI_RPC_NAME`）
  代替双沙箱，瞬时值只需遮罩计数器。
- 无法在 oracle 上复现的硬件面（nl80211）只能靠设备只读门禁：原实现与候选对同一硬件各答一次，遮罩瞬时字段。
- C 侧"忽略返回值"的地方（rpcd `main.c` 对核心对象注册）是可用的切换缝隙，但也意味着两份实现共存时错误静默，
  门禁必须比对对象归属而非只比对答案。
