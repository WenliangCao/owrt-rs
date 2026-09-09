# R77：P6 —— netifd-rs 的 wireless 半边 + 设备接管准备

> 2026-09-09。候选 netifd-rs md5 `ebee54cb112e96678c6df01433659ffc`（HEAD 树，
> oracle `~/netifd-r59/components/netifd`，cargo 1.98.1，aarch64-musl）。
> **离线部分全部完成；设备接管待授权窗口。**

## 现状纠正

接手时的判断是"wireless 半边没写、network.wireless 不注册"。核对代码后：**已实现**——
`wireless.rs`（1032 行）+ main.rs 的 WRadio 状态机（setup/teardown/pump/reap/notify/command）
+ ubus.rs 注册 `network.wireless`。R59 头注、main.rs 的 --dump-wireless 注释这两处过时文字
（都还写"不注册"）本轮改正。上一模型对 P6 的描述基于旧状态，实际代码已完整。

真正缺的是**离线验证 + 设备接管路径**，本轮补齐。

## 离线门槛（oracle，全部通过）

| 门 | 结果 |
|---|---|
| 148 单测 + 构建 | 全过；shipped bin 的 clippy 残留全是 IFLA_*/sysctl_* 等未用常量/FFI（死代码，非缺陷） |
| netifd_suite（r47–r62，22 例含 r59 投影 + r60 六个 handler 变体） | **22/22** |
| **r63（新）设备真 network+wireless，双侧活体 daemon** | **identical**：1881 ubus 行 + 50 kernel 行逐字节相同 |
| r63 红证（候选换 /bin/false） | **正确判红**：rs 侧不建 br-lan、lan2/3/4 裸露、静态路由缺失 |
| 无线失败路径一致性 | 两侧都落 `up=false pending=false retry_setup_failed=true`（无 phy 的一致失败） |

r63 是本轮新增的差分：r49 只证合成配置的 daemon 等价，r59/r60 只证投影与 handler 协议在 fixture 上；
**没有一个跑过这台机器自己的配置**。r63 把设备的 `/etc/config/network`+`/etc/config/wireless`
（含 PSK，故作参数不进仓库）在精确 rootfs 沙箱里对两个活体 daemon 各跑一遍，桥口作 dummy netdev，
真 mac80211.sh 在场。掩码只归一化不可构造相等的量（对象 id、统计计数器、内核自生 fe80/ff00 路由顺序、
uptime/retry）；一个"比较了空"的运行会被最短行数门和 wireless-status 探针在场检查挡下。

## 设备接管路径（tools/p6_switch.sh）

netifd 是唯一失败即致设备失联的 daemon，故切换脚本比 P4/P5 多一层**canary 自动回退**：
- `stage`：-V 惰性身份探针过后，替换 /sbin/netifd（overlay），并装 `S99p6-canary` rc 脚本。
- canary：启动 480 秒后若无 `confirm` 且原件还在，`mv` 回 C netifd 并重启——健康启动 ~3 分钟可达
  （R74–R76），够时间 confirm；网络起不来则 ~11 分钟自愈，不必碰按钮。
- `confirm`：拆 canary，netifd-rs 长驻。`undo`：恢复 C + 拆 canary。
- failsafe（mesh 键 + lan4）始终走 /rom 原件兜底。

## 待授权窗口执行

1. 基线：ubus 对象集、interface dump、wireless status、iwinfo 客户端数。
2. `p6_switch.sh stage`，重启。
3. 回来后核 wireless **真起来**（iwinfo 两频 AP、客户端能关联）——这是 sandbox 证不了的唯一一件事；
   核 interface/route 与基线一致。**480 秒内** `confirm`。
4. 观察 ~3 分钟：radio 不 crash-loop、客户端保持。
5. 决定长驻或 `undo`。

窗口没打开前，离线侧无可做。设备控制面接管 netifd 后，C 控制面清零，全项目全 Rust。
