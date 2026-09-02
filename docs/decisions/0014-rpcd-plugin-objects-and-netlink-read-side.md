# 0014：rpcd 余下插件对象迁入 rpcd-rs（rpc-sys、network.rrdns、luci-rpc、iwinfo），原 rpcd 进程退出

> 日期：2026-09-02。阶段 8（计划 §11.3）。状态：采纳，分两步落地。

## 决定

1. **8a**：`rpc-sys`（sys.c）与 `network.rrdns`（luci `rpcd-mod-rrdns`）先迁入 rpcd-rs，沙箱可完整差分
   （apk 数据库、`/etc/apk/world`、`/bin/passwd`、假 PTR 服务器）。原 rpcd 继续以插件裁剪形态运行，只剩
   `luci-rpc` 与 `iwinfo`。
2. **8b**：libiwinfo 的 nl80211 后端（`iwinfo_nl80211.c` @ f5dd57a8，设备安装版本）以纯 Rust 复刻为
   `components/rpcd/src/iwinfo/`（原生 netlink/genetlink，不引入 crate），在其上实现 `iwinfo` 对象与
   `luci-rpc`（getNetworkDevices/getWirelessDevices/getHostHints/getDUIDHints/getBoardJSON/getDHCPLeases）。
   完成后原 rpcd 进程不再启动（`owrt-rpcd-switch enable` 只启 rpcd-rs），插件目录 bind mount 不再需要。
3. rtnetlink（link/addr/neigh dump）与 sysfs 读取按 `luci-rpc.c` 与 musl `getifaddrs` 的顺序语义复刻，
   是"网络状态读侧"的第一份强类型模型。

## 为什么

- 阶段 7 后 C rpcd 只为四个对象存在；它们是 LuCI 概览/无线/DHCP 页面的数据源，也是计划 §11.3 的目标。
- nl80211 没有沙箱 oracle（oracle 主机无无线硬件），只能在设备上做只读差分（`iwinfo`/`luci-rpc`
  在原 rpcd 与 rpcd-rs 下各答一次，遮罩瞬时字段），因此把它与可沙箱验证的 8a 分开，避免一次窗口
  承担过多未验证面。
- 不引入 netlink crate：协议面小（RTM_GETLINK/GETADDR/GETNEIGH、GENL_ID_CTRL、约 40 个 NL80211 命令/属性），
  且需要与内核头逐位对应；crate 的抽象会遮住这些对应关系。

## 代价与退路

- 8b 的 nl80211 代码量约 3000 行，属本轮最大的单块移植；先由差分只读验证，`scan` 在设备上只跑一次。
- `owrt-rpcd-switch disable` 仍回到原 rpcd（全部对象）；8a 期间的混合形态与阶段 7 相同。
- `rpc-sys` 的 `upgrade_start`/`factory`/`reboot` 按原样移植但不在任何验证中触发（决策 0006 禁止）。
