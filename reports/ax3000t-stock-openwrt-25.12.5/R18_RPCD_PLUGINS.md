# R18：rpcd 余下插件对象由 rpcd-rs 接管，原 rpcd 进程停止（阶段 8）

> 日期：2026-09-02。决策 [0014](../../docs/decisions/0014-rpcd-plugin-objects-and-netlink-read-side.md)，合同
> [C8](../../docs/contracts/rpcd-plugins-stage8.md)。代码 `components/rpcd`（`rpcsys.rs`、`rrdns.rs`、`rtnl.rs`、
> `lucirpc.rs`、`iwinfo/`、`iwinfoobj.rs`）。包 `owrt-rpcd 0.1.0-r4`。原始输出在 `private/stage8/`。

## 1. 结果

| 项 | 结果 |
|---|---|
| 8a 沙箱差分 `tools/r18_rpcd_plugins_check.py`（精确 rootfs 双沙箱 + 主机假 PTR 服务器） | 74/74 相同：`rpc-sys` packagelist（world 过滤、ABI 后缀剥离、畸形 world/db、缺失文件的 errno 映射）、upgrade_test/upgrade_clean、password_set 错误路径（缺参、类型、无 `/bin/passwd`、不可执行）；`network.rrdns` 正常/多地址/重复/limit/静默地址超时/非法参数/默认 nameserver/无 resolv.conf；`iwinfo` 与 `getWirelessDevices` 在无无线硬件下的错误路径 |
| 8a 并排差分 `tools/r19_lucirpc_check.py`（同一沙箱，rpcd-rs 以测试名 `luci-rpc-rs` 与 C 插件并排） | 11/11 相同：getNetworkDevices（主机全部接口）、getHostHints（邻居表 + 合成租约/ethers/uci host + PTR 名字）、getDUIDHints、getBoardJSON、getDHCPLeases（族过滤与错误码）；dnsmasq 与 odhcpd 两种租约格式各 10 行畸形/边界样本 |
| 回归 | r13 63/63、r17 272/272 在同一二进制上不变；apk 发货二进制 r17 272/272、r18 74/74、r19 11/11 |
| 设备门禁（只读，49 项，原 rpcd 与 rpcd-rs 各一次，遮罩信号/计数器/expires） | `GATE_IDENTICAL`：9 个对象签名、`iwinfo` devices/info（两个 radio：phy、ssid、bssid、country、mode、channel、center_chan、frequency、encryption、htmodes/hwmodes、hardware id/name）/freqlist/txpowerlist/countrylist（16,510 字节）/assoclist（已连接站点，rate 表结构）/survey/phyname；`luci-rpc` 全部 6 个方法（真实 radio 状态转发 + iwinfo 子表、真实 DHCP/DHCPv6 租约、56 个主机提示、DUID）；`rpc-sys` packagelist 两种；`network.rrdns` 反查网关得 `OpenWrt.lan`；核心对象抽样 |
| 设备接管 | `owrt-rpcd-switch enable`：停原 rpcd → 起 rpcd-rs（9/9 对象）→ 校验 luci/session/luci-rpc/iwinfo → `/etc/init.d/rpcd disable`（S12 链接移除）；`boot-enable on`；`owrt-switch status` 六组件 enabled/on；系统上不再有 C rpcd 进程，`/usr/lib/rpcd` 不再被挂载覆盖 |
| `iwinfo scan`（每 radio 一次，只记录） | 两个 radio 均返回邻居 AP 列表（ssid/bssid/band/channel/signal/quality/ht_operation/vht_operation/encryption） |
| LuCI 路径（httpd-rs `/ubus` JSON-RPC） | 默认会话对 `luci-rpc getBoardJSON`/`iwinfo devices` 按 ACL 拒绝（-32002）、`session access iwinfo/info` → false、`luci getFeatures` 正常；rpcd-rs 单线程常驻、RSS 1.5 MB |
| 探针窗口（20:25:19、20:26:40、20:27:56 UTC，3 次） | rpcd-rs pid 15345 不变、无 C rpcd 进程、`objects=9/9`、`recent_rpcd_log=0`、快速探针答案不变 |

## 2. 结构

- `rpcsys.rs`（309 行）：sys.c 逐函数移植；`upgrade_test` 复用 `file.rs` 抽出的 `run_command`（rpc_exec 默认回调语义）。
- `rrdns.rs`（348 行）：res_mkquery/ns_parserr 手写（PTR 查询、名字解压、`ns_name_ntop` 转义）；一条 UDP 连接，
  `limit` 在途、每应答补发一个；进程内 `resolve()` 供 getHostHints 使用（C 走 ubus 自调）。
- `rtnl.rs`（313 行）：RTM_GETLINK/GETADDR/GETNEIGH dump，按 musl `getifaddrs()` 的组装顺序（先全部 AF_PACKET，
  再地址）给 luci-rpc 用。
- `lucirpc.rs`（961 行）：luci-rpc.c 移植（sysfs 读取 `readstr` 127 字节语义、租约解析、主机提示五源合并
  与优先级、DUID、board、getWirelessDevices 原样转发 `network.wireless status` 字段 + iwinfo 子表）。
- `iwinfo/`（5823 行，其中约 480 行测试）：libiwinfo f5dd57a8 的 nl80211 后端全量复刻——genetlink 传输
  （`netlink.rs`）、`iwinfo_nl80211.c` 全部 ops（`nl80211.rs`，含 hostapd/wpa_supplicant 控制套接字回退、
  scan 重试、频率/信道换算、IE 解析）、名字表与 ISO3166（`tables.rs`，与 C 逐项相同）、`iwinfo_utils.c`
  （devices.txt、mtd、RSN 解析、uci radio 查找）。8 处 `DEVIATION` 注释全部是 C 越界/空指针读的有界化。
- `iwinfoobj.rs`（595 行）：rpcd iwinfo.c 的 9 个方法与 luci-rpc.c 的 `rpc_luci_get_iwinfo`。
- 仍然零外部 crate；rpcd-rs 二进制 780,763 字节。

## 3. 探针窗口

`private/stage8/device/r20-probe-window.txt`：enable 于 20:24:46 UTC 完成；3 次 `state`（20:25:19、20:26:40、20:27:56 UTC）
rpcd-rs pid 15345 不变、`rpcd_pid` 为空、`objects=9/9`、六组件 enabled/on、`recent_rpcd_log=0`、
快速探针（ssid、2 个无线接口、56 个主机提示、session access、uci get）答案不变。

## 4. 有意偏离 / 未覆盖

- 无线 oracle 只有设备（oracle 主机无 nl80211）：门禁比较的是原 rpcd 与 rpcd-rs 对同一硬件的答案，瞬时值（信号、
  噪声、速率、计数器、survey 时间）遮罩后逐字节相同；`scan` 结果依环境变化，只记录。
- `iwinfo` 后端 8 处有界化偏离（见代码 `DEVIATION`）：C 在畸形 IE/缺失属性时越界或空指针，Rust 读为 0/跳过。
- `network.rrdns` 只接受数字 `server`（C `usock()` 也会解析主机名）；设备与 LuCI 只传 IP。
- `rpc-sys` 的 `upgrade_start`/`factory`/`reboot` 按原样移植，从未在任何验证中调用。
- ubus 连接断开时 rpcd-rs 退出（退出码 1）由 procd 重启，与 C rpcd 的 `uloop_end` 行为一致；会话随之丢失（C 同）。
- 开机路径（S11 rpcd-rs、S12 已移除）未验证（不重启）；下次自然重启时 `owrt-rpcd` init 会在 boot-enable 下自启。
- fw4 内嵌只读 UCI 解析器的合并（§11.6）仍未做。

## 5. 退路

`owrt-rpcd-switch disable`：停 rpcd-rs → `/etc/init.d/rpcd enable && start`（原 rpcd 恢复全部对象与 S12）；
`boot-enable off`；`apk del owrt-rpcd`。原 rpcd 二进制与插件目录从未修改。
