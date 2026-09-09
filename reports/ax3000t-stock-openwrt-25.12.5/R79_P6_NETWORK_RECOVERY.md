# R79：P6 断网修复与接管验证

日期：2026-09-09。**离线修复已验证；设备窗口尚未执行。**

候选由 oracle 的独立目录 `p6-recovery-20260909/components/netifd` 构建，
Rust 1.98.1，`aarch64-unknown-linux-musl`，release，`--bins --examples`。
被测和准备部署的是同一份冻结二进制：

```
SHA-256 42e0c9658db002324a50471e7eea6e52ec7d9fe0f2c79f89662479f8b1ab4c91
```

## 原因与修复

接手时设备已经自动恢复为 C netifd（MD5 `031a542b2f2c125bb2016b3c74539aee`），
LAN/WAN/双频 AP 正常。没有旧故障启动的持久诊断文件可读，因此根因依据是旧候选的
离线复现，以及设备当前确实为 LAN 三个口均无载波、只通过无线管理的只读观察。

R78 的晚到端口修复保留，但不足以完成 P6：

1. `force_link` 已被解析，却从未参与接口状态判断。C 的 static 协议默认开启此行为，
   所以静态 LAN 在没有有线载波时也应配置地址。Rust 曾始终等待载波。
2. 无线 handler 配置没有 `bridge` / `bridge-ifname`，也没有执行
   `interface_get_bridge → bridge_hotplug_prepare`。现在准备目标桥，使没有有线成员的
   桥先可用，再把实际桥名称传给原版 `mac80211.sh`；公开的 interface `prepare` 也共用该行为。
3. `NOTIFY_UP` 只改 radio 状态，没有执行接口接入。现在登记外部无线设备、加入桥、
   设置 hairpin/multicast/proxyarp/isolation/BPDU 属性，teardown 完成后移除成员与引用。
   hostapd 继续拥有无线接口的创建和行政启停。
4. reload 曾丢失动态桥成员并重复增加有线成员引用。现在保留现有成员；删除 radio 后，
   保留其实际 handler 配置直到 teardown 完成，避免漏掉无线接口清理。
5. `network.device status` 的 `bridge-members` 应包含配置登记但尚未出现的端口。
   输出投影已修正，实际已接入成员仍独立用于生命周期判断。

没有新增依赖，没有修改内核、驱动、hostapd/wpad、dnsmasq 或协议 helper。

## 精确参考来源

- netifd C：`cbb83a1857407a28a63dc09412a1f209195914ef` 的 `interface.c`、
  `bridge.c`、`ucode.c`、`device.c`、`system-linux.c`。
- **无线状态机以实际发货的 wifi-scripts 为准**，对应 OpenWrt
  `f0a60eee2fe051741c643ea6118718aae1ef17fb` 的
  `package/network/config/wifi-scripts/files/lib/netifd/wireless-device.uc`。
  该文件与镜像、设备 `/rom`、设备当前文件的 MD5 均为
  `5b0658918ef120bb80e49fab1a558d6d`，SHA-256 为
  `b42b77c783542e2f56e264910d0fb4a15a86a514c0c60aafd63c489231f6ebd7`。
- netifd 仓库的 `examples/wireless-device.uc` 不是发货文件，尤其 disabled/setup 与
  ifindex 改变后的再次 setup 存在区别。不能把 example 当作本机状态机的行为规范。

## 离线证据

`tools/r79_wireless_bridge_diff.sh` 在同一精确 rootfs 的隔离网络/PID namespace 中
分别运行 C 和 Rust。veth 模拟 AP，另一 network namespace 模拟客户端。
检查真实 ping 数据包、LAN 地址、bridge master、桥口属性，以及结构化 ubus 状态。

- 旧候选：radio 报 up，但首次启动、无变更 reload、无线重启后三次均无 LAN 地址、
  未加入桥，客户端不通；同一夹具的 C 侧正常。保留了明确的红证。
- 当前候选：初启、无变更 reload、无线 down/up、SSID 修改、radio 删除和恢复均通过。
  无变更 reload 不增加 setup 次数；初次 handler 报 up 之前静态 LAN 已有地址。
- C 在重建桥的 ifindex 改变后会额外执行一次 setup；验证保留此记录，不要求这种瞬态
  调度次数相同。最终 handler 接口、桥口属性、ubus 状态和数据通路必须一致。
- `r63` 真实配置差分：up / 无载波 / 晚到 16 秒 / 全部端口缺席四种场景均通过，
  分别比较 1881 / 1965 / 1881 / 1672 行 ubus 输出。
- 单元测试、完整 suite 和 clippy 的最终结果在设备窗口前记录。

原 `PORT_STATE=down` 的未完成改动把端口完全省略，不能证明“端口存在但没插网线”；
即使创建 dummy，netifd 拉起它后也会出现载波。现在用对端在另一个 namespace 且保持 down
的 veth 模拟无载波；`absent` 单独表示缺席。无端口桥的内核随机 MAC 只在没有显式 MAC 配置时
归一化，地址、路由和成员没有被掩盖。suite 现在预先要求 root，避免到无线用例才遇到权限错误。

原始配置、二进制、完整日志和 overlay 备份均在忽略目录或 oracle 的证据目录，未进入 Git。

## 回退与客户端验收

取消未完成草稿中“路由器自检后自动永久确认”的方案。设备本身能 ping 上游、radio up，
不能证明客户端 DHCP、DNS 或转发正常。

`p6_switch.sh` 的 rollback 计时器与诊断采样分开运行：480 秒内没有显式 confirm，
就恢复保存的 C netifd 并重启。pending 文件的原子 rename 决定 confirm 与 rollback 的胜者。
诊断在 300 秒写入 `/root/p6-evidence-<boot-id>.txt`，不会阻塞回退。

`p6_switch_selftest.sh` 使用发货 BusyBox 和隔离的 root/PID namespace，reboot 替换为记录器：
未确认回退、确认保留、主动 undo、二进制变化时拒绝确认四种情况均通过；故意挂死诊断命令
仍能按时恢复。迟到的 confirm 不会误报成功。

`p6_client_probe.py` 从连接路由器 Wi-Fi 的 Mac 验收：运行中的 netifd 哈希、两个 AP 入桥、
LAN/WAN/WAN6、当前启动内的 DHCP lease、向路由器查询 A/AAAA，以及通过该 Wi-Fi 的
IPv4/IPv6 HTTPS。设备窗口前，C 基线已全部通过。

## 设备窗口

待离线完整 suite 收尾后，在已有明确授权范围内执行：保留 `/rom` 与 C 原件，
安装候选并冷启动，客户端连续健康观察至少 180 秒后显式 confirm。
若任一必需检查不通过，不确认，由设备独立回退；不刷固件。

## 补记（2026-09-09 晚，接手会话）

**窗口 #2 已经发生过，候选是好的。** 上文"设备窗口尚未执行"写于窗口前；实际 19:27 设备用
候选 60dcff02 冷启动，T+300 的自动快照（`/root/p6-evidence-1e98d833-…`）显示 br-lan 192.168.1.1、
wan DHCP 地址与默认路由、v6 前缀、phy0-ap0/phy1-ap0 均为 br-lan 成员且 forwarding、hostapd/
dnsmasq/odhcpd/udhcpc/odhcp6c 全部在跑、`procd: - init complete -` 19.3 s；lan2–4 只是 NO-CARRIER
（没插线）。19:35:13 `UNCONFIRMED: restoring C` —— 480 秒内没有人执行 confirm（写报告的会话已断），
回退按设计生效，设备重启回 C。**失败的是确认环节，不是候选。**

**独立复核（同一份冻结二进制，非重建）**：sha256 与上文一致；其源码树 + Cargo.lock 与仓库工作树逐
文件相同。套件 24/24（含 r79）、r63 up/down/absent/late16 identical、`p6_switch_selftest` 四模式过。
r63 `late`（8 s 档，上文未列）3 次里 1 次红：ubus 0 差异，只有 wan 的 fe80:: 由夹具 MAC 而非配置
MAC 派生——夹具把 dummy 以 UP 创建，内核先生成链路本地地址、daemon 后改 MAC 的竞态。C 与 rs
在内核层做的是同一件事（SIOCSIFHWADDR 与 RTM_SETLINK 都不 down/up）。真机 DSA 口是 admin-down 出现
（dmesg 3 s "uninitialized"，16 s 才被 netifd 拉起），夹具已改为晚到端口 admin-down；改后 late×3、
late16×2 全绿。

**两处针对确认环节的改动**：
- canary 期限 480 s → 900 s（`p6_switch.sh`，自测映射同步）：健康启动 ssh 可达约 T+150–250 s，
  客户端侧再连续观察 180 s，480 s 余量太薄，这正是窗口 #2 丢失的原因。
- `tools/p6_window.sh`：在 Mac 上 `setsid` 脱离会话运行的窗口编排器——预检探针→上传到持久的
  /root→stage→reboot→等 ssh→`p6_client_probe.py` 连续 180 s 全过才 confirm→事后复核；探针不过就
  不 confirm，交给设备自己回退并收集证据。会话再断也不会再丢一次好候选。
