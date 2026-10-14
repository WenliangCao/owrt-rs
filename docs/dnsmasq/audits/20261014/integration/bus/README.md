# 审计 B：UBus / LuCI / odhcpd 独立证据

审计源为 main `58365e8c8ebe1805573baa02543baf1c9d45be68`。本次实跑并验证 C / Rust 进程 ELF；没有用旧报告的通过结论。`summary.json` 保留原始文件位置、SHA-256、实际结果与检查。原始文件在 oracle `/home/ubuntu/dnsmasq-predeploy-b-bus-20261014/private/`，均为合成数据、独立 mount/net/pid namespace 和可写 rootfs overlay；未接触物理路由器。

- 精确镜像 C ELF：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
- Rust ELF：`e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9`，复用 fix7 release；其全部 `components` 非 `target` 文件与本地 main 的路径+NUL+内容聚合哈希相同，方法及哈希见 summary。
- 最终实跑使用主审本次重新从固件提取的 `/home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity/rootfs-check`。没有引用早期提取目录中额外实验文件的行为。
- C 实现引用匹配且已打补丁的 `/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93/src/ubus.c`，SHA-256 `b3b50a4c9146de991f1eed49ee07ee3b76f5296b0118c66ca232f9437babd479`；`sources/components/dnsmasq/src/ubus.c` 是未完整打补丁的版本，不是本结论的代码依据。

## 发现

**B-BUS-1，P2，已复现，C / Rust 共有的恢复限制：降权运行后 ubusd 重启，会永久丢失 dnsmasq UBus 对象，直到重启 dnsmasq。**

正常启动两者均注册 `dnsmasq`（仅 `metrics`，30 个相同字段）和 `dnsmasq.dns`（无可调用方法）。终止并重新启动 exact-image ubusd，继续用 DNS 请求唤醒主循环，两者仍正常回答 `audit.lan -> 192.0.2.1`，但 `ubus list 'dnsmasq*'` 返回 Not found，日志均为 `UBus error: Invalid argument`。代码随后永久停止注册重试。重启 dnsmasq 后，两者均恢复两个对象。这里失效的是 dnsmasq 的 metrics、DHCP 通知和 DNS doctor 接口；不能据此说 procd 的 service 对象、UCI 或 LuCI 全部失效。

根因有对照验证：重启前后 socket 均为 `0666 root:root`；原镜像 `/usr/share/acl.d/dnsmasq_acl.json:2-3` 仅允许 user dnsmasq publish `dnsmasq`，不包含 `dnsmasq.dns`。首次注册在降权前完成；失联重连发生在 UID/GID 453 下，第二对象的注册被拒绝，整条连接及第一个对象被丢弃。只在一次性 fixture 的 publish 数组添加 `dnsmasq.dns`，Rust 便能重连并恢复两个对象；以 root 保持运行的诊断对照得到相同结果。**这些控制实验不是部署建议，也未修改产品 ACL。**

代码依据：Rust `components/dnsmasq/src/ubus_service.rs:76-87` 注册两对象，`components/dnsmasq/src/main.rs:478-488` 把注册错误变为永久禁用；匹配 patched C `ubus.c:118-133`、`dnsmasq.c:1288-1303` 有相同失败边界；ubusd `ubusd_obj.c:146-148` 检查 publish ACL。该限制是原镜像已有行为，不能当成 Rust 新增回归，也不能宣称回滚到 C 能消除它。若“系统管理不能失效”的上线标准包含这些接口，必须明确处理/接受这个共有故障边界及重启恢复流程。

**B-BUS-2，信息级，已复现，Rust 改善了一个 C 的失联恢复差异。**

在上述 root-user 或增补 ACL 的控制环境中，C 重连后恢复 `dnsmasq.metrics`，`dnsmasq.dns` 无法通过 lookup 找到；Rust 恢复两者。匹配 C `ubus.c:89-96` 只清除主对象及主 type ID，未重置 `ubus_dns_object_type`；Rust 新建 connection-local IDs。生产 stock ACL 会先触发 B-BUS-1，因此这个改善不能作为 stock 配置自动恢复成功的证据。

## 实际通过的协作路径

1. **DHCP → UBus → LuCI：** 用真实 UDP DISCOVER/REQUEST 获得 ACK 后，两者落盘相同五列 `/tmp/dhcp.leases`；exact-image rpcd 的 `luci-rpc.getDHCPLeases` 能返回 hostname/macaddr/ipaddr/剩余时间。真实 RELEASE 后文件清空。`ubus subscribe dnsmasq` 接收的 `dhcp.ack` 和 `dhcp.release` JSON 字段和值完全相同。LuCI 剩余时间允许墙钟导致的一秒差异。
2. **LuCI 特性探测：** 把被测 ELF 放到实际 `/usr/sbin/dnsmasq` 路径，调用 exact-image `luci.getFeatures`，19 项 dnsmasq 编译能力值完全相同。Rust 版本行额外标明 Rust implementation 不破坏其 Compile time options 解析。
3. **真实 odhcpd 发布：** 启动镜像原有 init/procd/ujail/netifd/rpcd/odhcpd，veth 隔离客户端真实完成 DHCPv6 SOLICIT/ADVERTISE/REQUEST/REPLY，odhcpd 自行写出 `/tmp/hosts/odhcpd.hosts.lan` 的 `fd00:2::7ed m2-dhcp6`，随后两者 DNS AAAA 返回该地址。测试没有直接写这个发布文件。原始四包 hex、发布内容、实际进程 SHA 均留存。
4. **UCI 与 reload：** rpcd `uci.set` 的 staged edit 在 apply 前不进入运行配置；apply 后原 init/procd 更新配置并启动新 inner ELF，DNS 能返回新 address 配置。C inner PID `263 -> 615`、Rust `263 -> 592`，两边都确实变化。普通 hosts SIGHUP 和无配置变更的 init reload 能继续得到正确回答。

消费者依据：

| 消费方 | 实际接口与依据 |
| --- | --- |
| LuCI 状态租约 | rootfs `www/luci-static/resources/view/status/include/40_dhcp.js:1` 调用 `luci-rpc.getDHCPLeases`；匹配 rpcd-mod-luci `luci.c:395-470` 按 UCI leasefile / `/tmp/dhcp.leases` 读租约，并不调用不存在的 dnsmasq DHCP 查询方法。 |
| LuCI capability | rootfs `usr/share/rpcd/ucode/luci:278-287` 解析 `dnsmasq --version` 的 Compile time options。 |
| odhcpd 名称发布 | 镜像匹配 odhcpd `statefiles.c:420-469` 写 hosts，`:643-656` 调用 leasetrigger；rootfs `usr/sbin/odhcpd-update:6-8` 调用 `procd_send_signal dnsmasq`。 |
| dnsmasq init | `packaging/openwrt/owrt-dnsmasq/files/dnsmasq.init:1001-1002` 注册实例名，`:1057-1067` 指定 hosts / leasefile，`:1377-1380` 用 procd 更新实例再发信号。 |

生命周期复用了已读过的 `m2_lifecycle.py` plumbing，最终入口为 `audit_integration_bus.py --suite lifecycle`。旧 harness 的 `uci_apply_restarted` 字段比较 jail 内 pidfile（两边都可能为 PID 1），因此不能作证；新增 `audit_actual_uci_apply_restarted` 比较已核对 ELF 的 namespace-visible `inner_pid`。同理不把旧 harness 的 pidfile 不变布尔单独当成进程身份不变证据。该旧 harness 在 init stop 后若 pidfile 残留，会额外给 inner 进程发一次 TERM，因此这里的 stop 布尔不能证明“init stop 单独足够”；启停可靠性须以主审专门实验为准。未传 `--jail-procfs`，原镜像 init 没有测试专用修改。

## 本次实际命令与复现

以下命令在 oracle 的工作目录执行。路径已存在时脚本拒绝重用，复现时给 `--output` 和 network `--output` 各换一个全新名字。

```sh
cd /home/ubuntu/dnsmasq-predeploy-b-bus-20261014
sudo -n sh tools/run_isolated.sh python3 tools/audit_integration_bus.py \
  --image-root /home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity/rootfs-check \
  --rust-binary /home/ubuntu/dnsmasq-audit-fix7-20261014/private/release/dnsmasq-rs \
  --output private/final2-bus
```

该命令依次在一次性 rootfs 内运行 stock 用户/ACL、root-user control、ACL control 六组 C/Rust 重连实验，再运行真实 DHCP UBus/LuCI 消费测试；不对宿主机系统 ubusd 发信号。`private/network-source/tmp/resolv.conf.d/resolv.conf.auto` 是空的合成文件，只用于建立无外网上游的实验网络。

```sh
sudo -n sh tools/run_isolated.sh python3 tools/actual_config_network.py \
  --source-root private/network-source --router-cidr 192.168.1.1/24 \
  --output private/final-network-c -- \
  python3 tools/audit_integration_bus.py --suite lifecycle --implementation c \
  --image-root /home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity/rootfs-check \
  --rust-binary /home/ubuntu/dnsmasq-audit-fix7-20261014/private/release/dnsmasq-rs \
  --output private/final-lifecycle-c

sudo -n sh tools/run_isolated.sh python3 tools/actual_config_network.py \
  --source-root private/network-source --router-cidr 192.168.1.1/24 \
  --output private/final-network-rust -- \
  python3 tools/audit_integration_bus.py --suite lifecycle --implementation rust \
  --image-root /home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity/rootfs-check \
  --rust-binary /home/ubuntu/dnsmasq-audit-fix7-20261014/private/release/dnsmasq-rs \
  --output private/final-lifecycle-rust
```

## 边界

- 是 oracle Linux 内核的合成 LAN/IPv6 配置及精确 userspace，不是实体 AX3000T 内核、Wi-Fi 或真实客户流量；没有执行完整 PID 1 冷启动。
- Bus 故障注入是进程终止/重启；没有枚举 ubusd partial-frame、恶意 subscriber、拥塞/资源耗尽时的所有时序。
- 没有测试 LuCI 浏览器页面交互；实测其真实 rpcd 后端租约、特性、UCI apply 消费路径。
- 默认镜像没有 `/etc/hotplug.d/dhcp` 用户 handler，生成配置不包含 dhcp-script；未测试用户自行安装的 handler 或第三方 `USER_DHCPSCRIPT`。
- 实测 odhcpd 初次租约发布；没有覆盖 DHCPv6 全部 renew/rebind/expiry、PD、RA/netifd 事件组合。
- 此子审不对 package lifecycle、磁盘内存压力和无人值守回滚作结论，这些由主审及其他子审负责。
