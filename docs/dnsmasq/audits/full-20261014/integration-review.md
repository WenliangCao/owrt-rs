# 完整审计分项：最新 main 的系统集成

审计冻结点：`e9d89b17d72a58b723cce88038ceaa1be58d7f8c`，2026-10-14。

**所测正常集成路径没有发现 Rust dnsmasq 独有的新缺陷。** 本轮从冻结源码新编译另外 9 个 Rust 组件，分别搭配精确镜像 C 和本轮新编译的 Rust dnsmasq，完成同一套真实服务调用。两边各 23 项管理检查、另各 5 项 DHCP helper 检查通过。仍须保留两项 P2 运维问题：APK 升降级不保证激活目标 ELF、ubusd 重启后管理对象丢失。前者是本轮核对源码后仍适用的历史实测；后者本轮重新配对复现。二者都有 C 共同边界，不能冒称 Rust DNS/DHCP 引擎的新回归。

本分项没有访问路由器、没有改产品代码、没有安装任何设备包、没有推送。物理设备与部署恢复结论由主报告单列；本分项的通过不能覆盖其它审计发现。

## 身份与方法

[派生结果与身份](integration-stack-summary.json) 保存构建、运行中的 ELF hash、源码校验、每个检查结果和原始证据 hash。

| 项目 | 本轮输入与核验 |
| --- | --- |
| 源码 | Git archive `e9d89b17`；全部 `components/` 334 个跟踪文件逐项 SHA-256 与 Oracle 构建树相同 |
| 另外 9 个组件 | **ubusd、procd、netifd、rpcd、logd、uci、reload-config、fw4、httpd**；`ubus` 是共享库，不是第 10 个独立重写组件 |
| Rust9 构建 | Rust 1.98.1、AArch64 musl、SDK GCC 14.3.0/linker、release/locked；每个 ELF 另存 SHA-256，常驻进程再核对 `/proc/PID/exe` |
| Rust dnsmasq | 本轮独立构建 `e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`，2,073,056 B；静态 PIE、opt3/LTO，未经过 APK/sstrip 封装 |
| C dnsmasq | **镜像 ELF** `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`；不是 Oracle 宿主重编 C |
| 用户空间底座 | stock 25.12.5 root SquashFS `3f315cf686c9cd951b24881a3a8e0c78448acaad6fd20d2ab6f1003a0e85b1cc`；本轮重新提取，881 普通文件内容/权限及 213 symlink 与所用底座全部匹配 |
| init / ujail / odhcpd | 原镜像资产，不改 init、不增加 jail procfs；只在私有 overlay 上放入本轮 Rust9 和选定 dnsmasq |
| 内核与网络 | Oracle AArch64 Linux `6.17.0-1020-oracle`，独立 mount/network/PID namespace；合成 bridge/veth 客户端与 loopback 上游，不是 AX3000T `6.12.94` 的硬件验收 |

这 9 个 ELF 是**冻结 main 源码的新构建**，不是路由器现有 9 个文件的复制品，也不是 9 月固件中旧的 Rust9。不同构建路径/参数导致 ELF hash 不等于现场既有二进制；本轮没有宣称它们是新正式固件或可直接部署的已封装 release。

## 按严重程度排列的现存问题

### I1 — P2：APK 成功升级或降级后，活进程仍可能是原来的 ELF

**证据强度：本轮静态适用性复核 + 既有精确镜像 APK 实测；没有把历史事务说成本轮新跑。**

`git diff 58365e8c..e9d89b17 -- packaging/openwrt/owrt-dnsmasq` 只有 README 增加 6 行；Makefile、全部附带文件和 linker 工具完全未变。当前 Makefile 没有定制 post-upgrade 激活步骤，仍由 SDK 生成 scripts。既有候选与 stock 包的 post-upgrade 都执行 `default_postinst`；本轮重新提取并核对的镜像 `/lib/functions.sh:398-408` 调用的是 init `start`。包内 init `dnsmasq.init:1267-1270` 提交相同 command 与配置文件；当前 Rust procd `components/procd/src/instance.rs:243-279` 比较命令字符串、配置和受监测文件等，**不比较 executable 内容**。

[既有 APK 派生结果](../20261014/integration/package/summary.json) 的 `cases.activation` 有三次身份观察：C→Rust 升级后数据库/磁盘已为 Rust，运行中仍是 C `(deleted)`；Rust→C 降级后磁盘已为 C，运行中仍是 Rust `(deleted)`；显式 restart 后才运行预期 C。同版本 stock 重装控制也保留原进程。完整 scripts 在 [APK metadata](../20261014/integration/package/apk-metadata.txt)。

实际影响：安装修复可能没有启用，回滚成功提示也可能仍在运行故障代码。**正式安装流程必须把事务、显式 restart、运行中 ELF hash 和客户端 DNS/DHCP 健康分别验收。** 如果希望单次 APK 升级完成激活，应显式解决这一包生命周期合同，并重新测 upgrade/downgrade，不以临时 bind trial 绕过它就宣称正式替换完成。

不能扩大为“卸载不会停服务”：既有 `candidate-uninstall` 实测通过；当前镜像 `default_prerm:219-247` 明确调用 init `stop`，本轮也验证了最新 Rust procd + Rust dnsmasq 的 init stop。全新安装原有 post-install 自动启动有历史证据。**本轮没有证据证明 erase 后残留活 Rust。**

### I2 — P2：重启 ubusd 后，dnsmasq 两个对象消失，DNS 继续工作

**证据强度：本轮精确 C / 当前 Rust dnsmasq + 当前 Rust9 配对复现。**

双方最初都有 `dnsmasq`、`dnsmasq.dns`，metrics 可以调用。服务已降权后重启 fresh Rust ubusd：三秒后 `ubus -v list 'dnsmasq*'` 为空；DNS 仍返回 `apply.audit → 192.0.2.62`。显式 init restart 后两边都恢复 DNS 与两个管理对象。这不是只检查 PID 的结论。

根因可直接定位：

- `packaging/openwrt/owrt-dnsmasq/files/dnsmasq_acl.json:3` 的 publish 仅允许 `dnsmasq`，缺少 `dnsmasq.dns`。本轮镜像 ACL SHA-256 与包内文件一致。
- `components/dnsmasq/src/ubus_service.rs:76-87` 顺序注册主对象和 `.dns`；第二次失败会丢弃整个连接及首对象。
- `components/dnsmasq/src/main.rs:456-488` 在重连注册失败后将 `ubus_name=None`，此后不再恢复注册。它明确复现 C 的 failure boundary。
- 当前 Rust ubusd 的精确名称 ACL 行为亦由 `components/ubusd/src/acl.rs:408-415` 固定；不是该组件允许了错误的发布权限。

实际影响：metrics、DHCP 事件订阅和 DNS doctor 通知消失，普通 DNS 可用却不代表管理功能恢复。LuCI IPv4 租约读取另有文件路径，本轮不能把此问题写成所有 LuCI 或 DNS 故障。应修正包 ACL/重连与恢复策略，并明确恢复检查要求两个对象；在修复前，ubusd 维护重启后需要再重启 dnsmasq。此项是**精确 C 与 Rust 共同的 stock 集成缺陷**，级别反映实际管理影响，不把它列为 Rust 特有上线阻断。

## 本轮通过的实际共存路径

| 组件 / 合同 | 新测试结果 | 能证明的范围 |
| --- | --- | --- |
| procd + 镜像 init/ujail | C/Rust 都启动；配置不变 reload 保留真实 PID；配置变化激活；SIGKILL 后恢复客户端；正常 stop 退出 | UID/GID 453、实际 ELF、原 jail 路径；不是完整 PID1 开机测试 |
| netifd → resolver 文件 → DNS | 真 netifd 依次写 `127.0.0.2`、`127.0.0.3`；两个受控上游分别返回 `192.0.2.82`、`.83`，C/Rust 都随之切换 | 实际 atomic resolver 文件写入与 daemon 接线；不代表 WAN PPPoE/真实 ISP/IPv6 link-local 全组合 |
| uci + reload-config + procd | `uci add_list/commit` 后执行 fresh `reload_config`，新增记录可查询 | 真实 config.change 派发和 init 重生成，不是直接给 daemon HUP 替代 |
| rpcd UCI apply | session 授权、staged set、apply 后新记录生效，随后真实 DHCP/DNS 客户端仍正常 | RPC 管理链路与配置重启 |
| httpd → rpcd → dnsmasq/LuCI | fresh httpd `/ubus` JSON-RPC 获取 `luci.getFeatures`、`luci-rpc.getDHCPLeases`；两版 DNS capability map 19 项相同 | HTTP bridge、实际 Rust rpcd、CLI capability 消费与真实租约；没有冒称浏览器点击 LuCI UI |
| fw4 | fresh fw4 `print`、`check`、`start` 成功，规则装入隔离网络后客户端继续 DHCP ACK、UDP/TCP DNS | LAN INPUT 与服务共存；不代表满速转发、NAT、VPN或运营商外网测试 |
| logd | 当前 Rust logd 实际接收启动、上游、租约和恢复日志，`logread` 保留证据 | 正常 syslog 接口；日志背压/ENOMEM 由其它分项审计 |
| ubusd / ubus 库 | C/Rust metrics 的 30 个字段名相同；fresh Rust ubusd 实际向订阅者传递相同 DHCP ACK JSON | **字段名**与本例事件一致，未声称所有动态 metrics 数值相等 |
| stock dhcp-script → fresh procd hotplug | 临时合成 `/etc/hotplug.d/dhcp` 脚本使原 init 启用原装 dhcp-script；两边记录相同 `add|192.168.1.101|02:00:00:00:00:27` | 真实 helper → shell → ubus → procd hotplug 路径；不是替代 helper mock |
| odhcpd → hosts → DNS | 精确镜像 odhcpd 与 veth 客户端真实 DHCPv6 Reply；自行生成 hosts 后 C/Rust 都返回 `fd00:2::7ed` AAAA | DNS/DHCPv4 与保留 DHCPv6 执行面共存 |
| 客户端本身 | 在初始、fw4 加载、UCI apply、崩溃恢复后实际发送 DHCP DISCOVER/REQUEST，检查 OFFER/ACK、router/DNS option，再从租约地址发 UDP/TCP DNS | 合成独立 veth 客户端，**不是用户手机重连 Wi-Fi** |

初始化两次失败属于测试器自身且均保留：第一次在 `Popen(chroot …)` 后过早读取 httpd root，修为等待实际 chroot；第二次 respawn 检查误用 decoder 不存在的 `rcode` 字段，修为实际 answer 地址断言。修正后重新完成 C/Rust 配对，没有删掉失败后直接累计通过数。

## 边界、重跑与收尾

没有重新执行完整 APK 事务、签名信任、变体互斥、物理启动、断电、UBIFS、overlay ENOSPC、所有多实例/TFTP/PXE/VPN组合。APK 体积门限是工程预算；超限不能据此宣称这台仍有可用空间的路由器“装不下”。本分项没有估计现场闪存占用或可接受预算。

Oracle 根路径为 `/tmp/full-audit-integration-20261014/`。`private/final-{c,rust}/result.json`、`private/helper-{c,rust}/result.json`、构建日志、原始 rootfs 身份、源码 hash map 和本轮工具保留于该路径；电脑镜像为 `private/full-audit-20261014/integration/`。Git 只提交本文和派生 JSON，不提交固件、ELF、原始配置或含 session 的命令记录。

重跑使用该冻结目录内工具，必须置于仓库已有 `run_isolated.sh` 内，并为 `--run` 选择新的名称：

```sh
base=/tmp/full-audit-integration-20261014
sudo -n sh "$base/src/tools/dnsmasq/run_isolated.sh" \
  python3 "$base/stack_replay.py" --side rust --run replay-new
sudo -n sh "$base/src/tools/dnsmasq/run_isolated.sh" \
  python3 "$base/helper_replay.py" --side rust --run helper-new
```

换为 `--side c` 做同配置镜像 C 对照。工具的 base 路径、stock rootfs 路径和候选 hash 已在派生结果中固定；更换输入需重新核验，不能沿用通过结论。原始工具仅用于本轮隔离环境，不作为产品或通用部署工具。

全部 namespace 测试已退出，所属常驻服务由 fixture 清理；未在主机网络留 listener，也未接触物理路由器。源码和正在运行的 9 个支撑进程分别校验；性能或路由器恢复问题不在本分项通过范围内。
