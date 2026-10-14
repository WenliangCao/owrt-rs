# dnsmasq 上线前独立审计 B：集成与故障

日期：2026-10-14。审计源码：main `58365e8c8ebe1805573baa02543baf1c9d45be68`。范围：AX3000T stock / OpenWrt 25.12.5 的系统管理、故障恢复和包回退。**结论：不能上线。**

正常管理路径已经能工作：当前 Rust ELF 在镜像原装 init、procd、ujail 下可以启停；配置修改、rpcd UCI apply、LuCI 使用的 RPC、真实 odhcpd 发布与 DNS 联动均完成了新一轮隔离对照。但运行时分配失败会把一次 hosts 重载扩大为整个 Rust daemon 的 SIGABRT，而同条件下 C 保持存活并恢复部分服务（B1）。另外，现有包并没有建立自动回退闭环（B2）：手动安装回 C 的路径可行，但依赖可用的控制平面、离线原包、可写空间、显式 restart 和运行中 ELF/客户端健康核验，不能把 APK 事务成功当作回退成功。

本审计没有修改产品代码，没有接触物理路由器，没有推送 GitHub。历史 M4/M5/fix7 报告只用于寻找输入和工具；下述行为结果来自本轮实际运行。复用了逐文件重新核验的当前 ELF，**没有把旧版本的生命周期通过记录算作当前通过**。

## 1. 输入、参照和证据强度

| 输入 | 本轮核验身份 |
| --- | --- |
| 官方 stock 固件 | `openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin`；SHA-256 `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` |
| 固件 root SquashFS | `3f315cf686c9cd951b24881a3a8e0c78448acaad6fd20d2ab6f1003a0e85b1cc` |
| 实际运行的镜像 C | dnsmasq 2.93-r1 / nodhcpv6；269,305 B；`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 实际运行的 Rust | 2,056,672 B；`e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9`；AArch64 musl static PIE、opt3、feature-off |
| 本轮新打包 APK | dnsmasq-2.93-r2.apk；1,118,297 B；`9b836ac3cb10c392247c529529db921155d7f7c84b9753c52b7f9cb6682bef68`；包内 ELF 逐字匹配上行 |
| 回退原包 | dnsmasq-2.93-r1.apk；`752fa57e5a986425f03c9f6579097c7f23750fc80b3af317e4ee0e2d1b7a0d89` |
| C 实现参考 | 匹配 OpenWrt patches 的 dnsmasq-2.93；recipe revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`，148 文件重新核验；行为裁决仍以镜像 ELF 为准 |

178 项产品、ubus 依赖及包构建输入逐项核对了冻结 Git blob、本地工作区、Oracle retained source，全部一致。[源码身份](audits/20261014/integration/identity.json)、[固件/rootfs/ELF/C 参考树核验](audits/20261014/integration/rootfs-identity.json)。

从原固件重新提取的 881 个普通文件、213 个符号链接与共用历史提取树中的原镜像文件全部相同。历史树额外存在两个无关的 `/tmp/r131-ubusd`、`/tmp/r134-ubusd` 实验 ELF，首次严格核验因此失败，未隐去；关键最终故障、包和系统集成实验改用本轮干净提取树。较早七项租约实验用了历史树，其执行路径是镜像的 `/usr/sbin/dnsmasq`，未执行这两个附加 ELF。该偏差及 hash 已记录，不能把历史树描述成毫无附加文件。

实验在 `ssh oracle` 的独立 network/mount/PID namespace、私有 overlay/tmpfs 和 chroot 中执行；C 使用镜像自身 loader/库，系统管理使用镜像的 ubusd、procd、ujail、rpcd、netifd、odhcpd。**用户空间精确，内核不是路由器内核**：Oracle 为 AArch64 Linux 6.17.0-1020，目标镜像为 6.12.94。没有以宿主重编 C、模拟 procd 或修改 init 代替实际组件；最终管理实验没有添加 `--jail-procfs`。

## 2. 发现清单与上线影响

P1：上线阻断，可能造成持续服务丢失或回退保证缺失。P2：有明确恢复步骤的管理/运维风险，须纳入部署程序。P3：诊断等较小行为差异。这里同时列出 Rust 差异与原镜像共有边界，**共有边界不冒充 Rust 新缺陷**。没有证据支持不可恢复的设备损坏。

| ID | 等级、状态 | 发现 | 归属与影响 |
| --- | --- | --- | --- |
| B1 | **P1，已复现** | hosts 重载遇到 ENOMEM，Rust SIGABRT；C 存活并恢复部分应答 | Rust 差异；DNS/DHCP 共用 daemon 退出，不能满足本次不中断门槛 |
| B2 | **P1，部署门槛未满足** | 没有健康失效自动切回 C 的闭环；挂住不被发现，快速崩溃会耗尽 respawn | 镜像 procd 的恢复边界与替换包缺少回退机制；不是 Rust 独有的 procd bug |
| B3 | P2，已复现 | APK 升降级成功后仍运行旧 ELF | 继承 stock scripts；仅看版本/磁盘文件会误判升级或回滚成功 |
| B4 | P2，已复现 | overlay 空间不足时 C 回退事务失败；当前产物也未通过既定体积门限 | APK/容量边界；不能在耗尽空间后假设降级必定成功 |
| B5 | P2，已复现 | ubusd 重启后降权的 daemon 失去 UBus 对象，DNS 仍工作 | C/Rust 共有的 stock ACL/重注册问题；需要重启 dnsmasq 恢复管理对象 |
| B6 | P3，行为已复现；尾日志丢失仅疑似 | Rust 停机日志 flush 最多 100 ms；C 在本例超过 2 s | 显式 async 日志配置下的差异；可能少保留尾日志，未证明具体丢失记录 |

### B1：可恢复的分配失败变为整个 Rust 进程中止

复现配置使用同一份有效合成输入：本地 `ready.test` host-record、`addn-hosts=/m2/hosts`，先确认 DNS 就绪；对**各自**进程设 `RLIMIT_AS = 当前 VmSize + 1 MiB`，把 hosts 更新为 30,000 个不同名字，发送 SIGHUP。这个规则控制新增地址空间，不声称两边初始内存相等。

| 观测 | 精确 C | 当前 Rust |
| --- | --- | --- |
| 初始 VmSize / 设置后的上限 | 1,332 KiB / 2,412,544 B | 2,316 KiB / 3,420,160 B |
| 系统调用 | 实际出现 mmap ENOMEM | `mmap(NULL, 401436, …) = -1 ENOMEM`，随后 SIGABRT |
| 限制仍有效时 | 活着；三次 300 ms DNS 探针超时后重新回答 `ready.test`；最后一条 hosts 未载入 | 退出 `-6`；原有名字和最后一条均超时 |
| 去掉限制并重载小文件 | 无需重启即可返回 `recovered.test` | 原进程已不存在 |
| 同样 30,000 条、无分配限制的负控 | 正常存活、最后一条可查询、退出 0 | 正常存活、最后一条可查询、退出 0 |

在历史树/干净提取树上重复成立；最终结果与 syscall 摘录见 [资源证据](audits/20261014/integration/resources/summary.json)。无压力控制中 RSS 为 C 4,044 KiB、Rust 15,952 KiB，仅代表这个合成 hosts 场景，不是该路由器常态内存或 OOM 概率。

代码依据：`components/dnsmasq/src/dns/hostsdir_runtime.rs:90` 累积 records，`components/dnsmasq/src/hosts.rs:133-162` 插入 Vec/HashMap 等使用不可恢复分配路径；匹配 C `src/cache.c:200-232,1513-1528` 使用 `whine_malloc` 和 NULL 分支跳过无法分配的记录。syscall 没有采集 Rust 调用栈，**不把某一个源行认定为已定位的唯一失败分配点**。

影响是进程级故障边界扩大：即使压力只来自一个可重载 hosts 输入，Rust 的共同 DNS/DHCP owner 也会退出。普通单次崩溃由 procd 约 5 秒后重启；持续资源不足是否在启动再次触发相同分配，本轮没有组合测量，不能将 B2 的六次人工 kill 写成已复现的“真实 OOM 崩溃循环”。本项已经足以否决上线，但不声称出厂配置或当前客户端数量一定触发。

复跑 [audit_integration_resources.py](../../tools/dnsmasq/audit_integration_resources.py) 的 `--kinds memory`；用 `--memory-headroom-mib 0` 做无压力控制。完整实参、实际 ELF hash、原始 strace 路径和 SHA 在资源证据内。以下为 Oracle 可直接使用的入口，输出需换成不存在的 private 路径：

```sh
tool=/home/ubuntu/dnsmasq-predeploy-b-resources-20261014/tools
sudo -n sh "$tool/run_isolated.sh" python3 "$tool/audit_integration_resources.py" \
  --image-root /home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity/rootfs-check \
  --rust /home/ubuntu/dnsmasq-audit-fix7-20261014/private/release/dnsmasq-rs \
  --rust-sha256 e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9 \
  --source-commit 58365e8c --kinds memory \
  --output /home/ubuntu/dnsmasq-predeploy-b-resources-20261014/private/replay-memory
```

### B2：procd 的 respawn 不是健康检查，也不是 C 回退

使用未经修改的镜像 init/procd/ujail，实际运行 ELF 从外层 `/proc/PID/exe` 判定；不能拿 jail 内 pidfile 中的 `1` 判断有没有换进程。

- 单次 SIGKILL、SIGTERM：两边均约 5 秒重启，原配置的 DNS 恢复。
- SIGSTOP 后 6 秒：两边 PID 未变，`service list` 仍是 `running=true`，DNS 超时；SIGCONT 后恢复。在所观察窗口没有健康失效检测。
- 重建 procd instance 后连续六次快速 SIGKILL：前五次均重启，第六次等待 7 秒仍无进程，`running=false`、`exit_code=9`；pidfile 残留 jail PID `1`，没有切到 C。

这是可复现的镜像管理策略，支持边界也可静态核对：包内 `dnsmasq.init:1267-1270` 只注册 daemon 和默认 respawn；配方 `Package/dnsmasq/install` 没有回退代理、离线 C 副本或健康确认逻辑。原 C 有相同的挂住/快速退出边界，不能因此称 Rust 与 procd 不兼容。

但项目要求在确认部署前验证自动回滚及客户端健康，当前包和所测流程没有满足该条件。手动回退通过只证明在管理通路、空间和原包都可用时可以恢复；不能保证远端 Wi-Fi 管理下故障后仍能执行这些操作。复现工具：[audit_integration_service.py](../../tools/dnsmasq/audit_integration_service.py)，结果见 [service 证据](audits/20261014/integration/service/summary.json)。未实际测量无限时长的挂住，也未模拟机器重启或外部恢复控制器。

### B3：磁盘已降回 C，活进程仍可能是 Rust

在真实 APK scripts 开启、配置不变的情况下执行：

1. stock C 正常运行，`apk --no-network --allow-untrusted add candidate.apk` 返回 0。
2. 数据库已为 r2，磁盘 `/usr/sbin/dnsmasq` 为 Rust；活进程 `/proc/PID/exe` 仍为 C，路径带 `(deleted)`。
3. 显式 `/etc/init.d/dnsmasq restart` 后才运行 Rust。
4. `apk --no-network --allow-untrusted add stock.apk` 返回 0；数据库 r1、磁盘 C，**活进程仍为 Rust `(deleted)`**。
5. 再显式 restart，运行中 ELF 才为 `097a9e…cab87`，并通过 DNS 健康检查。

原因是两包 `post-upgrade` 均调用镜像 `default_postinst`，由它调用 init `start`；procd 对相同实例描述/配置不必更换进程。stock 同版本重装控制也保留原进程。这是继承行为，已有 M4 文档曾提醒，本轮独立重新证明，不是新发现的 Rust 算法错误。

影响：升级可能未激活修复，回滚可能仍运行故障代码；APK 版本、文件 hash 或 pidfile 单独均不充分。回退验收必须包含显式 restart、外层真实 daemon ELF hash、DNS/DHCP 客户端检查。包测试的健康探针仅是合成 DNS，不替代真实 LAN 客户端验收。[包证据的 `activation`](audits/20261014/integration/package/summary.json)、[复现工具](../../tools/dnsmasq/audit_integration_package.py) `--scenario activation`；证据中保存完整重跑命令。

### B4：空间耗尽时不能保证 APK 回退；当前包体积门限也未通过

使用 16 MiB 私有 tmpfs 承载 overlay upper，填充至可用 **131,072 B** 后执行真实事务。原包与候选 APK 已离线放好；该实验不依赖 DNS 下载，隔离了空间问题。

| 事务 | 返回与结果 |
| --- | --- |
| Rust r2 → C r1 | 返回 1，`failed to extract usr/sbin/dnsmasq: No space left on device`；数据库仍 r2，磁盘与重启后进程仍是 Rust |
| C r1 → Rust r2 | 返回 2，提取失败且数据库写入报 ENOSPC；此采样点仍保留 C，restart 后可运行 |
| C r1 同版本重装控制 | 同样遇到 ENOSPC/数据库写入错误，证明属于 APK/文件系统共有边界 |
| 释放填充文件后重新安装 C + restart | 均恢复原 C ELF，并通过 DNS 检查 |

不能从这一采样点推断任意中断阶段均原子或安全；没有断电、kill apk、UBIFS 或 inode 耗尽实验。**131,072 B 是复现点，不是推荐预留空间阈值**。可靠回退必须提前保证离线原包和可写空间，并检查事务错误，不能把“换回更小的 C 文件”当作不需要额外空间。

本轮完整执行 SDK 的 frozen-ELF 包装，metadata/payload 和包内 ELF 均通过；但是 `build_package.py` 最终在 `size-target` 返回失败：ELF 2,056,672 B、APK 1,118,297 B，超过该次传入的 1,000,000/700,000 B 门限。这里使用其产物进行审计，**不称为全部 release gate 通过**。相较镜像 C 的 269,305 B ELF、155,123 B APK，替换占用明显更大；M4 曾接受的旧 ELF 大小不自动授权当前体积。未测这台路由器当前 overlay 剩余容量。

证据：[package summary](audits/20261014/integration/package/summary.json) 的 build、`full-upgrade/full-rollback/full-stock-reinstall`；[原始证据索引与 SHA](audits/20261014/integration/package/raw-index.json)。用同一 [包故障工具](../../tools/dnsmasq/audit_integration_package.py) 对应 `--scenario`、`--free-bytes 131072` 可重跑；每次须新 private 输出。

### B5：stock ACL 下，ubusd 重启导致 dnsmasq 管理对象消失

初次启动时 C/Rust 均成功注册 `dnsmasq`、`dnsmasq.dns`。在已降权至 UID/GID 453 后重启镜像 ubusd，socket 前后均为 root:root / 0666：两版继续回答 DNS，但重注册出现 `UBus error: Invalid argument`，对象不恢复；重启 dnsmasq 后恢复。这里没有把仅观察几秒直接解释成无限期故障，永久禁用分支另有源码依据。

根因对照：镜像 `/usr/share/acl.d/dnsmasq_acl.json` 的 publish 只允许 `dnsmasq`，不包含 `dnsmasq.dns`。仅在临时 fixture 扩大该 ACL 后，Rust 两个对象可重新注册；C 恢复 metrics 对象，但其 DNS object type 状态还有不同处理。这一 ACL 改动只用于定位，不是产品修复，也没有改原 rootfs。匹配 patched C 的 `src/ubus.c` 和 Rust ubus 实现均检查注册失败并断开；具体源码行见 [bus 分析](audits/20261014/integration/bus/README.md)，控制结果见 [bus 证据](audits/20261014/integration/bus/summary.json)。

影响：系统服务进程还活着并不代表 metrics/订阅管理可用；运维重启 ubusd 后应复查 dnsmasq 对象并重启服务恢复。LuCI 租约列表有读租约文件的独立路径，**不能把 UBus 对象缺失扩大为 LuCI 所有页面失效或 DNS 全断**。这是 C/Rust 共同的 stock 集成限制，未作为 Rust 独有回归。复跑 [audit_integration_bus.py](../../tools/dnsmasq/audit_integration_bus.py) 的 bus suite；包含原 ACL、root 用户控制和临时 ACL 控制。

### B6：日志背压时停止等待策略不同

显式 `log-queries`、`log-async=25`，让合成 `/dev/log` datagram socket 暂不读取：C/Rust 均回答 300/300 次 DNS。部分排空后发送 TERM，C 超过工具的 2 秒等待，被**测试工具**杀掉；Rust 正常退出。不是 procd 杀死 C 的证据，也不能称 C 永远挂住。

Rust `main.rs:1978-1989` 对最终日志 flush 设置约 100 ms 上限；C `src/log.c:457-474` 在连接仍有效时继续等队列排空。Rust 因此可能放弃尾日志，属于源码推断的**疑似诊断损失**；本次没有停机后继续排空 socket，不能确证具体哪一条丢失。该 async 设置不是镜像默认配置，不能外推默认 logd 场景。[资源证据的 logging_defaults 与 boundaries](audits/20261014/integration/resources/summary.json)。

## 3. 已验证的正常路径和恢复路径

| 范围 | 本轮实际覆盖与结果 | 证据 |
| --- | --- | --- |
| 包安装/升级 | 新 APK 同名 dnsmasq r2，提供 dnsmasq-any，保留 libc/libubus 依赖；真实 scripts 执行。C→Rust、候选同版本重装通过；需要显式 restart 的动作单列 | [package](audits/20261014/integration/package/summary.json) |
| 卸载/重新安装/回退 | 卸载停止服务、删除所拥有文件；修改后的 conffiles 保留；缺少 dnsmasq 账户时重新安装重建 453:453，post-install 启动；移除后装 C、直接降级 C 均通过 | 同上 |
| 包兼容资产 | 维持 stock init、ACL、dhcp-script、迁移脚本、UCI conffiles、路径及权限合同；SDK 自动生成 dnsmasq-any，并非配方缺少显式 PROVIDES 就实际遗漏 | 同上及 [metadata](audits/20261014/integration/package/apk-metadata.txt) |
| init/procd/ujail 启停 | 原 init 未加 procfs；jail 内 daemon 能启动、查询，stop 完全退出，无需测试工具补 TERM；检查外层 ELF 与 PID | [service](audits/20261014/integration/service/summary.json) |
| 不改主配置的 reload | 更新 hosts 后 init reload，同一真实进程返回新记录 | 同上 |
| 改主配置的 reload | UCI 修改使生成配置变化，procd 更换实际进程，新 DNS 配置生效；直接 HUP 不重读主配置，两版一致 | [service](audits/20261014/integration/service/summary.json)、[bus](audits/20261014/integration/bus/summary.json) |
| rpcd / LuCI 消费链 | 实际 rpcd UCI staged edit/apply 生效；`luci-rpc.getDHCPLeases` 读到新租约，`getFeatures` 的 19 项相同；不是浏览器点击 LuCI 的 UI 测试 | [bus](audits/20261014/integration/bus/summary.json) |
| ubus 正常合同 | 两个对象存在，metrics 30 个字段名一致；DHCP ACK/release 事件字段一致；未知 reload 方法两者均 Method not found，不把该方法当管理接口 | 同上 |
| odhcpd 合作 | 真 netifd/rpcd/odhcpd 与 veth 客户端完成 DHCPv6 请求；odhcpd 自写 hosts、触发更新后 `m2-dhcp6` AAAA 返回 `fd00:2::7ed`。另测 hosts 原子替换/删除及 DHCP 名称共存 | 同上 |
| 开机顺序的局部行为 | 镜像 S19dnsmasq 早于 S20network、S35odhcpd；调用 boot 钩子时早期 DNS 可用。随后 netifd 就绪及显式 service interface event 参与局部验证；没有宣称完整 boot 已通过 | [service](audits/20261014/integration/service/summary.json) |
| 单次崩溃恢复 | SIGKILL/SIGTERM 后约 5 秒重新启动并恢复查询，C/Rust 一致；见 B2 的上限 | 同上 |
| 租约文件异常 | 缺文件自动创建、父目录缺失、权限、只读 FS、持有 inode、重启恢复、写失败共七组 C/Rust 比较无失败 | [resources](audits/20261014/integration/resources/summary.json) |
| 租约 ENOSPC | **租约所在的** 4 KiB tmpfs 真正填满；两边仍处理 ACK/内存状态，释放空间且不增加 DHCP 请求后，约 59.77/59.82 秒自动重试写入恢复 | 同上 |
| FD 耗尽 | 限至没有空闲 fd，strace 确认 accept/accept4 真正 EMFILE；两边 TCP 超时、局部 UDP 可用；恢复限额后 TCP/UDP 均恢复 | 同上 |

租约 ACK 不等于已经持久化：ENOSPC 到重试成功之间若崩溃，两版都可能丢失尚未写出的租约。这是共同边界，不把“最终恢复落盘”写成压力期间无数据丢失风险。FD 耗尽两边都产生高频失败 accept；本轮没有把次数差异当性能结论。

## 4. 未覆盖范围与结论限制

- **物理路由器完全未操作**。没有确认当前配置、overlay 剩余空间、客户端数量、Wi-Fi 管理链路、内存余量、离线备份或恢复控制器；没有实际部署、重启、刷写和电源故障。
- 不是完整 OpenWrt 内核/硬件启动。验证了原 init boot 钩子和局部 interface 事件、真实 odhcpd 迟到后的链路；没有跑完整 rcS、驱动/无线/防火墙依赖、首次启动 uci-defaults 时序、sysupgrade 配置恢复。
- 没有全局 OOM killer、cgroup 内存压力、内核 slab/fragmentation、长时内存泄漏、全部分配点故障注入。B1 是可重复的进程 ENOMEM，不是实际 AX3000T OOM 概率测量。
- 没有所有 `/tmp` 写满后配置生成/reload 的交错；包 ENOSPC 与租约 ENOSPC 使用私有 tmpfs，不能等价为真实 UBIFS、坏块、只读 overlay、inode 耗尽、断电或中途 kill apk 的事务保证。
- 包事务为 `--no-network --allow-untrusted`；未验生产签名分发、默认信任链、离线下载可达性。没有 fresh 完整源码 SDK 编译，使用经重新核验的当前 release ELF 做 fresh SDK 包装；体积门限失败保留。
- 本轮没有 dnsmasq-full/dhcpv6 变体 solver 对照，没有覆盖所有多实例、helper/script 卡死或崩溃、TFTP、所有自定义 UCI 配置；未执行项不继承旧 M4/M5 的通过结论。
- 没有完整 LuCI 浏览器/UI 测试；已覆盖本镜像真实 rpcd 消费接口及 UCI apply。没有实际 WAN DNS 故障到路由器管理入口的端到端恢复验证。
- 没有证明自动 C 回退和 Wi-Fi 客户端健康确认。因此，即使修复 B1，也仍需补齐 B2 的部署恢复验证，不能仅凭本报告的手动回退通过批准上线。

## 5. 证据和收尾

Git 只收录本报告、独立复现工具、无秘密身份清单和派生结果。镜像、APK、ELF、完整 rootfs、strace 与原始运行日志保存在 Oracle 的 `private/`，没有提交。各 summary 记录原始绝对路径、hash、命令及限制；重跑时须改用全新的 private 输出目录。

| 证据域 | 派生入口 | 复现工具 |
| --- | --- | --- |
| 输入与镜像核验 | [identity](audits/20261014/integration/identity.json)、[rootfs](audits/20261014/integration/rootfs-identity.json) | [audit_integration_identity.py](../../tools/dnsmasq/audit_integration_identity.py) |
| 包/激活/空间故障 | [package](audits/20261014/integration/package/summary.json)、[raw index](audits/20261014/integration/package/raw-index.json) | [audit_integration_package.py](../../tools/dnsmasq/audit_integration_package.py)，正常全生命周期另复用 `m4_package_lifecycle.py` |
| 启停/重载/崩溃/挂住 | [service](audits/20261014/integration/service/summary.json) | [audit_integration_service.py](../../tools/dnsmasq/audit_integration_service.py) |
| ubus/LuCI/odhcpd | [bus](audits/20261014/integration/bus/summary.json) | [audit_integration_bus.py](../../tools/dnsmasq/audit_integration_bus.py)，真实网络场景复用 `actual_config_network.py` / `m2_lifecycle.py` |
| ENOMEM/ENOSPC/EMFILE/日志 | [resources](audits/20261014/integration/resources/summary.json) | [audit_integration_resources.py](../../tools/dnsmasq/audit_integration_resources.py)，租约复用 `m5_lease_recovery.py` |

收尾重新读取 Oracle 的 410 个源码、工具、APK/ELF及原始证据文件，hash 全部匹配；本任务没有残留进程或宿主 mount。全部派生 JSON、审计 Python 语法和报告文件链接有效，产品/配方无改动。[证据清单](audits/20261014/integration/oracle-evidence.json)、[最终检查](audits/20261014/integration/evidence-check.json)。独立交叉复核收紧了“完整载入”和“metrics 值相等”的过度表述，未改变上线结论。

当前只存在 main 任务分支，没有需要删除的过期任务分支。用户原有提示文档和同时进行的其他审计文件不属于本交付，保持原状。
