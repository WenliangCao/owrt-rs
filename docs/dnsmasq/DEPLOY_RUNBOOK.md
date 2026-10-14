# dnsmasq 受监护上线与 ROM C 回退

本流程对应 [上线前审计 B](PREDEPLOY_AUDIT_INTEGRATION.md) 的 B2、B3、B4、B5。目标是在一个受限、可核验的上线窗口内启用 dnsmasq-rs，失败时自动恢复精确镜像的 C dnsmasq。**上线机制通过不等于 Rust 产品的全部上线门槛通过**；B1、资源和协议审计的独立阻断仍须另行处理。

本次只在 Oracle 的精确镜像 rootfs 隔离环境实施和验证；没有操作物理路由器、刷写固件或推送代码。Oracle 用户空间来自目标镜像，宿主内核不等于目标 OpenWrt 内核。物理设备操作须另有明确授权和通过恢复门；Wi-Fi 管理允许，不要求先接 LAN 电缆。

## 1. 支持范围与恢复边界

v1 是**单实例、配置冻结、当前开机周期内有效**的受监护部署。保留磁盘上的 stock C `/usr/sbin/dnsmasq`、原装 init、procd、ujail、ACL、helper 和库。候选 ELF 放在单独路径，以临时 bind mount 激活；不把候选包覆盖安装到 stock 路径。启动参数来自正在运行且已验证健康的 stock ujail 实例。内核、驱动、netifd、odhcpd 等执行组件保持原有行为。

受监护阶段包括试运行和确认后运行。期间不允许 UCI apply、LuCI 修改 DHCP/DNS、包升级、手动执行原 dnsmasq init 的 start/reload/restart、改变网络拓扑，或人工编辑已冻结的配置及其引用文件。需要这些操作时，先回退并交还 stock 管理，再修改和重新准备一轮。正常的租约变化与 odhcpd 生成 hosts 更新继续支持，具体回调在下文说明。v1 不声称覆盖多 dnsmasq 实例、任意外部服务管理操作、固件升级或完整无人值守长期升级。

上线前由操作者按身份清单核验完整固件/rootfs、构建源码及工具 hash；这些完整核验不是控制器自动完成的。控制器在启用候选前：

1. 验证 `/rom` C、可见 stock C、候选的 hash，检查 stock init/odhcpd 回调与 ROM 一致，并拒绝覆盖 stock 路径的预先挂载；拒绝身份不符。
2. 用真实 stock C 验证当前配置、DNS/DHCP 和实际 ELF；准备独立的私有 tmpfs，把回退所需参数、状态和运行目录预先放好。
3. 保存 stock ujail 的完整参数，固定生成的主配置；接管原 procd 实例后，由独立的 root 监护服务拥有并启动该 ujail。引用文件沿用已验证的路径，v1 不会自动快照所有自定义 hosts/helper/配置目录，操作者须保持它们不变；odhcpd 的正常生成 hosts 更新除外。
4. 在候选启动前建立确认期限和监护；监护本身被 procd 重启时只进入 C 恢复路径，不能重新启用 Rust。

回退操作先终止属于该轮的候选进程，再把 `/rom/usr/sbin/dnsmasq` bind 到标准路径，按已准备的 ujail 参数启动 C。它**不执行 APK 事务，不重新生成配置，不需要 overlay 写入，不以 ubus 在线作为启动 C 的前提**。故障回退仅进行一次 C 激活；随后锁定 C，不会反复启动 Rust，也不会因持续探针失败循环重启 C。监护重启时可接管已健康的 C，保持其 PID；已记录的恢复失败不自动重试。

原 `/usr/sbin/odhcpd-update` 通过 `procd_send_signal dnsmasq` 发 HUP；接管删除原服务后，控制器对这个入口加临时 bind shim，转发 `hosts-reload` 请求。监护合并请求、核对实际 ELF 后向自己拥有的 Rust/C 发 HUP，只重读 hosts 等原有可重载数据，不重新生成主配置。shim 在私有 tmpfs 内生成，不增加第四个安装文件；交还或重启后恢复镜像原入口。

断电或重启使临时 bind mount 和该轮授权消失，磁盘上的 stock C 自然恢复。确认不会写入持久的“开机启用 Rust”标记。机器重启后的完整硬件启动、内核死锁、全局 OOM、损坏或不可读取的 `/rom`，不属于本次用户空间自动回退的保证范围。

## 2. 离线备份与身份门

上线前在管理电脑准备好以下离线资料，并实际核验文件能读取、SHA-256 与清单相符。备份、镜像、APK、ELF、完整配置、租约、抓包和原始日志不得提交 Git。

- 原固件与匹配的 stock dnsmasq APK；APK 用于后续人工维护，不参与紧急自动回退。
- 配置备份，包括 `/etc/config`、dnsmasq 引用的自定义配置/hosts/helper、网络和无线配置；包含密钥的备份只保留在访问受限位置。
- 当前租约、配置依赖清单、stock 与候选 ELF hash、工具 hash、路由器型号/版本和恢复入口记录。
- 已验证的恢复步骤与所需凭据；管理电脑离线保留手动回退命令，不能依赖故障后的 DNS 下载。

在已获设备操作授权且仍运行 C 的准备阶段，可用镜像自带的备份入口生成配置归档；`-b` 只创建备份，不刷写固件：

```sh
umask 077
sysupgrade -l
sysupgrade -b /tmp/dnsmasq-predeploy-backup.tar.gz
sha256sum /tmp/dnsmasq-predeploy-backup.tar.gz
```

把归档复制到管理电脑的受限目录，再用本地 SHA-256 对照并用 `tar -tzf` 检查可读性。对照 `sysupgrade -l`，单独备份没有被收录的自定义配置、hosts、helper 和租约。仅把归档留在路由器 `/tmp` 不算离线备份。

精确镜像身份：

| 对象 | 本流程基准 |
| --- | --- |
| 固件 | `openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin` |
| 固件 SHA-256 | `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` |
| root SquashFS SHA-256 | `3f315cf686c9cd951b24881a3a8e0c78448acaad6fd20d2ab6f1003a0e85b1cc` |
| `/rom/usr/sbin/dnsmasq` | stock 2.93-r1 / nodhcpv6；269,305 B |
| stock C SHA-256 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |

本轮隔离验证采用的候选/工具身份：

| 对象 | SHA-256 |
| --- | --- |
| 冻结 Rust ELF，2,056,672 B | `e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9` |
| 最终交付 `dnsmasq-deploy` | `83e8f1a3312e7583b319fc179af6795efae7354ffad5093ad881bd4639f6aef1` |
| `dnsmasq-deploy-lock-init` | `4947f6dab222031a9169fe9cd777e0408f00f6842e5d98d92af64118cdb28ad7` |
| 静态 `dnsmasq-deploy-probe` ELF | `f464051753c2d7fff832949ad5c1dc3010774259009bd77a8b24d9c50c8c00b9` |

[输入核验清单](audits/20261014/deploy/input-identity.json)重新比较了 881 个镜像普通文件、213 个符号链接和候选的 178 个冻结输入；[探针核验](audits/20261014/deploy/probe.json)保留构建与协议检查身份。Rust 的冻结源码对应审计 B 的 `58365e8c8ebe1805573baa02543baf1c9d45be68` 输入，不代表本轮工作区中并行修改后的任意新 ELF 已通过验证。

候选 ELF、构建源码和控制器身份必须使用本轮测试的清单，不能只看版本字符串、文件名或上一轮审计的通过记录。上线前 `/usr/sbin/dnsmasq` 必须仍是 stock C；已被包安装覆盖为 Rust 的系统不满足本流程的“重启回 C”前提，应先在独立维护流程恢复 stock，再重新准备。

```sh
sha256sum /rom/usr/sbin/dnsmasq /usr/sbin/dnsmasq
cmp /etc/init.d/dnsmasq /rom/etc/init.d/dnsmasq
cmp /usr/sbin/odhcpd-update /rom/usr/sbin/odhcpd-update
ubus call service list '{"name":"dnsmasq","verbose":true}'
```

hash 应为上述 stock hash，init 与 odhcpd 回调应和 ROM 相同；最后一项用于检查单实例状态。控制器也拒绝已覆盖 stock 程序/init 路径的现有挂载，避免把临时可见的 C 当成磁盘 C；它会进一步读取真正的 ujail/daemon 进程及生成配置，不以这组预检查代替实际身份验收。

身份验收分为两层：磁盘/ROM/候选文件 hash，以及**真实运行进程**的 `/proc/PID/exe` hash。ujail 内 pidfile 可能为 `1`，不能据此定位宿主进程。APK 数据库版本、`service list` 的 `running=true`、`--version`、进程名均不能代替运行中 ELF 身份。

## 3. 准备与约三分钟观察窗口

控制入口为 `/usr/sbin/dnsmasq-deploy`，协议探针为 `/usr/libexec/dnsmasq-deploy-probe`。先离线安装已核验身份的脚本/探针并赋予 root 执行权限，再准备；安装工具需要可写空间，**已经准备成功后的紧急回退**不需要 overlay 写入。

交付文件是 [控制器](../../tools/dnsmasq/deploy/dnsmasq-deploy)、[临时 init 拦截入口](../../tools/dnsmasq/deploy/dnsmasq-deploy-lock-init)、[探针源码](../../tools/dnsmasq/deploy_probe.c)及其 [Oracle 构建脚本](../../tools/dnsmasq/build_deploy_probe.sh)。探针用匹配 OpenWrt SDK 编译为静态 AArch64 musl ELF；不能把宿主 x86 ELF 或任意 `nslookup`/`udhcpc` 命令代替它。控制器通过现有 procd 动态注册监护服务，不安装开机启用 Rust 的 init 服务。

假设三个已核验的交付文件放在 `/tmp/dnsmasq-deploy-kit`，安装命令如下；只有获得物理设备部署授权后才可在设备上执行：

```sh
KIT=/tmp/dnsmasq-deploy-kit
mkdir -p /usr/libexec
cp "$KIT/dnsmasq-deploy" /usr/sbin/dnsmasq-deploy
cp "$KIT/dnsmasq-deploy-lock-init" /usr/libexec/dnsmasq-deploy-lock-init
cp "$KIT/dnsmasq-deploy-probe" /usr/libexec/dnsmasq-deploy-probe
chmod 755 /usr/sbin/dnsmasq-deploy \
  /usr/libexec/dnsmasq-deploy-lock-init /usr/libexec/dnsmasq-deploy-probe
sha256sum /usr/sbin/dnsmasq-deploy \
  /usr/libexec/dnsmasq-deploy-lock-init /usr/libexec/dnsmasq-deploy-probe
```

逐项对照本轮交付清单的 hash；有任何不符即停止准备。以上是工具安装，不会自动启动候选。

准备阶段必须在 C 仍健康时完成。记录当前客户端接入、默认网关、DNS 服务器和租约；先从管理客户端验证路由器可达、本地 DNS、上游 DNS 和 DHCP。保存当前 stock 实例真实 PID/启动时间/ELF hash，确认只有一个受管 dnsmasq 实例，ROM C 可以读取并执行。接管时会在原 C 完全停止后重新复制最终租约，因此 prepare 到 start 之间获得的租约不会被准备时的旧副本覆盖。

先把下列值换成本轮真实值。`DNS_NAME` 应是当前 C 已能给出确定 A 记录的本地域名，`EXPECTED_A` 是其预期地址；不要用公网域名作为自动回退探针。`DNS_SERVER` 和 `DHCP_SERVER` 使用路由器实际 LAN IPv4 地址，`DHCP_IF` 使用服务该网段的接口。候选文件放在单独路径，不能覆盖 stock C。

```sh
CANDIDATE=/tmp/dnsmasq-rs.candidate
CANDIDATE_SHA256='<本轮候选 SHA-256>'
DNS_SERVER='<路由器 LAN IPv4>'
DNS_NAME='<已有本地 DNS 名称>'
EXPECTED_A='<该名称预期的 IPv4>'
DHCP_IF='<例如 br-lan>'
DHCP_SERVER="$DNS_SERVER"

/usr/sbin/dnsmasq-deploy prepare \
  "$CANDIDATE" "$CANDIDATE_SHA256" \
  "$DNS_SERVER" "$DNS_NAME" "$EXPECTED_A" \
  "$DHCP_IF" "$DHCP_SERVER"
/usr/sbin/dnsmasq-deploy status
/usr/sbin/dnsmasq-deploy start
/usr/sbin/dnsmasq-deploy status
```

start 后应看到 `phase=trial` 且 `live_sha256` 是本轮候选。若已经进入 `fallback`、`recovery-failed` 或 `activation-aborted`，先按状态处理；命令返回或进程存在不等于候选上线成功。

如果 start 的前置健康检查拒绝启动，状态仍为 `prepared` 且实时 ELF 仍是同一个 stock C，说明尚未接管或启动候选。检查 `/run/dnsmasq-deploy/probe_result` 和真实客户端 DNS/DHCP；确认 C 恢复健康后可再次执行 start，或执行 abort 取消。不要修改探针结果或跳过前置门来强行启动。

准备会建立 `/run/dnsmasq-deploy` 的 8 MiB 私有 tmpfs，保存候选、冻结配置、租约和运行目录，并保留 1 MiB 应急空间，回退时释放。另在共享 `/tmp` 预留 256 KiB 和 32 个空文件的 inode，回退时删除这些预留，供原装 ujail 创建启动目录使用；原装 ujail 的 `/tmp/ujail-XXXXXX` 路径是固定的，不能只预留私有 tmpfs。确认后仍保留准备区。容量是当前工具的受限配置，不意味着可以承载任意大小的配置、候选和租约；准备失败时不得继续 start。

如果 prepare 已成功，但尚未 start，需要取消本轮准备，可执行 `/usr/sbin/dnsmasq-deploy abort`。该命令只清理未启动的准备区；试运行后使用 rollback/release。

控制器准备成功后才允许激活候选。确认截止时间默认为启动后 180 秒，以单调时钟计算；启动失败、进程消失或实际 ELF 身份错误触发回退；挂住或 DNS/DHCP 不可用由**连续两轮失败**的协议探针触发回退，中间一次成功会清零失败次数。每轮只执行一个协议探针，监护与确认共享其结果，避免确认分支立即重复运行 DHCP 客户端。

监护循环间隔 2 秒，单轮协议探针有 12 秒绝对期限，启动健康等待的轮询期限为 15 秒；进入最后一轮的探针可能在该轮询期限后结束。协议失败的两轮判定不会延长原定的 180 秒确认截止时间；探针前后都检查截止时间。停止采用 CONT/TERM，并在 1 秒后升级 KILL。确认截止时间和 C 服务完成恢复是两个时间点，实际回退还包含有界停止、启动和健康检查。监护不依赖远端 SSH 会话继续在线。

`status` 输出 `phase`、`reason`、`guard_pid`、`daemon_pid`、`actual_sha256`、`token`、`started` 和 `deadline` 等 `key=value` 字段；`live_pid` 和 `live_sha256` 是查询当时重新读取的实际进程身份，`daemon_pid` / `actual_sha256` 是最近一次监护记录。验收优先检查 `live_sha256`，为空或不符都不能确认。记录本轮 token，持续查看状态并完成下一节的客户端检查。工具只接受启动后 **150 秒至 180 秒之间**的确认；建议约 165 秒时确认，留出操作余量：

```sh
/usr/sbin/dnsmasq-deploy status
/usr/sbin/dnsmasq-deploy confirm '<当前 status 中的 token>'
/usr/sbin/dnsmasq-deploy status
```

一次确认只属于当前会话，不可复用上一轮确认。确认前必须已完成客户端检查，并且控制器当下的进程身份和本地协议探针仍健康。**不要为避免自动回退而跳过客户端检查。** 如果检查没有完成，等待自动回退或手动回退，然后修复原因重做一轮。

确认请求由监护在健康检查通过后接受，截止时间前可等待下一轮健康结果。若 CLI 等待超时，不能据此认为请求已取消；继续查看 status，或明确执行 rollback 取消本轮运行。只有 `phase=confirmed` 且实时候选身份正确，才能记录确认成功。

确认后仍保持健康监护。确认只解除本轮的“未确认自动回退”期限，不关闭崩溃、挂住、DNS/DHCP 检查，也不允许配置变更。重启后回到 stock C；再次启用 Rust 要重新准备和确认。

## 4. 客户端健康检查

控制器的本地健康探针不能替代真实 LAN/Wi-Fi 客户端验收。其 DNS 探针检查 UDP/53 的确定 A 应答；DHCP 探针在指定接口绑定 UDP/68，向本机 DHCP 服务发送 DISCOVER、REQUEST，核对 OFFER/ACK 的事务、客户端身份、server ID、租约地址与正租期，随后 RELEASE。固定合成客户端 MAC 为 `02:64:6e:73:70:01`，不得与真实客户端共用；指定接口上的 UDP/68 存在绑定冲突时准备应失败。

该探针证实本机 DNS/DHCP 协议路径正常，不证明 Wi-Fi、LAN 防火墙和外部客户端都可达。观察期使用至少一个真实客户端完成以下检查，并保留时间和结果；不要同时让所有客户端释放租约。

| 检查 | 通过标准 |
| --- | --- |
| 管理链路 | Wi-Fi/LAN 连接稳定，客户端仍能访问路由器 IP；SSH 或 LuCI 管理入口可达 |
| 本地 DNS | 向路由器地址查询已知本地名称，返回预期地址；UDP 与 TCP 都可查询 |
| 上游 DNS | 向路由器查询正常公网域名并访问实际服务；区分上游故障与本地 daemon 故障 |
| DHCP | 单个测试客户端续租，取得正确网段、掩码、路由器、DNS 与租期；确认收到 ACK，且能继续通信 |
| DHCP/DNS 联动 | 客户端名称在预期范围内可解析；不只检查租约文件存在 |
| IPv6（启用时） | 原有 RA、DHCPv6/odhcpd 与 IPv6 DNS 使用正常；不把 DHCPv4 探针当作 IPv6 验证 |
| 运行身份 | 控制器报告真实运行的 ELF hash 等于本轮候选；不是磁盘文件或包版本 |

若管理会话断开，不应反复尝试确认。监护会在未确认期限届满后自行切回 C。重新连接后先查看状态、真实 ELF hash 和客户端健康，再决定是否重新试运行。

## 5. 手动回退、锁定与交还 stock

手动回退与自动回退走同一路径，不要求卸载 Rust 包、下载文件、写 overlay 或依赖仍正常的 DNS：

```sh
/usr/sbin/dnsmasq-deploy rollback
/usr/sbin/dnsmasq-deploy status
```

rollback 是异步请求。重复执行 status，等待 `phase=fallback` 或 `phase=recovery-failed`；`reverting` 仅表示恢复正在进行。不得刚发出请求就执行 release。

回退成功必须同时看到：

- 本轮进入锁定 C 状态；候选进程已退出。
- 真实运行中 `/proc/PID/exe` SHA-256 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
- DNS 与 DHCP 探针通过，并完成客户端复核。
- 后续观察没有再次启用候选，也没有不断更换 C PID。

回退后的 C 仍由控制器拥有。需要恢复通常的 UCI/LuCI/stock init 管理时，执行单独的 release 操作：停止受控 C，解除本轮临时挂载和接管，显式启动 stock 服务，再核对真实 C ELF 与客户端健康。受控阶段原 `/etc/init.d/dnsmasq` 被临时替换为拒绝操作的入口，原 procd 实例及触发器已删除；不得绕过该保护创建竞争实例。

确认 `phase=fallback`、实时 C hash 和客户端健康后，再执行：

```sh
/usr/sbin/dnsmasq-deploy release
```

release 是恢复普通服务管理的维护动作，需要正常的 ubus、init 和运行时可写空间；空间仍不足或总线尚未恢复时，保留已经正常提供服务的锁定 C，稍后再 release。它不属于无需 overlay 写入的紧急回退路径。

交还动作由监护串行执行；只有 stock C 的实际身份、协议探针和 ubus 对象验证成功后才解除监护。可恢复的交还失败会重新建立受控挂载并恢复 C，返回错误而非伪报完成。若状态仍为 `released` 但清理空闲监护失败，可再次执行 release 清理；若为 `recovery-failed`，必须按恢复入口处理，不能盲目重试循环。

若 C 激活本身失败，控制器报告恢复失败并停止自动重复重启；已运行 C 的协议健康也继续检查，连续两轮失败会记录 `recovery-failed`，不循环重启。保留故障状态和日志，使用既定设备恢复入口。不能把“已发出回退命令”或“包版本为 C”报告为恢复成功。

## 6. B5：ubusd 重启后的对象恢复

精确镜像的 stock ACL 只允许发布 `dnsmasq`，不包含 `dnsmasq.dns`。C 与 Rust 降权后在 ubusd 重启时都可能无法重注册；DNS 仍可正常响应。因此 ubus 对象缺失是独立健康项，不能从 DNS 正常推导管理对象正常。

本流程保持镜像 ACL。监护检测 ubusd 的新一代实例/对象缺失，等待总线重新可用后，对自己拥有的 dnsmasq 执行一次有界的显式重启，使它在降权前重新发布对象。修复后检查 `dnsmasq`、`dnsmasq.dns` 两个对象，以及实际 ELF、DNS 与 DHCP。ubusd 不在线时，不以依赖 ubus 的 init restart 作为紧急 C 恢复路径。

为避免无限重启，每轮只给受控 Rust 一次 B5 修复机会；再次发生或修复失败则回退 C。锁定 C 也只允许一次 B5 修复；修复额度保存在本轮状态中，重启监护不会重置。再失败报告故障，不持续重启 C。扩大 ACL 不是本次修复：此前诊断中扩大 ACL 后 Rust 可重注册，但精确 C 仍有独立的对象类型状态问题，不能据此宣称两版都已修复。

交还 stock 管理后，若运维主动重启 ubusd，应等待总线恢复，显式执行 `/etc/init.d/dnsmasq restart`，检查 `ubus list 'dnsmasq*'` 包含两个对象，再复核实际 C ELF 和客户端 DNS/DHCP。不得只检查 ubusd 或 dnsmasq 进程仍存在。

## 7. Oracle 隔离验证与已知限制

2026-10-14 的 [最终验证汇总](audits/20261014/deploy/summary.json)：**完整矩阵 18/18 通过，最终一行修正的 4 项定向检查通过，共 19 种场景**。完整矩阵执行控制器 `6fe5804c` / `ae4cf7a01cef0f9057350b44c9b744527caa44ef7a58dd0ad1e2d98d992b8c28`；最终交付 `af66fd2d` / 上述 `83e8f1a…` 只增加 B5 恢复成功后清零失败计数。定向检查覆盖该计数序列、Rust/C 两侧正常 B5 恢复，以及 prepare/start 间的新租约。旧计数实现的负控按预期失败，最终实现通过。

| 场景 | 已观察的结果 |
| --- | --- |
| Rust SIGKILL / SIGSTOP | 自动恢复 C，并完成服务验收；分别 6.158 / 12.238 秒 |
| 故意启动即退出的静态故障 ELF | 从 start 调用起 7.214 秒完成 C 服务验收 |
| DNS / DHCP 单独黑洞 | 自动选择 C；移除共同外部故障后，分别 12.239 / 16.298 秒完成服务验收 |
| overlay ENOSPC / 只读 overlay / 共享 `/tmp` ENOSPC | 均无需 APK 恢复 C；分别 6.164 / 5.101 / 6.161 秒完成服务验收 |
| 180 秒未确认 | 自动恢复 C；从 start 调用到完整 C 服务验收 190.487 秒，包含观察窗口 |
| 真实客户端在 154 秒后检查并确认 | Rust 保持到启动后 185 秒以上；随后 SIGKILL，5.354 秒完成 C 服务验收 |
| ubusd 在 Rust / C 运行时重启 | 两侧均显式重启正确程序并恢复两个 ubus 对象与客户端 DNS/DHCP |
| 试运行时杀死监护 | procd 重启监护后回 C，5.156 秒完成服务验收 |
| 回退后再次杀死监护 | 接管现有健康 C，C PID 不变 |
| 手动回退与交还 stock | 实际 C 身份、客户端健康、stock 管理恢复均通过 |
| 交还中真实 `umount` EBUSY | 交还报错，重新建立受控 C 并恢复客户端服务 |
| prepare 到 start 之间分配新租约 | 激活、回退后租约仍在；前置探针拒绝时保持原 C，再健康核验后重试 |
| odhcpd hosts 回调 | Rust/C 均重读新记录，真实 PID 不变 |
| 两次失败之间有成功 B5 恢复 | 成功恢复清零旧失败；后续一次失败不被误算为连续两次 |

“完成服务验收”包含实际 `/proc/PID/exe` 为 ROM C、独立 veth 客户端取得 DHCP OFFER/ACK 和正确 DNS/网关选项、UDP/TCP DNS、两个 ubus 对象及 `phase=fallback`。首次出现 C ELF 的时间在 JSON 中另列。回退后再观察至少 15 秒，未出现重启循环；包数据库保持不变。以上为本轮实测时间，不是覆盖所有负载的硬实时上限。

早期控制器 `9474152b…` 在客户端检查成功后、约 161.5 秒发生过 `health-failed` 回退；旧诊断混合了身份与协议失败，具体根因未被唯一定位。随后改为单轮共享探针、连续两轮协议失败判定、分别记录身份/协议故障，并保持原 180 秒期限；同样的真实租约过期/续租/确认场景已通过。汇总同时保留过短客户端等待、未生效故障注入等测试校准记录与精确工具 hash，没有把这些失败记录隐藏为通过。

Oracle 实验采用独立 network/mount/PID namespace、私有 rootfs overlay/tmpfs 和 chroot。使用镜像的 C、loader、库、init、procd、ujail、ubusd、ACL 和实际生成配置；测试工具不得把模拟 procd、宿主重编 C 或删去 ujail 当成同等证据。原始证据留在 Oracle private 路径，Git 仅保存脚本、无秘密身份清单及派生结果。

DNS/DHCP 单独失效通过临时 nft 输入黑洞注入；它同时影响 C 和 Rust。测试先观察实际进程已切到 ROM C，再移除这个共同外部故障并检查客户端恢复。这证明监护能因协议不可用触发回退，不声称 C 能在防火墙仍丢弃相关请求时提供服务。

复跑入口为 [test_deploy_oracle.py](../../tools/dnsmasq/test_deploy_oracle.py)。在 Oracle 上运行以下命令，输出路径必须不存在；工具自行创建隔离环境，不要在 OpenWrt 设备上执行此测试入口：

```sh
TOOL=/home/ubuntu/dnsmasq-deploy-oracle-harness-20261014/tools
sudo -n python3 "$TOOL/test_deploy_oracle.py" \
  --image-root /home/ubuntu/dnsmasq-predeploy-b-20261014/private/identity-final/rootfs-check \
  --rust-binary /home/ubuntu/dnsmasq-audit-fix7-20261014/private/release/dnsmasq-rs \
  --probe-binary /home/ubuntu/dnsmasq-deploy-probe-20261014/private/build-01/dnsmasq-deploy-probe \
  --deploy-dir "$TOOL/deploy-b5-final" \
  --output /home/ubuntu/dnsmasq-deploy-oracle-harness-20261014/private/replay-new
```

当前工具不带 `--cases` 运行全部 19 种场景，包括新加的 B5 计数回归；需要定向复查时，例如追加 `--cases crash hang startup-failure`。每次重跑仍须使用新的 private 输出路径。该命令选择最终交付控制器，作为完整复跑入口。本轮已执行的完整 18 项矩阵与 4 项最终代码定向检查，按上述源码覆盖分别记录。

原始主矩阵位于 `guard-v2-fast`、`guard-v2-lifecycle`、`guard-v2-unconfirmed`、`guard-v2-confirmed` 和 `lease-preflight-base`；最终代码定向结果位于 `b5-final`、`lease-preflight-final`。精确命令、源码 hash、各原始 JSON 的路径/hash 与收尾检查均在最终汇总内。收尾未遗留测试进程或宿主挂载；镜像、ELF、完整 rootfs 和原始日志继续留在 Oracle private 路径。

未验证物理 AX3000T、目标内核 6.12.94 的完整启动、真实 UBIFS 损坏、断电、全局 OOM/内核阻塞、任意多个并发故障、私有准备区被特权进程破坏，以及全部配置/helper/多实例组合。共享 `/tmp` 的字节空间耗尽与 inode 耗尽是不同条件；没有对应实验就不能互相替代。特别是交还过程中同时失去 ubus，或监护恰在 C 启动交接的指令间再次终止，可能进入 `recovery-failed`；“不无限重试”不能解释为所有损坏都必定自动恢复。
