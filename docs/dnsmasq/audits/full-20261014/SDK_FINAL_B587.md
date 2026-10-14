# b587：真实 SDK 源码构建与同包生命周期

2026-10-14。冻结源码 `b587282081b72ea0f96cf909e0f70b0bc8de9372`，tag
`audit/dnsmasq-merge-b5872820-20261014`。**真实 SDK prepare、源码 compile、strip 和
APK 包装成功；该同一包的 14 阶段生命周期，以及 stock/Rust procd 下两套真实
veth DHCP/UDP/TCP 验收均通过。** 全部协议、资源和总线资格由主审另行绑定下列
同一产物，不能由本页包验收替代。

## 最终身份

| 产物 | 字节 | SHA-256 |
| --- | ---: | --- |
| SDK strip 前 `.pkgdir` ELF | 2,126,304 | `56bdfd13b8e3ec24aaea410f045fb1eb77fba3a0fcfeec040f9b59d6394b39c4` |
| r4 APK 提取的 strip 后 ELF | 2,124,571 | `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c` |
| dnsmasq-2.93-r4.apk | 1,154,800 | `880050e82f81ad3dff27dac9716f15f7e167346750a4c8c197e9fe8ce6001742` |
| 包内 init | — | `70fb3c6bd057c6981503138b91292182f07c9a0d5aa1aaf0454c34af4ca746f0` |
| 包内 ACL | — | `8bedbcdd3018c17f272f0d3ecf9573aa6f05253806cb8812ebf92e9b87ac6020` |

Oracle 根目录为 `/dev/shm/full-merge-sdk-b5872820-20261014/`；产物位于
`source/private/sdk-source-build/`，包内文件从其 `payload/` 读取。
完整 Git source 为根下 `source/`；实际送入 SDK 的快照为输出下 `source/`。

660 个 Git archive 文件逐项 SHA 核对。build 工具锁定 179 个产品/包输入，SDK
prepare 后再对 162 个组件文件逐项复核。输入 digest：
`3c9a37d5e5f5db8b2f1c098abba3144b0eb04b312539ca0b1a6177d5bfa8214c`。
源文件与 106 个 SDK 工具输入前后未变化，包 recipe 在退出后恢复原状。

## 真正源码构建，没有 frozen ELF 替代

匹配 SDK 为 OpenWrt 25.12.5 mediatek-filogic gcc-14.3.0 musl，archive SHA
`ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25`。
Rust 1.98.1，opt3、feature-off、LTO、panic abort、AArch64 musl static PIE；参数由
冻结 recipe 指定，完整 cargo/rustc/编译器版本和 argv 保留。

使用新的 task source、package-build、output 和 TMPDIR。没有设置
`OWRT_DNSMASQ_FROZEN_ELF`，没有复用旧 dnsmasq target，也没有通过复制已有 ELF
冒充编译。SDK `prepare` 和 `compile` 均返回 0；compile 日志实际包含正常
`rstrip.sh` / `sstrip -z` 调用。安装阶段 `.pkgdir` 先被复制为 ipkg，再 strip，
因此其保留副本提供上表的 pre-strip 身份。正常 `CONFIG_AUTOREMOVE` 保留，
SDK 自动清理可重建 Cargo target，避免额外占用 Oracle 空间。

首次构建尚未有可预知的最终 ELF SHA。private 测量驱动复用冻结工具的 source
snapshot、SDK 哈希、recipe 锁/恢复、payload、metadata、ELF 和体积审核函数，
记录新测量身份并标记 runtime pending，没有伪造“已预验的 expected SHA”。
未修改冻结产品或 repo 构建工具；随后实际生命周期均使用这一新 SHA。

原 ELF≤1,000,000 B/APK≤700,000 B 数字门仍失败，原错误独立保留在
`historical_size_gate`。这不等于源码编译失败；F7 对既有用户授权、实际增量和
设备预算另作工程判断。本页不创造新体积上限，也不转签旧产物的特批。

此前 b337 构建在源被后继修正前完成，只是[保留的中间产物](SDK_INTERIM_B337.md)。
其 initial measurement FileNotFound 和追加审计均未覆盖；本次是新源、新目录、
新编译与新 APK，未继承 b337 的任何 runtime 结论。只执行一次本次源码构建，
没有声称两次 clean build 可逐字复现。

## 同一个 APK 的实际安装与客户端

`m4_package_lifecycle.py` 同时启用 `--automatic-activation --dns-object-acl
--ubus-directory-mount`。严格核对包内 init 只有 `$PROG` 跟踪和精确只读 ubus
目录替换，ACL 只有指定 `dnsmasq.dns` publish；其余 ancillary 字节保持合同。
原 SDK post-install/post-upgrade 脚本仍与 stock 相同。

**14 阶段全部通过**，包括 C→r4、相同字节重装、卸载、缺账户首装、卸载后回 C、
直接降 C、实际已接受 M5 r2→r4、直接降 M5 和卸载后恢复 M5。数据库/文件所有权、
修改后的 conffiles、账户、启动链接、实际 ujail/daemon 身份和 UDP/TCP 全部核验。
镜像 APK 的版本比较器确认 r4 大于 r2 与 r3。

唯一手动 restart 仍是建立两个未修旧包之间的 `stock-to-m5-baseline`；它在收据
中明确标为 legacy setup，不是候选激活。所有涉及新候选的升级、重装和降级均
没有补 restart；不能把这一步准备称作所有旧包都已自动激活。

另在 stock procd 与当前 Rust procd（`9db9917e…`）下各执行 **8 阶段真实 veth
客户端**。通过实际 APK 安装使最终 init/ACL 生效，没有只复制 ELF 替代包行为。
每阶段均取得 OFFER/ACK，核对网关/DNS 选项、UDP/TCP DNS；记录数据库、磁盘、
实际运行 ELF/PID/启动时钟。正常升级/直接降 C 三层身份一致，同字节重装和未改
reload 保持 PID。两组均没有显式 restart，也没有结束后残留 daemon。

## 失败事务仍然单独报告

两套 procd 均测到相同坏包边界：截断 APK 在提取可执行文件时失败，数据库中的
dnsmasq 项消失，但原磁盘与活进程仍是最终 Rust ELF，客户端仍健康。随后的离线
stock **修复安装** 恢复数据库/磁盘/运行 ELF 与客户端 C；它不能被命名为成功
降级。正常直接降级已经在故障之前独立验证。

本页不声称任意中途 kill、断电、满闪存或 UBIFS 事务原子性。已有 F4 ENOSPC
实验与[失败恢复边界](F4_PACKAGE_ACTIVATION.md)保持原身份，不冒称在本最终包
重跑。最终系统恢复门和真实无线客户端资格仍是其它工作。

## 最终包 ELF 的一次真实回退中断

另以最终 strip 后 `50e591a9…` ELF、trial 脚本
`dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74`
新执行 `confirmed-rollback-killed`。这次使用精确镜像 stock init、C procd/
ubusd/logd/netifd/ujail，属于 **ELF-only trial**，没有安装 r4 包，不能称为整包
trial 或最终 Rust 九组件共存资格。

候选确认后仅剩 watch；ptrace 在真实 bind mount 已卸载、尚未执行恢复 restart
的系统调用窗口发送一次 SIGKILL。原始见证为 `phase=unmounted`、`mounted=false`、
`helper_files=[watch.pid]`，被杀 rollback 退出 -9。存活 watch 自动接续，实际运行
ELF 回到精确 C `097a9e21…`，独立 veth 再取得 DHCP OFFER/ACK 与正确网关/DNS
选项，UDP/TCP 查询通过；只有恢复后 helper 才清除。候选阶段的同一客户端检查
也通过，未用进程存在替代协议健康。

该原始资料单独归档为
`private/final-sdk-b5872820-20261014/trial-final-evidence.tar.gz`，SHA-256
`3aa932738d659b1777b0556a03b2a50e8dbff5de253781712f50ed6eaa6e3a0c`，35,078 B，
本机复算一致；见同一 JSON 的 `final_elf_trial`。这只关闭列明的一次中断窗口，
不声称两个恢复 owner 同时失效、所有信号交错或硬件故障均能恢复。

## 同一组合源码的 Linux 单测

另从 b587 exact Git source 的 components 构建三份独立 musl 测试 ELF，验证 F10
新增字段/hosts 状态与 F5 runtime 共同编译后的实际测试结果；没有重编最终 daemon
或 APK，也没有改变冻结源。构建前后各核对全部 660 个 archive 文件，均一致。

经 owner 明确交接后，复用 `/dev/shm/full-integrated-fix-20261014/target`，持有其
`.dnsmasq-build.lock` 直到三份测试 ELF 拷贝并核 hash 完成；没有 cargo clean 或
删除其它任务缓存。沿用原 helper 的 SDK musl linker、remap/RELRO 等 flags，
`CARGO_INCREMENTAL=0`、构建 jobs=1、私有 TMPDIR。每份测试独立进入 network/
mount/PID namespace，再挂私有 tmpfs `/tmp`，以 `--test-threads=1` 顺序运行。

| 测试 ELF | 通过 | 忽略 | 失败 |
| --- | ---: | ---: | ---: |
| lib | 808 | 20 | 0 |
| bin dnsmasq-rs | 81 | 3 | 0 |
| hosts_allocations | 16 | 0 | 0 |

这 23 个 ignored 未执行，不算通过。allocator 注入是独立测试制品，不冒称最终
release 进程所有分配点已经穷举。三份 ELF SHA、完整编译日志、每次串行执行命令/
日志和源身份保留在同一 JSON 的 `combined_source_tests`，原始归档为
`private/final-sdk-b5872820-20261014/unit-tests-evidence.tar.gz`，31,805,101 B，SHA
`fc4fc09593b4dc7d1b95061258d3c83ac4bb69015ef4f1955359ede937b9e2d6`。本机重新
校验归档及其中三份 ELF；收尾没有测试进程，原共享锁已释放。

## 保全和范围

[完整派生身份与执行收据](sdk-final-b587.json)。原始源码/SDK 输入、命令、日志、
APK、pre/post-strip ELF、包文件、事务输出、客户端观察和 rootfs 身份已归档到
持久主仓库 `private/final-sdk-b5872820-20261014/sdk-package-evidence.tar.gz`，
SHA-256 `19f39b3867d3ad7d2dc44a35c5c2c6d5c6f61b62b9bb6ab70fe36bd753923ff5`，
11,008,429 B，本地重新核算一致。可重建 rootfs/overlay 不入归档。

本任务收尾没有自有进程或宿主挂载。未操作物理路由器、未 push，报告提交到
独立 F4 分支；最终主分支合并由 root 按完整资格决定。
