# AX3000T stock / OpenWrt 25.12.5：控制面源码预期

> I0.2 状态：完成
> 日期：2026-08-30
> 性质：`SRC` 定向检查清单，不是 `RUN` 行为报告。

## 1. 用途和证据限制

本报告在精确 buildroot、feeds 和组件 commit 上恢复现有控制面的入口、配置、IPC、调用者、
失败边界和生成物。它回答“下一阶段应该去镜像和运行态检查什么”，不把源码中存在的路径
冒充为设备已经执行过的路径。

源码固定情况见 [SOURCE_BASELINE.md](SOURCE_BASELINE.md)，设备配方见
[DEVICE_BUILD_RECIPE.md](DEVICE_BUILD_RECIPE.md)。

## 2. 组件、构建选择和安装面

以下 package version 来自目标 SquashFS 的 APK database；revision、patch 和 flags 来自匹配
buildroot/feed。除 ucode 外，列出的 8 个 buildroot 组件 package 目录没有 OpenWrt package
patches。

| 组件 | 镜像 package | 精确源码 | 构建/feature 选择 | 关键安装面 |
|---|---|---|---|---|
| procd | `2026.03.13~58eb263d-r1` | `58eb263d5abe03f8c1280bdfa65a3b052614215d` | LTO、PIE；`EARLY_PATH=/usr/sbin:/usr/bin:/sbin:/bin`；镜像选择 jail、seccomp、utrace | `/sbin/{init,procd,askfirst,udevtrigger,upgraded,reload_config,service}`、hotplug JSON、`procd.sh`、ujail/seccomp |
| ubus/ubusd | `2026.06.28~24864e78-r2` | `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` | LTO、PIE；ABI `20251202`；Lua path 编译但目标不以 Lua binding 为主线 | `/sbin/ubusd`、`/bin/ubus`、`libubus.so.*` |
| uci | `2025.12.02~66127cd7-r1` | `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8` | ABI `20250120`；目标非 debug | `/sbin/uci`、`libuci.so.*`、UCI defaults |
| rpcd | `2026.06.04~28faf640-r1` | `28faf6403792d25b9826043aaf37880624c19568` | PIE；target link `-lcrypt`；选择 file、iwinfo、rpcsys、ucode 和 LuCI/rrdns 模块 | `/sbin/rpcd`、init/config、ACL、`/usr/lib/rpcd/*.so`、`/usr/share/rpcd/ucode/luci` |
| netifd | `2026.02.26~cbb83a18-r1` | `cbb83a1857407a28a63dc09412a1f209195914ef` | LTO；`libnl-tiny`；`-DDEBUG=1` | `/sbin/netifd`、proto/device scripts、hotplug、`/lib/netifd/*` |
| firewall4 | `2025.03.17~b6e51575-r2` | `b6e5157527d361f99ad52eaa6da273cb0f2dfd59` | 无 C 编译；将上游 `root/*` ucode/templates 原样打包 | `/sbin/fw4`、`/usr/share/firewall4/*`、nft include/config/init |
| odhcpd | `odhcpd-ipv6only 2026.06.29~5d7be43f-r1` | `5d7be43f8b9dec0eb47e245cfab81108bb131273` | PIE；`-DUBUS=1`；没有 `-DDHCPV4_SUPPORT=1` | `/usr/sbin/{odhcpd,odhcpd-update}`、init、defaults |
| uhttpd | `2026.06.16~7b1bec45-r1` | `7b1bec45826bd78c8afc993435bdc0f1df2fe399` | PIE；目标只安装 ubus plugin，没有 Lua/ucode plugin | `/usr/sbin/uhttpd`、init/config、`/usr/lib/uhttpd_ubus.so` |
| ucode | `2026.01.16~85922056-r1` | `85922056ef7abeace3cca3ab28bc1ac2d88e31b1` | ABI `20230711`；目标模块由 package deps 选择 | `ucode`/`ucc`/`utpl`、libucode、fs/log/math/nl80211/rtnl/ubus/uci/uclient/uloop 等模块 |
| LuCI | `luci-base 26.180.75667~128a781` | feed `128a7812f4be233c5dd7f7466f534fd888785caf` | `luci-base` 为 no-LTO；`luci-light` 选择 uhttpd、ubus proxy 和 rpcd rrdns | ucode dispatcher/templates、ACL/menu、JS、CGI、`rpcd-mod-luci` |

ucode 的五个 OpenWrt patches 是：

1. `100-add-include-for-older-kernels.patch`；
2. `110-uloop-allow-reusing-the-existing-environment.patch`；
3. `111-uloop-add-optional-setup-callback-to-process.patch`；
4. `120-ubus-fix-refcounting-bug.patch`；
5. `121-ubus-avoid-double-close-of-externally-owned-channel-.patch`。

后四项改变 uloop process environment/setup callback 和 ubus channel 的 ownership/refcount 行为，
因此 ucode 不是单纯“页面模板解释器”；它是 fw4、LuCI、netifd scripts 和 rpcd plugin 的执行
substrate，这些补丁属于兼容边界。

## 3. 启动与生命周期预期

### 3.1 procd / ubusd

源码状态机预期：

```text
PID 1 /sbin/init
  -> EARLY: hotplug/coldplug
  -> UBUS: 启动 /sbin/ubusd
  -> INIT: 解析 /etc/inittab，执行 sysinit/respawn/askconsole/askfirst
  -> RUNNING
  -> SHUTDOWN/HALT
```

若 `ubus` 用户存在，procd 以该用户启动 ubusd。procd 连接 ubus 失败后从 50 ms 开始退避，
上限 1 s，并在成功后注册 `hotplug`、`service`、`system`、`watch`。这定义了“ubus 暂时不可用”
的恢复预期，但设备实际重连时序仍需 `RUN` 证据。

### 3.2 其他 daemon

- rpcd 启动时必须连接 ubus，然后注册内建对象和动态插件；无效 timeout 或无法连接 ubus
  会使启动失败。
- netifd 先建立 UCI/ubus/netlink 上下文，再读取 board/device/interface/IP/rule/global 配置；
  network 配置读取失败是关键启动失败。
- firewall4 由 procd init script 启动/重载，不常驻；它生成 nft ruleset 并交给 `nft`。
- odhcpd 订阅 netifd 状态；ubus 初始化失败时每 1 s 重试，除非取消。
- uhttpd 由 init script 把 UCI `uhttpd` 转为命令行参数并加载选中的动态模块。

## 4. 配置 reader、writer 与状态文件

| 组件 | 读取 | 写入/派生状态 | 锁、提交或 reload 语义 |
|---|---|---|---|
| UCI/libuci | `/etc/config/*`；delta `/tmp/.uci` | package config、save delta | config dir 0700、file 0600；`save` 不等于 `commit`；支持 revert/import/export/batch |
| procd | inittab、init scripts、service JSON、hotplug JSON、firmware metadata | service/runtime state、watchdog/system actions | `service set/add/delete/update_*` 改变 procd state；`reload_config` 发出配置变化 |
| rpcd | `/etc/config/rpcd`、ACL JSON、shadow/passwd、plugin directories | `/var/run/rpcd/sessions`、per-session UCI dirs、apply snapshots | 默认 session 300 s；UCI apply 默认 60 s，可 confirm/rollback |
| netifd | UCI `network`、board config、procd service data、netlink | kernel network state、runtime interface/device data | reload 重建配置；失败可能留下既有执行面状态，必须差分验证 |
| firewall4 | UCI `firewall`、netifd ubus、procd `service.get_data`、nft includes | `/var/run/fw4.state`、nftables ruleset | `/var/run/fw4.lock` 串行；restart 先 `nft -c`；校验失败不应用 |
| odhcpd | UCI `network`/`dhcp`，可选 `system` timezone；netifd dump/events | lease/state files，经 temp file 再替换 | UCI/ubus/SIGHUP 触发 reload；目标 variant 不含 DHCPv4 server 代码 |
| uhttpd | UCI `uhttpd`、cert/key、HTTP request | socket/HTTP response；必要时生成证书 | module `dlopen`/参数错误可阻断实例；script/network timeout 分开 |
| LuCI | menu/ACL JSON、UCI、ubus replies、HTTP env/body | session、UCI mutations、HTTP output | apply/confirm/revert 通过 rpcd UCI API；认证和 ACL 先于受保护调用 |

生成文件必须追踪输入和 owner，不能仅按最后路径归属：

| 输出 | generator/owner | 主要输入 |
|---|---|---|
| `/etc/config/network` 初始内容 | board scripts / UCI defaults | board name、DTS/board data、MAC |
| procd service instance state | init scripts + `procd.sh` | UCI、package defaults、runtime detection |
| netifd protocol/device state | netifd + proto scripts | UCI network、hotplug、netlink、ubus |
| nft ruleset | fw4 `utpl`/ucode，最终由 `nft -f` 应用 | UCI firewall、network dump、service data、include files |
| `/var/run/fw4.state` | fw4 | 本次解析/应用结果 |
| odhcpd lease/state files | odhcpd | UCI、netifd state、protocol packets |
| `/var/run/rpcd/sessions` | rpcd session subsystem | login/session RPC |
| `/var/run/rpcd/uci-*` 与 snapshots | rpcd UCI plugin | session-scoped changes、apply/confirm/rollback |
| uhttpd argv/cert | uhttpd init script | UCI uhttpd、system hostname、cert defaults |
| UCI `uhttpd.main.ubus_prefix` | `uhttpd-mod-ubus` 的 `00_uhttpd_ubus` default | 首次启动的 UCI-default 阶段 |

## 5. IPC provider catalog

方法名来自目标 revision 的注册表。参数 policy 与返回 schema 要在 I0.5 逐方法整理；此处只
建立 I0.3–I0.5 的静态搜索边界。

### 5.1 ubusd transport

- 默认 Unix socket：`/var/run/ubus/ubus.sock`；
- ACL directory：`/usr/share/acl.d`；SIGHUP reload；
- protocol handlers：`PING`、add/remove object、lookup、invoke、status/data、subscribe/
  unsubscribe、notify；
- 权限检查包括 publish、access、subscribe、listen、send；
- ACL owner/permission 不正确或 JSON parse 失败时拒绝加载对应规则。

规范状态包括 OK、invalid command/argument、method not found、not found、no response、
permission denied、timeout、not supported、unknown error、connection failed、no memory、parse
error 和 system error。调用者必须保留这些类别，而不是统一压成布尔失败。

### 5.2 procd objects

| object | source 注册的方法 |
|---|---|
| `service` | `set`、`add`、`list`、`delete`、`signal`、`update_start`、`update_complete`、`event`、`validate`、`get_data`、`set_data`、`state`、`watchdog` |
| `container` | `set`、`add`、`list`、`delete`、`state`、`get_features`、`console_set`、`console_attach`；仅 jail 支持启用时 |
| `system` | `board`、`info`、`reboot`、`watchdog`、`signal`、`validate_firmware_image`、`sysupgrade` |

procd 还发布 service/system 相关通知并维护 ubus watcher；事件名、payload 和真实出现顺序留给
I0.5/I0.7。

### 5.3 rpcd objects

| object/module | 方法 |
|---|---|
| `session` | `create`、`list`、`grant`、`revoke`、`access`、`set`、`get`、`unset`、`destroy`、`login` |
| `uci` | `get`、`state`、`add`、`set`、`delete`、`rename`、`order`、`changes`、`revert`、`commit`、`apply`、`confirm`、`rollback`、`reload_config` |
| `rc` | `list`、`init` |
| `file` | `read`、`write`、`list`、`lstat`、`stat`、`md5`、`remove`、`exec` |
| `rpc-sys` | `packagelist`、`password_set`、`upgrade_test`、`upgrade_start`、`upgrade_clean`、`factory`、`reboot` |
| `iwinfo` | `devices`、`info`、`scan`、`assoclist`、`freqlist`、`txpowerlist`、`countrylist`、`survey`、`phyname` |
| `luci-rpc` | `getNetworkDevices`、`getWirelessDevices`、`getHostHints`、`getDUIDHints`、`getBoardJSON`、`getDHCPLeases` |
| `network.rrdns` | `lookup` |

rpcd 从 `/usr/libexec/rpcd`、`/usr/lib/rpcd` 发现 exec/shared-library plugin；exec plugin 先以
`list` 获取 signature。`rpcd-mod-ucode` 再从 `/usr/share/rpcd/ucode/*` 动态创建对象；目标
镜像的 LuCI backend 位于该目录。

认证边界：ACL 来自 `/usr/share/rpcd/acl.d/*.json`；全零 session id 只获得 unauthenticated
group；`$p$USER` 密码引用系统 passwd/shadow 后使用 `crypt()` 校验。

### 5.4 netifd objects/events

| object | 方法 |
|---|---|
| `network` | `restart`、`reload`、`add_host_route`、`get_proto_handlers`、`add_dynamic`、`netns_updown` |
| `network.device` | `status`、`set_alias`、`set_state`、`hotplug_event`、`stp_init` |
| `network.interface` 及各 interface object | `up`、`down`、`renew`、`status`、`prepare`、`dump`、`add_device`、`remove_device`、`notify_proto`、`remove`、`set_data` |

netifd 发出 `network.interface` 事件，并通过 procd `service.get_data` 读取
`network-device`/`network-interface` 类型的服务数据。

### 5.5 firewall4 与 odhcpd

fw4 不是 ubus provider，主要是 caller/command：`start`、`reload`、`stop`、`flush`、`restart`、
`check`、`print`、`reload-sets`、`network`、`device`、`zone`。它调用
`network.device.status`、`network.interface.dump`、`service.get_data`，最后执行 nft CLI。

目标 `odhcpd-ipv6only` 注册：

- `dhcp.ipv6leases`；
- `dhcp.ipv6ra`；
- `dhcp.add_lease`。

`dhcp.ipv4leases` 在 `DHCPV4_SUPPORT` 条件内，目标 variant 没有编译它。后续若观察到该方法，
应登记为源码/部署冲突，而不是修改预期。

### 5.6 HTTP / LuCI

`uhttpd_ubus.so` 提供 HTTP `/ubus` 的 JSON-RPC call/list，以及 REST-like get/list/subscribe/
call 路径。受保护调用先调用 `session.access`；`no_ubusauth` 可绕过认证，但默认配置未启用。
插件注入 `ubus_rpc_session` 并拒绝重复字段。

解包后的基础 `/etc/config/uhttpd` 仍把 `ubus_prefix` 留在注释中；同一镜像安装的
`/etc/uci-defaults/00_uhttpd_ubus` 会在设备首次 UCI-default 阶段启用它。因此 `/ubus` 是明确的
部署预期，但是否已生成、当前值是什么仍需运行态读取配置确认。

目标镜像没有 `uhttpd-mod-lua` 或 `uhttpd-mod-ucode`。LuCI 实际静态入口是 660-byte 的可执行
`/www/cgi-bin/luci`：

```text
#!/usr/bin/env ucode
HTTP CGI env/body -> luci.http -> luci.dispatcher -> ubus/rpcd/UCI -> HTTP response
```

镜像虽包含 `/usr/share/ucode/luci/uhttpd.uc`，但没有 `/usr/lib/uhttpd_ucode.so`，因此不能把
该文件存在解释为 uhttpd ucode-plugin 路径。`/etc/config/uhttpd` 中的 legacy `lua_prefix` 也
没有对应 Lua plugin；目标执行路径以 CGI 文件和已安装插件为准。

## 6. Caller graph 与控制权传播

```text
init/procd
  -> ubusd
  -> init scripts / service instances
       -> netifd -> netlink / protocol helpers -> kernel network state
       -> odhcpd <- network.interface dump + events
       -> fw4 -> network/service ubus -> ucode template -> nft -c/-f -> nftables
       -> rpcd -> UCI / ACL / plugins
       -> uhttpd -> CGI LuCI + /ubus proxy

browser
  -> LuCI CGI (ucode dispatcher)
       -> rpcd session/ACL
       -> rpcd UCI and LuCI modules
       -> netifd/system/service methods
  -> /ubus JSON-RPC proxy

UCI writer
  -> commit/apply/reload_config
       -> procd config-change triggers
       -> relevant service reload/restart
```

关键 caller/owner：

| 被调用面 | 已识别 caller | 需要保持的边界 |
|---|---|---|
| ubusd | procd、rpcd、netifd、odhcpd、uhttpd plugin、fw4、LuCI | socket、ACL、status、timeout/reconnect |
| UCI | CLI、rpcd UCI、netifd、fw4、odhcpd、LuCI | save/commit/apply/rollback、未知字段、多 writer |
| procd service/system | init scripts、netifd、fw4、rpcd/LuCI、sysupgrade tooling | lifecycle、事件、validation、watchdog、失败传播 |
| netifd | fw4、odhcpd、LuCI/rpcd、hotplug/proto scripts | object names、events、partial state、netlink errors |
| nftables | fw4 templates/CLI、include files | atomic validation/application、ruleset ownership |
| rpcd session/ACL | LuCI CGI、uhttpd ubus proxy、其他 JSON-RPC clients | session id、ACL、expiry、error mapping |

此图证明已识别主要静态 caller，不证明部署中所有动态 object、第三方 client 或调用顺序；
这些未知项进入 I0.5/I0.6。

## 7. Failure boundary catalog

| 边界 | 源码行为 | 后续必须验证 |
|---|---|---|
| procd -> ubus | 50 ms 至 1 s 退避重连 | 实际启动/重启期间事件是否丢失、实例是否重注册 |
| ubusd ACL | owner/mode/JSON 错误拒绝规则；每类操作独立授权 | 镜像 ACL 文件属性、实际拒绝 status |
| libubus call | timeout、abort/cancel、connection failure 分离 | 各 caller 是否保留错误类别和超时 |
| UCI parse/I/O | memory、invalid、not found、I/O、parse、duplicate、unknown | malformed/partial write、并发 writer、字节保留 |
| rpcd startup/plugin | ubus 不可用或 timeout 非法使 daemon 失败；plugin discovery/registration 可失败 | procd respawn、部分 plugin 缺失、ACL reload |
| rpcd UCI apply | session snapshot、60 s 默认确认窗、confirm/rollback | reboot/crash/超时下是否恢复原始 bytes 与 service state |
| netifd config | network UCI load 失败为 critical；netlink/helper 错误可造成部分状态 | 旧 state 是否保留、reload 是否幂等、失败 blast radius |
| fw4 generation | invalid section 可 warning/skip；restart 先 `nft -c` | warning 是否导致静默策略缺失；旧 ruleset 是否保持 |
| fw4 include | ucode/nft include 与 script include 都可能失败 | failure 是 warning、fatal 还是部分成功 |
| odhcpd ubus | 初始化每秒重试；statefile write 失败记录 error | netifd 消失/恢复、临时文件与最终文件一致性 |
| uhttpd module/script | `dlopen`、parse、CGI timeout、network timeout、JSON parse/access error | 实际 HTTP status/body、child termination、connection cleanup |
| LuCI/rpcd auth | login/access/session expiry/ACL failure | CSRF/session/permission 对 HTTP 和 ubus status 的映射 |
| sysupgrade | stock checker/UBI names错误会影响可启动性 | 仅离线 fixture；物理设备前必须恢复 gate |

这些失败边界阻止现在直接设计替代 daemon。至少要在 I0.5 建立 schema/调用级合同，在 I0.6
将静态不可回答的问题写成无副作用观测项。

## 8. 闭源与保留执行面

MT7981/MT7915 firmware、EEPROM/calibration data、boot firmware 和 NAND/NMBM 属于硬件/boot
执行面。默认保留 Linux 6.12.94、MediaTek drivers、nftables、Wi-Fi firmware、MTD/UBI 和
bootloader。控制面调查聚焦于它们已有的 UCI、ubus、netlink、file 和 CLI 接口，不将 blob
逆向作为 I0.2 或首个 Rust 切片的前置条件。

## 9. I0.3–I0.6 定向检查清单

### I0.3 / I0.4：部署一致性

- [ ] 把上述每个 executable、script、module、ACL/config 路径与 APK file list 对齐；
- [ ] 确认 procd jail/seccomp、rpcd module、ucode module 的文件/依赖闭包；
- [ ] 确认目标没有 uhttpd Lua/ucode plugin，CGI shebang/interpreter 可解析；
- [ ] 完整列出 init scripts、triggers、respawn/watchdog、owner/mode/capability；
- [ ] 将 fw4 templates、LuCI ucode/JS、netifd helpers 标记为可执行控制面，不漏算非 ELF；
- [ ] 生成 package → recipe → source → patch → installed file 映射。

### I0.5：静态接口合同

- [ ] 对每个 ubus method 提取 blobmsg policy、required/optional field、reply schema 和 status；
- [ ] 对每个 init script 提取 START/STOP、trigger、command、user/jail/limits/respawn；
- [ ] 对 UCI 追踪 config source、consumer、writer、reload/restart 和 unknown-field preservation；
- [ ] 对 fw4、netifd、odhcpd 追踪部分失败与旧 state 保留语义；
- [ ] 对 LuCI/HTTP 追踪 session、ACL、CSRF、ubus error 到 HTTP response 的映射；
- [ ] 区分 static object/method 与 runtime object/instance/event。

### I0.6：运行态问题

- [ ] 只为静态无法证明的 object、payload、时序、timeout/retry 和故障恢复设计观测；
- [ ] 每个命令先经源码审查，确认不会 scan/renew/reload/commit；
- [ ] 原始输出留在 private evidence，Git 只接收复核后的脱敏派生结论；
- [ ] 在新授权前不连接设备，不读取 flash/U-Boot env，不调用写方法。

## 10. I0.2 结论

I0.2 已把后续调查范围从“OpenWrt 控制面”收敛为一组精确版本、精确入口、静态 IPC 和失败
边界。它还没有选择 Rust 替换对象，也没有冻结运行时合同；这些决定必须等待部署文件归属、
方法 schema 和必要运行态证据。
