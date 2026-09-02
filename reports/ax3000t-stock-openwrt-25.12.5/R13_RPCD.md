# R13：rpcd 插件层 Rust 化（rpcd-rs：`file`、`luci`）

> 状态：complete_live_boot_enabled（监测窗口见下）
> 合同：C5（`docs/contracts/rpcd-plugins.md`）；决策：0011

## 范围与不做的部分

rpcd 的 `session`、`uci`、`rc` 编译在主程序内，插件只能整体加载，ubusd 拒绝重名对象；因此本阶段用 Rust
接管 LuCI 调用最多、暴露面最大的插件层对象 **`file`**（任意路径读写与命令执行，受 ACL 约束）与
**`luci`**（21 个方法），原 rpcd 继续提供 `session`/`uci`/`rc` 与 `iwinfo`/`luci-rpc`/`rpc-sys`/`network.rrdns`。
理由与证据见决策 0011。

## 离线验证

| 项 | 结果 |
|---|---|
| 精确 rootfs 沙箱差分（原 rpcd + file.so/ucode.so 对 原 rpcd 去掉两插件 + rpcd-rs），63 个请求：`file` 34 个（读/写/追加/base64/list/stat/lstat/md5/remove/exec 与错误码、ACL 拒绝），`luci` 29 个（21 方法含错误参数、未知方法、init 启停往返） | 63/63 相同（结构比较，仅遮蔽 inode/atime/ctime 及本次运行写入文件的 mtime；`getUnixtime`/`getMountPoints`/`getConntrackList`/`getProcessList`/`getRealtimeStats` 比较形状） |
| 原实现的一处竟态 | 原 file.so 的 `exec` 在管道 EOF 先于子进程退出回调时报 `code: 0`（沙箱中 `sh -c 'exit 3'` 得 0；设备上得 3）；rpcd-rs 始终报真实退出码，harness 对该请求固定要求 3 |
| 单元测试 | 4/4（MD5、Base64、路径规范化、fnmatch） |
| 设备只读采样（2026-09-02） | `ubus call luci/file …` 原实现输出已存 `private/stage5/device/`，用于窗口内对照 |

参数校验照搬 ucode.so（未知参数或类型不符 → INVALID_ARGUMENT，`ubus_rpc_session` 例外）；`file` 的
ACL 通过原 rpcd 的 `session access`（scope=file）完成，路径规范化与 exec 命令行拼接照搬 file.c。

## 包

`owrt-rpcd 0.1.0-r2`（`packaging/openwrt/owrt-rpcd`）：

| 文件 | sha256 |
|---|---|
| `owrt-rpcd-0.1.0-r2.apk`（r1 `7c664b75…` 先装后升级） | `04c12e29df3a4c03de8e7e65ec590e0e4fcd180ea325396e477a99f03d47c307` |
| `/usr/sbin/rpcd-rs`（477619 字节，零第三方 crate） | `e34bb92d18eb0f62948406317d53dc1423d5cf4b56272f9b9b97a08da46b4f27` |
| `/usr/sbin/owrt-rpcd-switch`（r2：`pidof` 代替 BusyBox 不支持的 `pgrep -x`） | `a77965a6e2fc8880ee6dcee67a69a45505847ce7a5fa2809b169093f08343f34` |
| `/etc/init.d/owrt-rpcd`（S11/K89，procd 服务） | `3ddd28f0d4eb35e934d77f23d2bd503f6173d58314a389664faca71390343433` |
| 原 `file.so` / `ucode.so`（rootfs 与设备一致） | `f181c959…` / `591c21ee…` |

切换：`enable` = 把去掉 file.so/ucode.so 的插件目录副本 bind mount 到 `/usr/lib/rpcd`，启动 rpcd-rs
（procd，respawn），`/etc/init.d/rpcd restart`，验证 `luci getVersion` 可达，否则自动回退；`disable` 逆序；
`boot-enable on` 让 S11 在 S12 rpcd 之前完成挂载并启动 rpcd-rs。rpcd 重启会清空现有 LuCI 会话（用户需
重新登录），这是原 rpcd 的固有行为。

## 设备步骤（2026-09-02，用户授权 1-3）

`tools/r13_go_live_device.sh`，每步一次 SSH，原始输出在 `private/stage5/device/r13-*.txt`。

| 步骤 | 结果 |
|---|---|
| install r1 14:37:43Z | `apk add` 成功，文件哈希一致（FILES_OK），switch=disabled，rc 链接 S11/K89；原插件哈希与 rootfs 一致 |
| 发现并修正 | 探针显示 BusyBox `pgrep -x` 匹配不到任何进程，而 switch 用它验证 rpcd-rs 是否在跑；改用 `pidof`，重建 r2 并升级（`apk add` 升级；升级过程中 prerm 的 `disable` 重启了一次 rpcd） |
| enable 14:39:26Z | `owrt-rpcd-switch enable` 成功：`/usr/lib/rpcd` 挂载为 4 个插件（iwinfo/luci/rpcsys/rrdns），rpcd 重启（pid 28509），rpcd-rs pid 28544，ubus 对象数不变（40） |
| 对象抽样（启用前后） | `luci getVersion`/`getInitList firewall`/`getBuiltinEthernetPorts` 相同；`getFeatures`、`getConntrackHelpers`、`getTimezones` 输出哈希相同；`file stat/list/md5/exec` 相同；带伪会话的 `file read` 仍被拒绝（rc 6）；`getMountPoints` 多出一条即新增的 bind mount |
| boot-enable on | 成功 |
| 其余 Rust 组件 | httpd-rs 22540、logd-rs 19348 未受影响；reload_config 与 fw4 的 bind mount 仍在 |
