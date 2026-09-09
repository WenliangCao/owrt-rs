# 最终报告：Xiaomi AX3000T（OpenWrt 25.12.5）控制面 Rust 化

> **现状（2026-09-09）**：这是 2026-09-02 五阶段收官时的报告。表中"保留 C，明确不做"的 procd/netifd/ubusd 已在 2026-09-09 全部由 Rust 接管（R74–R80），rpcd 核心对象也已迁入（R17/R18）。现状见仓库 README。

> 日期：2026-09-02
> 状态：五个阶段的组件全部在设备上以 Rust 实现接管并开机默认运行；综合监测窗口见文末。

## 1. 终点对照

计划 v4 §0 定义的终点：凡是"失效后不会切断唯一管理路径、也不会让设备无法启动"的控制面职责，由 Rust
实现并作为开机默认路径运行；其余保留 C 并写明理由。

| 职责 | 现状 | 实现 | 上线形态 | 证据 |
|---|---|---|---|---|
| R05 配置变更分发 `/sbin/reload_config` | **Rust** | `components/reload-config` 0.2.0（syslog trace） | bind mount，S11 开机重挂，boot-enable on | [R05_GO_LIVE](R05_GO_LIVE.md)、合同 C1、决策 0007 |
| R15 系统日志 logd | **Rust** | `components/logd`（自写 ubus 库 `components/ubus`） | 服务替换，S12，boot-enable on | [R15_LOGD](R15_LOGD.md)、合同 C2、决策 0008 |
| R14 Web 前端 uhttpd（静态/CGI/`/ubus` 桥/TLS） | **Rust** | `components/httpd` 0.1.1（唯一第三方依赖 rustls+ring） | 服务替换 80/443，S50，boot-enable on | [R14_HTTPD](R14_HTTPD.md)、合同 C3、决策 0009 |
| R09 防火墙规则生成 `/sbin/fw4` | **Rust** | `components/fw4`（fw4.uc 逐函数移植） | print 字节相同为门禁的 bind mount，S18，boot-enable on | [R09_FW4](R09_FW4.md)、合同 C4、决策 0010 |
| R13 管理 API rpcd | **Rust 插件层**：`file`、`luci` 对象 | `components/rpcd` | 裁剪插件目录 bind mount + rpcd-rs 服务，S11，boot-enable on | [R13_RPCD](R13_RPCD.md)、合同 C5、决策 0011 |
| R13 之 `session`/`uci`/`rc`、`iwinfo`/`luci-rpc`/`rpc-sys`/`network.rrdns` | 保留 C | 原 rpcd 2026.06.04 | — | 决策 0011：三者编译在 rpcd 主程序内，ubusd 拒绝重名对象，无法不打补丁地拆分；iwinfo/luci-rpc 依赖 libiwinfo/netlink |
| R01 procd、R03 启动编排、R07 netifd、R08 无线、R12 ubusd、R17 升级 | 保留 C，明确不做 | — | — | 计划 v4 §0：失效即失去 SSH 或无法启动，单台设备无恢复路径（决策 0006） |
| R02、R06、R10、R11、R16 | 保留 | — | — | 执行面或一次性脚本，无替换价值 |
| R04 UCI 库 | 未触及 | — | — | rpcd 的 `uci` 对象留在 C（上一行） |

Rust 代码量（不含测试）：reload-config、ubus、logd、httpd、fw4、rpcd 六个 crate；第三方 crate 仅
rustls/ring（httpd TLS，决策 0009）。所有包默认 disabled 安装，`owrt-<name>-switch enable|disable|
boot-enable` 显式切换；`owrt-switch` 一处查看/操作全部五个。

## 2. 验证方式与结果（按爆炸半径）

| 组件 | 离线 oracle | 设备 |
|---|---|---|
| reload_config | 合同 11/11、故障 6/6 与原实现一致 | H1.6 canary、真实 ubus 投递、drift 收口；开机重挂 |
| logd | 精确 rootfs 并排 10/10 | canary、boot-enable |
| httpd | 38 请求并排逐字节（掩蔽 Date/ETag 等） | 并排 8080/8443 + canary 80/443 与基线相同，TLS 握手 |
| fw4 | 上游 firewall4 31 个测试文件 stdout+stderr 逐字节；设备配置离线渲染 203 行相同 | `print` 门禁相同后接管；经候选 `reload` 后内核规则集哈希不变 |
| rpcd 插件层 | 精确 rootfs 沙箱 63 个请求与原插件相同（含 ACL 拒绝、错误码） | 启用前后抽样相同、ACL 拒绝保持；对象数不变 |

每次启用后一个约 3 分钟的只读监测窗口（用户要求），窗口内无回退。

## 3. 没有做到 / 需要说明的事

1. rpcd 进程仍是 C；Rust 只接管了 LuCI 调用最多、暴露面最大的插件层对象（`file` 任意路径读写与命令
   执行、`luci` 21 个方法）。完整替换需要重写 UCI 变更/回滚语义（R04）并接管 `session`，超出本轮范围。
2. LuCI 的动态 `/ubus` 调用清单只记录到 `session access`：本项目不使用用户口令，需要用户自己登录浏览后
   再读 `/tmp/owrt-httpd-calls.txt`。
3. httpd-rs 的 TLS 依赖 rustls/ring（唯一第三方 crate）。
4. 原 rpcd file.so 的 `exec` 存在退出码竟态（沙箱复现：`exit 3` 报 0）；rpcd-rs 报真实退出码，这是与原
   实现的有意差异。
5. 阶段 5 升级 owrt-rpcd r1→r2 时，包脚本里的 `disable` 无条件重启了一次 rpcd（LuCI 会话失效一次）。

## 4. 后续条件

- 若有第二台同型号设备作实验机，netifd 与 ubusd 可重新评估（不需要 UART）。
- rpcd 完整替换的前提：为 `uci` 对象写合同并以 `uci` CLI 为规范化后端，同时接管 `session`；`iwinfo`
  需要 nl80211 客户端。
- 任一组件出现异常：`owrt-switch disable-all` 或对应 `owrt-<name>-switch disable` 一步回到原实现，
  再 `boot-enable off`；都不需要重启。

## 5. 综合监测窗口（2026-09-02，用户授权并同时登录 LuCI 浏览）

`owrt-switch 0.1.0-r1` 安装后 `owrt-switch status`：

| component | switch | boot-enable | pid | version |
|---|---|---|---|---|
| reload-config | enabled | on | -（一次性程序） | 0.2.0-r1 |
| logd | enabled | on | 19348 | 0.1.0-r1 |
| httpd | enabled | on | 22540 | 0.1.1-r1 |
| fw4 | enabled | on | -（一次性程序） | 0.1.0-r1 |
| rpcd | enabled | on | 28544 | 0.1.0-r2 |

14:49:47Z 至 14:52:50Z 四次只读探测，间隔一分钟，全部相同：三个 bind mount 在位；logd-rs/httpd-rs/rpcd-rs
与原 rpcd 的 pid 不变，原 logd 与 uhttpd 不在运行；80/443 由 httpd-rs 监听；`fw4 print` 哈希 `6d2fb603…`、
去计数器规则集 `49e8ed95…`（152 行）不变；ubus 对象 40；伪会话 `file read` 被拒（rc 6）；
`/etc/config` 树哈希不变；主机访问 LuCI 登录页 403、互联网 200；日志中没有任何 Rust 组件的错误或 respawn。

窗口期间用户登录并浏览了 LuCI，httpd-rs 记录到的真实 `/ubus` 调用（对象 方法 次数）：

```
file list 5; file read 26; file stat 1
luci getBuiltinEthernetPorts 7; getFeatures 2; getMountPoints 8; getOdhcp6cStats 7; getTimezones 1; getUnixtime 9; getVersion 7
luci-rpc getBoardJSON 11; getDHCPLeases 7; getHostHints 11; getNetworkDevices 11; getWirelessDevices 11
iwinfo assoclist 14; network get_proto_handlers 11; network.device status 28; network.interface dump 11
rc list 2; session access 22; system board 14; system info 21; uci changes 56; uci get 43
```

其中 `file` 与 `luci` 的全部 71 次调用由 rpcd-rs 应答，页面正常；`uci`/`session`/`rc`/`luci-rpc`/`iwinfo`
由原 rpcd 应答。这份清单也是"完整替换 rpcd"的范围依据：`uci get/changes` 与 `session access` 是下一
个必须覆盖的对象。
