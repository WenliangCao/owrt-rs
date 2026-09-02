# 最终报告：Xiaomi AX3000T（OpenWrt 25.12.5）控制面 Rust 化

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

## 5. 综合监测窗口

（待执行：安装 `owrt-switch`，`owrt-switch status`，五个组件约 3 分钟只读探测。）
