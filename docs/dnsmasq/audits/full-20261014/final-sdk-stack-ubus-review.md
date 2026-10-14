# 最终 SDK payload：九组件与 UBus 恢复复验

2026-10-14，冻结 `b587282081b72ea0f96cf909e0f70b0bc8de9372`。**实际 SDK 包内 ELF、init 和 ACL 新跑 Rust stack23 23/23、helper5 5/5，以及 F5 restart、ACL 恢复、第二注册停滞三个场景，全部通过。** [派生收据](final-sdk-stack-ubus-review.json) 保存每项结果、运行身份和原始 hash。本专项不判断仍由主审处理的 F10，也不替代整体合并或部署资格。

执行者是集成/F5 修复贡献者，最终构建由另一执行线提供；这里独立核对输入并重新执行，没有重编译候选，也没有将旧 ELF 通过数改签为最终包。

## 输入身份

| 最终输入 | SHA-256 / 核验 |
| --- | --- |
| 包内 `usr/sbin/dnsmasq` | `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c`，2,124,571 B |
| 包内 `etc/init.d/dnsmasq` | `70fb3c6bd057c6981503138b91292182f07c9a0d5aa1aaf0454c34af4ca746f0` |
| 包内 `usr/share/acl.d/dnsmasq_acl.json` | `8bedbcdd3018c17f272f0d3ecf9573aa6f05253806cb8812ebf92e9b87ac6020` |
| 冻结源码 | 从 Git 独立计算 658 个 dnsmasq/ubus/packaging/tools 跟踪文件的 SHA，与 Oracle source 逐项一致，零缺失、零不符；init/ACL 另与对应 Git 包文件逐字一致 |
| Rust9 支撑 | 175 个非 dnsmasq 组件及共享 ubus 文件与原构建树一致；9 个 ELF 与已有清单一致，实际常驻支撑进程另核对 `/proc` 身份 |
| 执行工具 | F5 工具与冻结 Git 一致；stack 继续使用前轮的隔离底座，458 个支撑工具文件 hash 与前轮 C 对照一致 |

三份包内文件均先独立复制到新审计目录并核验。stack/helper 驱动明确把**实际包内 init/ACL**安装进私有 overlay，不能沿用原装 init 的单 socket 绑定。新 stack 额外断言总线重启后两个对象已自动恢复、daemon PID 未变，随后才执行原矩阵的显式 restart。

## 新执行结果

| 新运行 | 实际结果 |
| --- | --- |
| stack23 | 23/23；真实 init/ujail、fw4、UCI/reload_config、RPC apply、HTTP/LuCI、odhcpd→AAAA、netifd resolver 切换、procd 崩溃恢复和 stop 均通过 |
| stack 客户端 | 初始、fw4、apply、respawn 后均实际完成 veth DHCP OFFER/ACK 和 UDP/TCP DNS；无配置变化 reload 保持 PID |
| helper5 | 5/5；原 dhcp-script → ubus → Rust procd hotplug 真链路通过，hotplug 行和 ACK 事件同历史 C 对照 |
| F5 restart | 总线停 3.3 秒，无 DNS/DHCP 流量帮助重连；重启后约 **0.813 秒**内同 PID 恢复两个对象，metrics 可用，两个真实客户端周期得到准确两条 ACK 事件、ACK counter 增加 2 |
| F5 ACL 恢复 | 暂时只允许主对象，确认拒绝期没有半注册泄漏、客户端仍健康；重载精确双对象 ACL 后约 **0.407 秒**自动恢复，再完成同样的 metrics/客户端/事件检查 |
| F5 第二注册停滞 | 假总线完成 HELLO 和第一次注册后不答第二次。真实 daemon 完成 **600 次 UDP/TCP DNS 查询，零错误**，最大查询约 **96.1 ms**；真实 DHCP 客户端通过。TERM 前确认已发送两个注册请求，约 **2.24 ms**退出 |

三个 F5 场景均核对 UID/GID 453、effective/permitted capabilities `0x3400`；root 经 jail 路径写 socket 父目录得到 EROFS(30)。总线正常重启只换 socket inode，父目录不变，jail 与 fixture 看到同一新 inode。停滞场景只模拟损坏的总线对端，DNS/DHCP、Rust9 和 jail 均为实际服务。

## 对照与范围

没有新跑 C。复用[前轮 C 结果](integrated-stack-review.md)作有限正常功能对照，支撑 Rust9 相同；那轮使用原装 init/ACL，**不是本轮最终包文件完全相同的 C 对照**，其总线重启缺对象的失败仍保留。本轮新增数量是 28 项 Rust 检查加 3 个 F5 场景，不能写成新增 C/Rust 56 项。

前轮完整权限/启动负控、trial 等证据仍绑定各自旧 ELF，本轮没有重新计数。没有执行 APK 安装事务、物理 Wi-Fi 客户端、内存压力或路由器操作；最终源树中的其它兼容性问题由对应专项另判。

## 证据与收尾

Oracle 新目录 `/dev/shm/full-merge-f5-20261014/private/final-sdk-b5872820/`；本地 `private/final-sdk-f5-stack/`。私有归档 `final-sdk-b5872820-evidence.tar.gz` SHA-256：`6b81fbee14361ab43e356cd04f8023ba8783785cd5fe2ef1e5cb47bdba6c283f`，已回拷核对。包含候选输入、实际驱动、命令、结果和日志；不重复归档可重建 rootfs/overlay。

五轮全部退出 0；收尾没有所属进程或宿主可见挂载残留。原 payload、审计副本和九组件 ELF hash 前后不变。旧运行结果、报告和修复证据未覆盖。
