# v0.3.2：ubus 深度边界与 procd/rpcd 静态问题复现

本记录只报告 Oracle 离线结果；未修改物理路由器。基线源码为 `8bdf3ece`，
原始证据保留于 `/home/ubuntu/v032-ubus-procd-rpcd-20261019/evidence/`，
本地摘要位于 ignored `private/v032-ubus-procd-rpcd-20261019/`。

## ubus：过深 blobmsg 转换改为正常报错

模型是 TABLE/ARRAY 每嵌套一层就占一个递归栈层，100,000 层耗尽进程栈。
判据为进程退出状态、完整输出字节及错误传播；没有把运行耗时当性能结论。
参考为 OpenWrt 25.12.5 对应 libubox `7dd127841e82eb1cfb61185da37dde7b9bd9ba6d`
的 `blob.c`、`blobmsg.c`、`blobmsg_json.c`。

| 输入 / 检查 | 修复前 | 修复后 |
|---|---|---|
| 100,000 层 TABLE，800,016 B；固定 8 MiB 栈 | Rust 树构造、直接输出各 4/4 SIGABRT；C 格式器 4/4 SIGSEGV | Rust 两入口各 4/4 正常退出 2，返回明确深度错误，无输出 |
| 64 层，528 B | Rust 两入口与 C 各 4/4 成功，输出 395 B | 63/64 层每个入口各 4 次，完整输出与 C 逐字节相同 |
| 65 层 | C 正常处理 | Rust 两入口各 4/4 返回深度错误 |
| TABLE 与 ARRAY 边界、单字段转换、失败输出回滚 | 无深度限制 | 63/64/65/100,000 层单测通过；错误不留下部分 JSON |
| ubus 完整测试 | — | 73 通过，0 失败 |

上限是 **64 个嵌套 TABLE/ARRAY 字段**，不计隐含顶层对象和标量叶子。
三个转换 API 返回 `Result`；调用方将异常请求转成 ubus 参数错误，异常回复转成
调用失败或 HTTP JSON-RPC 内部错误。事件流对异常通知回复参数错误后继续服务，
不会输出半条事件。**这是刻意区别于 C 的安全边界：C 没有此限制且深输入会崩溃。**

可重放工具为 `tools/ubus_depth_check.{rs,c}` 和 `tools/check_ubus_depth.py`。
红色证据 `ubus-depth-before.json`；修后四轮边界差分 `ubus-depth-after.json`
共 32 个 Rust 用例；构建与完整测试日志 `ubus-{build,tests}-after.log`。
rpcd 和 httpd 完整测试各 62 通过（含 HTTP 深度错误两种回复格式），
两者诊断 examples 与 benchmark 全 targets 编译通过，均以 `-Dwarnings` 运行。
netifd 调用方先完整转换再修改状态，避免深度错误留下部分更新；该组件 175 项测试通过。
fw4/odhcpd 的调用方验证由整合检查记录。

## 剩余逐条复现清单

以下仍待实验，不能据此宣称已修复或“未复现”。每项先读匹配 C，
失败至少复现四次，再决定修改；无法复现时明确记“未复现、未修改”。

| 组件 / 项目 | 当前状态 |
|---|---|
| procd instance 顶层类型策略 | 四轮复现并修复；见下 |
| procd instance.update 事件 | 四轮复现并修复；见下 |
| procd 负 trigger timeout | 四轮复现并修复；见下 |
| procd watchdog 驱动实际 timeout | 四轮 ioctl 注入复现并修复；见下 |
| procd jsonscript include | 待复现 |
| rpcd 损坏 freeze 的 UTF-8 / 时间溢出 | 待复现 |
| rpcd 非法 UTF-8 SID 降为 None | 待复现 |
| rpcd UCI 错误被 unload 清除 | 待复现 |
| rpcd 非规范 base64 padding | 待复现 |
| rpcd LuCI 显式空 name 过滤 | 待复现 |

## procd 类型策略

`check_procd_static.py` 在私有 PID/mount/net namespace 的精确镜像副本运行真实
C/Rust daemon。四轮均见 9 个类型用例分歧：错误顶层 respawn/env/limits/data/netdev/error
类型被采用，netdev/file 非字符串元素未拒绝整个实例，非 TABLE 实例仍被登记。
其中 env/limits/data ARRAY 产生 ubus CLI 无法解析的 JSON。修复统一执行 C 的顶层
类型策略、拒绝不合法的 netdev/file 元素，并在 service 入口跳过非 TABLE 实例。
`procd-static-red/result.json` 四轮红；`procd-types-green-2/result.json` 四轮所有类型
用例与 C 相同，尚余事件/负 timeout 的预期分歧。file 顶层错误类型在本夹具中没有
可见输出分歧；它和其余字段统一经过同一策略。原始失败夹具和第一版候选未删，
前者缺少镜像启动时由 devtmpfs 提供的 `/dev/null`，零 timeout 阳性失败，不计复现。
类型修后完整 procd 套件 89 通过（`procd-types-tests-2.log`）。

## procd instance.update

C `service_instance_update` 对每次 vlist 新增、更新、删除发内部事件。基线四轮
新增/同值更新/删除的脚本动作是 C `[1,2,3]`、Rust `[0,0,0]`。补上 set/add、
delete 和 update_complete 的事件，保留 add 未提及实例、update_start 无事件。
扩展 11 个操作的四轮结果为双方 `[1,2,3,4,4,5,6,6,7,8,9]`，见
`procd-events-{red,green-2}/result.json`。首次绿夹具用 150 ms 观察窗，小于 Rust
现有 200 ms 维护 tick，出现延后动作而非缺失；最终每步等 500 ms 后比较动作总数。
这项修复恢复事件，不宣称改变触发器调度精度。

## procd watchdog 返回值

`procd_watchdog_check.c` 直接 include 精确 `58eb263d` 的 `watchdog.c`，只注入 ioctl
和 uloop timer；Rust `watchdog_status --adjust-timeout` include 产品 watchdog 模块并注入
相同 ioctl 写回。两边 WDTFD 都是 socketpair，未打开任何硬件 watchdog。
模型是驱动将请求 30/17 秒量化为 20 秒：四轮 C getter 均为 `20/20`，Rust 为
`30/17`。修复将已保存 timeout 直接传给 ioctl，四轮双方均 `20/20`，五个原有
GETSUPPORT/GETBOOTSTATUS 控制场景仍通过。证据为 `procd-watchdog-{red,green}.json`。
这是明确的接口模拟证据；没有断言 MT7981 驱动实际采用同一量化方式。

C probe 的构建参数为 `-I<exact-components>` 和
`-DPROCD_WATCHDOG_SOURCE='"<exact-components>/procd/watchdog.c"'`；Rust 用
`cargo build --release --example watchdog_status --manifest-path components/procd/Cargo.toml`
后对两程序各运行四次即可复现。所有构建和运行均在 Oracle Linux。

## procd 负 trigger timeout

C trigger 的 timeout 是 signed int，负值首次入队按 1 ms 处理；Rust 原先将同一
INT32 保留为 u32，`-1` 变成约 49.7 天。`procd-static-red` 四轮 C 执行动作、Rust
未执行，零 timeout 阳性均执行。改为 i32 后，`procd-static-green` 四轮所有类型、
事件、负 timeout 和零 timeout 与 C 相同。500 ms 观察窗仅判断动作是否执行，
不将它解释成 1 ms 调度精度验证；既有 pending 延期和运行中 requeue 规则保持。
