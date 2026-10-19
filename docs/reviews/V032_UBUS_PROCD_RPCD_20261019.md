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
| procd instance 顶层类型策略 | 待复现 |
| procd instance.update 事件 | 待复现 |
| procd 负 trigger timeout | 待复现 |
| procd watchdog 驱动实际 timeout | 待复现 |
| procd jsonscript include | 待复现 |
| rpcd 损坏 freeze 的 UTF-8 / 时间溢出 | 待复现 |
| rpcd 非法 UTF-8 SID 降为 None | 待复现 |
| rpcd UCI 错误被 unload 清除 | 待复现 |
| rpcd 非规范 base64 padding | 待复现 |
| rpcd LuCI 显式空 name 过滤 | 待复现 |
