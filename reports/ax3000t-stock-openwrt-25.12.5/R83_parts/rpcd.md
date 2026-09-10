# R83 · rpcd：F23、F24

日期 2026-09-10。实现参照为 rpcd `28faf640` 及镜像对应 LuCI 插件源；运行参照为
精确 OpenWrt 25.12.5 rootfs 的 `/sbin/rpcd`、file/rpc-sys/rrdns 插件和 ucode 脚本。
所有动作在 `oracle` 的一次性副本中执行；升级和 reload 程序替换为只写测试标记的脚本。
没有运行实体设备的升级、恢复出厂或重启动作。最终构建摘要见 [validation.md](validation.md)。

## 1. 逐项结果

| 项 | 裁定与修复 | 验证 |
|---|---|---|
| F23 file exec 阻塞主循环 | 成立；参数和 ACL 检查仍在循环上，子进程交由 worker，结果经既有 Deferrer 返回 | 一个 5 s exec 期间 session 立即回复；两个 4 s exec 总耗时 4 s |
| F23 luci shell helper | 原指控不成立；镜像的 `luci` 是进程内 ucode，`uc_vm_call` 同步执行 popen/system，保留此语义 | 固定源和 rootfs 脚本调用链核对 |
| F24 非 UTF-8 | STRING 值、文件路径、read/write/exec 的 argv/env/output、ACL 对象和键保持原字节 | raw_bytes 线级探针及 r26 |
| F24 umask 竞争 | 去掉 write 期间修改进程 umask 的窗口；新文件按要求 fchmod，既有文件不改权限 | 精确 mode 单测和文件差分 |
| F24 exec ACL 长度 | 命令行限制计入每参数的 NUL；1023/1024 字节及 253/254 参数边界对齐 C | 边界单测 |
| F24 延迟动作 | rpc-sys 与 uci.reload_config 全部 fork；准确回收自己的子 PID，跨 HUP re-exec 保存登记表 | reload/upgrade 跨 HUP 执行，回收完成且 rpcd 仍服务 |
| F24 DNS 截断 | 先检查所有 section 的结构长度，再提取 PTR | 截断包单测及插件差分 |
| F24 DNS 主机名 | 使用 getaddrinfo 对应的地址解析结果，按地址族创建 UDP socket | 数字 server 与 hostname server 均获得实际 PTR |

## 2. 延迟动作、HUP 与子进程所有权

C 的 `rpc_uci_reload` 和 `rpc-sys` 动作均 fork 后等待两秒；早期修复只处理了 rpc-sys，
`uci.reload_config` 仍在线程中，HUP 会丢掉动作。本轮统一到 `delayed::Children`：

- fork 前构造 argv；子进程只调用 sleep/execv/_exit，不接触父进程的 Rust 锁。
- 父进程登记具体 PID，SIGCHLD 唤醒循环，用 `waitpid(pid, WNOHANG)` 回收。
  不使用 `waitpid(-1)`，避免抢走 exec worker 的 `Child::wait` 结果。
- HUP re-exec 经 `OWRT_RPCD_DELAYED_PIDS` 携带登记表；启动时读取并立即移除该环境变量。
  exec 保留父子关系，因此仍能回收原先的子进程。
- 延迟子进程会继承尚未 exec 的 ubus fd。只 drop 父进程连接不足以释放旧对象名，
  replacement rpcd 曾因此无法注册对象。HUP 前调用 `Connection::shutdown()`，使 ubusd
  释放旧连接；这个安全 API 也用于 logd 重连。

加强后的 `r83_rpcd_defer.sh` 同时启动一个返回 17 的 worker 和 reload，确保子进程回收没有
窃取 worker 状态；再发 upgrade/reload 并立即 HUP，核对两项动作、剩余子 PID 和 session 响应。

最终观测：

```text
defer_session_list_s=0
parallel_two_execs_s=4
reload_ran=1
worker_reply={"code":17}
respawn_upgrade_ran=1
respawn_reload_ran=1
remaining_action_children=0
still_serving=1
r83 rpcd defer gate: PASS
```

旧二进制在同一加强门中未完成 reload-across-HUP，且 replacement rpcd 无法继续服务，门禁判红。
更早把 file exec 和延迟 fork 分别退回旧实现的红证也保留：session 被阻塞 4 s、两个 exec 耗时 8 s、
`respawn_upgrade_ran=0`。这些不是最终构建结果。

## 3. 字节串与文件权限

早期草稿把空串替换改成 U+FFFD，仍会损坏 `file read/write` 与 exec 输出；本轮引入
`Json::Bytes`、字节解析/序列化及 `BlobBuf::msg_string_bytes`，让 STRING **值**贯穿传输。
文件操作使用 `OsStr`/`OsString` 的原字节；路径归一化及 ACL 检查采用同一字节表示，不能因为
非法 UTF-8 绕过权限，也不再把 write 的 data 误读成空串并截断文件。

历史复现：C 的 `{"data":"a\xffb"}` 原字节为 `61 ff 62`；早期候选为 `61 ef bf bd 62`。
最终 raw_bytes 门直接比较 blob 内容，覆盖 raw read/write、非 UTF-8 路径、目录项、exec 参数/
环境/输出及允许、拒绝 ACL 路径。通用 JSON 对象字段名仍为 UTF-8；这不等于承诺任意非 UTF-8
JSON 键和 ubus 事件名的完整兼容。

`file write` 使用排他的创建路径与 fchmod，保留既有文件 mode；符号链接回退仍处理创建目标。
进程 umask 只在 rpcd 启动时设置，不在并发请求期间切换。故障注入退回旧代码时，权限测试
返回 0600 而非要求的 0666，ACL 长度测试放过 1024 字节，均判红。

## 4. DNS 门的修正

`rrdns_parse_response` 在 PTR 提取前对 question/answer/authority/additional 做完整边界检查，
避免截断包泄露部分结果；单个名字解压失败时的增量行为仍跟随 C。

原 r18 夹具在 5353 监听，但 ubus CLI JSON 数字编码为 INT32，而插件的 `port` 策略要求 INT16。
两侧实际上都使用 53，测试因此曾以两个空结果“通过”。现夹具在 `127.0.0.1:53` 监听，主线程
先绑定，权限或端口冲突会直接失败；使用 sudo 运行，并独立断言期望的 PTR 字符串。
数字地址、主机名都返回真实答案；不可达案例使用 `127.0.0.2`，不再依赖被忽略的端口参数。

## 5. 验证与边界

| 门 | 结果 |
|---|---|
| rpcd 单测 | 38 通过 |
| strict clippy | `--all-targets -- -D warnings` 通过 |
| r13 | 63 请求一致 |
| r17 | 272 步一致 |
| r18 | 77 步一致，含实际 PTR 哨兵 |
| r19 | 11 对一致 |
| r26 | 615 步、0 差异；只遮蔽 session ID 位置，MD5 保持比较 |
| r83 defer / bytes | 均通过；最新 fork/HUP/回收代码重新验证 |

r13 的 file_exec_sh code 掩码保留：C 的管道 EOF 与 wait 回调有竞态，但候选另有 `code == 3`
硬断言。r26 只在 `file_stat` 隐去两份 rootfs 必然不同的 inode，mode/owner/size/MD5 仍比较。
本轮没有通过修改正常输出或放宽全局掩码消除差异。
