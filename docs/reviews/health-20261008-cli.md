# HEALTH 2026-10-08：CLI 断管道修复

本项分类为 **我们的缺陷**。依据是精确 OpenWrt 25.12.5 镜像中的 shell/ucode/C 可执行文件在相同输入、预先关闭读端、相同 SIGPIPE disposition 下的对照，未在生产路由器制造断管道或 core。本报告的最终 CI 产物验证见总报告。

## 证据与边界

- 基线为 `a4053dd5` 的正式 r2 九组件镜像；oracle 上的 `canonical-root-a4053dd` 已逐组件校验匹配其 `release.json`。候选从该提交修改，不带入 main 的 dnsmasq 或 ubus/conn.rs 改动。
- oracle 为 aarch64 Linux。原版输入为 `owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`，测试前校验 fw4、ucode、BusyBox、uci SHA-256。测试复制该 rootfs，使用独立 mount/net/PID namespace；只在副本中替换候选与 nft 记录器。
- fw4 脚本 SHA-256：`c240b413a4cf80617ac1a71f601d2e0edae46b0493e3c00fbe883b2446e4a1a6`；ucode：`51b711c8e0016ddde3998ce66e23b387f9e57417c40f3c2c40f2694be5e29450`；uci：`050e9ab320b794f636174536ca4dbca2f615a1c6c37bc19e9ca06bfd6d6e7278`。
- 匹配源码：firewall4 `b6e5157527d361f99ad52eaa6da273cb0f2dfd59`、uci `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8`、ubus `24864e7840b3a02a9ef76284a373f6b2f00b8a9b`。
- 没有把当前 `/rom/sbin/fw4` 假定为原版；native-nine 镜像的只读层也包含 Rust。上述原版来自精确 stock 镜像，候选来自 r2/fixed 构建，身份分开记录。

## 已复现的差异与修复

| 路径 | 原版行为 | r2 缺陷 / 修复 |
|---|---|---|
| fw4 network/device/zone，SIGPIPE=IGNORE，stdout 无读者 | rc=0、stderr 为空 | `println!` 因 EPIPE panic，release SIGABRT。改为直接 `let _ = writeln!` |
| 相同查询，SIGPIPE=DEFAULT | stock shell 返回 141 | Rust runtime 启动时把信号改为 IGNORE，随后 abort。沿用现有 uci 的 libc main 入口，保留调用者 disposition |
| fw4 usage，IGNORE | rc=1，`cat: write error: Broken pipe\n` | 显式保留 BusyBox cat 的写失败诊断与退出码 |
| fw4 check 最终成功消息，IGNORE | rc=1，`sh: write error: Broken pipe\n` | 保留 shell echo 的写失败语义，不能统一吞错后返回 0 |
| fw4 print，包括 ubus 连接失败 | 原版 `ubus_connect_ctx` 在连接前初始化 uloop，从该点起忽略 SIGPIPE | 仅在对应真实 ubus connect 边界设置 IGNORE；查询模式不走该边界 |
| nft 输出、提前拒收 stdin、includes | nft/脚本继承 wrapper 信号；renderer writer 可遇到 EPIPE；子进程信号有独立退出码 | 在 wrapper/renderer 边界还原 disposition；nft stdin 写入期间忽略 SIGPIPE；子进程 exec 显式保留继承；nft 信号退出转换为 shell 128+signal |
| uci add / help / 参数错误 / perror | IGNORE 时继续正常的原退出路径 | 替换剩余 stdout/stderr panic 宏，不改变字节内容 |
| uci export | C `uci_export` 忽略 stdout 的 fprintf 错误，IGNORE 时返回 0 | r2 对 write_all 错误返回 1；改为与 C 一致忽略该输出错误 |

stock fw4 是 shell wrapper，其查询子进程被 SIGPIPE 终止后 wrapper 正常退出 141；候选是单一 ELF，raw wait status 为 `-13`。回归同时保存 raw wait status 和 shell 可见状态，后者均为 141；没有为伪造 wrapper 的 waitpid 形式增加进程层。

## 九组件一次性输出盘点

| 组件 | 覆盖与处理 |
|---|---|
| fw4 | 所有公开模式：start/stop/flush/restart/reload/reload-sets/print/check/network/device/zone/usage；另测内部 includes（C 通过 ACTION=includes 调用 utpl）。覆盖已加载报错、缺失 state、无 ubus、成功/失败 restart、nft 输出和提前关闭 stdin |
| uci | get/show/changes 本就使用 fallible Write；补 add、help/options/errors、perror、export。文件写入/提交错误处理不变 |
| reload_config | 主流程 Trace/SyslogWriter 已传播或忽略写错；补 Rust 专用 help、参数错误与 signal-handler 初始化错误的 stderr |
| ubusd | 补 usage 和版本环境变量输出。daemon 传输错误策略不变 |
| httpd | 补 Rust help 与启动诊断；没有新增 uhttpd CLI 选项或调整退出码 |
| logd | 补 Rust help/参数错误/启动诊断；运行时 log 传输不在本次 CLI 范围 |
| netifd | 补 version/dump-wireless/参数错误/启动诊断；没有改变 daemon 的信号启动约定 |
| rpcd | 补 invalid-timeout、iwinfo-bench usage/结果/错误。oracle 无 Wi-Fi 硬件，运行验证覆盖 bench usage 和不存在设备的诊断，硬件计时输出仅源码审查 |
| procd | 已使用 `write!/writeln!` 的显式 Result 处理，无需修改；示例程序、测试/debug-only 输出不算部署 CLI |

Rust 专用诊断没有对应的 C 命令，不能声称原版 help 文本逐字节等价。对这些路径，测试以正式 r2 的正常 stdout/stderr/退出码为兼容基线，确认新候选正常输出不变，关闭任一输出流后保留原退出码与另一流的完整字节。另记录 stock ubusd/uhttpd/netifd/rpcd 的诊断写失败策略作为原版参考；原本不同的参数语义、文案、退出码和 daemon SIGPIPE 启动策略不在此次修复中改写。

## 回归结果

- 正式 r2 与 C：37 个 case × 6 种流/信号条件 × 4 轮，888 行比较中 128 行失败；每个被采信差异均在四轮出现。
- 修后与 C：同样 888 行全部通过，包含默认 SIGPIPE、缺失 ubus、nft 不读输入提前退出、includes 写失败和 restart 失败边界。
- Rust 专用诊断：15 个 case × 6 条件 × 4 轮，360 行全部通过；同一测试的 r2 在断管条件下发生 120 次 SIGABRT，修后为 0。正常 stdout/stderr 字节与原退出码逐项匹配。
- 各实际二进制 SHA-256、失败行/轮次、比较字段、C 诊断参考观察及完整原始 JSON 的 SHA-256 见 [派生结果](health-20261008-cli.json)。

## 回归方法

`tools/health_20261008_cli.py` 对 C 与 Rust 每项运行：stdout/stderr 都打开、stdout 预先断管、stderr 预先断管，分别 SIG_IGN / SIG_DFL，重复 4 轮。父进程先 `close(read_fd)` 再 spawn；`restore_signals=False`，pre-exec 显式安装 disposition 与 `RLIMIT_CORE=0`。不使用 `head` 的竞态替代。比较实际字节与 shell 退出码，保留二者原始 wait status；正常查询、print、check、includes 有独立输出 sentinel；禁止空轮次，校验完整行数。

唯一既有兼容例外是无效配置导致的 ucode interpreter traceback：restart-abort 保留完整原始 stderr，在比较中只剥除原版解释器 traceback，精确比较最后的 wrapper 警告；没有过滤正常路径警告或任何退出码。与既有 r92 fw4 oracle 的约定一致。

`tools/health_20261008_diagnostics.py` 分开记录 C、正式 r2、候选三侧；15 个一次性诊断，四轮共 360 行候选比较。正常输出必须非空，并对 r2 与候选逐字节比较；断管后比较原退出码及未关闭输出流。C 参考观察不会被伪装成 Rust 扩展命令的等价性结论。

执行目录 `/home/ubuntu/health-20261008-cli` 的原始 synthetic 结果与构建文件不入 Git；派生结果与每个实际被测二进制的 SHA-256 记录在配套 JSON。八个修改组件均在 Linux 构建；httpd 的 ring 使用现有匹配 OpenWrt SDK C 编译器。正式 CI 产物还需运行同一套定向回归、既有 oracle、完整单元测试及基准（总报告负责记录）。

## 为什么读端可能先退出

匹配 odhcp6c `07d324ee7222c0e15b9975281f18236fdccc11bd` 的 `src/script.c` 中，`script_call()` 在先前 `running` PID 存在时先 `kill(prev, SIGTERM)`，随后 fork 新脚本；子进程重置 SIGTERM 后 exec 脚本。它终止的是先前脚本 PID，没有对整个进程组做同步清理，因此旧 shell 读端先消失、尚存的 fw4 子进程再写出而得到 EPIPE 是源码允许的顺序。不能据此断言每个历史 core 都已逐次关联到某一次 SIGTERM。

procd 原版忽略 SIGPIPE，子进程继承该 disposition；r2 的对应继承实现是兼容行为。`cat: write error: Broken pipe` 本身不是缺陷，不修改 procd/odhcp6c，不新增 core 轮转或配置变更。
