# 启动、CLI、配置、信号生命周期补充复审

日期 2026-10-14；冻结 main `e9d89b17d72a58b723cce88038ceaa1be58d7f8c`。当前候选 ELF SHA-256：`e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`；精确镜像 C SHA-256：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。

**本轮新增生命周期检查未发现当前残余产品缺陷。原 AUDIT 的 A01–A05、A09 已在当前 main ELF 上重新验证原反例关闭，不能继续当作当前问题计数。** 以下结论仅覆盖列明的输入和阶段，不是对任意信号交错、配置或运行环境的完整等价证明。

## 历史反例的当前状态

| 历史条目 | 当前新运行证据 | 结论 |
| --- | --- | --- |
| A01：USR1/ALRM 杀死 daemon | normal/debug × C/Rust × HUP/USR2/USR1/ALRM，共 16 次 daemon 运行，信号后仍回答 DNS；另 4 次真实缓存重复 dump、4 次 EFBIG 写失败后的 ALRM 提前持久化 | 原反例关闭 |
| A02：多 MAC 静态交接无 ACK | 第一 MAC ACK 后，第二 MAC DISCOVER 获 OFFER、随后两次 REQUEST 获 ACK，租约身份切换与 C 一致 | 原反例关闭 |
| A03：Rapid Commit 丢最终 pool tag 名称政策 | ignore/generate × 有/无 option 50 均与 C 的 ACK、租约与 A/PTR 相同 | 原反例关闭 |
| A04：Rapid Commit 不采用 hosts 权威名 | 普通 REQUEST 和 Rapid Commit 对照都采用 authoritative，客户端 claimed 不被额外发布 | 原反例关闭 |
| A05：11 个合法配置入口拒绝启动 | 原 11 项 + no-ident 正控制，共 12 对；`--test`、实际启动、有效本地 A 回答及正常退出全部一致 | 原反例关闭 |
| A09：Rapid ACK 漏 option 12 | 快速 ACK 和普通 REQUEST 的完整 DHCP 选项比较一致，包含客户端 hostname | 原反例关闭 |

A02/A03/A04/A09 共用本次 `audit_20261011_dhcp.py` 的 9 对定向场景，不重复计算成四套独立测试。A05 使用 `audit_20261011_config.py --a05-only`，没有把双方实际运行都不支持的编译功能算成 Rust 回归。

## 新增完整回归

### CLI 与配置退出

`m5_cli_final.py --family test`：**345 对用例全部通过**，覆盖冻结 inventory 的 169 个普通选项，各 CLI/配置文件形式，共 338 例，加 7 个控制。没有缺项；退出状态、输出、语法副作用与 C 一致，版本输出允许约定的 Rust 身份说明。确认 `--test` 不创建 daemon-only PID/log/dump/leases/lease-hook 产物；配置解析阶段的 `conf-script` 副作用仍按 C 契约比较，并未错误要求所有脚本都不执行。

`config_startup_exit_diff.py`：**5 对用例通过**，覆盖缺配置文件、缺目录、读取权限不足、非法语法、合法配置，明确区分文件错误退出 3 与语法错误退出 1。该驱动只核对退出码，未把 stderr 文案一致列为其证明。删除执行记录和改退出码的两个负控制均被拒绝。

### normal/debug 权限、能力与 PID

通过镜像 musl 执行精确 C ELF，复用 `startup_identity_diff.py` 和 `startup_privilege_diff.py`：**6 对 identity + 7 对 capability 用例全部通过**。两套驱动的身份配置位于各自私有 mount namespace 的 `/etc`，不会修改 Oracle 主机账户。

检查 foreground/debug 的 UID/GID/补充组/有效与允许 capabilities、正常 PID 创建与退出、debug 保留已有 PID 文件、PID 软链接目标不被破坏、未知用户/组、PID 路径错误、缺 NET_ADMIN/SETGID 能力、SIGINT 行为。debug 保留启动身份，普通模式按配置降权；SIGINT 在普通 foreground 模式保持服务，在 debug 模式按 C 退出 5。失败时 PID 生命周期按具体 C 阶段判断，没有一概要求所有失败都删除文件。capability 驱动的缺场景、错误 DNS flags、错误 worker capability、错误 PID 四个负控制均被拒绝。

为避免在 glibc Oracle 上错误调用动态 C，本轮只用小型外部 adapter 把实际启动 argv 转成镜像 loader/lib 路径；C/Rust 的二进制 SHA 仍取真实 ELF，并保存转换后的实际 argv。没有修改仓库产品或原驱动。

### 真正 daemonize 与失败返回

`m5_logging.py --scopes daemon`：**33 对当前 ELF 场景全部通过**。覆盖 daemon 默认 stderr/syslog、后台/foreground/debug 相对路径、debug 与 `-k` 的组合优先级、配置 nobody 身份、非 root PID 错误处理、PID 软链接、debug SIGINT、日志/PID 打开失败、父进程收到的错误设施/内容、helper 在 DHCP/TFTP 启动期间的所有权、未知用户/组、TFTP 根缺失、不可打印路径，以及 runtime servers-file 失败。

这是 daemon scope 的实际通过，不是整套 logging 所有 scope 的资格声明；本次结果 `closed=[]`，没有把未执行的 sink/query/overflow 等其它族宣称关闭。驱动的 49 个比较器负控制均通过，但这些控制不是 49 个额外真实 daemon 场景。

### 信号必须产生正确效果

在原 `audit_20261011_runtime_signals.py` 的真实服务函数上扩展 normal/debug，直接对精确镜像 C 与当前 Rust，不使用第三个宿主编译 C 作为依据：

- **16 次基本信号运行**：HUP、USR2、USR1、ALRM 后均存活且回答健康查询。
- **4 次 dump 运行**：真实转发并缓存 A，另产生普通 NXDOMAIN 与 bogus-nxdomain 转换；连续两次 USR1 的 cache、query、server、TCP 指标及 hosts/cache 行数与 C 一致，上游请求严格为 3 次。
- **4 次 ALRM 维护运行**：先以 RLIMIT_FSIZE 产生真实 EFBIG，DHCP 已 ACK 而 leasefile 尚未写入；解除限制后发送 ALRM，在 2 秒窗口内落盘，早于 60 秒自动重试；随后 USR1 可见租约，DNS 继续可用。此前专项已经跑过 ENOSPC 60 秒自动重试，本次没有重复那项长等待。
- **4 次 HUP/USR2 实际效果运行**：把 hosts 中 `audit.test` 从 `192.0.2.1` 改为 `.2`，HUP 后查询必须返回新地址；重命名日志文件后发送 USR2，之后的查询必须进入新日志，旧日志保持不变，服务最终正常退出。不能仅凭“信号后没死”把 reload/reopen 当作成功。

本补充分工没有另外长编译 fuzz target。前一专项已有当前 ELF 的 750 个不同 DHCP 请求组合及原始包检查；这不是全协议长期 fuzz，报告不这样表述。

## 证据、局限与收尾

派生收据：[lifecycle-evidence.json](lifecycle-evidence.json)。电脑原始目录 `private/full-audit-20261014/lifecycle/`，Oracle 原始目录为 `/tmp/full-audit-dhcp-20261014/private/lifecycle-*`。归档 `private/full-audit-20261014/lifecycle/oracle-evidence.tar.gz` 的 SHA-256：`ef8e299b4db9706171221aa0dd39c2e55eb5d9c43c0006bdab2a8509ca37f9ea`。原来的 DHCP 证据归档保持不变。

CLI、配置和 daemonize 测试在精确镜像私有 overlay 执行；原 DHCP 反例、信号和 identity/privilege 驱动则在独立 net/mount/PID namespace，使用镜像 musl/libs 与合成数据，不能冒充真实 procd/ujail 或真机启动链测试。十组件集成由主审另有证据。本轮没有覆盖任意信号风暴、持续内存压力下的全部启动阶段故障，或真实无线客户端重连。

本专项没有操作路由器、没有改产品代码、没有提交或推送 Git。所有本专项进程已结束。收尾看到另一个 `/m2/` 测试进程时核对了其 `/proc/PID/root`，归属 `/dev/shm/full-r2-fix-20261014/` 的独立修复任务，保持原状，没有误杀共享 Oracle 上的其它工作。
