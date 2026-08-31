# AX3000T stock / OpenWrt 25.12.5：R1 最小 Rust 实现审查

> 日期：2026-08-31
> 阶段：R1.2
> 结论：**通过；R1 完成，下一阶段是 V1**
> 设备操作：无；全部验证在本机与服务器的一次性 rootfs 副本中完成

机器记录见
[r1-candidate.json](../../manifests/ax3000t-stock-openwrt-25.12.5/r1-candidate.json)，实现见
[components/reload-config](../../components/reload-config/)。

## 1. 实现边界

R1 只创建一个 package、一个 binary，没有建立通用 control-plane framework，也没有修改
任何调用方。原 `/sbin/reload_config` 仍是系统唯一生效路径。

候选显式实现：

- `/var/run/uci` 优先、`/etc/config` 后备、同名 first-wins 的普通文件扫描；
- 旧基线行序比较，以及新增静默、修改/删除发事件；
- 字典序的新基线和完全相同的 `md5sum` 文本格式；
- 逐条、串行的 `service.event` 投递；
- 单实例锁、子进程 timeout、SIGINT/SIGTERM cancellation 与临时目录清理；
- stderr JSONL：比较数、变更条目、非零规范化、逐条投递、完成或致命错误。

它刻意不实现 UCI parser。规范化委托精确镜像 `/sbin/uci`，digest 委托 BusyBox
`md5sum`。因此含点文件名按真实 tuple lookup 处理，不存在错误的 `contains('.')` 捷径。
决策理由见 [0003](../../docs/decisions/0003-delegate-uci-normalization-in-r1.md)。

## 2. 正常与边界行为差分

目标 AArch64 静态 binary 被复制进一次性精确 rootfs。候选和原 17 行脚本分别从相同的
原实现基线与相同 UCI fixture 启动；两边都使用镜像中的真实 `uci`、BusyBox `md5sum`，
只把副本里的 `ubus` 换成记录器。

结果：**11/11 通过**。

| 检查 | 结果 |
|---|---|
| 事件集合 | 11 个用例全部相同 |
| 事件顺序 | 全部相同；按旧基线字典序 |
| 新基线 | 每个用例的完整 name→MD5 全部相同 |
| 含点 tuple | 不可解析为空；可解析 section 非空 |
| `/var/run/uci` override | 与原实现相同 |
| 实现切换 | c10 零事件 |
| trace 与实际投递 | 逐条一致 |

这已经比 token 模型更强：规范化和 digest 不是 stub。但它仍是 userspace/rootfs 差分，
不是 OpenWrt package 或物理设备验证；后两者分别属于 V1/H1。

## 3. 故障注入与差异裁决

**6/6 通过。** 合同内行为保持不变；以下故障原本位于 C1 §8 的未定义区，候选采用可观测、
fail-closed 的处理，不把它们倒写成兼容要求。

| ID | 候选结果 | 与原实现关系 |
|---|---|---|
| f01 部分投递失败 | 继续后续投递、推进基线、trace 失败并退出 2 | 保留事件/基线语义；消除静默退出 0 |
| f02 `uci` 消失 | 退出 70，基线不变 | 不复刻原实现的静默空基线污染 |
| f03 `ubus` 阻塞 | 超时退出 75，基线不变，重试仍发事件 | 给原实现的无限阻塞加上限 |
| f04 畸形 UCI | 仍为空规范化、发事件、写空 hash；另有 normalization trace | 保持观察到的原行为 |
| f05 并发调用 | 第二个进程退出 75，首个正常完成 | 关闭原实现共享目录竞态 |
| f06 SIGTERM | 终止子进程，退出 75，基线不变 | 明确 cancellation 与重试边界 |

投递返回非零后继续写基线看似不理想，但这是 C-08 已有事件语义的一部分；R1 的首要变化是
让它可见。要改成 durable retry 或确认订阅方处理，必须另建合同。

## 4. 单元、property 与静态检查

| 项 | 结果 |
|---|---|
| `cargo fmt --check` | 通过 |
| `cargo test --locked` | 5/5 |
| 状态空间 property | 3 种状态 × 4 个 before/after 位置，共 81 个组合 |
| `cargo clippy --all-targets --locked -- -D warnings` | 通过，0 warning |
| `Cargo.lock` | 固定；仅本 package，第三方依赖 0 |

外部输入限制：最多 4,096 个条目；单个源文件和单个规范化输出各 1 MiB；基线约 1.25 MiB；
命令输出 64 KiB；每个子进程默认 10 s，CLI 上限 60 s。文件名必须是 UTF-8，拒绝换行、
回车和 NUL。两个 FFI 仅覆盖 `flock` 与 signal handler，均有局部 safety 注释。

## 5. 目标产物与体积门

构建环境：Rust 1.78.0，target `aarch64-unknown-linux-musl`，`rust-lld`，LTO，`opt-level=z`，
`panic=abort`，strip。

| 项 | 值 |
|---|---|
| 格式 | AArch64 ELF，静态链接，stripped |
| 大小 | **432,248 bytes** |
| R1 预算 | **524,288 bytes（512 KiB）** |
| SHA-256 | `854d5ca02276afc9f2485f9b9567ad701515ee2a33330bb7a06598ab2a7a8c61` |
| 第三方 crate | 0 |
| license | `MIT OR Apache-2.0` |

二进制本身是构建产物，受 `.gitignore` 排除，没有进入 Git。连续两次完整差分生成相同的
manifest，SHA-256 均为 `013fd0c1…716eab`。

## 6. R1 gate 与剩余边界

R1 gate 通过：单元、property、合同、精确差分、故障、体积和重复性均满足；所有差异均有
书面裁决；crate 没有扩大 R05 职责。因为候选没有安装、没有接管调用方，关闭它不需要任何
恢复动作，原系统路径始终未改变。

V1 的工作仍不可省略：

1. 使用 OpenWrt 25.12.5 匹配 SDK/toolchain 构建正式 package；
2. 默认 disabled，以显式开关选择调用方，并验证 enable/disable/uninstall/upgrade；
3. 在隔离 OpenWrt 环境验证 ABI、权限、日志、资源与长期运行；
4. 再做一次 package 形态的新旧差分。

R1 不授权接触、安装或切换物理路由器。H1 仍需用户另行明确授权与恢复 gate。
