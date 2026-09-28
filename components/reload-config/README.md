# reload-config-rs

R05 配置变更检测与分发的最小 Rust 候选实现。行为边界由
[C1-01](../../docs/contracts/config-change-dispatch.md) 定义。

规范化复用共享 UCI 实现；运行时行为是：

- 在进程内调用共享 UCI show，并计算 MD5，保持规范化字节及 `/var/run/config.md5` 格式兼容；
- 按旧基线行序逐条调用 `service.event`，复用成功的私有连接，每条重新查询对象，等待最终 STATUS 后才继续；
- 将比较、规范化异常、每次投递和完成/致命错误写为 JSONL；默认发往本机 syslog（`/dev/log`，daemon.info，
  tag `reload_config`，致命错误为 daemon.err），`--trace-stderr` 改写到 stderr。syslog 不可用时只有致命行
  回落到 stderr，其余静默，与原实现的 stderr 行为一致；
- 投递超时按一次失败记账后继续本轮（C-08 要求投递失败不影响后续条目和基线重写），
  SIGINT/SIGTERM 仍 fail-closed；并发运行阻塞等锁而不是拒绝（原脚本无锁，两轮会互相删 config.check 并重复投递）。
- 最多扫描 4096 个去重 basename，旧基线上限 1,310,720 字节，超限保留旧基线且不投递；配置文件本身不设此大小上限。
  文件名保留原始字节，含点名称按真实 UCI tuple 查找；失败或超时保留已经渲染的前缀，取消不当成功处理。
- 通过同目录临时文件、`sync_all` 和原子 rename 提交基线，I/O 失败时保留旧基线。

默认路径均位于 `/`。`--timeout-ms` 为每个规范化条目、每条事件分别设置一次预算；同一条目的 base/override/delta 锁共享截止时间，
同一事件的连接、对象查询、调用共享截止时间。调用失败不重试该事件，后续条目使用新连接；取消退出 75，保留旧基线，已发送事件不撤销。
`--root` 只改配置和运行文件路径，不能隔离默认 delta、ubus socket 或 `/dev/log`；测试必须建立完整的文件系统、PID 和网络 namespace。
V1 package recipe 位于
[packaging/openwrt/owrt-reload-config](../../packaging/openwrt/owrt-reload-config/)；安装默认禁用，
显式开关使用重启即失的 bind mount，原 `/sbin/reload_config` 文件保持不变。

本机验证：

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

当前正式构建固定 Rust 1.98.1、OpenWrt 25.12.5 filogic SDK 和 `release-image` canonical workflow，
产出静态 AArch64 musl ELF，体积预算为 512 KiB。配方同时包含共享 UCI 和 ubus 源码；运行时不启动子进程。
构建产物与精确镜像原版、正式 R89、历史 R94 的成绩分别记录，不把 SDK 筛选当作正式实机结果。
