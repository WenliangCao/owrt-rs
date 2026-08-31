# reload-config-rs

R05 配置变更检测与分发的最小 Rust 候选实现。行为边界由
[C1-01](../../docs/contracts/config-change-dispatch.md) 定义。

它没有实现 UCI parser，也没有引入通用 control-plane framework：

- 调用目标系统的 `uci show` 得到与原实现相同的规范化内容；
- 调用目标系统的 BusyBox `md5sum`，保持 `/var/run/config.md5` 可互换；
- 按旧基线顺序调用 `ubus call service event`；
- 将比较、规范化异常、每次投递和完成/致命错误写为 stderr JSONL；
- 对依赖超时、SIGINT/SIGTERM 与并发运行 fail-closed。

默认路径均位于 `/`。`--root` 只用于隔离测试，`--timeout-ms` 控制每个子进程的等待上限。
当前阶段没有安装规则，也不切换 `/sbin/reload_config` 的任何调用方。

本机验证：

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

R1 使用 Rust 1.78.0 将其构建为 stripped、静态的
`aarch64-unknown-linux-musl` ELF。release-matched OpenWrt SDK package 属于 V1。
