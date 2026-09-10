# reload-config-rs

R05 配置变更检测与分发的最小 Rust 候选实现。行为边界由
[C1-01](../../docs/contracts/config-change-dispatch.md) 定义。

它没有实现 UCI parser，也没有引入通用 control-plane framework：

- 调用目标系统的 `uci show` 得到与原实现相同的规范化内容；
- 调用目标系统的 BusyBox `md5sum`，保持 `/var/run/config.md5` 可互换；
- 按旧基线顺序调用 `ubus call service event`；
- 将比较、规范化异常、每次投递和完成/致命错误写为 JSONL；默认发往本机 syslog（`/dev/log`，daemon.info，
  tag `reload_config`，致命错误为 daemon.err），`--trace-stderr` 改写到 stderr。syslog 不可用时只有致命行
  回落到 stderr，其余静默，与原实现的 stderr 行为一致；
- 子进程超时按一次失败记账后继续本轮（原脚本没有超时，只是一直等；C-08 要求投递失败不影响后续条目和基线重写），
  SIGINT/SIGTERM 仍 fail-closed；并发运行阻塞等锁而不是拒绝（原脚本无锁，两轮会互相删 config.check 并重复投递）。
- 输入不设上限：任意大小的 `/etc/config` 文件、非 UTF-8 或含空格的文件名都照原脚本处理（`uci show` 失败即空条目），
  基线按字节写出与 `md5sum` 输出一致。
- 通过同目录临时文件、`sync_all` 和原子 rename 提交基线，I/O 失败时保留旧基线。

默认路径均位于 `/`。`--root` 只用于隔离测试，`--timeout-ms` 控制每个子进程的等待上限。
V1 package recipe 位于
[packaging/openwrt/owrt-reload-config](../../packaging/openwrt/owrt-reload-config/)；安装默认禁用，
显式开关使用重启即失的 bind mount，原 `/sbin/reload_config` 文件保持不变。

本机验证：

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

R1 的独立体积门使用 Rust 1.78.0 静态构建。V1 正式 package 使用 matching packages feed
的 Rust 1.94.0 和 OpenWrt 25.12.5 filogic SDK，产出 dynamic musl AArch64 PIE；验证结果见
[V1_VALIDATION.md](../../reports/ax3000t-stock-openwrt-25.12.5/V1_VALIDATION.md)。
