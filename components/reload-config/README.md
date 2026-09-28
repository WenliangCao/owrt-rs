# reload-config-rs

R05 配置变更检测与分发的最小 Rust 候选实现。行为边界由
[C1-01](../../docs/contracts/config-change-dispatch.md) 定义。

它复用共享 UCI 和 ubus 库：

- 进程内调用共享 UCI 的 `show` 渲染器，得到与 CLI 相同的规范化字节；
- 进程内计算 MD5，保持 `/var/run/config.md5` 与 BusyBox 格式可互换；
- 按旧基线顺序调用 `service.event`，复用 ubus 连接，每条重新查询对象并等待最终 STATUS；
- 将比较、规范化异常、每次投递和完成/致命错误写为 JSONL；默认发往本机 syslog（`/dev/log`，daemon.info，
  tag `reload_config`，致命错误为 daemon.err），`--trace-stderr` 改写到 stderr。syslog 不可用时只有致命行
  回落到 stderr，其余静默，与原实现的 stderr 行为一致；
- 单条投递超时按一次失败记账后继续本轮（C-08 要求投递失败不影响后续条目和基线重写），
  SIGINT/SIGTERM 仍 fail-closed；并发运行阻塞等锁而不是拒绝（原脚本无锁，两轮会互相删 config.check 并重复投递）。
- 扫描最多 4096 个去重 basename，基线最多 1310720 字节，超限不产生部分投递；配置文件大小不设上限。
  非 UTF-8 或含空格的文件名按原始字节处理，含点名称仍走 UCI tuple 查找。
- 通过同目录临时文件、`sync_all` 和原子 rename 提交基线，I/O 失败时保留旧基线。

`--timeout-ms` 控制每个规范化条目、每条事件的总预算；每条事件的连接、查询和调用共享一个截止时刻。
调用还保留原 ubus CLI 的 30 秒内部上限。取消停止后续事件、退出 75 并保留旧基线；已发送的事件不撤销。
失败连接被丢弃，事件不会自动重试。完成的 STATUS 只表示接收端处理了请求，不表示下游服务已完成重载。

`--root` 只重定位配置、覆盖目录、基线和运行锁。UCI delta、`/dev/log` 和 ubus socket 仍须另行隔离；
不能仅凭 `--root` 对生产配置做变更实验。
V1 package recipe 位于
[packaging/openwrt/owrt-reload-config](../../packaging/openwrt/owrt-reload-config/)；安装默认禁用，
显式开关使用重启即失的 bind mount，原 `/sbin/reload_config` 文件保持不变。

本机验证：

```sh
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

正式 package 使用仓库固定的 Rust 1.98.1 和 OpenWrt 25.12.5 filogic SDK，并复制共享 UCI/ubus
源码参与构建。沿用 512 KiB 体积预算；历史构建门见
[V1_VALIDATION.md](../../reports/ax3000t-stock-openwrt-25.12.5/V1_VALIDATION.md)。
