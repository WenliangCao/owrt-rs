# DNS hosts/cache SIGHUP 生命周期

本阶段只关闭已接线 DNS hosts 文件和 forward cache 的 SIGHUP 子合同，不代表
完整 reload、OpenWrt 集成或生产验收。

## 精确源码与实现

- `dnsmasq.c:1570–1603,1834–1866`：SIGHUP 执行
  `clear_cache_and_reload`；普通主配置不重读。`no-poll` resolver、servers-file、
  DHCP 配置/租约/DNS/script 重读另有调用链，仍未关闭。
- `cache.c:1548–1682`：清转发 cache、重读 hosts/config，保留 DHCP 记录；
  `read_hostsfile:1436–1450` 的缺失/读取错误只记录日志，不保留旧文件名字，
  不退出 daemon。Rust forward cache 不含 hosts/DHCP，`Cache::clear` 保留容量、
  策略与 slot generations，并清 pending insertion，防止旧 CNAME handle 复活。
- `main.rs`：signal handler 只设原子标志；主线程读取 hosts 快照，TCP service
  更换 hosts；每个 UDP worker 接收容量为 1 的通知，应用最新 hosts 并清 cache。
  重复信号合并且队列有界。已有上游事务与配置不重建。
- `read_hosts` 的 startup/reload 文件错误与 C 一致：日志后继续；其他文件与
  `host-record` 保留。`-d` 与 `-k` 均可进入当前 foreground runner。
- SIGHUP storm 实际暴露 UDP `recv_from` 因 EINTR 退出 worker 的缺陷；已修为
  retry。DHCP/TFTP worker 同样容忍 interrupted syscall。

## 可重跑的 C 服务差分

`tools/dnsmasq/dns_reload_diff.py` 必须经 `run_isolated.sh`，使用 Linux 私有
net/mount/pid namespace。C/Rust 启动参数、配置、容量、TTL、上游实现相同。
比较客户端 ID、flags/rcode、question、记录类型/地址/TTL、记录顺序、上游计数
和退出结果。缓存 TTL 仅允许实际测得的整秒时间窗口，原 TTL/报文始终保留；
其余 TTL 精确比较。C 输出是期望，校准为 1 个等值通过与 6 个注入差异拒绝
（ID、flags、地址、TTL、丢行、上游副作用）。

`private/dnsmasq-rewrite/dns-reload-20260930/run-04/summary.json`：
**21 个查询检查 + 2 次正常退出 = 23 passed、0 failed**。覆盖：
UDP/TCP hosts、AAAA、原地更新、主配置不重读、正负 cache 清空及重新命中、
文件删除时旧名字消失/固定记录保留、文件重建、信号合并、启动时 hosts 缺失。
精确 C ELF `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`；
Rust ELF 及完整报文/配置/计数在 private summary/trace，不提交原始输入。
参考源码与依赖审计见 `REFERENCE_AUDIT.md`。

失败轮次保留：run-01 在 C `-d` 同步 TCP 的 partial-frame shutdown 上超时，
该模式没有正式 fork worker，故从此窄差分移出；run-02 真实暴露 Rust EINTR
导致 UDP worker 退出；修复后的 run-03 为 19/19，run-04 加入负缓存为 23/23。
`dns_signal_smoke.py` 另用 Rust `-k` 完成 SIGINT/SIGTERM 各 6/6，包含 idle、
partial-frame 与重复 TCP 请求；正常退出约 0.13s。这不是 C 生产模式的完整
连接生命周期差分。两项原始结果在 `reload-signal-{int,term}-20260930/`。

Cache 12 个回归、主程序 6 个回归与 binary clippy `-D warnings` 通过。
该结果不是吞吐/资源收益，也不覆盖 resolver polling、ubus、租约脚本或
DHCP→DNS 名称同步。配置相关 metrics 尚未接入，不能据此推导清缓存后的
累计计数与 C 已等价。
