# R93 HTTP 间隔三侧诊断

从管理 Mac 调用，HTTPD、rpcd、ubusd 与负载客户端在路由器私有 namespace 中运行。Wi-Fi 是管理链路，负载走私有 loopback。生产进程保持运行，不安装包、不切换服务。

## 输入与运行

- `candidate`：独立的、静态链接 AArch64 ELF `httpd-rs`。应来自与正式 R89 相同编译器、SDK/linker、flags、固定源码路径的发布 recipe；工具校验 ELF 和 SHA256，recipe 仍须独立核对。
- `diagnostic`：已有 `tools/benchmark/src/main.rs` 编译出的独立 AArch64 静态 ELF，支持 `http-paced`，例如 `private/r92/diagnostics/http-diagnostics`。不替换冻结 `owrt-benchmark`。
- `--baseline-manifest`：已审定正式 R89 本地清单。远端 `/root/r89-before-r90/manifest.json` 必须逐项相同，HTTPD ELF 哈希也必须吻合。
- `--recovery-gate`：已经验证离线备份、当前 boot/config、自动回滚的预检 JSON；同目录必须保留 `config-before.sha256`。工具会重新检查实际 Wi-Fi 路径、健康、boot 与配置。

先执行只读本地准备，不使用 SSH：

```sh
python3 tools/benchmark/r93_http_gap.py \
  /absolute/path/to/httpd-rs \
  private/r92/diagnostics/http-diagnostics \
  private/r93/http-gap-plan \
  --baseline-manifest private/r93/recovery-01/r89-before-r90.manifest.json \
  --recovery-gate private/r93/recovery-01/experiment-preflight.json \
  --interface en0 --fixture 16384 --plan
```

检查生成的 `settings.json`、`order.json` 和 `isolated-gap.sh` 后，使用新的输出目录执行（去掉 `--plan`）：

```sh
python3 tools/benchmark/r93_http_gap.py \
  /absolute/path/to/httpd-rs \
  private/r92/diagnostics/http-diagnostics \
  private/r93/http-gap-a53-01 \
  --baseline-manifest private/r93/recovery-01/r89-before-r90.manifest.json \
  --recovery-gate private/r93/recovery-01/experiment-preflight.json \
  --candidate-build-record /absolute/path/to/build-attestation.json \
  --interface en0 --rounds 4 --clients 4 \
  --iterations 1000 --hot-iterations 10000 --fixture 16384
```

`--fixture 512` 对照小响应局部诊断；`--fixture image-css` 使用精确镜像 44 KiB 样式表，保留 `.css` 扩展名及 MIME 路径。不同 fixture 使用独立输出目录。`--cpus 0` 可选择统一单核 taskset，缺省不绑核；不要混合两种结果。

默认每 fixture 60 个样本：4 轮 × 3 侧 × 0/20/40/60/80 ms。侧顺序和间隔顺序交错。`iterations` 是每个 paced 样本所有客户端的请求总数，必须能被客户端数整除；gap 0 独立使用 `hot-iterations`，避免 CPU tick 太少。默认 pacing 下限为 600 秒，连同 namespace 启动、SSH 下载、4 次中途健康检查及收尾，预计每 fixture 15–20 分钟；真实机器更慢时以原始时间为准。三个 fixture 约 45–60 分钟。每次独立样本 workload 有 namespace 内 KILL timeout，默认 530 秒。

## 输出与计数口径

`results.json` 包含每轮结果和每侧每 gap 的中位数、最小/最大值：

- 逐请求响应状态/完整字节校验、成功数量、错误数，原始延迟数组及 mean/p50/p95/p99。
- HTTPD 请求区间 CPU tick、秒和 µs/request，不含预热。
- HTTPD/rpcd/ubusd **一个共同 outer 区间** 的各自 CPU 与等待子进程 CPU，以及总量、依赖量；此区间含每客户端一个预热请求，单独按 `N + clients` 归一化。禁止与 inner 区间相加。
- 三个 daemon 在预热前、结束、约 1 s、约 2 s 后的 RSS/匿名页/文件页/VmHWM/fd/thread；2 ms 观察到的 HTTPD 线程出生数仅是下限。精确镜像 sleep 只支持整数秒；此工具不覆盖原 200 ms 内存采样门。
- 每次 `/proc/PID/exe`、依赖、fixture、harness、client、冻结工具及 boot 身份；生产栈前后 snapshot 和每轮健康结果。

这些 CPU 总量不含负载客户端和线程观察器；不能称为全机 CPU。资源是有限时点采样，VmHWM 是进程峰值，不是每段连续峰值；RSS 不是 PSS/USS。每轮分位数的中位数不是混合全部请求计算的分位数。

## 失败与清理

复用现有 `isolated.sh` 的只读镜像、私有网络/PID/mount、遮蔽 kmsg、ns-exec 父进程退出清理。生成副本只增加 fixture 选择、共同计数区间、延迟资源快照及 namespace 内 workload timeout；不更改运行库或生产 HTTPD。

每次远端数据下载、完整文件集与哈希校验之后才删除该次 owned 输出。失败不会写集合 `COMPLETE`；`collector.json` 保留精确 `/tmp/r93-http-gap-…` 目录，SSH timeout 还会写 `TIMEOUT.json`。确认 namespace 已退出并取回证据后，仅清理记录的目录。工具不复用不完整样本、不自动覆盖/续跑。中断后重新收集使用新目录；不要把残缺样本纳入比较。

本地验证：

```sh
python3 -m unittest discover -s tools/benchmark -p test_r93_http_gap.py -v
```

精确镜像不提供 BusyBox timeout applet。生成 harness 在 ns-exec 的 namespace 命令中启动 `sleep` + shell 内建 `kill` 看门狗，捕获当前 namespace 命令 PID；该命令即使 exec chroot，PID 也不变。超时仅杀这个 PID，ns-exec 的 PID 1 随之退出，内核清理整个 namespace；正常退出也会清理尚在睡眠的看门狗，没有可遗留到下一轮的计时器。

截至编写完成，本地计划/语法/证据推导及看门狗 exec 后定向 SIGKILL 测试通过。物理运行前仍须由 root 统一在 Linux namespace 做一次业务 smoke 和短预算超时清理 smoke，确认增补产物在目标上的行为。
