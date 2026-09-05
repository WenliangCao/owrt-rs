# R34 复审：0c050a6 与 httpd/ring 可重复性

日期：2026-09-05。范围：审查最新四个提交、重跑本机测试、读取匹配锁定依赖源码。只新增指导文档，不修改代码、不操作设备或构建服务器。

## 结论

上轮核心正确性问题已修好，可以认可这部分成果。但不能说只剩 httpd/ring：本轮发现停顿上传的 CPU 忙等，以及编译器身份检查仍漏掉一种 Cargo 支持的覆盖方式。

R33 报告记录设备实际上传成功、SDK 重建、主要差分及 CI 镜像成功；本轮没有重新独立执行这些远端步骤，不能将报告中的设备事实说成本轮实测。

## 本轮重跑结果

- 七个 crate **80/80 单元测试通过**；check-tools、正常工具链身份检查通过；HTTP --locked build 通过。
- 当前上传矩阵的 17 个用例全部通过，含 32 MiB、chunked、Expect、停顿上传、慢速滴灌。传输中采样 RSS delta 1264 KiB（10 ms 采样不是数学意义上的精确峰值）。
- 用上一轮原失败 probe 重跑：停顿上传 1.001 s → 504；提前拒绝保留 403；62001-byte header → 200。
- 现有 negative-test 在本机“PATH 直接指向固定版 cargo”的布局下，旧版 `RUSTUP_TOOLCHAIN` 用例失败：env 本来就不能切换一个直接调用的 cargo binary。这是探针对 rustup proxy 的环境假设，不能据此指控现有版本检测失效。R33 中 CI 通过是另一环境的报告结果。

## 1. P1：就绪循环空转，停顿上传占满一个 CPU 核

位置：`components/httpd/src/cgi.rs:194–208`。

只要 stdin 存在，就把它以 POLLOUT 注册。stage 为空、客户端没发更多正文时，pipe 依然可写，因此 poll 每次立即返回；body.read 返回 WouldBlock，随即再次 poll，直到 script deadline。现有延迟断言只能证明超时有效，不能捕获 CPU 空转。

本轮实际探针：`-t 1 -T 3`，发完 `Content-Length: 100` 的请求头但不发 body，CGI 等待 stdin：

- wall time：1.001 s；
- httpd 进程 CPU time（ps，不含 CGI 子进程）：0:00.00 → **0:01.00**；
- 504 如期到达，但几乎整整占用一核。

执行要求：

1. 只有 `stage_pos < staged`（确实有待发送字节）时才等待 stdin POLLOUT。
2. 需要更多正文时监听客户端可读；先处理 BufReader/rustls 已缓冲的数据，再真正等待网络 readiness。不要因改兴趣集合而丢失无需新 socket 事件的明文。
3. stdin HUP/ERR 仍要可观察：可以保留 fd、events=0 接收这些错误事件，或者采用等价且明确的机制；不能为避免忙等重新引入错误的阻塞 read。
4. 保留先处理提前响应、固定大小缓冲、脚本退出和总 deadline；不要用 sleep(1ms) 掩盖错误的 readiness 注册。
5. 新增“停顿上传 CPU”回归：比较 httpd 自身 CPU 时间与 wall time，允许调度噪声但不能近似一核满载；同时复测提前 403、慢滴灌和 TLS。用多个空闲上传连接确认开销不会线性吃满多核。

优先修这个问题，再花时间做发布字节可重复性。

## 2. P2：工具链身份仍漏掉 CARGO_BUILD_RUSTC

位置：`tools/toolchain_identity.sh:36–56`。

Cargo 同时支持 `RUSTC` 和 `CARGO_BUILD_RUSTC`（本机安装的 Cargo reference/config.html 的 build.rustc 文档明确列出）。当前脚本只看前者及部分配置文件。

本机：PATH 指向 1.98.1，同时设置

```sh
CARGO_BUILD_RUSTC=/Users/USER/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc \
  sh tools/toolchain_identity.sh
```

结果 exit 0、`official=yes`、记录 rustc 1.98.1。该入口没有验证 Cargo 实际选择的编译器。本轮只跑了 identity，没有用旧版本发布。

实施：正式发布入口至少拒绝或正确解析 `CARGO_BUILD_RUSTC`、`CARGO_BUILD_RUSTC_WRAPPER`、`CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`，并明确处理实际工作目录祖先中的 Cargo 配置以及 `cargo --config` 覆盖。可以采用明确的正式构建环境白名单/拒绝覆盖策略，不必不断补一套不完整的通用 Cargo 配置解析器。研究性覆盖只能标非正式。

增加相应负向用例；测试旧版切换要确认被测试入口确实是 rustup proxy，或用已知旧编译器的绝对路径验证，不能依赖机器碰巧装了第二个工具链。

## 3. R33 的“全部执行完毕”表述需要更正

R33 开头称剩余六项全部完成，但 §5 明确仍有：

- 1.94 与 1.98.1 的体积/性能对照未做；
- uci/logd/fw4/reload-config 四组件 reference harness 未重跑；
- httpd/ring 可重复性未解决；
- 只有 3 分钟设备窗口，未长时间 soak。

这些不是新增运行故障，不应否定已完成的上传/主要差分；但报告要区分“已执行的发布步骤”和“尚未达到的原验收范围”。编译器变化也可能影响行为，不能以源码未改代替这四个组件的验证。

## 4. httpd/ring 有多重要

这是**发布来源核验与构建可靠性**问题，值得收口。不同机器不能重建相同产物，就不能直接凭哈希证明设备 binary 与被审查源码/配方一致；也难以区分正常构建差异和意外输入变化。

但当前证据只是“不一致”：不能由此直接推导 TLS 加密有漏洞、性能退化或设备不稳定。对当前优先级，它低于第 1 项已经复现的 CPU 故障；对长期维护和正式可核验发布，它应有明确验收。

必须分清目标：

1. 同一源码/环境重建：binary 字节相同。
2. CI 与构建机跨宿主重建：相同 target binary 是否相同。
3. APK 是否相同：还包含打包/签名元数据，不等于 binary。
4. 整个固件镜像是否相同：范围更大，不能用第 1 项证明。

详见可直接交给 Opus 的 [One-Shot 执行方案](R34_HTTPD_RING_ONESHOT.md)。方案给出一次排查闭环，不承诺在没有两份中间产物时能凭猜测保证一行修好。
