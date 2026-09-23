# R139：原镜像 libubus 注册延迟调用者

新增独立 `register_libubus_latency.c`，补 R101 只有整窗 CPU／wall、没有注册尾延迟样本的覆盖缺口。旧 R101 源码与调用者保持不变。R136 主矩阵使用 Rust `Connection`；原镜像 libubus 的直接 SEND 结果也不能替代注册延迟。

接口为 `register-libubus-latency SOCKET N WARMUP SUBJECT_PID`。调用者固定 CPU 0，要求 daemon 固定 CPU 1；fixture 沿用 R101 的 `bench.cycle`、一个八字节方法名和一个 INT32 policy。预热与测量前后完整签名检查不计入测量，每次 ADD 前要求对象和类型 ID 为零，每次 REMOVE 后要求两者清零。最终再次核对完整签名并删除对象、检查对象表为空。

每个 ADD＋REMOVE 周期由两次 `CLOCK_MONOTONIC` 读取包围，输出原始顺序的 `latency_ns`。数组在预热前分配并写入；排序和输出在测量及连接清理后进行。mean/p50/p95/p99 由同一数组计算，分位索引为 `round((N-1)*q)`，半值向上。不扣除取时成本。整窗另按原 R101 顺序读取 daemon／caller 进程 CPU 与 wall；CPU 包含调用者取时和记录样本的开销，不是纯协议成本。

这是新的 native libubus 工作负载。接收算法、编码、分配和取时形状不同，不能与 Rust caller 混样、把两者差值全归于接收函数，或据 native 结果撤销已经确认的 Rust caller 负项。守护进程源码没有因本调用者改变。

构建入口：

```sh
sh tools/benchmark/build-register-libubus-latency.sh SDK COMPONENT_SOURCES NEW_OUTPUT_DIR
```

复用原 SDK link-symbol recipe；`link-only/` 仅供链接。运行必须加载镜像原版 libubus、libubox、libgcc_s、libc，并核验实际依赖和哈希，不能上传重建库代替镜像库。

Oracle 功能 smoke 已完成：精确 C 与 R136，各 100 周期／20 预热；完整签名、每周期 ID 清理、原始样本数量、mean 与三分位独立重算、daemon PID/starttime/线程数/亲和性、四个镜像库及 ELF 身份、进程/socket 清理均通过。这不是性能筛选，没有从这 200 个样本推导胜负。

- 调用者源码 SHA-256：`050625a50cf2ab2bf8bd1ec09c478f63946c350b87cdf48b7f47103dda1584ab`
- 调用者 ELF：`959819747e8e9d221c8ebd02e31cb9ddf71c346a255277f997acb34b8b32ccfd`
- 功能结果：`private/r139-libubus-caller/smoke-01/result.json`，SHA-256 `d1e7b092bd190847106a679173852d63c38369cc48bb3df1bc4c3fda1a78d107`
- 本地产物：`private/r139-libubus-caller/register-libubus-latency`

初次构建因辅助脚本没有可执行位而退出，日志保留；入口改为显式 `sh` 后重新构建成功。SDK 的 runas.so preload 提示与既有 recipe 一致，编译以 `-Wall -Wextra -Werror` 完成。没有改动或执行路由器状态。
