# R132 注册 profile 调用者

新增 `registration-perf` 编译 feature，只构建为独立静态诊断 ELF `owrt-register-perf`。
原 R131 路由器 benchmark ELF SHA `984f6ec0…09cd1e` 未改变；daemon 没有修改。
新 ELF SHA 为 `ad707cee9684aeaccbddf548f59eda18c2b6ce3eb7590cee5436296e18251b4f`。

接口沿用原 Rust caller：

```text
owrt-register-perf register-cycle SOCKET METHODS NAME_BYTES N WARMUP PID
```

METHODS 支持 1–64，NAME_BYTES 支持 8–128，N 支持 1–1000000，WARMUP 支持 0–100000；PID 必须只有一个。
调用者自己固定 CPU0，并在计量前后检查 daemon CPU1。环境变量 `OWRT_PERF_CTL_FD` 和
`OWRT_PERF_ACK_FD` 指定已打开的继承管道。warmup 及空 registry 检查后发送 `enable\n` 并等待 ACK，
然后读取外层 CPU/wall 时钟、执行 n 个原始 ADD/REMOVE 周期、读取结束时钟，最后发送 `disable\n` 并等待 ACK。
ACK 是 **5 字节**：`a c k LF NUL`，与既有 C perf helper 的 `sizeof("ack\n")` 一致。

首次构建把 ACK 数组误写成 4 字节，被 Rust 的数组长度类型检查阻止；构建日志和失败源码归档均保留。
修正后的第二次构建成功。Oracle 上精确 C/R124/R131 × 1/16 方法，共六项 n=100、warmup=20 的
mock-ACK 前检全部通过：前置完整签名检查、两个控制边界、活体 caller ELF/CPU affinity、每次成功状态、
100 个正整数 latency 样本、CPU/wall 包围区间和末尾空 registry 均验证。
mock 控制器在收到 enable、尚未 ACK 时，还用独立 `ubus list` 确认 registry 已空。

与原失败 fixture 的关系可以直接核实：方法名仍为八位十进制编号加可选 `x`，path 仍为 `bench.cycle`，
每方法仍只有 `policy: Int32`；fixture 构造和完整签名 preflight 源码与 R127 保存的 benchmark 源码逐字相同。
`components/ubus/src/conn.rs`、`blob.rs`、`sys.rs` 也与该保存版本同 SHA；循环直接调用同一
`Connection::add_object/remove_object`。没有换成另一套 libubus 调用流程或改变注册 signature。

诊断仍不是原 ELF 的逐字复现：增加了 warmup 后 empty barrier，样本数组在计量前预触页，CPU 时钟只包围循环，
并在 disable ACK 及最终 empty 检查后输出独立 JSON。因此新数据不能与旧 router 窗口混样。
preflight 校验完整签名、路径和 ID；逐周期沿用原 caller 的成功 STATUS 与 ADD OBJID 检查，
没有声称每条 REMOVE DATA/OBJTYPE 或每个回复字节都独立校验。JSON 显式写 `wire_reply_bytes_checked:false`。

本步骤只完成工具和协议前检，不给性能结论。实际 perf stat/record 必须再分别做低 n 真控制前检，
随后才可运行预冻结的 Oracle 诊断计划；路由器仍是最终性能比较的依据。
[派生验证结果](r132-registration-caller-validation.json)记录完整 ELF/源码身份、六项前检与失败记录。
