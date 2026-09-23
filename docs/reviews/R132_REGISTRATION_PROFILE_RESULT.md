# R132 注册路径按符号 profile 复核

这份报告只审核 `private/r132-registration-attribution/profile-02` 的 12 个 Oracle 窗口，
不访问路由器，也不把 profile 结果当作路由器性能结论。原始批次采用固定的
正式 499 Hz 计划（collector 标识对应 `f0da992`）；被拒绝的 997 Hz 批次没有混入本报告。

## 证据完整性

本地审计命令为：

```sh
python3 tools/r132_registration_profile_report.py \
  private/r132-registration-attribution/profile-02 \
  private/r132-registration-attribution/profile-audit-04
```

12 个窗口全部完成，C/R124/R131 的精确 ELF、符号源、动态库映射、caller/daemon PID 与 CPU 亲和性检查通过。
每窗 `perf` 的 `SAMPLE` 与解析样本数相等；`LOST`、`LOST_SAMPLES`、`THROTTLE` 和 `UNTHROTTLE`
全部为 0。C 的动态库只使用已冻结的导出符号范围，未解析的 libc/libubox 用户态 PC 被保留为
`unknown`，没有被错误地归入某个 Rust 函数。

派生审计结果见 [r132-registration-profile-results.json](r132-registration-profile-results.json)。
完整本地逐窗审计结果在 `private/r132-registration-attribution/profile-audit-04/results.json`；
原始数据仍在 `private/r132-registration-attribution/profile-02`。

## 观察到的热点组成

下面的百分比是**该组已解析用户态 flat samples 的组成比例**，不是 CPU 时间比例、调用次数、p95
贡献，也不是候选相对 C/R124 的性能比。

| 工作负载 | 组 | send_obj_event | handle/free | Registry/Object lookup | allocator |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 方法 | R124 | 1.26% | 10.58% | 7.42% | 13.74% |
| 1 方法 | R131 | 1.10% | 9.94% | 5.84% | 11.36% |
| 16 方法 | R124 | 0.66% | 12.43% | 4.24% | 39.17% |
| 16 方法 | R131 | 0.66% | 14.66% | 4.92% | 33.30% |

Rust 组全部用户态样本均能按 linker map 解析。两个窗口合计，C 组仍有未解析样本：1 方法为 476/837，
16 方法为 718/1174；这些样本主要来自 libc/libubox 动态导出范围之外，
所以不能用它们与 Rust 的已解析函数比例直接做一一比较。

`send_obj_event` 在 Rust 每组两个窗口合计只有 7 或 8 个 flat samples（约 0.66%–1.26% 用户态样本）。
Registry/Object lookup 家族在 Rust 组为 37–52 个样本（约 4.24%–7.42%）。16 方法时 R131 的
handle/free 组成较 R124 高（14.66% 对 12.43%），allocator 组成较低（33.30% 对 39.17%）；
这不支持“只要改 allocator 就能解释退步”的结论。

## 对 R133 空 patterns 候选的判断

这批 profile **不能证明**注册 p95 回退来自空 pattern 路径，也不能证明 `send_obj_event` 或一次
Registry lookup 对应某个具体 ADD/REMOVE 操作。它们是采样到的指令地址，不是每次调用的计数，不能
从 flat sample 比例反推出尾延迟根因。

它只提供了一个有限的优先级线索：Rust 注册工作负载中确实能看到 Registry/Object lookup，且 R131
在 1 方法组的 flat 占比低于 R124、16 方法组略高于 R124。因而可以**单独设计** R133 空 pattern
早退实验，但不能由这份 profile 直接实现、接受或声称修复了 p95。实验前必须用静态源码和单测证明：

- 仅对合法且已有 path 的 ADD/REMOVE 生效；
- 不改变 epoch、回绕处理、无 recipient 时的序号和事件顺序；
- 不越过 monitor、scratch 与 reply ownership 边界；
- 不增加完整 pattern 预扫描，也不改变私有 `send_obj_event` 的无效/pathless 语义。

通过这些正确性门后，还需要独立的路由器窗口测量。profile 本身只能说明“值得验证”，不能说明“已
找到 p95 根因”。

## 结论

R132 profile 批次的**仪器与数据完整性通过**，但函数级因果归因仍然不成立。当前最稳妥的决定是：
保留 R124/R131 的现有结论，允许把 R133 空 pattern 作为一个窄范围、可回滚的候选实验；不要因为这
批 flat samples 而扩大改动范围，也不要把 Oracle 的 profile 组成替代路由器实测。
