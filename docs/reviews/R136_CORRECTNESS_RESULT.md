# R136 正确性复核

**combined 的实际运行时代码差异未发现阻断问题，Oracle 和路由器的本轮正确性门均通过。** 这允许继续评估它的实机性能，不等于证明“没有任何 bug”，也不构成部署结论。主代理正在进行的性能窗口不属于本报告。

| 候选／环境 | daemon 单测 | 七项 wire | 六项 FD | 两项 ubusd 恢复 |
|---|---:|---|---|---|
| combined／Oracle | 55/55 | C、R131、候选逐字相等 | 通过既定契约 | 全部通过 |
| raw sendmmsg／Oracle | 59/59 | C、R131、候选逐字相等 | 通过既定契约 | 全部通过 |
| combined／物理路由器 | 55/55 | C、R131、候选逐字相等 | 通过既定契约 | 本轮未重跑 |

combined 的精确 release ELF 为 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`；raw sendmmsg 为 `c3cf584e4e516f96df03ac087d52a1e2c8051c37c7ba927498ca2e1fe74927ad`。单测执行的是同源码的独立静态测试二进制；wire、FD 和 Oracle 恢复案例执行上述 release ELF。路由器的测试二进制为 `fc80fe5f5af3ac52313c3ee9738990a3f0b8ba4c665d20ea35b70000099e8d5a`。

独立复核比较了冻结的 `sources-01/combined` 与 `sources-01/base`。运行时仅 `obj.rs`、`server.rs` 两个文件变化，未包含 sendmmsg 实验：

- **Entry、ID 与引用计数：** 随机 ID 冲突只重试，不增加引用、不覆盖现有条目；固定 ID 冲突在修改引用前返回 `AlreadyExists`。只有空槽插入增加一次类型引用，ADD 的临时引用、发布失败时的销毁、最后一次释放的删除条件均保留。随机冲突分支通过代码审查核对，没有新增强制碰撞测试。
- **借用路径：** 输入仍先按第一个 NUL 截断，再做 ACL 和唯一性检查。`Rc<[u8]>` 在请求缓冲复用前复制数据，路径索引和对象各持有所有权；事件派发先克隆 Rc，因此不会保留接收缓冲的借用，也没有新增可变别名。`set_path` 原有的“对象存在且首次绑定”内部前提未改变。
- **字符串编码：** 对象事件的方法名是固定且不含 NUL 的字节串；唯一运行时路径注册入口已去掉 NUL 后缀，所以 `msg_string_bytes` 的截断行为不会改变已存路径。新的写入函数仍保留非 UTF-8 字节、追加一个终止 NUL，属性类型、长度、填充和嵌套顺序与原写法一致。

FD 的三个常规按帧发送案例与 C 相等；三个手工构造案例按已经接受的 read-ahead 契约判断，**不声称其 FD 归属与 C 全部相等**。两项 Oracle 恢复是 `ubusd_halfclose`、`ubusd_lookup_delete`：候选所有检查为 true；C 的已知不完整回复和删除中查询崩溃仍保留为原门预期失败。

失败草案同样保留。最初 libc sendmmsg 草案虽然通过 59 个单测，但实际 SDK 链接后的跟踪显示它变成多个 `sendmsg`；musl 的循环不具备 Linux 原始 syscall 的短写停止语义，因此在筛选前拒绝。改用原始 syscall 后，SDK 单测和实际 syscall 跟踪通过，正确性门也通过；它的性能是否值得保留由独立筛选结果决定。[详细研究](R136_SENDMMSG_RESEARCH.md)

`sources-01` 的 path/combined 示例曾因借用 API 调整漏改调用点而编译失败。`sources-02` 只修正两个示例文件，运行时源码逐字不变；跨组件的已有 `profile_support` 文件补在独立测试 overlay 中，不属于运行时快照。九个声明示例和单测 target 已编译通过，**没有把仅编译的示例说成已运行通过**。

Oracle 两套各 99 个归档文件已逐项校验；路由器 events 48 个、FD 17 个原始文件与对应 tar 一致。路由器两次运行的六项健康／清理标志全部为 true，`installed=false`、`production_mode=stock`；正式服务仍为 C。完整脱敏结果、每项正负检查、精确 workload/probe 哈希、失败草案及证据哈希见 [派生 JSON](r136-ubusd-correctness-results.json)。
