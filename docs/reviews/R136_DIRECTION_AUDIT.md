# R136：批量检验减少分配、表探测和发送调用的方向

冻结运行时基线 `db6a6b6`（其 ubusd 与 R134 `c84108b` 相同）。R135 的负项和否决不撤销。本轮先构建、单测和 Oracle 预筛，最终优势只由路由器独立验证；未部署。

## 同时推进的五个候选

| 候选 | 具体变更 | 要观察的机制 | 主要约束 |
| --- | --- | --- | --- |
| path | ADD 的 cstr slice 直接构造 Rc 路径，不先创建 Vec | 每次命名 ADD 少一次临时分配/释放及复制 | 仍按 C 字符串截断、拒绝重复路径，失败不改变旧绑定 |
| entry | 对象/类型创建通过 HashMap Entry 探测后直接插入；类型删除复用 occupied entry | 减少重复哈希/表查找 | 保留随机源、保留 ID、冲突重试、固定 ID AlreadyExists、引用计数时机 |
| strings | 对象事件 METHOD/path 直接追加字符串编码 | 每次有监听者的对象事件少两个 with_nul 临时 Vec | 只适用于已 canonical 的注册路径，保留任意非 UTF-8 字节及事件顺序 |
| combined | 以上三个小改动组合 | 判断收益能否叠加、是否引入交互代价 | 必须同时保留各单因素结果，不把组合胜负归给其中某一项 |
| sendmmsg | ADD 两条独立消息用单次 sendmmsg；查询合并不变 | 一次 syscall、两个独立 stream 提交 | 完整处理 msg_len/短写/排队/FD/monitor；不能假设小包原子 |

前三项来自具体源码成本：`obj.rs::set_path` 的 Vec→Rc、`Registry::create/new_type/unref_type` 的重复查表、`send_obj_event` 的 `with_nul`。它们不是 R95–R98 的借用 lookup/方法 Vec→Box 或 R118–R120 的换哈希算法/容器实验，也不是 R133 的空 patterns 早退。结构成本能从源码确认，CPU/尾部幅度未知。

匹配 C 在创建对象时 strdup 一份路径、直接 avl_insert 完成占位；C 的方法存储采用一块 calloc 包含节点和 blob。当前 Rust 的注册路径生成两份短暂路径拥有存储，且创建对象先 alloc_id contains_key、再 contains_key、最后 insert；本次不改数据结构或哈希算法，只删可避免的工作。

依据 pinned Rust 1.98.1 [Rc 实现](https://raw.githubusercontent.com/rust-lang/rust/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/rc.rs)与 [HashMap Entry API](https://raw.githubusercontent.com/rust-lang/rust/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/collections/hash/map.rs)。字符串编码使用项目已有 `BlobBuf::put_string_bytes/msg_string_bytes`；路径先经 `cstr_bytes`，因此后者截断首 NUL 不改变字节结果。sendmmsg 必须另以匹配 Linux 源码核实，不从 syscall 名称推导行为。

## 执行和停止规则

源码快照生成器 `tools/r136/make_sources.py` 同时生成基线、三个单项和组合，运行时工作树不改；sendmmsg 使用独立补丁。记录源码与最终 ELF 哈希，一旦计时开始不再修改注释或重编译替换。主机最多两组 CPU 对并行筛选，构建/单测/trace 不和计时混跑。

每组至少四个正反平衡重复、五条 register/object-event 负载（1/16 方法、1/8/no-match监听），保留所有样本。主指标是 mean 和 daemon CPU，并公开 p50/p95/p99/caller CPU；±1% 记未分辨。Oracle 只作方向筛选，不能依据不复现的 router tail 作否决。优选候选进入少数独立实机窗，旧结果不能拼接为新 ELF 的全系统性能声明。
