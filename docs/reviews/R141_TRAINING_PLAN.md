# R141：一次固定八类 PGO 训练

R140 已按原门否决，继续使用原 generic R136 源码和编译目标。训练 ELF 为
`9452594e10f36ea2008382ea513525e5bdadfa7f32bf954031f1fca36a7451c9`；与逐字重建的
R136 控制同源，仅增加 profile-generate。以下命令和次数在正式训练前冻结，训练耗时
不参与权重、筛选或是否补跑的判断。不新增 ubus 业务测试代码。

先在独立目录用原 caller 执行 `register-cycle SOCKET 1 8 10 2 PID`，确认
`LLVM_PROFILE_FILE=/tmp/out/profile-%p.profraw` 覆盖默认输出目录，SIGTERM 后 daemon
正常返回 0，唯一非空 raw 的 PID/ELF 与运行记录一致，pinned LLVM 22.1.8 profdata
可完整解析。这份能力 smoke 永不进入训练合并。

正式训练依次运行下列八类，各自启动 **一只**新 instrumented daemon，类内各命令按表顺序
执行；每类独立 namespace、输出目录、profile，daemon 固定 CPU1、caller/provider
允许 CPU0–1。原生 C event helper 自身固定 caller CPU0。`SOCKET`、`PID` 指该类 daemon。
`bench` 为原 `0ca42fb…` caller，`wire` 为已通过功能门的 `5500effd…` probe；两个原生
event helper 同样冻结现有 ELF，不重新构建。

| 类别 | 固定命令与次数 |
| --- | --- |
| registration | `bench register-cycle SOCKET M B 1000 20 PID`，依次 `(M,B)=(1,8),(1,128),(16,8),(16,128)`，四组各 1,000 周期＋20 预热。 |
| lookup | 分别以 `bench serve SOCKET C` 建立 C=1/64/128 个对象。每次依次 exact `bench.target`、prefix `bench.*`、all `*` 各 1,000 查询＋20 预热。C=1 使用 `bench lookup SOCKET SELECTOR 1000 20 PID`；C=64/128 使用 `bench lookup-fixture SOCKET SELECTOR C 1000 20 PID`，完整签名与对象集合由现有 fixture 校验。每组结束退出 provider、等待对象表清空。 |
| invoke | 一个 `bench serve SOCKET 1` provider。`bench rpc SOCKET bench.target ping INPUT EXPECT 1000 20 PID` 一次；再同时启动四个相同 caller，各 250 次＋20 预热。INPUT=`{"n":1}`、EXPECT=`{"ok":1}`，总测量调用 2,000 次。全部退出后清理 provider。 |
| object_events | `bench register-watch SOCKET H MATCH 1000 20 PID`，依次 `(H,MATCH)=(1,1),(8,1),(1,0)`，各 1,000 ADD/REMOVE 周期＋20 预热。 |
| user_events | 原生 `user-event user-event SOCKET H MATCH 1000 20 PID`，同样三组 `(1,1),(8,1),(1,0)`，每组 1,000 SEND＋20 预热，验证回调内容／数量并删除 handlers。 |
| ownership | 原生 `event-stress event-stress SOCKET MODE 1000 PID`，依次 grouped、interleaved、monitor；每组 1,000 SEND＋工具既定 20 预热，八 handlers，验证 owner 分组、顺序、monitor、FD 与对象清理。 |
| transport | `wire SOCKET fd_boundary_read_ahead` 一次；`wire SOCKET slowlookup` 一次；`event-stress event-stress SOCKET slow 192 PID` 一次。后者既定零预热、192 个 2,048-byte payload 的 SEND，验证有界丢弃后一次恢复发送。slowlookup 使用既有 200 对象／64 长方法 fixture 和 32 个并行 owner 查询，完整恢复 DATA/STATUS。 |
| lifecycle | 依次 `wire SOCKET pathless`、`release`、`remove_reply`、`method_acl`、`monitor_lookup`、`utf8`，每个既有完整 fixture 一次。ACL grant 使用 R138 原配置；覆盖未知对象／方法、订阅及对象删除／断连、可见性拒绝、monitor 注册／注销、非 UTF-8 载荷。pathless 保留原观察型 transcript，不称新的拒绝正确性门。 |

不强称建议范围全覆盖：没有交替重复路径 ADD、任意字节分片、halfclose/lookup-delete
故障恢复、daemon crash/restart/OOM 注入。FD 和 slowlookup 覆盖它们原有的边界与队列
语义，不代表所有短写时序。选择无需杀掉受测 daemon 的 fixture，未修改旧测试或放宽
其退出／内容断言。

每类结束检查对象表空、所有 caller/provider 收尾、daemon PID/starttime/ELF 与环境；
随后 SIGTERM，必须退出 0 且只产生该 PID 的一个 raw。120 秒硬限仅防止卡死；任何
超时、异常退出、fixture 失败、缺失／多余 raw、解析警告都保留原始目录并停止整个训练，
不重新跑失败类、不补样本、不合并部分成功结果。

八个类的 raw 按上述确定顺序 **只合并一次**，使用 pinned profdata22
`merge -o merged.profdata CLASS1_RAW … CLASS8_RAW`，不指定额外权重，不丢弃坏文件。
记录八个 raw 的所属 PID/ELF、字节数、SHA、全部函数／计数输出，以及 merged profile
的同类摘要；smoke、默认目录和其他进程的 profile 不进入列表。

这是不同计数和 fanout 的固定组合，**不是八类等权或真实设备流量权重**。仅显式循环
就有 24,192 个测量迭代、540 个预热迭代，另有固定 fixture、连接／注册／查询及恢复
请求；一次迭代也不等于一条总线消息。按 LLVM 原计数相加，不按耗时或后续结果调权。
Oracle N1 的调度、EAGAIN、背压比例及插桩成本不等于 A53，不作性能结论。

[train.py](../../tools/r141/train.py) 的 `prepare` 只冻结已成功 smoke、generate build
proof、所有 ELF／库／脚本及逐类工作脚本；`run` 仅执行该固定计划。
原始 `environ` 留在 ignored 证据，公开派生报告只写必要的 LLVM_PROFILE_FILE 配置。
候选 profile-use 构建与独立测量属于后续步骤，训练成功不等于优化成功。
