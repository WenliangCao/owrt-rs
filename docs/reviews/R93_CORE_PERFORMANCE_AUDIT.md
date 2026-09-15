# R93 核心组件算法性能审计

2026-09-15。只读源码审计；没有修改运行时或运行 CPU 压力。以下是**待测候选**，不是
已经快于 C/R89 的结论。当前 procd 为 source05（运行时提交 `7d5cb38`），正式 R89 为
`d9c10483d95590143f9d6a1f41310e2a13e63fb3`。匹配 C revisions 见
[source-baseline.json](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json)：
procd `58eb263d`、ubus `24864e78`、netifd `cbb83a18`。

## 1. ubusd：无 OBJPATH 的慢读 LOOKUP 每次续传收集整个剩余表

**证据。** [lookup](../../components/ubusd/src/server.rs:412) 在缺少 OBJPATH 时，先把
`paths.range(resume..)` 的全部剩余 id 收集到新 Vec，再逐项发送。一旦发送开始缓冲就退出；
下一次恢复重新分配/遍历剩余尾部。如果每次只能推进少量对象，id 遍历总量可从 O(N)
放大到 O(N²)，瞬时临时数组 O(N)。这是代码复杂度上界，不是设备实测结果。

R89 同样重建完整 `path_order()`，再线性定位旧 id；当前按 path 恢复修复了对象删除的
正确性问题，但没有去掉尾部数组。匹配 C 的 `ubusd_proto.c:204–240` 直接遍历 AVL，
遇缓冲保存续传点，不先复制完整 id 表；其删除续传点的已知缺陷不能带回候选。

**74 项矩阵的盲区。** `lookup_all_64/128` 实际传 `"*"`，走有 OBJPATH 的 prefix 分支，
见 [isolated.sh](../../tools/benchmark/isolated.sh:355)，所以名字中的 all 不代表此无路径分支。
现有 `ubusd_lookup_delete` 是恢复正确性门，未报告不同 N/续传次数下的 CPU 和分配成本。

**小改候选。** 按现有 path 下界遍历有限批次的 id，发送后再取下一批；或者拆分只读注册表
和可变输出字段，直接遍历借用 range。优先选择局部实现，避免长期持有跨事件循环的迭代器。
批大小是待测工程参数，不能以未经比较的常数宣称最优。

**必须保留。** 原始字节路径顺序、ACL 过滤、每条 DATA 和最终 STATUS/seq/peer、发送排队、
monitor 可见性、删除续传点后的下一个合法路径；不能重新从头导致重复，也不能保存悬空 id。

**验证。** 同 C/R89/候选各用无 OBJPATH 和 `"*"` 控制组；64/128/512 对象，固定大小签名，
快读和每次只读少量字节两种客户端。报告实际完成条数、重复/遗漏、DATA 字节、续传次数、
daemon CPU/对象和峰值分配。复用 `r92_recovery_probe.py` 的删除续传点反例；C/R89 的已知
失败保留为失败，不能把其不完整回复当低 CPU 胜出。该候选优先级最高。

## 2. procd：全量 watch 刷新中的线性队列去重可形成二次扫描

**证据。** [refresh_watches](../../components/procd/src/main.rs:1626) 用 Vec.contains 合并实例
watch；[resubscribe](../../components/procd/src/main.rs:1654) 克隆全部 path、排序去重，再对每条
调用 queue_watch，而后者线性扫描已有 VecDeque。W 条唯一路径从空队列重建时，去重比较
可达 W(W−1)/2；每条泵送还扫描所有服务的 watch 确认所有者。R89 已有克隆/排序和实例内
Vec 去重，但没有这个新的异步队列扫描。C watch_add/list_add 是单条插入，object.add
匹配才线性扫 watch，不重建一个全局待办表。

**矩阵盲区。** [procd 夹具](../../tools/benchmark/isolated.sh:434) 创建的是只有 data 的服务；
定时测量为 list/info（32/128 服务、1/4 客户端），没有 watch、对象重建或重连批次。

**小改候选。** 全量 reconciliation 中，先建立一次借用的 pending-path 集合，再把不存在的
path 依原顺序加入尾部；不要为每条重新扫队列。实例路径合并可同样用一次集合辅助保留
首次出现顺序。先做只存在于该函数调用中的辅助集合，不先引入需要每个删除/重连分支维护的
长期全局索引；额外集合分配对常见小 W 可能更贵，须实测。

**必须保留。** 首次出现顺序、已有重试截止时间、去重、删除过滤、同 id 通知不查找、新 id
重新订阅；set/add 只等待本服务一次尝试，rc running/service.start/成功 STATUS 的完成边界
及触发器启动屏障绝不能为了更快回复而回退。全量后台队列与待回复 set 的所有权不能混淆。

**验证。** 0/1/8/64/256 个唯一 path，分别单服务与多服务共享 path；配置重复提交、删除、
对象 churn 和重连。独立统计路径比较/分配数、LOOKUP/SUBSCRIBE 数、总 CPU、完成时间和
维护延迟；对快总线和慢总线分开报告。保留现有 83 单测、11 项业务门、两种首次通知各
12/12、r65/r71 与回收顺序门。C 不承诺预存对象在 set-return 前全部附着，该行为差异要
单列，不能把它少做的订阅直接算成等价任务的性能胜负。

## 3. netifd：IPv6 delegated-prefix 状态每次重复扫描和复制 assignments

**证据。** [dump_interface_status](../../components/netifd/src/main.rs:738) 对每个属于当前接口的
prefix，扫描全部接口和全部 prefix_assignments，克隆匹配接口名/class，分配 assigned Vec
并按地址排序，再构造临时 Prefix Vec。全接口 dump 对各接口重复该过程。以 P 为 prefix
总数、A 为总 assignment 数，关联扫描可达 O(P×A)，另有分配、字符串复制和排序成本。
当前与 R89 该实现相同，所以这是旧有成本，不是 source05 引入的新回退。

匹配 C `ubus.c:686–738` 的 prefix 输出直接遍历该 prefix 自带的 assignments 链表，
不构造相同临时 owned view；但 C 的 assignment 输出也有全局遍历，不能由局部源码比较
宣称 C 整个状态方法是线性或必然更快。

**矩阵盲区。** 既有 netifd 矩阵虽有 32-interface dump，夹具是静态地址且没有启用 delegated
prefix/assignment 负载；命中 status 方法不代表覆盖这个非空分支。

**小改候选。** 先在一次 dump 请求内按 `(owner, prefix address, length)` 建立借用 assignment
索引，并保留现有地址排序；直接序列化借用记录，避免克隆名字/class。优先限定在请求作用域，
不缓存跨请求的状态或生命期。named status 与全接口 dump 分别比较，单 prefix 小配置可能
不值得建索引，可先只移除 owned 字符串复制。

**必须保留。** prefix owner/地址/长度匹配、assigned 排序、delegate=0、class、preferred/valid
生命期和省略字段规则、同地址不同 owner、移除/重分配后无陈旧内容；不改变内核地址/路由或
netifd 协议生命周期。

**验证。** 在私有 namespace 用固定协议输入建立 1/4/16 prefixes、1/8/32 下游 assignments，
对 C/R89/候选比较完整规范化 blob/JSON、排序与仅允许的时间差，再测 named/full dump 的
CPU、分配和 p99。加入 prefix remove/recreate、生命期更新及 delegate 切换；最终使用同一
SDK 构建和路由器同批三侧验证，构建机计时不替代设备成绩。

## 比较纪律

以上三项都先证明输出/恢复等价，再使用冻结 C/R89/候选、同一客户端和夹具测量。原 74 项仍
作为不回退矩阵保留，这些新场景只能补齐缺口，不能替换较差旧指标。报告逐项真实结果和
失败样本；未测量前不写节省比例、吞吐提升或“全面优于”。
