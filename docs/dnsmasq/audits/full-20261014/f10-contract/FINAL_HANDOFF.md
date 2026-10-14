# F10 修复回交：238e7ca4

产品代码已冻结；原缺 PTR、查询引起的 A/PTR 顺序、增量租约所有权和重载发布
问题均已修复并留下对应正负证据。**主审独立批准四项精确源码合同后，最终
Oracle ELF 和主审 SDK 包内 ELF 的 13 场景／704 观察均离线重判通过，未获资格
差异为零。** 修复方又从原始归档独立重算，清单与两份结果逐字节一致。
原 observed-only 失败结果不改写；没有部署授权。本修复已可交主审完成组合
资格与 main 合并，本方不执行 main 合并、push 或路由器操作。

## 可重建身份

- 产品源码：`238e7ca4374b1889696f91816c1c239d7fe32baa`。
- 分支：`fix/dnsmasq-full-rotation-contract-20261014`；工作树：
  `/Users/USER/Developer/owrt-dnsmasq-full-rotation-contract`。
- 保留 tag：`audit/dnsmasq-f10-238e7ca4-20261014`。
- Oracle 源：`/dev/shm/full-f10-product-20261014/private/source-238e`。
- Oracle ELF：`/dev/shm/full-f10-product-20261014/private/release-238e/dnsmasq-rs`。
- ELF SHA-256：`2692c760be3719b15f4bcadb6c5a1445a9f37993a11c1369619550218e4c76eb`；
  2,122,208 bytes，比 340ed 增加 32,768 bytes。

653 个 dnsmasq/ubus/packaging/tool 输入在构建前后均与 Git 一致，本机归档解开后
再次逐项重哈希。构建保持 Rust 1.98.1、匹配 SDK linker、opt3、static PIE 和
既有 allocator，没有删功能或放宽资源限额。这是源码构建的 Oracle ELF，不是
完整 SDK/APK 交付身份。[完整身份与构建收据](core-final238e/identity.json)。

精确镜像 C 保持
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
原 19bd、340ed、b99e、435f、4ff6、ce04 的反例和产物未覆盖。

## 代码提交与最终行为

| 提交 | 改动 |
| --- | --- |
| `bf4b2a49` | 有界 bulk reverse 链、多个 reverse owner、完整 PTR、配置载入分配失败传播 |
| `b99eae7e` | config/default/addn/初扫 hostsdir 共用未发布代，HUP 保留旧视图，watch 事件延后并保持增量语义 |
| `435fe2d6` | 先按新 hosts 更新租约名，再由真实 DHCP provider 一次发布；慢 DHCP 文件期间仍服务旧 hosts/leases |
| `6b69d679` | 强制 DNS 发布失败保持 dirty，复用有界既有维护定时器重试，不延迟更早期限 |
| `564c6440` | A 和 PTR 共用真实全局名字哈希链；next/head 以 64 项独立页共享，修改前预留全部受影响页 |
| `4ff6a8a2` | 独立首次加载准入状态，不再由 HUP 标志推导；配置租约协调保留旧 DHCP 节点至正确边界 |
| `ce04a28d` | 单个增量文件的所有别名读完前保留已发布 DHCP 首 reverse 记录，修复无限租约两名称缺 PTR |
| `238e7ca4` | staged reader 保留真实行结束偏移，在地址行边界扩容哈希，防同一长别名行中途改序 |

临时地址哈希、租约辅助节点和源行偏移只属于加载/协调阶段。发布前剥离临时
租约节点；TCP 快照只持不可变记录与有界顺序页的共享句柄，没有历史链，也不
按连接复制全表。源删除不把原先受抑制的记录升级为 reverse owner；已有多个
真正 owner 则保留剩余项。所有结构性复制、元数据增长和工作代组装可返回分配
失败，失败保留原发布代，不靠重新申请旧代来恢复。

`a2ae1456`、`b8db2a26`、`f4ccde32`、`13c8bf8c` 是相邻回归或测试夹具修正。
其它提交为诊断、验收器和派生证据。最终组合合并应按最终树核对，不能只择取
最早的 flags/PTR 修改而遗漏生命周期和全局顺序修复。

## 同一最终 ELF 的已完成验证

| 门 | 结果与边界 |
| --- | --- |
| Linux musl 库 / 串行主程序 / native 分配失败测试 | 808 / 81 / 16 通过；20+3 ignored 未执行 |
| 首次 held hosts FIFO 后真实 HUP | 原负对照 exit 101；最终 DNS、DHCP、helper 初始准入继续关闭，完成后原请求正常 |
| 慢 DHCP options FIFO | 新 hosts 与租约一并等待真实 provider 发布，旧 local/daemon/TCP 视图保持；回调一次 |
| 原六行 / 13 个协议场景 | 704 观察，无记录集合、字段、TTL、数量、TC 或 A/AAAA 顺序差异；PTR 顺序资格见下一节 |
| 原 repeated 188 条顺序反例 | 6,020 条原始观察与 C 全同，64 MiB 无 OOM |
| unique 2000 rolling | 6,020 条原始及相对序列全同，64 MiB 无 OOM |
| warm 60k hosts / 20 TCP | 20 条匹配 C，峰值 26,931,200 B，无 OOM |
| repeated / unique rolling 内存 | 峰值 26,673,152 / 34,504,704 B；各只增加 28 KiB，没有随 2000 连接累计增长 |
| 五行同进程 query-induced 反例 | 每个实际进程的碰撞名独立确定；PTR `[y,x]` → A `[.4.1,.2.1]` → PTR `[x,y]`，旧 b99e 失败保留 |
| 50k hosts / 20 TCP / 64 MiB + HUP | C/Rust 旧新视图正确；Rust peak 49,184,768 B，无 OOM；另 42 项 wire 快照一致 |
| 2000→30000、held HUP、+256/+512/+1024 KiB | 三档 Rust 旧代、缓存清除、UDP/TCP/DHCP、恢复全过；C 历史压力失败原样保留 |
| 2000→6000、held/no-held inotify、三档余量+无限制 | 八档通过，未发布半代，后续更新恢复 |
| retained DHCP HUP 三例、增量有限/无限两例 | owner 集合、字段和进程健康通过；两增量例各 UDP3+TCP3 完整轨迹稳定；具体 PTR 初态资格另列 |
| 单次真实回退中断 | confirmed 后 unmount 窗口 SIGKILL，自动恢复精确 C；三次 DHCP OFFER/ACK、UDP/TCP DNS 健康通过 |
| 长行扩容 | 冻结 ce04 同进程源码负例 A/PTR 反序；最终流式/分阶段源行规则一致，跨 4096-byte chunk 和展开重复单测通过；不冒充完整 C daemon 长行实测 |

收据：[核心与完整测试](core-final238e/result.json)、
[TCP 顺序/资源](rotation-final238e/REVIEW.md)、
[DHCP 边界](dhcp/report.md)、[启动准入](startup-hup/positive-238e.json)、
[ELF trial](final238e-trial/summary.json)。

第一次完整 bin 默认并行运行出现一个 owner 测试失败（80/1）。同一测试 ELF
单条运行与完整串行运行通过；原失败日志保留。共享信号/owner 测试状态互扰是
当前解释，未声称抓到唯一根因。串行运行是明确记录的最终主程序测试命令，
没有重跑挑选后覆盖旧结果。

## PTR 顺序资格：保留原失败，追加独立批准的重判

[最终 observed-only 结果](final238e/report.md) 保留真实 exit 1：44 条 PTR
初态顺序差异中 16 条有既有 C/C 相应状态与完整轨迹证据，另 28 条当时未获资格：
`six-hostsdir-initial` 8 条、`leases-dhcp` 12 条、`ipv6-repeated-ptr` 8 条。
所有有序回复保持原样；205 个重复状态族没有自身抖动。

验收器 `796ec884` 默认拒绝，绑定 case/question/type/transport/state 与完整
查询轨迹，不允许把不同 C 控制的前后阶段拼接，也不把 PTR 条件转用于前向查询。
具体源码限定的初态提案另有精确 fixture、输入、源码 hash/行号与负控；未经
独立审查的 proposed 项不会生效。五行 A→PTR 的真实状态变化不在这些静态初态
范围内，必须按实际变化序列通过，不能以 ASLR 为理由放过。

主审随后逐项核对 matching C 源码哈希和指定行，批准四个固定输入合同：上述
三个 case，以及 SDK 所需的 `six-host-record`。只允许一套完整两 owner 初态
排列贯穿同 case 的所有重复、phase 和 UDP/TCP；DHCP case 还绑定请求 wire、
发生位置和 decoded 输出。未知 case、改动输入、query-induced 顺序变化及内容/
前向差异仍拒绝。这是精确源码合同解释，不是用户兼容豁免。

[统一批准清单与重判](qualifier/approved/report.md) 提交为 `2beb9fcf`，清单
SHA-256 为 `57da7fe59de8de504cb77f5982b8e15a3d599a083b1387e1a7451936f64a8f78`。
Oracle `2692c760…` 和主审真实 SDK ELF
`50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c`
各 13 场景／704 观察均通过，各有 16 条 observed-qualified 与 28 条
source-bound-qualified 顺序差异、零未获资格差异。SDK 的 `ipv6-three-duplicate`
和 `mixed-sources` 已由既有 observed 条目覆盖，未新建源码条目。

修复方从保留归档与 SDK 原 JSON 独立重算，manifest、两份 recheck 和 summary
与提交收据逐字节一致，24 个验收器单测通过。没有修改 raw 或再运行 daemon。
这不将旧 observed-only 失败改写成全部字节相等；原失败与后续合同判定并列。

## 证据与合并边界

源码/ELF 本地备份：`private/f10-product-20261014/artifact-238e.tar.gz`，SHA-256
`776451ff57caa7258bea07fc0dfeb9888100eebc98293f6034eecdcd317aa835`；完整核心收据：
`private/f10-product-20261014/core-238e.tar.gz`，SHA-256
`cb75c214e1764a505fefdad97fbd0953a4e0ac9c75f79ad305b7e2d887e024d2`。
各域还有独立 private 归档、逐文件 SHA 和 Oracle 位置，不依赖 tmpfs 唯一副本。

所有产品工作限于独立 contract 分支，未修改 main、push、操作物理路由器或
删除他人 worktree/证据 refs。F4/F5/F7 由主审另行负责。ELF trial 沿用精确镜像
init/ACL，只验证本 ELF 的恢复；不承接最终 r4 包的 F5 重连资格。主审必须从
最终真实 SDK APK 提取 ELF、init、ACL 一起复验；Oracle 产物的通过不自动转签。
