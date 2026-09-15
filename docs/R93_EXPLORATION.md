# R93：统一探索分支、正确性收尾与双基线优化

> **2026-09-15 用户已从第二次暂停点恢复工作。** 已完成项与候选身份见
> [R93_PAUSED_HANDOFF_2](R93_PAUSED_HANDOFF_2.md)，本次恢复进度见本文末尾。

## 当前状态摘要

- source05 九组件历史/新故障门已闭合；后续 prefix 漏对象修复也已合入并通过整组故障门。
- C/R89/source05 实机矩阵已完成八组件 **696 个负载观测**，完整 HTTP 矩阵仍在采集。
  每份报告注明逐轮结果和未覆盖范围；没有整栈冷启动或全场景胜出结论。
- HTTP worker/head、ubusd borrow、RPCD glob、logd span 均为独立性能候选，未合入运行时。
  HTTP/ubusd Oracle 初筛已完成；RPCD 新四轮结果正在整理，logd 正在验证新 runner。
- 已修复统计工具会接受错误分位数/吞吐率的问题；八组件完整派生结果已重新计算，
  与既有报告逐项一致。

下文保留每个阶段的记录；早期“尚未验证”只描述当时状态，不代表需要重跑已完成验收。

## 分支与授权

2026-09-15 将原本线性相承的 R90→R91→R92 整理为
`codex/exploratory-fixes-and-performance`，起点 `6bb1226`。
删除已经包含在该历史里的本地 `codex/r90-lifecycle`、`codex/r91-netifd-logging`，
原 `codex/r92-recovery-compat` 重命名。main 和远端历史未改。

用户明确要求先完成可确认的遗留/新发现 bug，再开展性能改进；已明确授权 Wi-Fi 实机运行对照。
设备变更前继续执行离线备份、产物身份、自动回退及客户端健康门。没有授权刷固件。

性能对照必须同时包含精确 C 原版和正式 R89 `d9c1048`；R92 仅为定位增量的额外参考。
赢过 C 是最低目标，在已验证功能正确的前提下全面优于 R89 是最终目标。
所有平均/尾延迟、组件与依赖 CPU、空闲负载、常驻/保持连接/关闭后内存及恢复结果分别报告。
不能用混合得分遮盖某项退步，也不能把有限测试写成绝对无 bug。

## 初始阶段记录：正确性修复

- logd：旧 poll 下标误断健康流；断连期间积压/oneshot/关闭回收；重连节拍；总预算保护健康读者。
- HTTPD：共享连接限额恢复时广播所有监听器，覆盖关闭、停放到期与错误释放路径。
- ubusd：accept 暂态错误有界重试，资源错误 100 ms 自动恢复；正常无额外周期唤醒。
- ubus：请求 deadline 覆盖发送及完整 header/body；部分帧超时中止损坏 transport，完整帧边界的
  正常超时保持连接，避免 rpcd 内部调用 service.event 超时导致进程退出/配置回滚丢失。
- ubus：新连接与完整 HELLO 共用一秒期限；各 daemon 服务端收发启用一秒预算。
- rpcd：断连保留会话和回滚，离线到期恢复文件；所有文件先恢复再通知，失败通知按包名去重
  轮转，防止第一个包永久失败饿死后续包。断连、半帧注入分别 20 项通过，旧版反例保留。
- netifd：重连注册的固定对象和全部接口对象都成功后才切回在线；局部失败释放半注册连接
  并继续重试，不能把缺少接口对象的状态当作恢复成功。
- procd：将全量 watch 和热插拔对象注册分批，保留初始 rcS 前对象注册顺序；避免目录/订阅
  数量乘以单次请求上限而拖延 watchdog、日志与子进程期限。最终 source-05 修复已冻结，完整集成门正在对同 SDK recipe 九组件产物核验。

证据放 ignored `private/r93/`，构建机独立目录 `/home/ubuntu/r93-exploration/`。
`source-01/02` 是不可混用的开发快照，开发二进制不是 canonical 发布产物。
`source-05` 是当前九组件统一 SDK recipe 冻结快照，对应运行时提交 `7d5cb38`；
`source-03/04` 的 procd 存在已确认的 set-return/service.start 通知时序回归，不得部署。
新门为 `r93_httpd_cap_probe.py`、`r93_ubusd_accept_probe.py`、`test_logd_stream_recovery.py`；
共享库新增部分报文、背压、完整超时与 fd 回收单测。

Linux 旧版反例已确认 accept 8/8 不恢复、logd 三项恢复失败和共享库 40 ms deadline 不生效。
候选 accept 8/8 通过、HTTP 多监听器通过、logd 修正夹具后 5/5 通过、十 crate 单元测试通过；
完整原版差分/故障门仍在运行，不提前宣布收尾。

记录的夹具/构建问题：

- logd oneshot 测试初版误传 `lines=0`；改为 600，暂停 daemon 后验证非空内核前缀且确有未发尾部，
  再断总线。旧失败保留，修正后同 probe 旧版红、候选绿。
- 构建机 ring 需要 `CC_aarch64_unknown_linux_musl=clang`，未指定编译器的初次失败保留。
- 本地审查阶段 macOS/APFS 非 UTF-8 文件名夹具失败，Linux 全量测试覆盖了该路径。
- source-03 HTTP extended 首次因遗漏编译 `notifier` example 在启动夹具前失败；补建后单独重跑，
  不覆盖失败记录。其余运行时全部来自 `bins-03`，不直接取可变 Cargo target 文件。
- HTTP 性能副本曾误指向共享 target-03；实验编译失败，未生成实验运行时或 example。
  已核验恢复 `target-03/.../httpd-rs` 与冻结 `bins-03/httpd-rs` 哈希一致；实验现使用独立 target。
- 原始回归文件含 root 私有日志，普通 scp 无法读全；改用 sudo tar 完整读回并核验，保留初次记录。

2026-09-15 本轮 Wi-Fi 只读健康检查通过；新读回配置、overlay、R89/R90/R92 三包和两份
恢复镜像均已核验，证据在 `private/r93/recovery-01/`。只读备份不是候选部署验收；对应组件正确性通过后可在私有 namespace
采集修复版本的实机基线，统一正确性门闭合后才合入性能算法或开展整栈切换。基线、恢复入口和完整比较矩阵见
[R93_BASELINES](reviews/R93_BASELINES.md)。

## 性能阶段入口

正确性门闭合后才修改算法。优先解决已实测的 HTTP 50 ms 停放后每请求重建线程，
同时保留连接内存、过载恢复、TLS 状态、超时和 CGI 行为门；以 gap 0/20/40/60/80 ms、
TLS 延迟、三侧完整 HTTP 矩阵验证，不通过移动阈值规避诊断。

其后按每组件实际瓶颈选择小改动，以固定输入、相同产物来源、交错次序和原始样本作证。
任何“全部指标优于 R89”的结论都需对应实测；未实现该目标时明确保留未通过项。

## 复核修复本身（历史进度）

分步 watch 的第一个候选虽然解决批量维护饥饿，却让 `service.set` 提前返回。相同精确
C ubusd 和预先存在的六个 watch，set 返回后立即通知最后一个路径：正式 R89 12/12 已订阅且
触发，source-03 队列版 0/12。这是相对 R89 的真实功能回归，不能仅凭 C 不保证该时点而接受。
修正为单个待回复 set/add：保留请求，每轮维护后尝试一项，全部本次尝试完成才返回状态；
失败的后台重试不无限扣留回复，旧连接请求不能跨重连发送。最终 source-05 的 set/add 和
service.start 两个首次通知场景均恢复 12/12；83 项 Linux 单测、11 项业务检查通过，
all-targets Clippy 通过。新鲜编译的 output_lifecycle 补齐后，最终开发产物 r92-recovery 全绿；
同 SDK recipe 产物的完整历史门仍待完成。

HTTP 独立实验仅缓存工作线程可减少 clone，但跨线程唤醒、停车时接收超时和 epoll 增删仍在；
立即停车会让连续请求大幅回退，已否决。logd 的候选正文复制消除必须同时限制归一化后的
capacity，否则长尾空白日志可能增加 RSS。两类实验仅在 private/临时副本，无生产算法改动。

已落本地提交：独立审查 `7da29b9`、HTTP/ubusd 接入恢复 `13d4e48`、总线/daemon 恢复
`453ceed`。这些提交是探索性修复记录，不是正式发布或完整设备验收。

### 统一门中的夹具与产物边界

- source-03 `procd_bundle` 记录器用文件存在表示参数已写完，出现一次空数组误报；改为
  先写临时文件再 rename，原候选同一 binary 与 C 重跑均通过。不放宽 argv 断言。
- 默认链接的 reload-config 为 528544 字节，超过既有 512 KiB 门，功能差分未报告失败。
  同发布 SDK/4 KiB 链接与 sstrip 后为 498415 字节，原门 11 个参考 + 9 个故障用例通过，
  未修改大小限制。仍是构建主机产物，非 canonical CI。
- source-04 修复 set/add 返回时点后，立即通知 12/12 恢复；但 `service.start` 完成通知仍提前，
  单独复现 R89 12/12、source-04 2/12。继续修正完成副作用顺序，source-04 也不是部署候选。
- source-04 all-targets Clippy 抓到单测 fcntl 缺少 SAFETY 注释；补注释后原命令通过，
  运行时未变。之前的子任务 Clippy 仅 `-D warnings`，未开启此额外 lint，不等同该门。

- source-04 r92-recovery 的失败发生在业务执行前：缺少 `output_lifecycle` example。
  source-05 重新编译 procd/rpcd 全 examples 并冻结后，开发产物原恢复门完整通过；没有删减断言。
- source-05 完整源码快照归档 SHA256 为
  `6f8700bf5af4ca80a9113b5624229bde3e373f53553dec4dc95524dba33abd7c`；
  procd main SHA256 为 `dcf5ba9966f09fc21fe463d717c95325349e3602ed46cbd2b6ff26d7c54647cf`。
  九组件同 SDK recipe 产物仍是构建主机诊断构建，不能称 canonical CI 发布。

最终 procd 的控制流独立审查见 [R93_PROCD_FINAL_REVIEW](reviews/R93_PROCD_FINAL_REVIEW.md)，
红绿对照及测试身份见 [procd evidence](reviews/r93-procd-evidence/summary.json)。

## source-05 验证进度与物理基线

- 同 SDK recipe 九个二进制冻结完成；所有 157 个组件源码/依赖文件与 source-05 一致。
  三个 core 按 `ci_build_core.sh` 不做 sstrip，六个 package 按 Makefile 做 sstrip；
  全部 4 KiB PT_LOAD 对齐、静态、RELRO。构建主机为 aarch64 GNU Rust 1.98.1 + 镜像 SDK，
  与 x86_64 canonical CI 的 host 不同，不能称字节相同的正式发布。
- 当前构建机整组门为 `gates-sdk-05`：十 crate 单测/all-target Clippy、procd 全历史、HTTP
  全历史与 CGI 压力已通过；ubusd 全历史已通过；netifd 等后续继续运行。
- RPCD r26 733 步中的一个原版 `getFeatures` 返回漏掉 dnsmasq，候选完整返回，其余值相同。
  已交独立诊断，不把原始 FAILED 改为通过、不删除该字段；真实助手输出另有 r85 门。
- 历史 driver 增加按所选 gate 检查所需 executable example 及记录其 hash，避免运行数分钟
  后才发现 notifier/output_lifecycle 漏编。该 tooling 提交晚于冻结快照；正在运行的旧 driver
  身份原样保留，不能回填为新 hash。
- HTTP 在自身完整正确性门通过后启动物理三侧固定间隔基线；生产 R92 栈未切换。
  `tools/benchmark/r93_http_gap.py` 使用原版、正式 R89 和当前 SDK HTTPD，四轮 × 五种 gap。
  独立目标镜像 smoke 完整 8/8 请求与 derive 校验通过，1 秒 timeout smoke 的 10 个观测
  owned 进程全部退出。镜像没有 BusyBox timeout、不支持小数 sleep，初始失败记录保留；
  当前定时器用私有 namespace shell，关闭后资源采样为 1 秒和 2 秒，不宣称覆盖 200 ms。
- logd 固定语料新工具在三侧五场景 15/15 smoke 通过，全部标记 non-performance；
  无订阅完整保留集、1/8 readers 每条完整帧、trim-heavy、600 history；不能替代原恢复门。
- HTTP worker-cache、logd 最终 span 单次分配、ubusd 无路径迭代优化仍只存在于私有副本，
  当前生产源码没有这些性能改动。先采修复基线，再单项对比。

## 恢复工作：修复版验证闭合与性能实测

- 用户要求恢复后重新核对工作区、source05 九组件 SHA、离线备份、当前配置、运行身份和
  Wi-Fi 客户端健康，均与暂停时一致。
- source05 SDK 的最终新故障整组 8/8 通过；历史 68 个必需门结合独立修正夹具后的
  R26 733/733 及 features/CGI 队列重跑完成对应。身份与范围见
  [验证摘要](reviews/r93-sdk-05-validation.json)。此结论只允许进入隔离组件性能测量，
  不是绝对无 bug 或整栈部署验收。
- 恢复时的第一次新故障批次被一次硬链接误操作污染：准备 ubusd 实验副本时短暂修改了
  共享源目录的 ubusd，logd-streams 的自身 SHA 记录识别出了实验版本。共享产物恢复后
  核对全部 11 文件；原批次不计验收。回归工具现复制独立 inode 并取消写权限，每个门前后
  校验完整 hash，随后在独立副本重跑整组通过。污染记录与初次输出原样保留于 private。
- 开始以 source05 修复版采集 C / 正式 R89 / 候选九组件 74 负载实机矩阵，生产栈继续 R92；
  与此同时三个私有性能候选完成各自验证，尚未替换矩阵中的候选。
- logd 四轮三侧、24 个负载观测及文件/健康核验完成。固定 128-byte 写入的自身 CPU
  C/R89/source05 为 32.3/8.5/7.2 µs；读取 100 条为 808/420.5/389.5 µs。
  RSS 中位数 1010/504/568 KiB，source05 尚未全面赢 R89 内存。
  详见 [本轮 logd 实机基线](reviews/R93_LOGD_DEVICE_BASELINE.md)。
- 恢复过程中一度误将历史暂停指令当作当前任务，停止了本地矩阵 driver；当时的 ubusd
  第三样本 namespace 自行完整结束。恢复前核验完整原始文件 hash、COMPLETE、boot、
  配置及生产身份；`03-candidate/collector-recovery.json` 明记延迟的 host-after 观测。
  前两样本未动，第三样本取回后由原工具 `--resume` 继续，不覆写历史原始数据。
- 私有 ubusd 诊断发现真实未修故障：64 个大签名对象的 `*` 慢读，C/source05/lookup 优化
  候选都只返回 62 条 DATA 后发 STATUS；无 OBJPATH 同输入完整返回 64 条。正式 R89
  同输入也为 62/64。失败交付不能纳入成功性能比较。
- HTTP worker-cache SDK 候选主要历史/故障门通过，但尚无实机收益；Linux 一次内存诊断
  冷态/64 连接/关闭 2 秒 RSS 为 952/1228/1112 KiB，线程 1/5/1，FD 7/71/7。
  关闭后仍比自身冷态高 160 KiB，不能宣称内存胜出。解析缓冲复用是另一个私有小实验。
- logd span 候选运行正确性通过；Oracle 单轮 no-subscriber 的 source05/span CPU 均
  1.9 µs/条，尚未显示额外收益。小型分配计数证明减少临时分配，最终 ring 存活字节相同；
  不能用分配次数下降替代 CPU 或 RSS 验收。

### Prefix 漏数据修复通过整组验证

- 前缀 LOOKUP 现在在输出开始缓冲时按 owned 路径下界暂停，排空后续传，保留 1 MiB
  发送上限；当前 LOOKUP 结束仍有缓冲时，后续 LOOKUP 继续等待。仅修改正确性路径，
  未合入 pathless 遍历、HTTP worker 或 logd span 性能实验。
- C/R89/source05 同输入严格失败，修复版 64/64 DATA 的完整 payload 和最终 STATUS 通过。
  同客户端排队查询、PING seq、半关闭到 EOF、删除/重建续传点和撤销 ACL 均通过。
- SDK 修复 ELF `49b0244d…`，507872 B；最终同源码 GNU ELF 单独用于 accept 注入。
  27 项 Linux 单测、Clippy、五个 ubusd 历史门、四个恢复场景、三项专用门通过。
- 替换 source05 bundle 的 ubusd 后，在独立冻结工具/二进制上执行新整组 **9/9 通过**，
  包括 procd、HTTP cap、accept、prefix、logd、rpcd 断连/半帧、netifd 两种注册失败。
  [验收摘要与身份](reviews/r93-ubusd-prefix-validation.json)。生产路由器未部署此修复。
- source05 的 ubusd 四轮实机基线另已完成，共 120 个观测。部分查询延迟仍未赢 C/R89；
  [完整对照](reviews/R93_UBUSD_DEVICE_BASELINE.md) 明确不包含本次新修复。
- 旧 contract 关于 `txq_ofs` 残值破坏下一条消息的说法缺乏运行反例，且下一次部分写入
  会重设 offset，已更正为未证实疑点。不能将旧文档断言当成新复现的故障。

### RPCD 新实机退步

三侧四轮、18 项负载的 216 个观测完成。`session_access_granted` 自身 CPU 四轮范围
R89 22–24、source05 27–28 µs，范围没有重叠；`session_access_64_c4` 平均延迟中位数
241.98→275.37 µs（+13.80%），CPU 17.86→22.82 µs。已有恢复正确性通过不代表性能
已赢 R89；源码/总线期限开销正在定位，未通过撤除保护换分数。
完整数据与限制见 [rpcd 本轮基线](reviews/R93_RPCD_DEVICE_BASELINE.md)。

## 第二次恢复

- HEAD 从 `d19f370` 恢复；工作区干净，source05 九个冻结 ELF hash 全部匹配。
  离线归档、boot、配置、生产身份、恢复工具和保留基线 manifest 均与暂停时一致；
  Wi-Fi/客户端健康通过，无未完成的回退事务。核验在 ignored `private/r93/resumed-02/`。
- 已完成的四组件 456 个观测不重复采集；剩余 netifd、UCI、fw4、reload-config、HTTP
  从新组件目录继续，仍使用 source05 冻结基线。生产保持 R92。
- HTTP 五侧 pilot 先修正输出权限，再使用新目录完整初筛；RPCD 私有 glob 草稿先做
  精确语义与分配验证；ubusd 借用遍历对照先修平衡顺序与完整矩阵校验。
- HTTP 新五侧 pilot 已完成 20/20，112000 次响应完整正确。Oracle 上 60/80 ms 档
  source05 CPU 为 275/287.5 µs，worker-cache 为 150/150，追加 head-cache 为
  137.5/137.5，C 为 50/50。候选仍输 C；head 比 worker 仅少一个 tick，不能认定独立收益。
  缓存线程退出后仍有额外 RSS，不能宣称全面省内存。旧权限失败的原始样本保持不动；
  [初筛报告与测量边界](reviews/R93_HTTP_ORACLE_PILOT.md)。
- RPCD 本机计数确认：成功 ACL 查询中的两次 `net*`/`r*` 匹配，source05 每请求
  四次 Rust 分配、四次释放、21 B；ASCII 单尾星号候选均降到零。两种 locale 各
  6500243 组 source05/candidate 语义对照通过；这只是本机机制证据，目标镜像和
  SDK 验证及 CPU 对照仍待完成，未合入运行时。
- 修复统计发布工具的真实校验缺口：原 `native()` 会接受被改写的 p50/p95/p99 和
  `ops_per_s`；现在按原始延迟数组和墙钟重算，并拒绝负值/非整数延迟与非有限墙钟。
  25 项相关测试、1489 条已完成原始记录回放通过，现有记录数字无需更正；c4 的四个
  客户端文件计入回放条数，不是新增独立负载。原采集工具与正在运行的矩阵未改变。
  [验证范围](reviews/r93-benchmark-analysis-validation.json)。
- RPCD ASCII 尾星号候选精确 SDK 控制复现和 22/22 正确性门已过，包含 56 单测、
  原镜像 libc、断连/半帧/输出恢复及 733 步稳定模糊对照；仍待 CPU 对照，未合入。
  [验收报告](reviews/R93_RPCD_GLOB_VALIDATION.md)。
- netifd 实机 168 个观测完成，累计五组件 624 个观测。14 项的 source05 平均延迟和
  自身 CPU 中位数均低于 C，部分未赢 R89：空无线查询 CPU 25→26.5 µs，四轮范围
  24–25 对 26–27；device_status_c4 CPU 608.13→614.09 µs。RSS 比 R89 多 66 KiB，
  匿名页只多 2 KiB。查询前初始化/回调/子进程回收证据完整；非空 IPv6 prefix 仍未测。
  [netifd 实机报告](reviews/R93_NETIFD_DEVICE_BASELINE.md)。
- UCI 36 个观测完成，三项输出逐次字节校验通过；本轮三项延迟和 CPU 均优于双基线。
  export_network / export_64 / set_commit_get CPU 为 900/1840/6820 µs，R89 为
  950/1880/6960，C 为 1750/3270/8970。固定 shell 编排包含在最后一项里，不能把它当
  单次 UCI API 成本。 [UCI 实机报告](reviews/R93_UCI_DEVICE_BASELINE.md)。
- ubusd 借用遍历新版 48 smoke 与 192 个 Oracle 四轮样本全过，严格交付约 28.27 亿
  wire bytes。512 对象大签名慢读的四轮配对 CPU 均下降，中位 −4.01%；但每样本仅
  15.98–18.14 ms CPU，其余 11 cell 方向混合，暂不支持稳定收益或合入。
  [初筛报告](reviews/R93_UBUSD_LOOKUP_ORACLE_SCREEN.md) 保留全部原始范围与低采样限制。
- fw4 实机 24 个观测完成。print/check CPU 为 9300/19650 µs，R89 为 9500/19900，
  C 为 96000/107650；check 延迟仍比 R89 高 1.24%，四轮范围重叠，未定因。
  [fw4 实机报告](reviews/R93_FW4_DEVICE_BASELINE.md)。
- reload-config 12 个观测完成，固定 unchanged-config 的延迟/CPU 显著低于 C；
  source05 CPU 26270 µs，R89 26420，C 41440，source05/R89 的逐轮范围重叠。
  配置摘要前后与原版相同，未测改动传播或整栈冷启动。八组件累计 696 个观测完成，
  source05 完整 HTTP 矩阵正在采集。
  [reload-config 实机报告](reviews/R93_RELOAD_CONFIG_DEVICE_BASELINE.md)。
