# R68：Astra 对 P3.1 的审查（外部审查，结论：不通过）

来源：`gpt-6-astra`，2026-09-08，问题见 `/tmp/ask4.txt`。
审查基线冻结在 **db5afa1**（我后来的 `0c5fc3f`、`444da85` 等提交不在其中），
所以 F01/F02/F04 及"实例日志 FD"在阅读时要对照当前 HEAD 逐条核实。

**最重要的一条不是任何 F 编号：** 它把两边的监管器启动命令都换成 `/bin/false`，
r65 依然输出 `r65: ok`、diff 为 0 字节、退出码 0。也就是说这个验收门槛
**允许整套调用根本没有到达任何监管器**。在补上就绪断言之前，
r65 的绿不能作为 P3.1 的验收证据。

原样保存，未删改。文中的 `/tmp/ask4-evidence/...` 是它留在本机的证据副本，
不在 Git 内。

---

这份 P3.1 目前不能认定为“服务监管核心离线验收通过”。Rust 已能完成一组真实的基本调用，但现有验收门槛会放过根本没有启动监管器的运行；实现也存在已复现的权限、配置更新、事件链和故障恢复差异。最严重的不是输出顺序，而是声明 jail 的命令直接以 root 运行、结构化 data 被丢弃、设备依赖的触发链不执行，以及 ubusd 重启导致监管器退出。

本次是对 /tmp/ask4.txt 的完整审查，日期为 2026-09-08。以下先给实现问题，再审查 harness、十条合同和已知缺口的设备优先级，最后列出实验记录与复现入口。

**审查基线固定在 db5afa120cda7826e373d4c4323a81f2de7bf0ae。** 审查期间工作区继续变化，所以我冻结了源码、合同、harness 和依赖的 components/ubus，随后从这一份快照构建和实验。收尾时工作区 HEAD 已是 cdb4329a0f0893ab2634e7c73fa85099b6a2c587；本报告不把后来提交混入结论。完整哈希见 [reviewed-manifest.json](/tmp/ask4-evidence/reviewed-manifest.json)。下文 Rust、合同和 harness 的链接均指向这份冻结副本，行号不会跟着工作区漂移。

你的题面所说“797 行、十条合同、service.watchdog 方法没做”已经落后于这个快照：本次 harness 是 386 行、22 例；合同有第 1–10 条及第 11 节已知差异；watchdog 方法和 rc(name, "running") 队列已经存在。本次原样运行得到的是两边各 874 行、0 diff。这不是对原来的 797 行日志作事后猜测。

| 项目 | 本次实际使用的基线 |
|---|---|
| C 参考源码 | procd 58eb263d5abe03f8c1280bdfa65a3b052614215d；本地冻结在 /tmp/ask4-evidence/procd |
| C 实验对象 | oracle 上发货 rootfs 自带的 /sbin/procd，未重新构建 C |
| rootfs | oracle:/home/ubuntu/h1-4-extract.JK5fNS/rootfs |
| C procd SHA256 | 36269ae10ae267b9753233bfecdea48bd6fed4b2f7980f722f96413bd2ca681a |
| rootfs ubusd SHA256 | cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88 |
| Rust 构建目录 | oracle:/tmp/astra-p31-reviewed-db5afa1 |
| Rust 目标 | aarch64-unknown-linux-musl，release，--locked |
| Rust 二进制 SHA256 | 4de1254d39adb9e266cb363c65283eb7fce901b4ec50f55d73da1d16584480ff |
| 实验内核 | oracle 的 aarch64 Linux 6.17.0-1020-oracle |

构建有一项明确限制：[Cargo.toml:5](/tmp/ask4-evidence/reviewed/components/procd/Cargo.toml:5) 要求 rust-version=1.98.1，而 oracle 是 rustc 1.98.0。正常构建先被版本检查拒绝；随后使用 --ignore-rust-version 构建成功，没有改 manifest。因而本报告证明的是这份源码在上述编译器下产出的二进制行为，不能替代项目声明工具链下的正式构建检查。环境和补充检索记录见 [runtime-metadata.json](/tmp/ask4-evidence/runtime-metadata.json)。

所有实验都在 oracle 上复制出来的 rootfs 内，以私有 PID、mount、net namespace 运行普通 procd 进程，使用同一 rootfs 的 ubus/ubusd。新探针分别给 C/Rust 创建独立副本，并检查总线、service 注册、监管器 /proc/<pid>/exe 以及调用退出状态。没有切换物理路由器 PID 1，没有修改、刷写或重启物理路由器，也没有修改仓库实现。这里的“设备会用到”来自发货脚本和已有 R63 只读运行报告；离线模拟结果不冒充这台路由器的实测。

**实现方面，以下 F01–F18 都有具体可观察后果。** “高”表示监管核心的行为或设备常见路径受损；“中/低”表示影响较局部或尚未证明当前设备会触发。每项都给出最小触发、C/Rust 差异、源码原因和修正方向。

1. **F01，阻断：has_jail 跳过降权，却从未委托 ujail。**

    [proc.rs:39](/tmp/ask4-evidence/reviewed/components/procd/src/proc.rs:39) 直接用 command[0] 构造 Command；[proc.rs:87](/tmp/ask4-evidence/reviewed/components/procd/src/proc.rs:87) 在 has_jail 时跳过 initgroups/setgid/setuid。注释写着“ujail does it”，但执行路径里没有 ujail。[instance.rs:486](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:486) 看到 jail 字段就置 has_jail，并没有完成 C 对 jail、require、helper 存在性等条件的处理。

    C 在 [instance.c:513](/tmp/ask4-evidence/procd/service/instance.c:513) 调用 jail_run；[instance.c:293](/tmp/ask4-evidence/procd/service/instance.c:293) 构造 /sbin/ujail 的 argv，将 user/group、capabilities、no_new_privs、mount 等交给既有 helper；[instance.c:1467](/tmp/ask4-evidence/procd/service/instance.c:1467) 还处理 trace、ujail 不存在和 require_jail。

    最小实验是在一次性副本内把 /sbin/ujail 换成只记录 argv、随后退出的脚本，提交 user=p31user、group=p31group、no_new_privs=true、capabilities=/tmp/p31caps.json，以及 jail={name:p31,procfs:true,require:true,mount:{"/tmp":"1"}}；原始 command 是执行 id 并写入另一个文件。结果：

    - C 调用了记录 helper，argv 包含 -t 5 -n p31 -U p31user -G p31group -C /tmp/p31caps.json -c -p -w /tmp -- /bin/sh -c …；没有直接执行原始命令。
    - Rust 没有调用 helper，原始命令输出 uid=0(root) gid=0(root) groups=0(root)。
    - C 的 list 有 jail 和 mount 表；Rust 丢掉这两部分，尽管还回显 user/group/capabilities/no_new_privs。

    这项实验只验证“是否委托、委托参数是什么”，没有声称测试过真实 ujail 的内核隔离。直接 root 执行是实际观测，不能用“隔离实现留给 ujail”解释。

    这也是当前设备路径，不是边缘字段：[R63:16](/tmp/ask4-evidence/reviewed/reports/ax3000t-stock-openwrt-25.12.5/R63_PROCD_SCOPE.md:16) 记录了实际实例中的 jail/capabilities/no_new_privs/mount/user/group；[dnsmasq:1277](/tmp/ask4-evidence/rootfs/etc/init.d/dnsmasq:1277) 和 [sysntpd:73](/tmp/ask4-evidence/rootfs/etc/init.d/sysntpd:73) 有直接调用。

    修正方向是实现这张镜像对应的 ujail 调用契约，保留成熟 helper，不另造沙箱；helper、require 和降权的分支必须一起对齐。在委托完成前，不能接受这组配置后把命令当普通 root 子进程启动。proc.rs 中 trace/seccomp 也没有 C 的 wrapper 构造；单设 SECCOMP_FILE 不能证明 seccomp 已生效，具体还要以镜像编译选项和 helper 为准。

2. **F02，高：service 和 instance 的 data 被限制为字符串，结构化值静默消失。**

    根源在 [service.rs:57](/tmp/ask4-evidence/reviewed/components/procd/src/service.rs:57)、[instance.rs:60](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:60) 的 BTreeMap<String,String>；[main.rs:416](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:416)、[instance.rs:428](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:428)、[main.rs:1009](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:1009) 都只收 as_str() 成功的字段；get_data 又在 [main.rs:959](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:959) 逐项 msg_string。

    最小输入：服务 data={object:{x:1},bool:true,text:"ok"}；实例 data={nested:{enabled:true},array:["a",2],n:7,text:"ok"}。C 的 list 和 get_data 保留全部值和类型，Rust 在两个层级都只留下 text:"ok"，调用仍返回成功。

    C 的 [service.c:135](/tmp/ask4-evidence/procd/service/service.c:135) 保存 blob；实例走 [instance.c:1412](/tmp/ask4-evidence/procd/service/instance.c:1412) 的 instance_fill_any，dump 在 [instance.c:1703](/tmp/ask4-evidence/procd/service/instance.c:1703) 用 blobmsg_add_blob，get_data 同样直接加入原始 blob。

    发货接口本身就允许嵌套 data：[procd.sh:604](/tmp/ask4-evidence/rootfs/lib/functions/procd.sh:604) 打开 data 对象；[procd.sh:627](/tmp/ask4-evidence/rootfs/lib/functions/procd.sh:627) 的 mdns helper 放入对象、整数 port 和数组 txt。firewall 数据触发也是实际设备接口。修正时应保留 blob 类型和嵌套结构；仅把 dump 补成更像 JSON 没用，解析、比较、存储和 get_data/set_data 都需要一致。

3. **F03，高：service.data.update 走错通路，内部 trigger 不执行；实例更新还读取了服务级 data。**

    [main.rs:563](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:563) 的 data_trigger 只从 service.data 取键，再调用 conn.notify(service, "service.data.update", …)。它没有执行 self.triggers.fire。C 的 [service.c:56](/tmp/ask4-evidence/procd/service/service.c:56) 调用的是内部 trigger_event，不是把内部规则执行替换成 ubus 对象通知。

    实验先注册 service.data.update → run_script 的观察规则，再把服务 data 从 {old:"one"} 改为 {new:"two"}。C 文件记录 old、new 两次；Rust 没有生成文件。随后只更新一个正在运行实例的 data，从 old_instance 改为 new_instance：C 文件包含这两个键，Rust仍没有输出。

    源码还有两处独立损失：[main.rs:460](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:460) 的 set 路径先覆盖 service.data，之后只处理新键；[main.rs:531](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:531) 的 instance_update 先搬新配置，再调用接收服务名的 data_trigger，既没有旧实例 data，也没有新实例 data。C 在 [service.c:140](/tmp/ask4-evidence/procd/service/service.c:140) 和 [instance.c:1585](/tmp/ask4-evidence/procd/service/instance.c:1585) 显式处理旧、新两份。实例释放在 [instance.c:1597](/tmp/ask4-evidence/procd/service/instance.c:1597) 也触发 data 规则，Rust 的 remove 路径没有对应动作；释放这一分支是源码确认，本次实测的是更新分支。

    这里要区分“旧、新两轮 trigger_event 调用”与“外部脚本的完成顺序”。本次实例实验的文件顺序是 new_instance、old_instance；命令经过延迟和队列，不能把旧、新回调顺序进一步写成所有 run_script 都必须旧先新后的合同。

    [firewall:7](/tmp/ask4-evidence/rootfs/etc/init.d/firewall:7) 明确注册 procd_add_reload_data_trigger firewall。这会影响真实 reload 链。修正应保留旧、新数据快照并接回内部规则引擎；set_data 带 instance 的特殊“不触发”语义则应继续保留。

4. **F04，高：watch 的 ubus 对象订阅链缺失，手工 service event 通过并不能覆盖它。**

    先纠正题面的概念：watch.c 不是 file/netdev 的持续监视器。它在 [watch.c:111](/tmp/ask4-evidence/procd/service/watch.c:111) 注册 ubus subscriber 和 ubus.object.add 事件处理器；[watch.c:33](/tmp/ask4-evidence/procd/service/watch.c:33) 在对象出现后查 ID、订阅；[watch.c:94](/tmp/ask4-evidence/procd/service/watch.c:94) 把对象 notification 交给 trigger_event。实例的 watch 数组在 [instance.c:1339](/tmp/ask4-evidence/procd/service/instance.c:1339) 进入这条链。

    Rust 的 instance 解析没有 watch 分支；[main.rs:319](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:319) 只分派自己的 service/container/system 调用，也没有对应订阅对象及通知路由。

    最小实验：先注册 watch:["p31.source"] 的实例和匹配 p31.notification 的规则，再创建一个名为 p31.source 的 ubus 对象并发送真正的对象 notification。两边发布器都成功运行并写出 ready；C 的规则文件有 fired，Rust 没有文件。本实验没有绕过 watch 直接调用 service event。

    设备使用证据是 [network:18](/tmp/ask4-evidence/rootfs/etc/init.d/network:18)，其中第 21 行声明 watch network.interface；[sysntpd:110](/tmp/ask4-evidence/rootfs/etc/init.d/sysntpd:110) 和第 125 行注册 interface.* 规则；dnsmasq 第 1315 行也有接口规则。网络对象通知进入规则引擎，是 P2/P3 之间的正常接口。

    修正方向是补完整订阅生命周期，包括对象后出现、消失/重建、总线重连、watch 所属实例释放；不能只增加一个解析字段或多测几次 service event。

5. **F05，高：file/netdev 只比较名字，没有比较文件内容和接口身份。**

    [instance.rs:188](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:188) 比较 Vec<String>；解析在 [instance.rs:442](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:442)。C 则在 [instance.c:1075](/tmp/ask4-evidence/procd/service/instance.c:1075) 记录 if_nametoindex，在 [instance.c:1092](/tmp/ask4-evidence/procd/service/instance.c:1092) 计算文件 MD5；比较函数分别在第 1066、1083 行，配置解析时的填充在第 1417、1420 行。

    两个已复现输入：

    - file=["/tmp/watched.conf"]，先写 old，再覆盖成 new，重新提交完全相同的实例 JSON。C 进程 PID 56→59；Rust 48→48。
    - netdev=["p31dummy"]，在私有 net namespace 删除、重建同名 dummy，ifindex 2→3，再提交相同 JSON。C PID 50→56；Rust 47→47。

    这里没有声称 C 在不提交配置时持续观察文件写入或链路状态。正确行为是“解析新实例配置时取快照，并与旧配置保存的快照比较”；补一个随时自动重启的文件监视器反而会改变合同。

    [dnsmasq:1268](/tmp/ask4-evidence/rootfs/etc/init.d/dnsmasq:1268) 声明生成配置文件，后面第 1275 行声明 netdev；[sysntpd:65](/tmp/ask4-evidence/rootfs/etc/init.d/sysntpd:65) 追加 netdev。常见后果是配置文件已经更新、命令路径和 argv 未变，Rust 却认为无需重启，DNS 等服务继续使用旧内容。修正应保存匹配 C 的内容/ifindex 快照及失败取值规则。

6. **F06，高：ubusd 断线导致整个 Rust 监管器退出，原有子进程失去监管。**

    C 在 [ubus.c:34](/tmp/ask4-evidence/procd/ubus.c:34) 到第 64 行安装断线重连，退避从 50 ms 增至最多 1 s；首次连接失败也重试。Rust 在 [main.rs:1103](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:1103) 只连接一次；第 1139 行把读总线错误直接返回，第 1083 行 exit(1)。

    实验先确认 persistent::one 正在运行，停止隔离环境自己的 ubusd，重新启动一个 ubusd，确认新总线可用后等待 3 秒：

    - C 监管器继续存活，service list 恢复可用，仍显示原 PID 16。
    - Rust 监管器退出码为 1；日志为 procd-rs: ubus connection closed；原 PID 15 仍存在，但 service list 返回 Not found，退出码 4。

    原始证据见 [C 断线观测](/tmp/ask4-evidence/experiments/bus/c/observed.json)、[Rust 断线观测](/tmp/ask4-evidence/experiments/bus/rs/observed.json) 及 [Rust 日志](/tmp/ask4-evidence/experiments/bus/rs/daemon.log:1)。这里“子进程仍存在”来自 /proc 检查；本次没有再杀它去模拟下一次崩溃，但监管器已经退出，本身就足以证明监管状态丢失。

    需要把总线连接生命周期与服务监管状态分开：连接丢失期间继续回收、停止超时和 respawn，随后重连、恢复对象与订阅。这项属于普通服务监管器的故障边界，不需要等 PID 1 才处理。

7. **F07，高：运行实例更新先覆盖配置，用新 reload_signal 控制旧进程。**

    [main.rs:545](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:545) 先 take_config(new)，再 instance_restart。C 的 [instance.c:1573](/tmp/ask4-evidence/procd/service/instance.c:1573) 对运行中的实例先调用 instance_restart，再 instance_config_move；因而这次停止/重载动作使用的是旧 reload_signal、旧 term_timeout 和旧 has_jail。

    最小实验：先运行 /bin/sleep 300，不设置 reload_signal；然后只新增 reload_signal=10。C 使用旧配置的正常重启分支，PID 50→53，新进程继续运行。Rust 对旧 sleep 发送新配置的 SIGUSR1，进程终止，list 为 running=false、exit_code=138，且没有 respawn，所以没有新进程。

    修正应对齐“判断变化—处理旧进程—搬新配置”的顺序。只把新旧字段都加入 config_changed 无法修复。也因此，合同中“声明 reload_signal 后 PID 不变”不成立：首先要看这次动作使用的旧值，其次被信号通知的进程也可能退出。

8. **F08，高：exec 失败仅记 exit_code=127，没有进入退出/respawn 状态机。**

    [proc.rs:114](/tmp/ask4-evidence/reviewed/components/procd/src/proc.rs:114) 的 Command::spawn 返回错误后，[main.rs:101](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:101) 只设置 stopped/127。它没有走实例退出处理、respawn 延迟及相关通知。C fork 成功后，execvp 失败在子进程以 127 退出（[instance.c:559](/tmp/ask4-evidence/procd/service/instance.c:559)），会走 [instance.c:843](/tmp/ask4-evidence/procd/service/instance.c:843) 的正常退出逻辑。

    实验提交 command=["/tmp/late-exec"]、respawn=["3600","1","5"]，起初文件不存在；0.4 秒后创建可执行文件，随后等待 1.7 秒。C 后续重试成功，记录 ran，实例运行；Rust 始终 stopped/127，没有 ran，虽然 list 还显示 respawn 策略。

    “回显与 C 一样的 127”不是行为等价。要区分父进程 fork 失败和 fork 后 exec/降权失败；本次复现的是 ENOENT 导致的 exec 失败，不把 C 的所有 fork 失败也说成会产生 127。修正需要保留这些路径的状态机、重试和可观察事件。

9. **F09，高：超过 crash-loop 重试预算后，失败实例被误删。**

    [main.rs:194](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:194) 在放弃分支置 halt=true，随后 reap 调用 collect_stopped；[main.rs:293](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:293) 把任何 halt && Stopped 的实例删除。C 在 [instance.c:875](/tmp/ask4-evidence/procd/service/instance.c:875) 只是清 restart/respawn、置 halt、发 instance.fail；它不会在本次回调里再回到前面的删除分支。

    最小输入是反复输出 run 后 exit 7，respawn=["3600","0","1"]。两边都确实执行两次，然后停止：

    - C 保留 one，显示 running=false、exit_code=7，且不再有 respawn 字段。
    - Rust 返回 {"crash":{}}，实例和最后失败原因从 list 消失。

    应区分“主动删除/停止后释放”和“因崩溃预算耗尽而保留的失败实例”。此外，[instance.rs:337](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:337) 按是否保存配置策略决定是否输出 respawn，而 C [instance.c:1731](/tmp/ask4-evidence/procd/service/instance.c:1731) 依据当前 in->respawn；仅存有历史策略不代表仍在监管重试。

10. **F10，中高：trigger 所属对象的生命周期不完整。服务删了规则还在，实例规则从未注册。**

    服务更新时 [main.rs:447](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:447) 会删除旧 service 规则，但 [main.rs:602](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:602) 的 delete 和第 289 行的回收没有相应清理。C 在服务实际释放时调用 [service.c:1143](/tmp/ask4-evidence/procd/service/service.c:1143) 的 trigger_del(s)。

    实验注册一个无实例的服务规则，先发事件，确认两边均记录 fired；待它执行完，删除服务并清空观察文件，再发一个新事件。C 不执行，Rust 仍执行。因为先前的工作已经完成，这不是“删除前已经排队的任务尚未结束”。

    第二个缺口是 [instance.rs:490](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:490) 只保存实例 triggers，没有把它交给引擎；dump 的 verbose 参数也没有用于输出这部分。C [instance.c:1334](/tmp/ask4-evidence/procd/service/instance.c:1334) 注册实例规则，[instance.c:1602](/tmp/ask4-evidence/procd/service/instance.c:1602) 释放它，verbose dump 在第 1808 行输出。把同一条规则放到 instances.one.triggers 后，C 记录 fired，Rust 无输出。

    修正需要分别表示服务和实例的规则所有者，并在对应配置替换/对象实际释放时清理；不能只按服务名更新一个规则列表。设备热重载和服务删除后，不应继续运行已注销服务的脚本。

11. **F11，中高：trigger 的“延迟已到、等待串行队列”被误当成“仍在去抖延迟”，丢掉一次 requeue。**

    C [trigger.c:163](/tmp/ask4-evidence/procd/service/trigger.c:163) 判断 !cmd->delay.pending 就置 requeue。虽然注释写 currently running，条件也包含“延迟到期、已进入 runqueue、但前面任务还没结束”的命令。[trigger.rs:143](/tmp/ask4-evidence/reviewed/components/procd/src/trigger.rs:143) 只在 pid.is_some() 时置 requeue，漏掉这一状态；[main.rs:824](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:824) 的单任务 pump 会让它真实发生。

    实验让命令 A 占住队列约 2 秒；B 的 0 ms 延迟到期后等待 A；0.4 秒后再次触发同 argv 的 B。C 最终输出两行 fired，Rust 只有一行。A 的已启动标记被检查过，B 不是还未触发的空用例。

    应分清延迟待定、已入队、运行中、完成后待重排几种状态。仅给 pending 结构添加 pid 不能等价表达 C 的 delay.pending 与 runqueue 状态。设备上多个 reload 命令串行竞争时，这个差异会丢掉需要的第二次执行。

12. **F12，高但依赖用户配置：没有显式 group 时，把 UID 错当成主 GID。**

    [proc.rs:102](/tmp/ask4-evidence/reviewed/components/procd/src/proc.rs:102) 调用 drop_privileges(u,u)。C 在 [instance.c:1354](/tmp/ask4-evidence/procd/service/instance.c:1354) 从 passwd 同时读取 UID、pw_gid，并把主 GID 初始设为 pw_gid；显式 group 才覆盖它。[sys.rs:124](/tmp/ask4-evidence/reviewed/components/procd/src/sys.rs:124) 实际已经返回了正确的二元组，问题在调用方丢了第二项。

    实验账号 p31user 的 UID=1234，passwd GID=2345，另有补充组 3456；只设置 user，不设置 group。C 子进程输出 uid=1234 gid=2345 groups=2345,3456；Rust 输出 uid=1234 gid=1234 groups=2345,3456。

    这是一次性 fixture 中的合成身份用例，不代表已证明发货账号的 UID/GID 当前不同。设备确实使用 user/group，但默认 GID 错误只在满足相应条件时暴露。修正应使用解析出的 pw_gid，并保持显式 group 与零值分支的 C 语义；不能假设 UID 总等于 GID。

13. **F13，中：pidfile 只是回显，没有进程生命周期效果。**

    Rust 在 [instance.rs:474](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:474) 解析 pidfile，随后 dump；[proc.rs:39](/tmp/ask4-evidence/reviewed/components/procd/src/proc.rs:39) 的启动路径没有写文件。C 的写入实现是 [instance.c:443](/tmp/ask4-evidence/procd/service/instance.c:443)，在父进程记录子 PID 后第 688 行调用；halt 退出路径在第 863 行删除。

    提交 pidfile="/tmp/out/managed.pid" 后，C 写入 73 加换行，Rust 没有生成文件。写入差异已经实测；删除行为由源码确认。不能把 C 的规则概括成“任何退出都会删除 pidfile”，它是在具体 halt 分支清理。

    这类差异会影响依赖 procd pidfile 的外部调用方，但我没有据此宣称本机 dnsmasq 一定受影响：dnsmasq 自己的 -x 参数与 procd 实例的 pidfile 属性是两回事。应在实现生命周期写入/清理后用不自写 PID 的子进程验证。

14. **F14，中：TERM 宽限期内进程仍活着，list 却提前宣称 running=false。**

    [instance.rs:281](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:281) 把 running 定义为 state==Run::Running，Run::Halting 立即隐藏 pid，并在第 296 行输出旧 exit_code。C [instance.c:1676](/tmp/ask4-evidence/procd/service/instance.c:1676) 看的是 proc.pending，直到子进程被回收前都继续报告 running=true 和 pid。

    实验启动忽略 TERM 的 shell，term_timeout=2，确认 ready 后删除实例，0.3 秒后读取 list。C 仍是 running=true、pid=62；Rust 为 running=false、exit_code=0。再等到停止超时后，两边实例均消失。

    公共状态必须反映进程是否尚在，停止意图不能替代进程生命周期。还要避免把 C 的 halt 布尔值等同于 Rust 的所有 Halting 状态：C [instance.c:804](/tmp/ask4-evidence/procd/service/instance.c:804) 只在 halt 时强杀；state(spawn=false) 使用 halt=false，不宜从删除实验外推成“所有停止超时都 SIGKILL”。本次实测的是 delete 的宽限期，不是所有 state/update 交错。

15. **F15，中：blobmsg 类型过滤与实例有效性校验不一致。**

    C 在 [instance.c:1310](/tmp/ask4-evidence/procd/service/instance.c:1310) 先按 policy 取字段；对 env/netdev/file/limits/error 的元素类型再在第 1414–1427 行检查。Rust [instance.rs:399](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:399) 按名字分派，很多字段用 filter_map 丢掉坏元素，或把错误类型当作出现过的合法字段。

    三个实际结果：

    | 输入 | C | Rust |
    |---|---|---|
    | command=["/bin/true"]，env={A:"ok",B:7} | 实例无效，list 的 instances 是空表 | 丢 B，执行命令，显示 exit_code=0 和 A |
    | command="/bin/true"，字段类型为字符串 | policy 忽略错误类型，相当于未提供 command；实例有效、列出但不启动 | saw_command=true，却找不到数组项，判无效，不列出 |
    | command=["/bin/true"]，nice=21 | 第 1348–1351 行校验后实例无效 | 未按 C 范围拒绝，命令执行并退出 0 |

    三种 set 调用本身均成功，差异在实例是否被接受、是否执行；检查 ubus 返回码不足以覆盖它。nice 用例没有读取子进程实际 nice 值，因此这里的实测结论是“有效性和启动行为不同”，不是一份调度优先级测量。

    修正需要把 policy 层、字段元素层和实例整体有效性分开。还应补 command 缺失、空数组、错误顶层类型、混合类型数组的互相区分；不能把“C 很宽容”实现成所有坏元素都静默丢弃。

16. **F16，中，当前调用频度未证实：service.watchdog 回答成功，但没有任何超时动作。**

    这个快照已经有方法：[main.rs:649](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:649)。getter/setter、self_managed 和 dump 有实现，第 679–681 行也明写没有定时器。它不应再被称为“方法未做”；真正的问题是只实现了协议外观。

    对运行的、未配置 respawn 的 sleep 设置 mode=2、timeout=1，两边都回答相同的成功结果。1.6 秒后，C 的实例已被停止并移除，Rust 原 PID 28 仍运行，list 回显 watchdog={mode:2,timeout:1}。C 的 [instance.c:927](/tmp/ask4-evidence/procd/service/instance.c:927) 在超时时依据 respawn 决定 restart 或 stop；这条软件定时器路径在 getpid()!=1 时同样可达。

    另一个实测是 watchdog=["0","-1"]、autostart=false。C 的 getter 经发货 ubus CLI 显示 timeout:-1；Rust 返回 30。C [instance.c:1440](/tmp/ask4-evidence/procd/service/instance.c:1440) 的临时数组是 uint32_t，atoi("-1") 存入后是 0xffffffff，之后的 >0 检查不会回落到 30。负数显示源于 32 位值的 CLI 表示，不能把它理解为 C 内部保存了一个有符号负频率。本实验关闭 autostart，只测转换和回显，没有运行这个异常频率定时器。

    修正应实现每实例软件定时器，或者在明确收窄的候选模式下拒绝尚不支持的启用请求。继续成功回显但不执行，会让调用方误判保护已经生效。系统 /dev/watchdog、WDTFD 和 PID 1 交接是另一条后续工作，不能把两者混成一个延期理由。异常负数可以选择明确拒绝并记录兼容差异，不必为了“相同”照搬潜在危险的溢出行为。

17. **F17，中：rc(name, "running") 只在 set/add 后调用，真实 respawn/restart 后漏调用。**

    [rcs.rs:20](/tmp/ask4-evidence/reviewed/components/procd/src/rcs.rs:20) 已实现宽度 8 的 rc 队列，[main.rs:556](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:556) 也会排 running 脚本；所以合同第 11 节和旧报告里“没有 rc running/runqueue”的描述已过期。

    但调用点只有 handle_set 的路径。C 在 [instance.c:810](/tmp/ask4-evidence/procd/service/instance.c:810) 的延迟 respawn 和第 889 行的直接 restart 都调用 rc；Rust 对应的 [main.rs:242](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:242)、第 278 行只调用 instance_start。

    实验放置一个只记录 running 的同名 init 脚本，让实例第一次启动立即退出，respawn 后保持运行。两边实例都恢复运行；C 脚本记录两次 running，Rust 只有一次。

    应在与 C 相同的生命周期点补调用，并保留队列去重条件，避免粗暴地把它塞进所有 start 后造成额外调用。另有两个源码边界不能误报已完成：rcS 的宽度 1 队列仍没有；rcs.rs 的 deadline 字段虽然设置了，但 [rcs.rs:111](/tmp/ask4-evidence/reviewed/components/procd/src/rcs.rs:111) 并未消费 now，也没有 stop/shutdown 取消超时。目前主路径只排 running，故后者作为 P3.2 接入前的缺口记录，未冒充本次 stop 实测。

18. **F18，低：合并 validator 后的 option 顺序不是合同所说的全局字母序。**

    C [validate.c:46](/tmp/ask4-evidence/procd/service/validate.c:46) 先遍历 validator，再把每个 validator 自己按 AVL 排序的 rules 加入同一个 JSON 对象；不同 validator 的新键按加入先后保留顺序。Rust [main.rs:742](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:742) 把同 package/type 的所有选项再次合进一个 BTreeMap，做了全局排序。

    实验先注册 package=same,type=same,data={z:"string"}，再注册同 package/type 的 data={a:"string"}。C 原始 validate 输出是 z、a；Rust 是 a、z。值相同，文本顺序不同。

    如果目标是这张镜像的逐字节 CLI 兼容，应保留 C 的合并顺序并补同名 option 覆盖案例。如果只要求 JSON 对象语义等价，这项可以明确降级；不能让这种低风险排序问题排在前面的权限和监管故障之前。

九个指定文件均纳入上述审查，覆盖关系如下，便于回到实现定位：

| 文件 | 本次重点结论 |
|---|---|
| [instance.rs](/tmp/ask4-evidence/reviewed/components/procd/src/instance.rs:178) | F02/F05/F09/F10/F14/F15/F16：数据模型、变化判定、dump 与有效性 |
| [service.rs](/tmp/ask4-evidence/reviewed/components/procd/src/service.rs:57) | F02：服务 data；同时检查 set/add 计划、删除保留和 verbose 输出 |
| [main.rs](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:65) | F03/F04/F06–F11/F16–F18：状态机、事件接线、注册/释放和总线失败边界 |
| [trigger.rs](/tmp/ask4-evidence/reviewed/components/procd/src/trigger.rs:103) | F10/F11：所有者生命周期、延迟与运行队列状态 |
| [jsonscript.rs](/tmp/ask4-evidence/reviewed/components/procd/src/jsonscript.rs:55) | 正常字符串变量 DSL 的正向控制通过；include 明确缺实现，未建立本机调用证据 |
| [rcs.rs](/tmp/ask4-evidence/reviewed/components/procd/src/rcs.rs:47) | F17；rc 与 rcS 是两条队列，已有部分不能掩盖缺失调用点 |
| [proc.rs](/tmp/ask4-evidence/reviewed/components/procd/src/proc.rs:39) | F01/F08/F12/F13：真正启动什么、身份、失败后的可恢复性、pidfile；日志见后文 |
| [sys.rs](/tmp/ask4-evidence/reviewed/components/procd/src/sys.rs:78) | 对照 limits/priority/身份 helper；pw_gid 已正确解析，但 proc 调用方错误；harness 未验证子进程实际 rlimit |
| [ubus.rs](/tmp/ask4-evidence/reviewed/components/procd/src/ubus.rs:22) | 基线确认了三个对象的签名；静态 policy 表不等于实际参数校验，注册方法不等于效果已经实现 |

**harness 的结论是：它确实比较了一部分真实行为，但不能作为唯一验收依据；本次已证实假绿。** 不是说 874 行全部没有价值，而是它的成功条件允许整套调用没有到达任何监管器。

| 本次运行 | C/Rust 原始日志行数 | 每侧 rc= 标记数 | calls.diff | PID 身份结果 | 脚本最终结果 |
|---|---:|---:|---:|---|---|
| 冻结版原样基线 | 874 / 874 | 12 / 12 | 0 字节 | 两组均 same / same | exit 0，r65: ok |
| 只把两边监管器启动命令换成 /bin/false | 308 / 308 | 84 / 84 | 0 字节 | 两组均 differs / differs | exit 0，r65: ok |

第二行保留了相同 ubusd、drive、等待和 scrub，只替换 [r65_procd_diff.sh:57](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:57) 与第 63 行的监管器启动命令。差异脚本是 [r65-no-supervisors.sh](/tmp/ask4-evidence/r65-no-supervisors.sh)，结果见 [故障注入原始 C 调用](/tmp/ask4-evidence/experiments/astra-p31-r65-no-supervisors/c-calls.txt)、[Rust 调用](/tmp/ask4-evidence/experiments/astra-p31-r65-no-supervisors/rs-calls.txt) 和 [pid-identity.txt](/tmp/ask4-evidence/experiments/astra-p31-r65-no-supervisors/pid-identity.txt)。84 只是 call 包装器打印的失败计数，尚未包括 signature 等直接命令的失败。

这里有五处相互叠加的验收漏洞：

1. **正常基线的第 2 例已经是“两边同样失败所以通过”。** [脚本第 73 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:73) 使用 ubus call "$1" "$2" "${3:-}"；第 83 行 call service list 没给第三个参数，却被包装器变成显式空字符串 JSON。发货 CLI 在解析消息阶段就失败，两边都记录：

    ```text
    --- service list
    Command failed: ubus call service list  (Parsing message data failed)
    rc=244
    ```

    它没有测到“空服务表”。直接不传第三个参数，或者显式传 {}，才是这个用例需要的输入。原始记录在 [基线 c-calls.txt:33](/tmp/ask4-evidence/experiments/astra-p31-r65-baseline/c-calls.txt:33)。第 22 例直接执行 ubus call service list，没有经过这个包装器，因此它的最终全表调用能成功；不能把两例混为一谈。

2. **只检查 ubusd 可往返，没检查监管器真的就绪。** 第 48–52 行的 ubus list 只能证明总线服务存在；[第 315 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:315) 启动监管器后固定 sleep 2，没有检查进程仍活着、/proc/exe、service 对象及必须的方法。signature 缺失也只是进入可比较文本。两个 /bin/false 就因此穿过准备阶段。

3. **成功用例、预期失败用例和驱动失败都没有独立的期望。** call 把失败转换成 rc= 文本继续；[第 317 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:317) 又用 || true 吞掉整个 drive 的失败。正常基线 12 个 rc= 中，11 个对应脚本刻意安排的参数/不存在对象错误，另 1 个是上面的意外 CLI 解析错误。不能一律“出现错误就失败”，但必须逐例声明哪个调用应成功、哪个应返回哪一种错误。

4. **应该存在的效果文件，缺失也能通过。** trigger 和 rc 用例在 [第 210 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:210)、第 264 行等使用 cat … || echo "(no file)"。基线的正向文件确实有内容；然而验收逻辑并不强制正向内容出现，两边都没有文件也可以相等。空回复、空列表、缺文件应有各自的期望，不能都交给 diff 猜。

5. **PID 检查只比较两边结论相同，没有要求结论正确。** [第 351 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:351) 的 same_pid 在缺 PID 时输出 differs，混同“确实换了 PID”和“压根没获得 PID”。[第 377 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:377) 只检查 c==rs，故 differs/differs 也算通过。对于注释写明“必须保留同 PID”的两例，应该分别要求两边都有唯一有效 PID，且两边各自 before==after；不能只要求两个布尔结果碰巧相等。

scrub 规则需要分开评价：

| 规则位置 | 本次判断 | 应保留/修改的边界 |
|---|---|---|
| [第 339 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:339)，签名对象 ID | 对 service/container/system 的本次签名合理；锚定整行，只替换随机对象 ID，保留名字和方法文本 | 缺对象、缺方法不能仅靠 diff，仍需就绪和签名存在断言 |
| 第 340 行，所有 "pid": 数字 | 过宽，会把任意同名 JSON 字段都当进程 PID | 将来 data 内的业务 pid=7 与 pid=9 也会被抹成同一值；应只规范化明确的实例运行 PID 路径 |
| 第 341–344 行，pid1/pid2/wdpid1/wdpid2 | pid1 规则不锚定，先吃掉 wdpid1 的尾部，使它变成 wdpid1=P1，后续 W1 规则不再生效 | 当前身份比较读取原始文件，故这主要是规则顺序/范围问题，不是本次假绿主因；应锚定完整标记行 |
| 跨时刻 PID 全部抹掉 | 会隐去幸存实例是否被意外重启 | 目前只给第 10、21 例另做身份比较；set/add、update window、file/netdev、respawn 等也需要各自的生命周期断言 |

例如 service.data 中业务字段 "pid":7 与 "pid":9 都符合第 340 行的模式；这是规则本身直接造成的信息损失，不是本次基线恰好含有这种业务字段。不要把 UID、GID、信号、次数、exit_code、watchdog 值或业务 data 纳入模糊 scrub。

**逐例检查如下。** “有真实输出”只表示本次基线确实执行到相应路径，不表示该例的验收断言已经健全。

| 例号与脚本入口 | 本次实际测到什么 | 仍然未测到或会假绿的部分 |
|---|---|---|
| [1，第 76 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:76) | service/container/system 的方法签名真实一致 | 方法效果完全没验证；三个对象都消失时错误文本也能相同 |
| [2，第 82 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:82) | 客户端解析空 JSON 字符串失败 | 没有测空服务表，已经是假绿 |
| [3，第 85 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:85) | /bin/true 的 running=false、exit_code=0 | exec 失败、respawn、快速更新未覆盖 |
| [4，第 90 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:90) | exit 7 的退出码真实覆盖 | 崩溃预算、失败实例保留未覆盖 |
| [5，第 95 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:95) | 长寿 sleep 的运行状态 | 没验证子进程身份、实际 argv/FD/权限；运行 PID 被 scrub |
| [6，第 101 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:101) | 缺 command 的有效声明实例，两边真实列出且不启动 | 注释仍写“无效、不列出”，与源码、合同和实际输出矛盾；没测空数组或非字符串成员 |
| [7，第 107 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:107) | respawn 配置和 term_timeout 的 dump | 没让它自然退出并经历 retry、timeout、放弃 |
| [8，第 112 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:112) | env/data/limits 的简单投影 | data 全是字符串；未读子进程环境、真实 rlimit，也未测降权 |
| [9，第 117 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:117) | set/add 后实例名字集合 | b 是否被无故重启被 PID scrub 隐去；没测同名实例真实配置变化 |
| [10，第 129 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:129) | 两次完全相同 set 后 PID 相同 | 没有实际 config change，也没有 reload_signal；且 differs/differs 仍会被接受 |
| [11，第 138 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:138) | 正常 sleep 删除后的最终状态 | 未检查 TERM 宽限期、超时强杀、ujail 或规则释放 |
| [12，第 146 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:146) | 对 t5 发 TERM 后读取中间状态 | 只等 2 秒，respawn timeout 是 5 秒；这一检查点没有证明重启发生 |
| [13，第 151 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:151) | 无 respawn 实例的 state 停/起及三种参数错误 | 未覆盖已有延迟、忽略 TERM、停止中重启和 update 交错 |
| [14，第 166 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:166) | 一次 update_start/add/update_complete 的名字集合 | 未检查保留实例身份、跨调用交错、重复 start/complete 与中途 set |
| [15，第 177 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:177) | get_data 的 *、实例名与筛选 | 数据值都是字符串，无法暴露 F02 |
| [16，第 186 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:186) | 字符串 set_data 的替换与错误返回 | 没有观察内部 data trigger，无法暴露 F03 |
| [17，第 196 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:196) | 新服务 autostart=false 的初始状态 | 不是“更新已有 stopped 实例时也不启动”的证明 |
| [18，第 202 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:202) | 真实输出文件验证 eq/case/.*、变量展开、忽略非 run_script 等 | 没有 watch 通知、实例规则、删除规则、串行队列竞争；正向输出缺失仍能相等 |
| [19，第 245 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:245) | 基本 validate 分组、筛选、倒序、缺 type 丢弃 | 没有多个 validator 合入同 package/type 的顺序或重名 option |
| [20，第 260 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:260) | set 后 running 脚本确实产生输出，再次 set 再执行 | 没有真实 respawn/restart 后 hook、队列宽度/去重/超时；文件缺失也能相等 |
| [21，第 274 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:274) | watchdog getter/setter、自管理配置比较、零值/越界模式及错误参数 | 没等软件 watchdog 超时；未测负数字符串；只证明属性，不证明保护生效 |
| [22，第 296 行](/tmp/ask4-evidence/reviewed/tools/r65_procd_diff.sh:296) | 真实全表输出和字段顺序；其中 t5 已重新 running，间接观察到第 12 例之后的一次 respawn | 没有把前后 PID、重启时机和执行次数绑定成断言，仍未覆盖 exec 失败重试、预算耗尽和失败实例保留 |

因此不能笼统说这份 harness“完全没测到 respawn”：第 12 例看到 signal 后的中间状态，第 22 例最终看到 t5 两边都已恢复运行。它缺的是专门的生命周期断言和失败边界覆盖，F08/F09 的反例仍会被现有用例漏掉。

直接把这份 harness 补成可验收，最小方向是：

1. 修正第 2 例参数；把调用分为“应成功”和“应失败且错误码为 X”，记录请求、stdout、stderr、退出码和实际结果。正向调用任何一侧失败都应使该例失败。
2. 在 drive 前检查监管器存活、可执行文件身份、service 必要方法及一个成功的空 list 往返。保留总线就绪检查，但不能把它当监管器就绪。
3. 给每个正向效果设置最低断言：实例存在、进程存活、指定文件存在且内容/次数正确；PID 必须有效且唯一，再判断保留或更换。保留预期“不存在”的负向断言。
4. 缩小 scrub 到明确运行时字段，并保留独立生命周期证据。固定 sleep 可以作为上限辅助，主要等待条件应是期望状态/marker 在有界时间内出现。
5. 把 /bin/false 这项故障注入纳入 harness 自测，要求它稳定返回非零；再加入下文已经复现的少量关键反例。

脚本目前只复制一次 rootfs（第 20 行），第二侧只清 /tmp/out 的文件（第 330 行）。现有用例主要写这个目录，所以本次没有把它列成已证实的污染错误；但补 file、账号、pidfile、jail 和配置文件实验时，应像本次独立探针一样给两侧独立 rootfs，避免 C 的副作用成为 Rust 的初始状态。

**十条合同中，有的核心结论正确，有的条件写宽了，还有两条已被新的反例直接推翻。** 不应为了让 Rust 输出接近一次基线，而反向把缺失行为写成 C 的合同。

| 合同及文档位置 | 判断 | 应怎样精确表述 |
|---|---|---|
| [1，有效性，第 20 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:20) | command 缺失/空数组/非字符串成员的核心区分正确；不是完整有效性定义 | 前提是 policy 接受了字段类型，其他属性也通过校验。错误顶层类型可能被 C 忽略；env 坏成员、nice 越界等仍能使实例无效。bundle 跳过 command 解析也以该构建 policy 实际识别 bundle 为前提。instance_start 被调用不等于必然 fork；错误、缺命令、已有子进程均可早退。F15 是反例。 |
| [2，retry=0，第 39 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:39) | 对合法字符串配置的关键结论正确 | > 而非 >=，并且 retry>0 才放弃；默认 3600/5/5 和 term_timeout=5 的描述正确。但合同应补“放弃后保留失败实例、respawn 不再输出”，不能用计数条件正确证明 Rust 退出状态机完整。F08/F09 没被原 harness 覆盖。 |
| [3，reload_signal，第 54 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:54) | “声明后 PID 不变”和“第 10 例证明了它”均错误 | C 在一次更新中按旧配置发送信号；只是不主动走正常 stop/start，不保证信号接收进程不退出。第 10 例只有完全相同的 set，根本没配置 reload_signal。jail 段应写成“这些停止路径不由 procd 设置超时 SIGKILL，交给真实 ujail”，不是任何声明 jail 的进程都永远不会被 SIGKILL。 |
| [4，更新三条路，第 71 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:71) | 分支框架基本正确，但“正在停”和执行顺序需收窄 | C 的 stopping 是 in->halt；!proc.pending 或 halt 才先搬配置再调用 start。运行中变化是先处理旧进程再搬新配置。data-only 分支处理旧、新实例 data。两轮 trigger 回调不保证外部命令执行两次或按同样顺序完成，因去重/队列仍适用。既有停止实例的 update 也不能套用“autostart=false 永不启动”。 |
| [5，list 顺序，第 82 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:82) | 常见前缀顺序有依据，但字段条件和清单不完整 | running/pid 看 proc.pending；respawn 看当前运行策略开关，不是“有历史策略就有”。后面还有 jail、mount、setns、extroot、overlaydir、tmpoverlaysize、verbose 的实例 triggers 和 watchdog。作为精确镜像 CLI 文本目标可要求顺序；一般 JSON 对象语义不能据此声称所有消费者都依赖字节顺序。 |
| [6，validate 顺序，第 93 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:93) | 两套 validator 顺序基本正确；option 的结论过度概括 | 单个 validator 的 rules 按自己的 AVL 排序；多个 validator 合入同 package/type 后，不会重新全局排序。实际 z→a 的注册顺序得到 C:z,a，Rust:a,z。缺 package/type/data 丢弃，以及提供 service 参数提前返回的主要结论有源码依据。 |
| [7，trigger，第 107 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:107) | .*、run_script、正常字符串变量和 regex 的主体描述正确；requeue 状态写窄了 | “正在跑”应改成“原 delay 已不 pending，包括已入队但未得到运行槽位”。真正仍等待 delay 时才延长不缩短。F11 已复现。规则所属对象生命周期和事件入口也应写进合同，否则 DSL 本身对了仍可能完全收不到设备事件。 |
| [8，update window，第 139 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:139) | 基本 vlist 描述正确 | 这是跨调用的实例版本/保留语义。一条 start/add/complete 序列只能支持这一窄结论；不能当成重复调用、并行服务、途中 set、停止中 re-add 等所有交错的证明。保留实例的 PID 和进程状态也应观察。 |
| [9，get_data/set_data，第 145 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:145) | *、实例名以及 set_data 的特殊触发分支基本正确 | 应补“data 是任意 blob 类型”；instance 筛选不把服务级 * 数据一并过滤掉。带 instance 的 set_data 不触发规则；服务级非相同数据则先旧键后新键调用内部 trigger。不能把通知 service 对象当成执行规则，也不能把两轮事件直接等同两次命令执行。 |
| [10，watchdog，第 153 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:153) | self_managed 的核心结论正确；“freq 不大于 0 回落 30”错误 | 配置字符串先经过 atoi 再存 uint32_t，只有转换后为 0 才走回落；"-1" 是实测反例。self_managed 只排除 mode/freq 的变化比较，不排除其他字段变化和 stopped 实例更新。软件定时器效果属于普通进程可测范围，不应只记 getter/setter。 |

还要同步修正合同的阶段边界。[文档第 18 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:18) 将 watchdog 一概划入 P3.2，忽略了每实例软件定时器；[第 172 行](/tmp/ask4-evidence/reviewed/docs/contracts/procd.md:172) 仍说没有 rc(name,"running")，与当前源码和第 20 例冲突；第 177 行虽然承认 watchdog 定时器缺失，却不能据此称普通服务监管行为已对齐。

container/system 的签名对齐也应如实标成接口外观。本快照 [main.rs:334](/tmp/ask4-evidence/reviewed/components/procd/src/main.rs:334) 只实现列出的 service 分派，其余走 NOT_SUPPORTED。第 1 例不证明 system board/info 或 container 的实际行为等价。对当前明确限定的阶段，可以保留受限范围；报告应说明受限范围，不能把三个签名对象的存在当成整个 procd 已可替换。

**已知缺口的优先级，要同时写清普通监管器阶段与 PID 1 启动阶段。** 对现在的 P3.1，最危险的是 watch 事件入口与 file/netdev 变化判定失效；若下一步真要让 Rust 当 PID 1，rcS 缺失就是启动链的硬阻断，不能因为离线普通进程暂时没调用它而说设备“不用”。

| 缺口 | 发货镜像/设备使用证据 | P3.1 应怎样排 | 切换 PID 1 前的要求 |
|---|---|---|---|
| file 内容、netdev ifindex 快照 | dnsmasq:1268、1275；sysntpd:65。生成配置覆盖和同名接口重建都是合法更新输入 | 第一组，已复现实际更新失效；file 配置内容变化尤其直接影响 DNS reload | 必须对齐，不能只比路径/接口名 |
| watch.c 的真正职责：ubus 对象订阅 | network:21 显式 watch network.interface；sysntpd、dnsmasq 有 interface.* 规则 | 与上一项同属第一组；它们是两条不同实现路径，应各有端到端用例 | 对象注册、重建和总线重连后通知仍须到达规则引擎 |
| 实例 stdout/stderr 日志 FD | [uhttpd:122](/tmp/ask4-evidence/rootfs/etc/init.d/uhttpd:122) 明确 stderr=1；C 在 [instance.c:648](/tmp/ask4-evidence/procd/service/instance.c:648) 建管道，在第 713 行消费；stdout 管道还关联第 491 行的 libsetlbf | 第二组，有直接发货调用；日志丢失会隐藏启动/崩溃原因，降低故障可诊断性 | 需要同时实现管道消费、关闭和回收；不能仅建无人读取的管道 |
| 每实例软件 watchdog | R63 那次实际 list 字段没有 watchdog；补查 etc/init.d 和 lib 的 306 个普通文本文件，没有找到直接 procd_set/append_param watchdog 或 ubus call service watchdog 调用 | 当前使用证据弱于前两组，但“成功无效果”必须修正或明确拒绝；F16 已证明 C 在非 PID 1 下会执行 | 明确支持范围；若允许启用，就必须有真实定时器/喂入/停止行为 |
| rcS() 串行启动/关机队列 | [inittab:1](/tmp/ask4-evidence/rootfs/etc/inittab:1) 的 sysinit 和 shutdown 必经；[C rcS.c:200](/tmp/ask4-evidence/procd/rcS.c:200) 宽度为 1；R63 记录本机 rc.d 启停链接序列 | 它是 P3.2 工作，不因为 P3.1 普通监管器还没实现它就单独否定阶段边界；已有 rc running 缺调用仍是 P3.1 问题 | 硬阻断。每次启动都依赖它；必须保留顺序、完成回调和关机超时，不能用现有宽度 8 的 rc 队列代替 |

watchdog 的检索只针对上述两条目录下可读的普通文本文件，跳过 symlink 和二进制；没有报不可读文件。它不能排除原生程序、动态生成参数或未扫描路径的调用，所以我没有写“本机绝不用每实例 watchdog”。系统硬件 watchdog、WDTFD 继承、magic close 的风险仍属于下一阶段必须独立验证的职责。

在你列出的已知缺口之外，F01 的 ujail 委托、F02/F03 的 data 与内部 trigger、F06 的重连和 F08/F09 的失败状态机应先补。R63 第 21–26 行本来就把 jail 和 data 列进监管核心的实际范围，不能把它们也顺手归到 P3.2。即使把日志和 rcS 完整补上，这些问题仍会阻止“核心监管已保真”的结论。

**实验记录保存在 /tmp/ask4-evidence，未放进 Git。** 原始 calls.json 保存每次方法名、输入、退出码、stdout、stderr；observed.json 保存脚本效果、生命周期和比较结果。报告中的 PID 是对应运行的原值，只能做各自运行内部的身份比较，不能比较 C 的 50 与 Rust 的 43 谁更“正确”。

| 实验组 | oracle 原始目录 | 本地证据 |
|---|---|---|
| 原样 22 例基线 | /tmp/astra-p31-r65-baseline | [完整 C 调用](/tmp/ask4-evidence/experiments/astra-p31-r65-baseline/c-calls.txt)、[完整 Rust 调用](/tmp/ask4-evidence/experiments/astra-p31-r65-baseline/rs-calls.txt)、[scrub 后 diff](/tmp/ask4-evidence/experiments/astra-p31-r65-baseline/calls.diff)、[PID 判定](/tmp/ask4-evidence/experiments/astra-p31-r65-baseline/pid-identity.txt) |
| 不启动两边监管器的故障注入 | /tmp/astra-p31-r65-no-supervisors | [C 调用](/tmp/ask4-evidence/experiments/astra-p31-r65-no-supervisors/c-calls.txt)、[Rust 调用](/tmp/ask4-evidence/experiments/astra-p31-r65-no-supervisors/rs-calls.txt)、[diff](/tmp/ask4-evidence/experiments/astra-p31-r65-no-supervisors/calls.diff)、[PID 判定](/tmp/ask4-evidence/experiments/astra-p31-r65-no-supervisors/pid-identity.txt) |
| 核心状态与数据探针 | /tmp/astra-p31-probe-sik4iei6 | [探针源码](/tmp/ask4-evidence/probe.py)、[C 观测](/tmp/ask4-evidence/experiments/c/observed.json)、[Rust 观测](/tmp/ask4-evidence/experiments/rs/observed.json)、[C 请求记录](/tmp/ask4-evidence/experiments/c/calls.json)、[Rust 请求记录](/tmp/ask4-evidence/experiments/rs/calls.json) |
| 队列、通知、watchdog、rc 等补充探针 | /tmp/astra-p31-extra-uo5v0ith | [探针源码](/tmp/ask4-evidence/probe2.py)、[C 观测](/tmp/ask4-evidence/experiments/extra/c/observed.json)、[Rust 观测](/tmp/ask4-evidence/experiments/extra/rs/observed.json)、[C 请求记录](/tmp/ask4-evidence/experiments/extra/c/calls.json)、[Rust 请求记录](/tmp/ask4-evidence/experiments/extra/rs/calls.json) |
| ubusd 重启探针 | /tmp/astra-p31-bus-2tcy75fc | [探针源码](/tmp/ask4-evidence/probe3.py)、[C 观测](/tmp/ask4-evidence/experiments/bus/c/observed.json)、[Rust 观测](/tmp/ask4-evidence/experiments/bus/rs/observed.json)、[C 请求记录](/tmp/ask4-evidence/experiments/bus/c/calls.json)、[Rust 请求记录](/tmp/ask4-evidence/experiments/bus/rs/calls.json) |

下面按观测键列出实际结果，方便不重跑也能逐项对照原始 JSON：

| 观测键 | C | Rust | 对应结论 |
|---|---|---|---|
| typed / typed_get_data | 对象、数组、布尔、整数、字符串均保留 | 两层都只剩字符串 text | F02 |
| service_data_events | old 换行 new 换行 | null，文件未生成 | F03 |
| instance_data_events | new_instance 换行 old_instance 换行 | null | F03；不把脚本完成顺序等同事件调用顺序 |
| delete_trigger_before / after | 删除前 fired；删除后 null | 删除前、后均 fired | F10 |
| instance_trigger | fired | null | F10 |
| crash_runs / crash | 两次 run；保留 stopped/7 的 one | 两次 run；实例消失 | F09 |
| late_exec_runs / late_exec | ran；恢复 running | null；stopped/127 | F08 |
| reload_change | 50→53，继续 running | 原 43 退出，exit_code=138 | F07 |
| file_changed | 56→59 | 48→48 | F05 |
| halting / halting_after | 宽限期仍 running；之后实例消失 | 宽限期已 falsely stopped；之后实例消失 | F14 |
| identity | UID 1234，主 GID 2345，补充组 2345/3456 | UID 1234，主 GID 1234，补充组 2345/3456 | F12 |
| pidfile | "73" 加换行 | null | F13 |
| jail_argv / jail_direct_command | helper 有 argv；直接命令未执行 | helper 未调用；直接命令为 root 身份 | F01 |
| bad_env | instances={} | 执行 /bin/true，留下 A | F15 |
| wrong_command_type | 有效、无 command、stopped/0 | instances={} | F15 |
| typed_event | A=,B= | A=,B= | 一致性控制，不能当 F02 的另一个例子 |
| queued_requeue | fired 两次 | fired 一次 | F11 |
| object_notification / emitter_ready | fired / ready | null / ready | F04 |
| wd_set / wd_after_timeout | 设置成功，超时后实例消失 | 同样成功，原进程继续运行 | F16 |
| wdnegative | timeout:-1（CLI 对 0xffffffff 的表示） | timeout:30 | 合同 10/F16 |
| rc_after_respawn / rc_process | running 两次；实例已恢复 | running 一次；实例已恢复 | F17 |
| merged_validate_raw | z 在 a 前 | a 在 z 前 | F18 |
| netdev_recreated | ifindex 2→3，PID 50→56 | ifindex 2→3，PID 47→47 | F05 |
| bad_nice | instances={} | /bin/true 已执行、exit_code=0 | F15 |
| dsl | matched 换行 has 换行；没有 BAD | 完全相同 | 正向 DSL 控制 |
| daemon_exit_after_bus_restart / child_still_exists | daemon 未退出；子进程仍在 | daemon exit 1；子进程仍在 | F06 |
| list_after_bus_restart | 恢复 list，保留原 PID 16 | Not found，rc=4 | F06 |

本次也保留了没有成为缺陷的检查，避免把怀疑写成结论：

- 数字/布尔事件变量的 %A%/%B% 在 C trigger 的 libubox 解析中也不会自动转字符串。[json_script.c:94](/tmp/ask4-evidence/json_script.c:94) 只返回匹配的字符串，trigger 的 handle_var 返回 NULL；两侧实际都是 A=,B=。这与 service/instance data 必须保留任意 blob 类型是不同问题。probe.py 第 147 行保留了一句实验前假设性的旧注释，结果推翻了它；本报告与原始观测为准。
- regex + and + not + has + return 的正常组合，两边都输出 matched、has，并跳过 return 后的 BAD。它支持正常 DSL 子集的保真结论，不证明 include、所有错误输入或全部表达式已经覆盖。
- sys.rs 的常见 rlimit 路径和常量经过源码对照；现有 harness 只检查 limits 的投影，本次没有声称测量过每个真实子进程 rlimit、所有数值解析边界或全套 seccomp 行为。
- 本次记录的 jail 测试使用了明确的记录 helper；它证明委托缺失，不是对真实 ujail 隔离强度的压力测试。
- 初次自写探针曾因把 namespace PID 用到宿主 /proc 路径而在准备阶段失败。随后修成 root/proc/<pid>/exe，成功组是 sik4iei6；失败准备过程没有算成 C/Rust 差异。

可复现入口如下，使用的是 oracle 上已冻结的源码和二进制；这些命令重新创建离线副本，不涉及物理路由器。输出目录请保持独立。

```sh
# 在 oracle 上从冻结源码构建；本次因主机工具链为 1.98.0 使用了版本检查豁免。
ssh oracle '/home/ubuntu/.cargo/bin/cargo build --locked --ignore-rust-version --release --target aarch64-unknown-linux-musl --manifest-path /tmp/astra-p31-reviewed-db5afa1/components/procd/Cargo.toml'

# 原样验收：当前冻结版本会得到 r65: ok。
ssh oracle 'sudo -n sh /tmp/astra-p31-reviewed-db5afa1/tools/r65_procd_diff.sh /home/ubuntu/h1-4-extract.JK5fNS/rootfs /tmp/astra-p31-reviewed-db5afa1/components/procd/target/aarch64-unknown-linux-musl/release/procd-rs /tmp/astra-p31-recheck-baseline'

# 故障注入：冻结版本即使完全不启动两个监管器，也错误地报告 r65: ok。
scp /tmp/ask4-evidence/r65-no-supervisors.sh oracle:/tmp/astra-p31-recheck-no-supervisors.sh
ssh oracle 'sudo -n sh /tmp/astra-p31-recheck-no-supervisors.sh /home/ubuntu/h1-4-extract.JK5fNS/rootfs /tmp/astra-p31-reviewed-db5afa1/components/procd/target/aarch64-unknown-linux-musl/release/procd-rs /tmp/astra-p31-recheck-negative'

# 三组独立探针，外层会为每次运行建立新的临时目录并打印位置。
ssh oracle 'sudo -n python3 /tmp/astra-p31-probe-sik4iei6/probe.py'
ssh oracle 'sudo -n python3 /tmp/astra-p31-extra-uo5v0ith/probe.py'
ssh oracle 'sudo -n python3 /tmp/astra-p31-bus-2tcy75fc/probe.py'
```

补充探针所需的 ubus 通知发布器源码在 [emitter/src/main.rs](/tmp/ask4-evidence/emitter/src/main.rs)，其二进制位于 oracle:/tmp/astra-p31-reviewed-db5afa1/emitter/target/aarch64-unknown-linux-musl/release/p31-emitter。probe2 会把它复制到各自的临时 rootfs。它先注册 p31.source 对象，再发送真正 notification；没有通过 service event 伪装通知链已经工作。

下一轮最小验收增量应直接取本次反例：监管器缺失必须红；正向 CLI 解析失败必须红；结构化 data 保真和真实 data/watch 触发；同路径文件变化及同名接口重建；旧配置决定 reload 动作；ENOENT 后可恢复、crash-loop 后保留失败实例；规则删除和排队重触发；子进程实际 UID/GID 与 ujail argv；TERM 宽限期状态；软件 watchdog 到时动作；respawn 后 running hook；总线断线后的持续监管与重新注册。先让这批输入在现有候选上稳定变红，再修实现并转绿，比继续增加类似 sleep/list 的日志行数更能提高验收可信度。

这些反例修正后，仍需用项目声明的工具链重新构建同一提交，并在这张 rootfs 上运行改正后的验收。P3.2 的 rcS/inittab、硬件 watchdog 交接和启动恢复边界另行验证；本次没有执行或申请任何物理路由器状态变更。
