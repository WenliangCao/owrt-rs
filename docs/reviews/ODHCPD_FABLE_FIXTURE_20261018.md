# Fable F1–F5 实包夹具：计划与结果

**最终SDK一次通过129/129项：baseline 20、extended 62、Fable 47。**
身份、原始计数和证据边界见文末；本轮没有真机或性能验证。

旧20＋62项及其原始输入脚本不变更归档。新工具默认provider增加本机字段类型形状：
LAN之外的WAN带`dhcpserver`字符串与整数`leasetime=60`，使用合成地址；UCI的WAN
维持disabled、ignore=1。`--provider-shape legacy`保留旧baseline与control的精确
provider输入用于重放；新SDK统一使用默认typed形状。工具哈希因此变化，不能将
旧运行标成采用新输入。19条baseline payload预期不变，最终SDK运行时逐字节验证。

新增独立`--case fable`，不扩展旧extended的62断言。全场景只在Oracle独立网络/
挂载/PID namespace，沿用真实veth包与精确rootfs；180秒上限，正常包等待3秒。
初次实施仅语法/仪器自检，旧失败候选不跑矩阵；最终Fable SDK身份冻结后才运行
20＋62＋本case。失败保留原件并停止，不改产品、不重跑选好数、不做性能或真机操作。

成本模型：F1–F3由配置解析/提交边界决定，F4由通知过滤决定，F5由worker请求期限
决定；协议处理速度不是本轮变量。预测修复后单个坏host/无关WAN数据不阻断LAN，
坏reload不改变PID/现役服务，ignored通知不增加dump，250ms回复不会重建dhcp对象。

| 场景 | 固定输入 | 必须观察 |
|---|---|---|
| F1 | 启动前删WAN dhcp段；dump含typed WAN与无UCI段typed WWAN | LAN首RA与Rapid NA成功；进程仍活，非服务客户端接口不影响LAN |
| F2 | 现役LAN下追加alias dhcp双server段，dump把alias也映射br-lan；同时改LAN DNS | reload拒绝；PID、dhcp对象和原LAN RA/已绑定NA继续，DNS仍旧值；撤销冲突后的正确reload可生效 |
| F3 | 两条合法静态host中夹奇数DUID、坏MAC、坏IP；启动及reload分别检查 | LAN服务继续、两条合法host按固定hostid分配；reload更改合法hostname在导出中生效，证明没有整份拒绝；ubus非法host继续返回协议status2 |
| F4 | provider按interface参数通知计数；disabled WAN、active LAN即使共享ignore=1、unknown；独立aux池模式disabled→server→disabled并HUP | disabled WAN/aux不dump，active LAN/unknown照常dump；aux模式变化后名单同步，原LAN PID/服务保留 |
| F5 | provider用uloop timer异步延迟250ms才reply完整dump；启动和运行期各一次 | 首RA/IA正常；运行期dump中DNS变更真正进入DHCP回复，完成计数增加，PID及dhcp对象ID不变；期间RS/DHCP能继续服务 |

仅对provider延迟做功能计时确认，不能加入产品性能样本。原始dump、计数、pid/object
身份、包hex、文件与拒绝日志一起保留，状态码不以CLI进程退出码代替。

F4源码细节已定案：按精确C内部effective-mode ignore处理，非直接读取共享UCI
ignore开关；默认disabled为ignored，有效RA/DHCPv6 server使其非ignored，同轮
后续禁用不反向清该sticky状态。夹具通过独立aux模式＋HUP测试重读后名单更新，
不错误地把单改WAN共享ignore字段当C行为。Fable建议在此按源码语义细化。

准备完成的工具SHA256为
`5705bd39a538e81b333505a069ea19f498027b8dac5e0fc0b117b6fffdedb8d7`。
Oracle Python语法检查、typed/legacy/control输入形状断言、精确rootfs的ucode
字节码编译均通过；仅运行provider仪器自检，250ms timer后收到完整dump且计数
为1次请求/1次完成/0pending，未启动C或Rust odhcpd。该计时只是人为延迟生效的
仪器确认，不是产品性能观测。证据位于Oracle私有
`/home/ubuntu/odhcpd-validation-20261018/fable-provider-selftest-01/`。

最终SDK到达后的调用保持同一rootfs与全新out：先默认baseline，再`--case extended`，
最后`--case fable`；均传精确`--daemon ELF`。首次最终运行前核对ELF SHA，任何
失败保存后报告，不自行改产品。短时真实trial及新镜像资格另由主线程安排。

## 最终 Fable SDK 固定批次结果

source `e2adbe1c2bc32cdfbaef5ea4fa01acc81e9385ba`，canonical SDK CI `39114432614`，
ELF 802928字节，SHA256
`c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30`。
先核对该SHA，再使用上述冻结工具和默认typed WAN输入，串行运行一次
baseline→extended→fable。全部129项通过，无失败、无重跑、未改变产品或阈值。

| 组别 | 通过 | 原始报文离线比较 |
|---|---:|---|
| baseline | 20/20 | 19条payload与精确C06逐字节相同 |
| extended | 62/62 | 33条payload与此前SDK资格轮原件逐字节相同 |
| Fable F1–F5 | 47/47 | 新场景按本页冻结断言验收，不冒称与C全包等价 |

F1无WAN dhcp段及新增typed WWAN时，LAN首RA/NA正常且只有LAN服务DHCP。
F2双server别名冲突被拒绝，原PID、dhcp对象、DNS及NA绑定保留；纠正reload后
新DNS生效。F3非法host不阻断启动或重读，两条合法host分配和合法改名导出均生效，
ubus非法host实测协议状态为2。

F4以provider实际dump调用次数验证：disabled WAN通知 **6→6**；active LAN即使
共享ignore=1为 **6→7**；unknown为 **7→8**；disabled aux为 **8→8**；HUP将aux
启用为server后通知 **9→10**；再次禁用后通知 **11→11**。HUP自身产生的刷新独立
保留在计数里，没有将它误算作通知触发。原LAN PID/对象/RS服务持续。

F5启动时250ms延迟dump完成计数 **11→12**，接口/DNS/NA成功初始化；运行期
真实观察到`calls=13, completed=12, pending=1`，随后完整完成到13、pending=0，
版本由5进到6，新的DNS通过DHCP包可见。期间及完成后PID、dhcp对象ID不变，
RS/DHCP继续服务。这是有意延迟的功能门，不是产品性能样本。

Oracle完整原件在 `/home/ubuntu/odhcpd-validation-20261018/fable-final-01/`；
本地ignored `private/odhcpd-20261018/fable-final-01/observations.tar.gz` 与
`comparison.json` 保存脚本、日志、包、计数、状态和离线比对。旧C及旧候选原件
没有覆写，typed输入的变化明确记录在新instrument身份中。

**身份边界：**旧`79f1349e…`/`c4a7c273…`的性能或物理trial结果不转授给这个
`c7c5f1f9…`。本轮未访问router、未跑性能、未刷机或发布。新ELF仍须按用户要求
单独完成短时真机trial及最终镜像恢复门后才可刷机。
