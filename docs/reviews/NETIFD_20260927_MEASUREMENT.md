# netifd 最终确认前的计量修订

状态：工具和候选正确性验证完成的部分如下；最终确认尚未冻结，不能据此宣布netifd收尾。
生产始终精确C，全部AX3000T执行均在现有隔离namespace中，管理链路为Wi-Fi en0。

## 组合候选门

H4c+H7b组合Oracle ELF SHA256为
`c2dadd110eddc86b4afd61ae84bebb8cf9e8c7475bd95e223e02a35b8d3c1f6c`。
166单测、clippy、release/ABI、完整31/31场景、overflow、restart、两种reconnect通过。
宿主前后网络/挂载/namespace相同，post census无项目root存活进程。
1392项下载证据索引为ignored `private/netifd-20260926/final-combined-gates-index.json`。

三方raw66检查中，组合候选与C的错误码、DATA字节和顺序全部一致。正式R89的既有差异
保留：无线5个整数的INT64/INT32编码导致20字节差别，以及旧selector/坏参数处理差异。
不能把这些R89差异算成优化收益，也不能为它修改候选的C兼容合同。数据位于
`private/netifd-20260926/final-combined-raw-return-01/final-combined-raw-01/`。

## 事件与reload工具

新增的单条event操作是lan down/up、wired down/up四动作完整cycle。两条空bridge只存在于
隔离network namespace；运行镜像原版hotplug脚本，完整保留listen、subscribe、hotplug、
状态、内核输出、child完成边界和失败journal。不把整cycle的p99除以4冒充单动作p99。
候选使用精确C参考合同；C/R89的独立capture有差异就先停止对账，不允许候选自采自认。
reload复用既有RPC路径，额外校验配置、脚本、接口和无线状态没有发生非预期变化。

工具01 benchmark SHA256为
`b99df865daa3d80a40e0113cc7dbc6421918868d59c7ba9614b4f253c3533693`。
Oracle完整check-tools/check-benchmark、clippy、native负例/namespace回收通过。
C/R89 capture的四动作合同一致；C及组合候选N2/W1重复周期、实际无线夹具unchanged reload
和中途失败留证验证通过。首次stock烟测在namespace启动前因宿主aggregate5.704%超过5%
门而停止，原文件保留；独立续验只执行未运行的步骤，不更改N/W或阈值。该流程是工具
功能验证，不作性能判断。证据在 `private/netifd-20260927/tools-validation-01/return/`。

AX3000T对精确C及正式R89的独立untimed capture也完成，四动作合同无差异；boot、19个配置、
生产九组件C、挂载和客户端健康前后均通过。原数据和合同在
`private/netifd-20260927/event-hardware-capture-01/`，plan SHA256为
`e11f572cff450a7451ec181eb846c09b01666d99359d087b905ef73675ba587c`。
这些capture没有任何正式性能样本。

## caller子进程CPU导出

旧/proc child user/system各自被导出为USER_HZ计数。HZ100时，一个parent的两个端点
差值保守导出量化带为±2tick；四客户端不能仍按一个parent记账。在最终采样前发现这
会让部分tree CPU比较的量化带大于预定工程预算，故先修订测量工具，没有测后放宽阈值。

新benchmark只对自己的snapshot增加getrusage(RUSAGE_CHILDREN)的两个累计微秒字段；
保留旧tick、own process clock和所有外部daemon字段。Linux6.12.94的
[wait累计](https://github.com/gregkh/linux/blob/v6.12.94/kernel/exit.c#L1145)、
[getrusage](https://github.com/gregkh/linux/blob/v6.12.94/kernel/sys.c#L1810)和
[导出转换](https://github.com/gregkh/linux/blob/v6.12.94/kernel/time/time.c#L470)
说明它读取相同kernel累计量，但去除了USER_HZ导出截断。精确musl1.2.5 LP64公共rusage
结构272字节（含reserved），已用完整缓冲和ABI断言处理。

相对kernel累计量，单parent两个分量差值的保守**导出截断**带为±2us，配对为±4us；
四caller为±16us，再除以aggregate操作数。这不是微秒物理精度或实际测量准确度声明。
外部observer与daemon仍是proc计数，不能因为caller换了API就一并消除其误差。
源码、源URL与hash、FFI和校验记录见私有 `child-cpu-rusage-01/REPORT.md`。

工具02 benchmark SHA256为
`0e9fa8eab6b486d1907d77ea1f436b3346d10078e88d00fb120f873be1f11876`。
Oracle再次通过完整工具门、6单测、clippy和native负例。固定12-child探针分别覆盖
250/1000/4000/16000us目标、自身CPU不计入child、live/WNOWAIT zombie不提前计入、
exit7仍计CPU、wait4分量floor carry≤1us以及正的sub-tick导出。直接执行和benchmark
内执行均通过。后者caller+已回收后代累计69138us，旧tick值0.05s，两套原始值均保留。

AX3000T在独立隔离诊断中执行相同固定探针两次（一次由benchmark等待），全部通过。
独立probe的最小正增量393us；benchmark caller累计73305us，旧tick值0.06s。
这证明新导出路径在该内核保留了sub-tick信息，不证明微秒实际精度。两轮没有netifd
性能负载；所有生产/boot/config/mount/健康及清理门通过。数据在
`private/netifd-20260927/child-cpu-router-01/`，逐项核验见 `verified.json`。

## 尚待冻结

工具03的窗外身份采集使用了精确镜像未提供的`od`，C capture因此失败，原目录保留。
改用镜像已有的`hexdump`后，13项fake-proc正负例通过；工具04复用工具02的精确
benchmark ELF，Rust/Cargo输入不变，只更新shell/Python。C/R89捕获合同仍完全一致。
工具04的C N2/W1功能窗完成，但窗后宿主进程忙碌度5.331104%超过原5%门，整个队列
停止，原结果仍为failed。独立审计核验542个原始文件，确认事件合同、四个端点的
boot/kernel/挂载/link/namespace身份和退出清理均通过；该窗不能用作性能结论。
原窗因guard异常缺少address/route后快照，后续延时只读对账相同，但不能冒充原post采样。

有限续验只运行原未执行的候选事件、unchanged reload及失败工具负例，全部通过，
350个下载原始文件逐项核对hash，前后宿主身份和网络通过。原失败窗没有重跑、替换或
放宽阈值。证据及独立审计在`private/netifd-20260927/tools-validation-04/`。
新增窗外no-spawn资料只标记证据已采集：精确PID/PPid/starttime、可执行文件和映射ELF、
LD环境、子进程枚举及前后身份。它不是零child CPU证书，不自动消除proc计数量化带。

最终analyzer必须逐parent保留counter来源；11项指标任一缺失不得从别的summary静默补齐。
在源码及运行证据没有建立特定进程不创建子进程以前，显示child=0也不自动将其量化带置零。
正在补齐时间窗外的精确角色身份和子进程边界；采样数与600秒namespace上限也要在确认前
完成可执行设计。所有旧A/A和旧候选样本保持原身份/计数精度，不追溯升级。
