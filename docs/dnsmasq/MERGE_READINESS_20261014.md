# dnsmasq 最终修复与 main 合并验收

2026-10-14。**本轮确认的产品/恢复/交付缺陷已完成修复，最终组合已在 `861782a8` 合入 main。**
用户已授权修复全部已知问题并在验收通过后直接合并。此前审计的F10开放状态和
“不合并产品”边界属于旧轮次；原报告和失败证据保留，本页记录新的验收决定。

## 精确产物

| 对象 | 冻结身份 |
| --- | --- |
| 最终组合源码 | `b587282081b72ea0f96cf909e0f70b0bc8de9372`；tag `audit/dnsmasq-merge-b5872820-20261014` |
| F10产品输入 | `238e7ca4374b1889696f91816c1c239d7fe32baa`；组合另含F4包激活/r4及F5重连/ACL/jail |
| 真实SDK包 | `dnsmasq-2.93-r4.apk`，1,154,800 B，SHA `880050e82f81ad3dff27dac9716f15f7e167346750a4c8c197e9fe8ce6001742` |
| APK内最终ELF | 2,124,571 B，SHA `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c` |
| init / ACL | `70fb3c6bd057c6981503138b91292182f07c9a0d5aa1aaf0454c34af4ca746f0` / `8bedbcdd3018c17f272f0d3ecf9573aa6f05253806cb8812ebf92e9b87ac6020` |

SDK走真实源码prepare/compile/strip/APK，不是包装旧ELF。660个归档文件、179个
SDK实际输入、106个SDK工具/配置文件及提取payload均核验；原recipe恢复。后续
报告/检查器提交没有改变上述产品或包文件。[SDK收据](audits/full-20261014/SDK_FINAL_B587.md)。

## 已知问题闭合

| 项目 | 最终状态与证据 |
| --- | --- |
| F1 TCP/轮转内存放大 | 不可变记录及有界共享顺序页；最终SDK 60k warm/64MiB、50k HUP/64MiB均通过，Rust峰值26,759,168/49,471,488 B，OOM0。[资源](audits/full-20261014/final-sdk-memory-review.md) |
| F2/F9 低内存重载中止/不完整发布 | fallible私有整代、两owner提交前完成克隆、失败保留旧代。最终no-held inotify全量census完整保留2000旧名，held HUP清缓存、旧TCP及正常更新通过。[重载](audits/full-20261014/final-sdk-resource-review.md) |
| F3/F6 回退被中断/上传路径 | 恢复owner留到C身份与DNS健康；脚本和运行目录分离。最终SDK ELF在confirm后卸载/restart间真实SIGKILL，自动回C及DHCP/UDP/TCP通过。[回退](audits/full-20261014/SDK_FINAL_B587.md) |
| F4 APK未激活新ELF | procd跟踪配置和可执行文件内容；r4高于旧r2/r3。最终包14事务阶段与两套procd各8客户端阶段通过，安装数据库/磁盘/活进程一致。[包](audits/full-20261014/SDK_FINAL_B587.md) |
| F5 总线重启丢管理对象 | 精确双对象ACL、只读专用socket目录、空闲有界重试及100ms总重连预算。最终包文件下同PID自动恢复双对象；临时ACL/stalled注册和DHCP/DNS通过。[集成](audits/full-20261014/final-sdk-stack-ubus-review.md) |
| F7 体积解释错误/最终测量 | 用户已接受M5双产物并授权合理PIE取舍；旧1MB/700k不能再作为未获准硬阻断。最终ELF/APK比已接受M5增10.124%/8.425%，结合资源实测批准这份精确产物用于main合并。[预算](audits/full-20261014/release-budget-review.md) |
| F8 工具错误归属 | 删除硬编码旧提交，保留实际ELF/tool hash；最终协议检查器绑定显式ELF身份并拒绝错误身份 |
| F10 多PTR/轮转与相邻发布合同 | 多reverse-owner、真实共享hash顺序、bulk与增量lease上下文、配置改名后发布、初载HUP准入门及地址行重哈希。原缺名/查询诱发顺序/无限租约双别名/长行反例已固定；最终SDK13场景704观察通过精确合同检查。[协议](audits/full-20261014/final-sdk-protocol-review.md) |

F10没有无条件忽略PTR顺序：16条差异匹配实际C完整轨迹，28条符合主审逐一核验
匹配源码后批准的4个精确初态合同。配置/来源hash、问题、传输、阶段和完整查询
序列都固定，跨阶段拼接、缺名、TTL/count/TC/header和前向顺序仍拒绝。原失败及
原始有序wire保留；这是验证C真实合同，不是改变产品合同或用户兼容豁免。

## 最终组合验证

- 同源码Linux串行lib **808**、bin **81**、allocator **16**通过；23 ignored明确未跑。
  私有namespace/TMPDIR防止旧测试全局状态干扰，660源文件前后不变。
- 同SDK ELF协议368对，366字节一致；另2条C压缩循环与Rust合法答案保留。
  同ELF缓存110场景/337客户端观察/150上游报文通过，452比较器负控拒绝；C参考复用原留档。
- 实际包内init/ACL/ELF与Rust9：23管理+5helper通过；总线重启自动恢复且同PID；
  F5三项定向故障通过。包事务、回退、资源和F10分别绑定同ELF，不拼接不同候选计数。
- 所有新原始证据已回拷本机忽略的private目录并核SHA；旧失败与中间产物不覆盖。
  参考及测试器自身失败均保留，不计入通过。

## 合并与剩余部署边界

主审在独立集成工作树验证后，将main从 `6eedacbf` fast-forward到 `861782a8`，未push。
合并后核对产品/包输入与已测试b587完全一致；
用户原有10份prompts未提交文件按hash核对保留。退役任务分支删除前，以持久标签
保留完整tip与独有证据。本轮12个退役分支均已打archive标签后删除分支指针；
干净工作树在同一提交上保持detached，全部private材料保留。5个含未合入独有证据的
tip也已完整归档，见[分支归档清单](audits/full-20261014/branch-retirement.json)。

本轮没有修改物理路由器。**合并资格不等于已完成正式上线。** 真Wi-Fi客户端续租、
睡眠/漫游、设备重启/长期运行和当前现场恢复前置检查仍属于实际部署验收。ELF-only
trial保留stock init/ACL，不能继承完整r4包的总线恢复资格。

APK自身中途提取失败可能留下不完整数据库而旧进程仍活着，这是实测的共有执行面
边界；成功事务自动激活修复不使APK具备断电原子性。失败安装需按runbook恢复空间、
离线stock包及实际C/客户端身份核验。没有宣称任意配置、任意故障或未来运行“零bug”。
