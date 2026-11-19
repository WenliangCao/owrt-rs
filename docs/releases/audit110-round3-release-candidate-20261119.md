# audit110 round3 release candidate · 发版说明草稿 · 2026-11-19

**状态：`release_qualified=false`。尚不能根据本草稿推荐刷机，也没有发布固件或创建Release。** 正式v0.3.3配方A/A已通过；四方真机比较、最终组合CI和固件SHA256仍待主代理补证据。

本候选以v0.3.3（`1e25d61dc707833f97afa5a56148f4dbceb50ed3`）为行为基线，升级到Rust1.100.0与更新后的锁定依赖，保持OpenWrt内核、硬件驱动与执行面。最终产品为`1f9de983757880c14133998a5befcfdf1d4fafe5`；干净历史重组前后完整Git tree相同，components tree也与最终Oracle门禁受测树一致。动态CI、发布工件及四方结论仍由主代理续填。完整逐项台账见`docs/reviews/AUDIT110_ROUND3_20261119.{md,json}`。

拟交付内容：

- HTTP请求体及CGI遇到短暂I/O错误时保留处理状态；parked TLS不会因空readiness丢连接。兼容测试继续覆盖PATH_INFO。
- DNS修正fatal startup日志、local ownership、label内分隔符、non-QUERY回复策略、relay出接口选择及hostsdir推断刷新。配置CNAME缓存链、relay hostname及N1 stale过滤标记/N2 UDP DO修复均已集成，最终DNS内容组为`f3c98f1b`。
- netifd修复reload自启动、协议IP过期与inactive状态、typed UCI、设备消失和自管桥清理；补齐offlink失败恢复、IPv6 assignment路由所有权和class。无线非有限数据不再在teardown abort，编码遵循ucode；删除排队radio后仍执行旧setup再推进后继。
- odhcpd分离refresh与reply容量，并使混合/0、/32、/60来源产生全部有效PD前缀。C/base/fixed的前缀数为3/2/3；修复的合同是前缀、长度及寿命集合等价，**不承诺包字节或同preferred时的排列相等**。
- logd满环历史读取不再使Rust abort；正常stream、lines参数与后续恢复保持合同。**有意不仿造C被正文覆盖的损坏历史头，因此该损坏状态下默认history与C并不严格相等。**
- fw4、uci、procd与rpcd保留已有C合同测试；这些测试不是新增产品故障修复。唯一保留的性能改动是iwinfo重复查询去重及首次调用顺序修订，perf内容已归入`1f9de983`，新的真机验收数据待填。

本轮决策已收齐：39个候选提交均有盲审映射，其中25项最初只读源码、14项有有界执行；19项旧待定最终采纳/修订采纳4项、关闭其余15项，剩余0。9项任务均有处理；DNS TCP65536与重复DHCP选项未观察到用户规定的abort/非法发送条件，决定不修。RA零lifetime、-S docroot、HEAD错误正文、CLOEXEC/rpcd信号顺序和netifd强杀旧helper依既定取舍不做。

最终Oracle全部门禁已通过（Linux aarch64、Rust1.100）：`make test check-rust fmt-check check-benchmark check-toolchain check-toolchain-negative check-tools check-harnesses`。原组件证据包括netifd 193测试及36次namespace运行、DNS最终分片883通过和23 ignored、ring公共接口及PD解码对照。**23项ignored未执行；源码推导、组件门禁与整机验收分开记载。** N1/N2由`95ce2040`、`8a3f2390`修复，经`4fb8a8cf`集成并重组至DNS组`f3c98f1b`；两项新测试在前修订均失败、最终均通过。N1仅验证Stale owner边界，没有新增真实上游刷新实验。最终DNS报告HEAD`54740216`及net报告已原样保全到主证据`closeout/`；详见台账S09/S10/S25/S26。

最新交接确认：tmpcanonical generator `44603802652`和transport assembly `44607652850`成功，11场景/50份raw profile，合并SHA256为`f6a8dfed8230a70522d22ba2a3c38a2404c97c24b6d38a97bac7fa13037bbed1`；use `44607990145`已成功，产物SHA256为`f6bd7dc0906a61a44ab82dd1cf5e91a168b41cd3db02ea9b7c69bc68718a6c53`，大小2321243 bytes，无profile mismatch或编译warning。v0.3.3 core `44601798412`的host/target通过；私有DNS/DHCP6（6个DHCPv4客户端）冒烟通过、身份健康一致（`device/smoke/COMPLETE`）。profile与use产物摘要均不是最终固件SHA256。这些是主代理报告的已有结果，本草稿未轮询或重跑。

**正式配方A/A通过。** `device/aa-result.json`记录3组45窗，CPU、latency、throughput、RSS、anon及idle的全部已测区间重叠；低负载DNS、饱和DNS、DHCP6（6个DHCPv4客户端）的CPU中位数差分别为 **+0.592%、+1.944%、−4.034%**。主代理报告生产身份与健康一致。此结果完成A/A基线校验；工具链only与最终candidate的四方比较仍待补。证据及内容摘要见台账S23/S24。

扩展smoke的iwinfo、uci-memory、fw4-memory、reload-config-memory、odhcpd共5项全部通过（`device/extensions/smoke/COMPLETE`），生产身份与客户端健康未变。**DHCP6表示6个DHCPv4客户端，不是DHCPv6。** smoke不替代待补的四方数值。

兼容和成本边界：ring损坏历史、PD等优先级排序有上述明确差异；netifd部分base既有typed/设备设置差异与DNS继承的负缓存filter差异未扩修。Round2已知typed约+8KiB和小idle成本由本轮最终真机比较裁决；不把旧性能结果写成本候选的新收益，也不宣称尚未测量的内存或CPU无退步。

| 发布身份或验收 | 待填值 |
| --- | --- |
| 最终product commit / CI分支同tip | product=`1f9de983757880c14133998a5befcfdf1d4fafe5`；CI绑定待填 |
| v0.3.3正式配方A/A结果及噪声区间 | **passed**；3组45窗所有已测区间重叠，见台账S23 |
| 工具链only与最终版各自PGO manifest | `null` |
| 四方真机memory、idle CPU、性能比较 | `null` |
| 每binary体积及reload-config ≤512KiB结果 | `null` |
| 最终五workflow运行与结果 | `null` |
| 正式CI固件artifact与SHA256 | `null` |
| 路由器前后身份和健康验收 | `null` |

DNS后续意见已闭环，产品身份已确定；主代理补齐四方、动态CI与固件等剩余证据后，才能将`release_qualified`改为true。草稿没有授权刷机、替换生产服务、改持久配置、打标签或发布Release。
