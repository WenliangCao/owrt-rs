# AX3000T stock / OpenWrt 25.12.5：替换边界

> I0.8 状态：完成
> 日期：2026-08-31
> 实现授权：**无**。本报告不授权创建任何替代组件 crate。

## 1. 分类规则

每项职责只能进入五类之一，**默认是保留或延后**。离开默认类必须同时给出书面理由和
DEP、SRC、RUN 三类证据引用；`禁止触碰`还必须写明恢复约束；有未解阻塞问题的职责
**不得**进入`优先用 Rust 替换`。

这些分类不变量由 [i0_8_boundary.py](../../tools/i0_8_boundary.py) 强制，违反即生成失败。
follow-up 后，十项 I0 gate 中七项直接由 manifest 推导；报告分层、原始材料不入 Git和
设备无写入三项分别明确标为“manifest + 人工审查”“commit-time scan”“collector attestation”，
不再伪装成纯自动证明。
机器记录见
[replacement-boundary.json](../../manifests/ax3000t-stock-openwrt-25.12.5/replacement-boundary.json)。

## 2. 分类结果

| 类别 | 数量 | 职责 |
|---|---:|---|
| 保留 | 5 | R02 init 框架、R06 首启配置生成、R10 dnsmasq、R11 odhcpd/odhcp6c、R16 hotplug 分发 |
| 禁止触碰 | 5 | R01 procd、R03 启动编排、R08 无线、R12 ubusd、R17 升级/重启 |
| 延后评估 | 4 | R04 UCI、R07 netifd、R09 firewall4、R14 uhttpd |
| Rust 接入或包装 | 2 | R13 rpcd、R15 logd |
| 优先用 Rust 替换 | **1** | R05 配置变更检测与分发 |

17 项中 10 项停在默认类。只有 3 项进入 Rust 工作范围，其中只有 1 项是完整替换。

## 3. 唯一的替换候选：R05

**`/sbin/reload_config` —— 配置变更检测与分发。**

| 维度 | 内容 |
|---|---|
| 现状 | `procd` package 安装的 17 行 shell；base-files 的 boot 调用点注释称其为 `temporary hack until configd exists` |
| 合同 | 对每个 config 包比较规范化 `uci show` 输出与 `/var/run/config.md5` 基线，对每个不一致的包发一条 `config.change` 事件 |
| 失败模式 | **静默**。漏发事件不报错，服务继续用旧配置运行 |
| 持久副作用 | 仅 tmpfs 中可重建的基线文件 |
| 恢复 | 删除基线文件即可重建；错误版本不会留下不可逆状态 |
| DEP | `/sbin/reload_config` 全文已读 |
| SRC | procd package install recipe；base-files boot 调用点注释 |
| RUN | Q12 观察到基线及其跟踪的包列表；Q06 观察到消费方服务上的 config.change trigger |

选它不是因为"可以用 Rust 写"，而是因为四个条件同时成立：静态接口面窄、运行态基线与
trigger 注册已观察、
失败是静默的（正是类型化实现能消除的缺陷类）、无持久副作用、恢复代价为零。

**先决条件**：替换实现必须先让"变更已送达"可观测，再改变检测方式。见
[RISK_REGISTER.md](RISK_REGISTER.md) RK-01。事件投递本身尚未被主动触发验证，不能称为
“合同已完整观察”；这正是 C1 oracle 要补的部分。

## 4. 两项包装候选

### R13 rpcd —— 包装 ACL 与会话判定，不替换对象族

rpcd 是远程管理边界，经 `file.exec` 与 `rc.init` 等价于远程代码执行。它的 ACL 是
**按方法**的，会话语义可观察。有价值的第一步不是替换它，而是在 ACL 与会话判定处放一层
类型化的 Rust，使错误可被约束和审计。

完整替换需要复刻 9 个对象族，LuCI 按精确字段名依赖它们——那是 C1 之后的问题。

### R15 logd —— 最低风险的端到端契约验证场

logd 只有两个方法，失败仅影响可观测性。它是把「ubus 对象注册 + ubusd ACL + procd
instance」三条契约端到端跑通的最低风险场所。

选包装而非替换的理由：环形缓冲区没有保留启动记录，默认 procd 又不输出逐项 duration
（见 RK-07、OQ-09），
重写不应以改变保留语义开场。

## 5. 五项禁止触碰及其恢复约束

| 职责 | 恢复约束 |
|---|---|
| R01 procd | PID 1，无带内恢复，只能 bootloader 或断电 |
| R03 启动编排 | 只能 failsafe 或 TFTP/bootloader，需要物理接触 |
| R08 无线 | 无线故障会切断纯无线客户端的唯一管理路径 |
| R12 ubusd | 重启一次性丢失全部 40 个已注册对象，恢复取决于每个 daemon 自行重连 |
| R17 升级/重启 | 刷写失败需 bootloader 恢复与物理接触 |

R12 还有一条顺序性理由：**在任何客户端被替换之前替换总线，会颠倒依赖顺序。**

## 6. 四项延后及其阻塞问题

| 职责 | 阻塞问题 | 为什么现在不能定级 |
|---|---|---|
| R04 UCI | OQ-04、OQ-05 | 约束条件是未建模字段的保留和三类写入方的并发窗口，两者都不能被动观察 |
| R07 netifd | OQ-06 | rcS 顺序与失败传播已关闭；剩余阻塞是 proto handler 与 wireless notify 契约从未被执行 |
| R09 firewall4 | OQ-02 | 兼容合同是生成的 ruleset，尚无差分比较 |
| R14 uhttpd | OQ-03 | 以 root 运行且终结 TLS，是可信的 Rust 目标，但 LuCI 耦合路径未被执行 |

R09 值得单独说明：它已经是 ucode 而非 C、一次性执行、输出可完整 diff，
**是四项里最容易升级的**。只差一个差分测试。

## 7. 本次没有做的事

- 没有排名"最想重写"；分类依据是证据完整度与风险，不是偏好。
- 没有为任何职责创建 crate、目录或接口草稿。
- 没有把"可以用 Rust 写"当作任何一条分类的理由。
