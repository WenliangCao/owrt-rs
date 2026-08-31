# AX3000T stock / OpenWrt 25.12.5：I0 最终报告

> 阶段：I0.1 – I0.8 完成
> 日期：2026-08-31
> I0 gate：**通过**（范围见 §6）
> 实现授权：**无**

## 1. I0 做了什么

I0 的任务是把"这台设备上的控制平面到底是什么"变成可复核的证据，而不是设计方案。
八个子阶段依次固定了：部署身份 → 匹配源码 → 镜像验证 → 物料与归属 →
启动/服务/配置/IPC 链 → 候选职责与运行态问题 → 只读运行态观察 → 替换边界。

结论是 17 项控制面职责的分类，其中 **10 项停在默认类**（保留或禁止触碰），
4 项延后，只有 3 项进入 Rust 工作范围。

## 2. 部署规格（已独立复核）

| 项 | 值 |
|---|---|
| 设备 | Xiaomi Mi Router AX3000T（`xiaomi,mi-router-ax3000t`，stock 布局） |
| 发布 | OpenWrt 25.12.5 `r33051-f5dae5ece4` |
| target | `mediatek/filogic`，`aarch64_cortex-a53`，kernel 6.12.94 |
| rootfs | SquashFS |
| 镜像 | 官方 `sysupgrade.bin`，SHA-256 `a94ac2c7…9eea`，签名链已验证 |
| 排除 | `-ubootmod` profile 与 `.itb` 镜像 |
| 设备实测 | 与上述逐字段一致（I0.7 Q00） |

用户初报的 25.12.4 经实测澄清为滞后信息，记录为"同一设备的两个时间点"，
不构成证据冲突。

## 3. 证据规模

| 阶段 | 产出 |
|---|---|
| I0.2 | 6 个 repository 固定 revision；14 个组件 checkout |
| I0.3 | 全字节、FIT/DTB、SquashFS、文件属性与偏差验证 |
| I0.4 | 159 packages → 75 recipe origin；全文件/ELF/service 归属；313 个 patch 资产 |
| I0.5 | 启动链、25 个 init 脚本、配置生成链、两层 ubus ACL |
| I0.6 | 17 项职责、15 个运行态问题、23 条已批准命令、11 条排除命令 |
| I0.7 | 40 个 ubus 对象、19 个 procd 服务、包/配置偏移、特权实测 |
| I0.8 + follow-up | 五类分类、7 个开放问题、2 个本次关闭问题、7 条风险 |

## 4. 最重要的十条部署事实

1. `/etc/init.d/rcS` **不存在于镜像**。inittab 的 `sysinit` 由 procd 内建 `rcS()` 处理，
   argv[0] 的路径字符串从不被执行。
2. `network`、`system`、`wireless`、`board.json` **都不随镜像发布**，在首次启动生成。
   镜像里的 `/etc/config/` 不是设备上的配置。
3. 25 个 init 脚本 = 13 长驻 procd + 5 一次性 procd + 7 非 procd；另有 1 个
   **没有 init 脚本的 procd 服务**（`ubus`，由 `service_start_early` 注册）。
4. 只有 8 个服务实现 `reload_service`；其余 `reload` 退化为重新提交服务定义。
   **`reload` 没有统一语义。**
5. ubus 有两层独立 ACL（ubusd 按 unix 用户、rpcd 按会话组），socket 本身是 0666，
   **文件权限不构成访问控制**。
6. 两层 ACL 都授权了不存在的对象（`udebug`、`dsl`、`fingerprint`）。
   **ACL 是意图声明，不是接口清单。**
7. 三个方法在源码方法表里但不在本 build 里（`dhcp.ipv4leases`、
   `network.device.hotplug_event`、`dnsmasq.set_connmark_allowlist`）。
   **方法级 build gating 必须回到 recipe 读。**
8. `/usr/share/ucitrack/*.json` 是 LuCI 的意图声明，不是本部署的实际 trigger 集合：
   procd 服务的 `init` 字段不注册，`affects` 指向未安装包仍注册且无订阅者。
9. **声明 jail ≠ 获得 namespace 隔离。** wpad 声明了 `procd_add_jail` 却没有任何
   namespace，因为调用只传了名字、没有 flag 也没有 mount。
10. kernel command line 不含 `rootfs_mount_options.*`，I0.5 标记的 rootfs 挂载风险
    在本设备上确认无影响。

## 5. 分类结果

| 类别 | 数量 | 职责 |
|---|---:|---|
| 保留 | 5 | R02、R06、R10、R11、R16 |
| 禁止触碰 | 5 | R01、R03、R08、R12、R17 |
| 延后评估 | 4 | R04、R07、R09、R14 |
| Rust 接入或包装 | 2 | R13 rpcd、R15 logd |
| 优先用 Rust 替换 | 1 | R05 配置变更检测与分发 |

理由与证据引用见 [REPLACEMENT_BOUNDARY.md](REPLACEMENT_BOUNDARY.md)。

唯一的替换候选 R05 之所以入选，不是因为"可以用 Rust 写"，而是四个条件同时成立：
静态接口面窄、运行态基线与 trigger 注册已观察、失败是静默的、无持久副作用、恢复代价
为零。事件投递的主动 oracle 尚未完成，由 RK-01 明确阻塞 C1 合同冻结。

## 6. I0 完成定义逐条核对

| 项 | 状态 | 证据 |
|---|---|---|
| 镜像身份和来源可独立复核 | 满足 | IMAGE_IDENTITY.md；签名 `sha256sums`、`profiles.json`、buildinfo；Q00 证明设备运行的正是它 |
| 容器、payload、rootfs 和分区预期已解释 | 满足 | DEPLOYMENT_VERIFICATION.md、PARTITION_EXPECTATION.md、SOURCE_IMAGE_DEVIATIONS.md |
| 软件物料和文件归属完整 | 满足 | SBOM.md、FILE_OWNERSHIP.md；Q14 显示设备偏移仅 +4 个翻译包 |
| 启动、服务、配置和 IPC 链已成图 | 满足 | 四份链路报告；两处静态漏报已按方法修复并重新验证 |
| 关键组件均有精确源码映射或明确阻塞 | 满足 | SOURCE_MAP.md、PATCH_MAP.md；14 个固定 checkout + 校验通过的 dnsmasq 源码包 |
| 每个候选都有接口、调用者、失败边界和兼容要求 | 满足 | RESPONSIBILITY_CANDIDATES.md，17 项全模板 |
| 关键行为取得必要运行态证据 | 满足 | I0.7 强制身份门与 23/23 采集验收；follow-up 关闭 OQ-01、OQ-07 |
| 事实、推断、未知和冲突分离 | 满足 | 每份报告都有证据边界章节；未知集中在 OPEN_QUESTIONS.md |
| 原始材料和秘密未进入 Git | 满足 | 固件、解包树、源码 checkout、原始采集输出全部在 Git 之外；脱敏自检 0 命中 |
| 未接触物理机持久状态 | 满足 | I0.7 只执行只读命令；无 UCI 写、无 commit、无 reload、无重启、无 MTD 读 |

**gate 通过的范围限定**：本 gate 针对**这一个镜像、这一台设备、这一种配置**通过。
follow-up 已关闭 OQ-01（rcS 顺序与失败传播）和 OQ-07（配置漂移）。真实逐项启动耗时
另列为不阻塞职责的 OQ-09；任何分类仍不构成实现授权。

## 7. I0 内的两次自我修正与 follow-up 审查

I0 期间有两处结论被后续证据推翻，都已按方法修复而非个案打补丁：

1. **"字节缺失即方法不存在"判据被废弃。** 中间稿用部署二进制里方法名字面量的缺失
   判定方法不存在，产出 12 条"缺失"。运行态证明**全部是假阳性**——链接器合并字符串
   常量，短名作为更长字符串的尾部存放。改为只报正向证据，build gating 结论改依据
   recipe 条件，被运行态全部证实。
2. **源码解析必须覆盖 patch stack，服务枚举必须覆盖 procd 内部注册。**
   I0.7 发现两处漏报：`dnsmasq.dns` 只存在于 OpenWrt 补丁中，`ubus` 服务没有 init
   脚本。两者都是方法缺陷。修复后重新核对，40 个运行态对象**零未预测、零过预测**，
   目录与运行态双向闭合。

后续独立审查又发现并修复两处验收缺口：I0.7 原生成器未强制消费全部采集、也未执行
身份门；I0.8 的 checklist 原为预填 `True`。现在 I0.7 会拒绝缺文件、异常退出和身份不符，
I0.8 的 machine-checkable 项从实际 manifest 推导，人工/commit-time attestation 单独标注。
详见 [I0_FOLLOWUP_REVIEW.md](I0_FOLLOWUP_REVIEW.md)。

## 8. 下一步

I0 完成不等于可以开始实现。按计划：

1. **C1**：为 R05 冻结第一个兼容合同和参考 oracle。OQ-07 已完成，本设备可在固定当前
   配置与完整文件集的前提下作为 oracle。剩余前置条件是 RK-01——先让"变更已送达"可观测。
2. **R1**：C1 冻结后才实现第一个最小 Rust 切片。
3. 在 C1 通过之前**不创建任何替代组件 crate**。

未解问题见 [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md)，风险见
[RISK_REGISTER.md](RISK_REGISTER.md)。
