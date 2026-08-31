# AX3000T stock / OpenWrt 25.12.5：I0 follow-up 与 I0.5–I0.8 审查

> 日期：2026-08-31
> 结论：OQ-01、OQ-07 已关闭；I0 gate 在原范围内继续通过
> 设备操作：仅经授权的只读 SSH；无 UCI 写、commit、reload、restart、reboot 或 MTD/UBI 读取

机器记录见
[i0-followup-review.json](../../manifests/ax3000t-stock-openwrt-25.12.5/i0-followup-review.json)。
原始配置只保存在 Git 之外的私有 evidence 目录；本报告不含地址、MAC、SSID、密钥、
策略值或会话标识。

## 1. OQ-01：关闭

原问题把“顺序、耗时、失败传播”合成了一项，并认为必须观察真实启动才能回答。精确
procd `58eb263d…` 与 libubox `7dd12784…` 源码证明其中两部分并非运行态未知：

| 子问题 | 结论 | 证据 |
|---|---|---|
| rcS 顺序 | `q.max_running_tasks = 1`；全部 `/etc/rc.d/S*` 按 glob 插入顺序严格串行 | `procd/rcS.c:200-206`；`libubox/runqueue.c:37-60` |
| 普通脚本失败 | child exit status 未被 runqueue callback 使用；任务完成后下一项继续 | `runqueue.c:237-243` |
| `exec` 失败 | child exit 1，随后按普通脚本失败处理，继续队列 | `procd/rcS.c:108-109` |
| pipe/fork 失败 | 在 child 注册前直接返回，活动任务无完成路径，rcS 队列停住 | `procd/rcS.c:78-95` |
| start timeout | 无；15 秒 run timeout 与 10 秒 cancel timeout 只用于 `stop`/`shutdown` | `procd/rcS.c:163-166` |
| 精确耗时 | 仍未观察；duration 用 `CLOCK_MONOTONIC_RAW` 算，但日志受 `DEBUG(2)` 保护 | `procd/rcS.c:78,117-125`；`log.h:20-23` |

设备复核显示 PID 1 只是 `/sbin/procd`，没有 `-d`，环境中也没有 `DBGLVL`，保留日志中
不存在 rcS start/stop debug 行；设备 uptime 约 29 天，pstore 为空。因此“普通重启后再读
logread”也不能得到逐项 duration。顺序与失败传播已关闭 OQ-01；真实逐项耗时拆为不阻塞
任何当前职责的 OQ-09，只能由串口或经单独授权的 instrumented lab boot 回答。

这也修正了 [BOOT_CHAIN.md](BOOT_CHAIN.md) 先前“同编号可能并发”的错误边界。OQ-01 不再
阻塞 R07；R07 只剩 OQ-06。

## 2. OQ-07：关闭

审查把当前 `dhcp`、`firewall`、三份 DHCP 历史备份和两份 dnsproxy 残留读入私有目录，
按 UCI AST 做脱敏语义比较；同时只读取运行态布尔值与计数确认配置是否真的生效。

### DHCP 与旧 DNS 修改

- 当前 DHCP AST **完全等价于镜像配置加 `/etc/uci-defaults/15_odhcpd` 的预期首启变换**。
- 旧 `disable-ipv6` 与 `nextdns-doq` 备份的 AST 都与当前 DHCP 相同；备份名字本身不能证明
  当前仍禁用 IPv6或仍走 NextDNS。
- rollback 备份曾包含 `noresolv` 与自定义 `server`；当前两项均不存在，resolver 已回到
  镜像预期的 `resolv.conf.auto` 路径。
- 当前没有 dnsproxy 主配置、没有 dnsproxy/https-dns-proxy 进程；两份历史 dnsproxy 文件
  字节相同，只是未清理的备份。

结论：旧 DNS override **不再 load-bearing**。

### Firewall

去除注释、排版与引号差异后，当前 firewall 相对镜像只有两个新增 option：

- `flow_offloading = 1`；
- `flow_offloading_hw = 0`。

`fw4 print` 能生成 flowtable，当前 nftables ruleset 也确实有活动 flowtable。因此软件
flow offloading 是真实生效的设备特定输入；硬件 offloading 未启用。

### 对 R05 oracle 的影响

本设备现在可以作为 C1 oracle，但必须固定：

1. 经审查的**当前**配置，而不是 SquashFS 里的默认配置；
2. 完整的 `/etc/config` 文件集合，包括那些对 dnsmasq/fw4 已惰性、却仍被
   `reload_config` 全文件扫描纳入 `config.md5` 的备份文件。

历史操作者无法从现存元数据完全重建，但操作者身份不属于 R05 的输入/输出合同，不再是
oracle 阻塞项。

## 3. I0.5–I0.8 审查结果

### I0.5

结论：**通过，带一项已修正的边界错误。** 四份 manifest 在精确 rootfs 与 pinned source
上重新生成，除本次新增的 `rcS_scheduling` 外均与提交结果逐字节一致。patch stack 与
procd 内部服务枚举两项自我修正是正确的：运行态 40 个对象仍为零漏报/零过预测，`ubus`
服务来源也准确。

修正项：原报告没有把 `rcS.c` 的 `max_running_tasks = 1` 与 libubox runqueue 合并推理，
误把并发/完成顺序列为未知。现已把串行、退出状态和底层失败语义写入机器 manifest。

保留边界：I0.5 提取的是对象/方法名，不是完整 blobmsg schema；报告已明确把逐方法字段与
类型留给 C1，因此不构成虚假完成声明。

### I0.6

结论：**通过，两个记录缺陷已修正。** 17 项职责与全部引用仍通过 manifest 交叉检查。
实际规模是 15 个问题、23 条批准命令、11 条排除命令；执行计划里残留的 13/19 已更正。
Q10 的 `ubus Not found` 合法退出码是 4，原问题表只写 expected 0；现改为允许 0/4，避免
把“对象不存在”这个有效答案误报为采集失败。原始采集 header 还暴露出 Q06 的 shell
引号、Q11 的 `cat | grep`/`grep file` 和 Q12 的分隔行与声明文本不同；三者均为只读且
语义等价，但机器清单现已回填实际执行文本，不再掩盖这类漂移。

### I0.7

结论：**事实结论继续成立，但原生成器的验收不够强，现已修复。** 原工具只解析部分 raw
文件，未强制 23 个采集文件齐全，也没有把 Q00 身份门写成失败条件；因此缺文件或换一台
设备仍可能生成 `status: complete`。修复后生成器会：

- 强制 23/23 文件名、collector header/footer、header 命令逐字匹配与允许退出码；
- 对 release、revision、target、board、kernel、rootfs 做精确身份比较；
- 要求 `ubus list` 与 `ubus -v list` 的对象集合相同；
- 把 Q07/Q08/Q12/Q13 派生为仅含计数/布尔值的 network、firewall、baseline、HTTP/RPC 记录；
- 保留 `ubus -v` 的参数类型映射，不再只留下参数名；
- 继续执行脱敏自检，且不复制原始地址、rules、password 或配置路径列表。

用原始 evidence 重跑后：身份门、23/23 完整性、退出码与脱敏检查全部通过；40 个 ubus
对象、19 个服务、包偏移和 privilege 结论不变。结构化规则集实际为 1 个 table、28 个
chain、1 个 flowtable；I0.8 中旧的“24 chains”手工数字已更正。

### I0.8

结论：**分类结果保留，gate 实现已修正。** 五类 17 项分类仍一致；R05 仍是唯一优先完整
替换候选，但措辞从“合同已完整观察”收紧为“静态接口面、基线与 trigger 注册已观察”，
事件投递本身仍由 RK-01 阻塞。

原 `I0_CHECKLIST` 把十项状态直接写成常量 `True`；这只能生成一份声明，不能作为 gate。
现工具实际加载 I0.2–I0.7 与 follow-up manifests，强制 stage/status/evidence identity、
17 项模板、23/23 collector、身份门、IPC 双向闭合及 OQ-01/OQ-07 关闭状态。七项可由
manifest 推导；另外三项明确保留验证类型：

| 项 | 验证类型 |
|---|---|
| 事实/推断/未知分层 | manifest 不变量 + 人工报告审查 |
| 原始材料/秘密不入 Git | redaction assertion + commit-time repository scan |
| 设备无持久写入 | collector attestation |

DEP/SRC/RUN 仍是人工撰写的证据引用字符串，不是可自动解引用的 typed reference；本阶段
没有为此引入复杂 schema。生成器现在不再声称它能自动证明这部分。

## 4. 最终判定

- OQ-01：**关闭**；剩余非阻塞 OQ-09。
- OQ-07：**关闭**；设备可作为固定当前配置的 C1 oracle。
- I0.5–I0.8：**审查通过，发现的问题均已修正或明确降格为人工 attestation。**
- I0 gate：仍针对**这一镜像、这一设备、这一配置**通过，不外推到其他配置或故障态。
- 下一步：C1/R05；唯一剩余前置是 RK-01。C1 通过前仍不创建替代组件 crate。
