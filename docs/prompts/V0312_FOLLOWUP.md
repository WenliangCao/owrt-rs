# 追加任务：并入同一版本的三组修复（接在 AN8855 DTB 任务之后）

你正在做 `docs/prompts/AN8855_DTB_TRIM.md`。**先把那个任务做完（含离线资格），再开始这里的任务。**
这里的所有修改和 DTB 改动合并成同一个版本发布，然后只刷一次机。

**版本号**：用户说的是"3.1.2"。现有版本号是 v0.3.0 / v0.3.1，"3.1.2"不符合这个格式，
可能指 v0.3.2，也可能是别的意思。请在打标签前停下来问用户，不要自己决定。

规则不变：先读 `AGENTS.md`，Mac 上不构建；每个修复都要有"修复前失败、修复后通过"的红绿对照，
差分测试以 C 原版为准，红的结果至少重跑 3–4 次再下结论；每完成一项单独提交，按路径 stage；
刷机前必须得到用户在对话里的明确同意；不要读 `/proc/kmsg`。

## 1. 串口内核日志级别

- 证据（2026-10-19 真机 dmesg）：
  - 小米 U-Boot 传入 `loglevel=8`，`/proc/cmdline` 为
    `console=ttyS0,115200n1 loglevel=8 swiotlb=512 rootfstype=squashfs firmware=0 mtd=ubi uart_en=1`。
  - `printk: legacy console [ttyS0] enabled` 出现在 0.142 s，`random: crng init done` 在 0.919 s。
  - 控制台启用前已积攒 8560 字节日志，按 115200 波特率（约 11.5 KB/s）打印需要约 0.74 s，
    与观察到的 0.78 s 空档吻合。这个数是推算的，还没实测。
- 改法：在 AN8855 那份 DTB 补丁里再加 `/chosen` 下的 `bootargs-append = "loglevel=4"`。
  - 内核已经支持这个属性：`target/linux/generic/hack-6.12/920-device_tree_cmdline.patch`。
  - 只追加参数，U-Boot 原有参数（包括 preinit 会读取的那些）一律不动。
  - 不要用 `bootargs-override`：它会把 U-Boot 传入的 `firmware=` / `mtd=` 写死。
  - 先在离线 DTB 上用 fdtget 确认属性已加入；再从内核源码确认，当命令行里出现两个
    `loglevel=` 时，以后出现的那个为准。
- 用户态部分：设备上 `system.@system[0].conloglevel='8'`。procd 启动后会按这个值重设控制台级别。
  先查清这个 8 来自哪里（stock 默认、config_generate，还是之前的操作），再用最小方式改成与内核一致，
  并说明理由。改动必须在保配置 sysupgrade 后仍然生效。
- 验收：两次启动后 `/proc/cmdline` 末尾都有 `loglevel=4`；`dmesg` 内容完整，没有减少；
  对比 0.142 s 到下一条内核消息的间隔、以及 `DSA: tree 0 setup` 的时间点，报告实测差值。

## 2. 日志缓冲区太小

- 证据：`log_size='128'`（KiB）。上游抖动的噪声约每分钟 6 行，2.4 小时就把缓冲区写满。
  今天 v0.3.1 的开机日志已经被覆盖；`docs/reviews/DHCP_EVENT_BOOT_20261017.md` 也因为
  "开机窗口缺失"没能下结论。
- 目标：缓冲区在当前噪声水平下至少能保留 24 小时，包括开机窗口。按现在的速率估算，1024 KiB
  大约够 25 小时。请先实测每小时写入的字节数，再定具体数值。
- 要求：
  - 在 oracle 上用这个数值确认 logd-rs 的内存占用、`logread` 全量读取的耗时和正确性，并和 C logd
    在同一数值下对比。
  - 改动必须在保配置 sysupgrade 后生效，而且不覆盖用户以后手动改过的值。比如只在值仍是 128 时才改，
    方式自选，但要写明理由。
  - 不要通过删日志、改日志级别来"省空间"。噪声的来源另行处理，不在这次范围内。
- 验收：刷机后 `logread` 能看到完整的开机过程；记录 logd 的 RSS。

## 3. 独立审查中还没修的问题

来源：`docs/reviews/V030_INDEPENDENT_REVIEW.md`。下面这些都只在 oracle 上复现过，真机上没有自然出现过。
用户要求把它们一并修掉。

| 项 | 位置 | 要求 |
|---|---|---|
| F23 dnsmasq 半边监听不恢复 | dnsmasq/main.rs:1753–1837，修复 `ee3596ee` | 修复已在主线，需要重走 dnsmasq PGO 插桩、训练、冻结流程，产生新的冻结身份。冻结身份门本身不能放松；v0.3.0 的 ELF 不再沿用。 |
| F25 dnsmasq helper 积压无上界 | dnsmasq/dhcp/lease.rs:128–137、dhcp/daemon.rs:2548 | 先读 C dnsmasq 在同一场景下的行为，再定一个有上界的投递策略。不改脚本超时的约定，不静默丢弃事件。和 F23 放在同一次 PGO 冻结里。 |
| P2 netifd reload igmp_snooping | 见审查表 | reload 后内核里的桥属性要和 C 一致更新，并补进 green-all。 |
| P2 fw4 锁文件打开失败 | fw4 lib.rs:36–46 | 行为对齐 C：打不开锁就退出 1，不执行 nft。 |
| P2 uci reorder 超大数值 | 见审查表 | 对齐 C 的 strtoul 饱和语义。 |
| P2 logd ID 回绕 | logd ring.rs:173–181 | 回绕窗口内不丢历史列表，按 C 的行为修。 |
| P2 odhcpd DNS 选项过长 | odhcpd dhcpv6.rs:75 | 对齐 C：超长时截断或拒绝，不能产生 wire length=0 的包。 |
| P2 ubus 深嵌套 | ubus convert.rs:31–48 | C 在这里也会崩。修成有深度上限、正常报错，不 abort；在报告里说明这一点和 C 不同。 |
| P2 platform GSTRINGS 长度 | netifd.rs:123–140 | 按内核实际返回的长度做校验。 |
| P2 静态发现（procd / netifd / rpcd 各条） | 审查表"静态"各行 | 先在 oracle 上逐条复现。复现出来的就修并补测试；复现不出来的，在报告里列明"未复现、未修改"，不要凭推测改代码。 |

不在范围内：F24（卸载原生包的操作边界，只写文档）、P3 各条、legacy 打包工具，以及防火墙随 wan6
频繁重载的问题（需要单独调查）。

## 发布与刷机

1. 全部修复合入主线后，`ci`、`core-safe-check`、`dnsmasq-target-check` 以及新 PGO 冻结的身份门全部通过；
   在 oracle 上重跑全部组件测试，并做两次 release-image 运行确认逐字节可复现。
2. 精确镜像的离线资格检查与 v0.3.1 相同（`native_boot_check`、`native_image_check`、APK、
   守卫、回滚配置包），另加 DTB 两处改动的核对：`switch@1f` 为 disabled，`/chosen` 下有 `bootargs-append`。
3. 刷机流程同 v0.3.1：刷前完整备份，回滚目标为 v0.3.1 镜像 `099db992…`，守卫开启，
   客户端连续健康约 3 分钟后确认，再由用户物理断电重启一次。核对设备是 AN8855 硬件。
   分离运行不要用会自动重启的 launchd 任务。
4. 验收报告写入 `docs/reviews/`，内容包括：两次启动的开机时间线实测（MT7531 等待是否消失、
   串口空档、DSA 和 WAN 起来的时间点）、`logread` 的开机覆盖情况、logd RSS，以及每项修复的
   红绿证据路径。只报告实测数据，不写估算。
