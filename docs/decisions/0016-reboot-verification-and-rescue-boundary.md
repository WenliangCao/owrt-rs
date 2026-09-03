# 0016：允许一次受控重启以验证开机路径；救援边界重划（部分撤销 0006）

> 日期：2026-09-03。状态：采纳。第三轮第 1 项。

## 背景

阶段 1–8 的六个 Rust 组件（uci-rs、reload_config_rs、logd-rs、httpd-rs、fw4-rs、rpcd-rs）在设备上
均以"开机接管"（boot-enable on）形态运行，但决策 0006 禁止为本项目重启，因此开机路径从未执行过。
设备当前 uptime 33 天；所有 boot-enable 开关都是在这次开机之后打开的。这是 REPORT_ROUND2 §4 列出
的最大未验证项。

2026-09-03 用户明确表示：可用网线把路由器 LAN 口接到电脑（SSH 断了仍可到达）；接受"系统玩崩"的
后果，只要求有完整备份和能救回来的机制；ubusd 排在最后。用户同时要求"一万分把握"——本决策如实
回答：不能承诺 100%，能做到的是把每一步失败面压到有备用路径，并把剩余风险写清楚。

## 设备事实（2026-09-03 只读核实）

1. **bootloader 是原厂小米 U-Boot**（board `xiaomi,mi-router-ax3000t`，非 ubootmod）。OpenWrt 的
   `ubi_kernel`（mtd8，34 MiB）+ `ubi`（mtd9，78 MiB）布局吞掉了两个固件槽位；槽位 1 里没有可启动固件。
2. **选槽逻辑**（论坛公开的 bootloader 反汇编，与设备行为一致）：`flag_ota_reboot=0` 时，
   `boot_fw_num = flag_last_success` 的反面当且仅当对应槽位的失败计数 `>5`。本机
   `flag_last_success=1`、`flag_try_sys2_failed=8`（>5，槽位 1 判失败）→ 每次都启动槽位 0。
   `flag_try_sys1_failed`（当前 22）每次开机 +1，**不参与判断**；本机已这样开机 14 次（8→22）。
   OpenWrt 的 `/etc/init.d/bootcount` 对 `flag_try_sys2_failed=8` 的机型直接退出，不改任何值。
   因此重启不可能因计数切到空槽位；开机失败循环也不会。
3. **failsafe 路径完整**：`/lib/preinit/30_failsafe_wait`（4 秒窗口）、`hotplug-preinit.json` 把
   preinit 期间任何按键交给 `/etc/rc.button/failsafe`；`05_set_preinit_iface` 对本机型只拉起 `lan4`，
   地址 192.168.1.1；failsafe 不挂载 overlay，本项目所有改动（都在 `/overlay/upper`）全部不生效。
4. **按键语义**：reset（KEY_RESTART）正常运行时短按=重启、长按 ≥5 秒=恢复出厂（`factoryreset -y`）；
   开机时按住 reset 触发小米 TFTP 救援。mesh 键（code 0x109）正常运行时无处理脚本、无副作用，
   preinit 期间同样触发 failsafe——**进入 failsafe 用 mesh 键**。
5. **LED**：boot/failsafe/upgrade 别名都指向黄色状态灯，running 指向蓝色；正常启动黄灯闪、
   `done` 后转蓝；failsafe 为黄灯更快闪烁。
6. **开机时依赖 uci-rs 的脚本**：cron、dnsmasq、dropbear、led、system、sysntpd、ubihealthd、
   owrt-\* 等 15 个 init 脚本经 `config_load` 调用 `/sbin/uci -S -n export`。2026-09-03 在设备上用
   `/rom/sbin/uci` 与 uci-rs 对 19 个包逐一比较 export/show/get：全部相同（含全量 export 哈希）。
   uci-rs 的 S00 开关若门禁失败则不挂载，回到原二进制。
7. 开机时 `/etc/init.d/firewall` 执行 `fw4 -q start`；fw4-rs 实现了 `start`（与 `reload` 同一生成
   路径），设备上已验证 `reload`。原 rpcd/uhttpd/log 服务已 disable，对应 Rust 服务在 S11/S12/S50。

## 决策

1. **撤销 0006 第 1 条中的"不重启"与"failsafe 不作为回退"两项**。允许为验证开机路径执行一次
   `reboot`；允许在开机失败时进入 OpenWrt failsafe 并在其中恢复；允许恢复出厂（清 overlay）作为
   第二道回退。以上都不写 flash 的 bootloader/内核分区，不写 nvram。
2. **仍然排除**：拆机、UART、写入 BL2/FIP/Nvram/Factory、刷写任何 OpenWrt 或原厂镜像作为
   *计划内*步骤。小米 TFTP 原厂固件救援只作为 flash 损坏时的最后手段，由用户按
   [RUNBOOK_AX3000T_RECOVERY](../RUNBOOK_AX3000T_RECOVERY.md) 操作；本项目不主动触发。
3. **重启前置条件**（全部满足才执行）：
   - `private/backup/2026-09-03/`：`sysupgrade -b` 配置备份、`/overlay/upper` 全量 tar、mtd0–mtd7
     只读转储（BL2/Nvram/Bdata/Factory/FIP/crash/crash_log/KF，设备端与本地 SHA-256 一致）、
     `fw_printenv` 全文、系统事实；
   - `private/images/25.12.5/`：官方 sysupgrade/initramfs 镜像，SHA-256 与官方 `sha256sums` 一致；
     `private/images/stock-rd03/`：小米官方 CDN 的 RD03 1.0.47 原厂固件；
   - `tools/r23_reboot_gate.sh pre` 已采集参考态；
   - 用户在设备旁；网线接在 `lan4`（用 `/sys/class/net/lan4/carrier` 确认）；电脑另有上网途径
     （手机热点），使路由器失联时对话不中断；用户已读救援手册。
4. **执行形态**：`reboot` → 等待 → `tools/r23_reboot_gate.sh post` 与 pre 逐文件 diff（ubus 对象、
   init 使能、三个 bind mount、进程集合、nft 规则集（计数已掩蔽）、配置与二进制哈希、无线状态、
   JSON-RPC 探针、uci export 哈希）→ 约 3 分钟只读观察。预期 `flag_try_sys1_failed` 22→23，其余不变。
5. **失败处置**：
   - SSH 在 3 分钟内可达但某 Rust 服务未起：用对应 `owrt-*-switch disable`/`boot-enable off` 回退，
     记录后修复再来；不算事故。
   - SSH 不可达、蓝灯未亮：断电重上电，黄灯开始闪时按 mesh 键 → failsafe → `mount_root` →
     `owrt-switch boot-enable off`（或直接 `firstboot` 后用配置备份恢复）→ `reboot`。
   - 以上都不可达：按手册 TFTP 原厂固件救援，之后重新安装 OpenWrt。

## 后果与残余风险

- 开机路径验证通过后，第一轮和第二轮的"boot-enable on"才算真正成立；REPORT_ROUND2 §4 的第一项关闭。
- 不能排除的风险：断电重上电时的硬件故障（电源、NAND），与本项目无关；用户错过 4 秒 failsafe 窗口
  （可重复断电再试，无副作用）；用户误长按 reset 触发恢复出厂（有配置备份可恢复）。
- ubusd（阶段 9）不因本决策解锁：0015 的技术结论不变（在线替换须重启 netifd/dnsmasq/odhcpd）。
  用户放宽约束后它变得*可做*，排在本轮最后单独评估，默认建议仍是不做。
