# AX3000T stock / OpenWrt 25.12.5：启动链

> I0.5 状态：完成
> 日期：2026-08-31
> 范围：从 kernel 交出控制权到 `S95done`，仅静态证据
> 设备连接：无。本报告没有任何一条结论来自物理设备。

## 1. 结论

本镜像的启动链可以从 `/etc/preinit`、`/lib/preinit/*`、pinned procd 源码、`/etc/inittab`
和 `/etc/rc.d/*` 完整还原为一条静态路径。链上每一步都能指向具体文件和行号。

三处与"通用 OpenWrt 文档描述"不同、且只有实际镜像能证明的事实：

1. `preinit_essential` hook namespace 在本镜像中**没有任何注册项**。早期 `/proc`、`/sys`、
   `/dev` 挂载由 procd 的 `initd/early.c` 完成，不是 preinit shell hook。
2. `/etc/init.d/rcS` **不存在于镜像中**。`/etc/inittab` 的 `::sysinit:/etc/init.d/rcS S boot`
   由 procd `inittab.c` 的 `sysinit` handler 解析，它只取 argv[1]=`S` 和 argv[2]=`boot`
   并调用内建 `rcS()`；argv[0] 的路径字符串从不被执行。
3. `/etc/board.json`、`/etc/config/network`、`/etc/config/system`、`/etc/config/wireless`
   都**不在镜像里**，由 preinit 阶段和 `/etc/init.d/boot` 生成。详见
   [CONFIG_FLOW.md](CONFIG_FLOW.md)。

完整机器记录见
[boot-chain.json](../../manifests/ax3000t-stock-openwrt-25.12.5/boot-chain.json)。

## 2. 静态启动路径

```text
bootloader / FIT
  → kernel
  → /sbin/init                      (procd initd，DEP: 16649 bytes)
      early()                       SRC: initd/early.c
      /sbin/kmodloader              SRC: initd/init.c:145
      setenv PREINIT=1              SRC: initd/preinit.c:145
      exec /bin/sh /etc/preinit     SRC: initd/preinit.c:126,157
  → /etc/preinit                    DEP: 5 个 hook namespace，2 次 boot_run_hook
      boot_run_hook preinit_essential   (本镜像 0 个注册项)
      boot_run_hook preinit_main        (17 个注册项，见 §3)
  → exec /sbin/procd                SRC: initd/preinit.c:94,114
      STATE_EARLY     hotplug("/etc/hotplug.json"); procd_coldplug()
      STATE_UBUS      service_start_early("ubus", "/sbin/ubusd", "ubus", "ubus")
      STATE_INIT      procd_inittab(); 依次跑 respawn/askconsole/askfirst/sysinit
      STATE_RUNNING   respawnlate / askconsolelate
      STATE_SHUTDOWN / STATE_HALT
  → sysinit → 内建 rcS("S", "boot") → glob /etc/rc.d/S* → 见 §5
```

`state_enter()` 的状态序列取自 `sources/components/procd/state.c:127-200`。
`/sbin/init` 与 `/sbin/procd` 是两个不同的 ELF；`/sbin/init` 只负责 early + preinit + exec。

## 3. preinit hook 注册（本镜像实际内容）

`/etc/preinit` 初始化 5 个 namespace：`preinit_essential`、`preinit_main`、`failsafe`、
`initramfs`、`preinit_mount_root`。`/lib/preinit/` 下 21 个文件按文件名顺序 source，
注册结果如下。

### preinit_main（17 项，按执行顺序）

| 文件 | 注册函数 | 作用（源码可证部分） |
|---|---|---|
| `02_default_set_state` | `define_default_set_state` | 定义默认 `set_state` |
| `02_sysinfo` | `do_sysinfo_generic` | 从 `/proc/device-tree` 写 `/tmp/sysinfo/{board_name,model}` |
| `04_set_netdev_label` | `set_netdev_labels` | 网络设备标签 |
| `05_set_preinit_iface` | `set_preinit_iface` | 选择 preinit 网口 |
| `07_trigger_fip_scrubbing` | `trigger_fip_scrubbing` | target 专有 |
| `09_mount_cfg_part` | `preinit_mount_cfg_part` | target 专有 |
| `10_fix_eth_mac.sh` | `preinit_set_mac_address` | target 专有 MAC 修正 |
| `10_indicate_preinit` | `preinit_ip` | 配置 preinit IP |
| `10_indicate_preinit` | `pi_indicate_preinit` | failsafe 提示与 `/bin/board_detect` |
| `30_failsafe_wait` | `failsafe_wait` | failsafe 触发窗口 |
| `40_run_failsafe_hook` | `run_failsafe_hook` | 进入 failsafe 分支 |
| `50_indicate_regular_preinit` | `indicate_regular_preinit` | 常规提示 |
| `70_initramfs_test` | `initramfs_test` | initramfs 判定 |
| `75_rootfs_prepare` | `rootfs_prepare` | rootfs 准备 |
| `80_mount_root` | `do_mount_root` | `mount_root start`；随后处理 `sysupgrade.tgz` |
| `81_urandom_seed` | `do_urandom_seed` | 恢复熵种子 |
| `82_config_generate` | `do_config_generate` | 生成 `/etc/board.json` 与首套 UCI |
| `99_10_run_init` | `run_init` | `preinit_ip_deconfig` |

### 其他 namespace

| namespace | 注册项 |
|---|---|
| `preinit_essential` | 无 |
| `failsafe` | `10_indicate_failsafe:indicate_failsafe`、`99_10_failsafe_dropbear:failsafe_dropbear`、`99_10_failsafe_login:failsafe_shell` |
| `initramfs` | `82_config_generate:do_config_generate` |
| `preinit_mount_root` | 无注册项；由 `80_mount_root` 调用 `boot_run_hook preinit_mount_root` 供包扩展 |

`00_preinit.conf` 提供的 preinit 参数（DEP）：`pi_init_cmd=/sbin/init`、
`pi_ip=192.168.1.1`、`pi_netmask=255.255.255.0`、`fs_failsafe_wait_timeout=4`。
这些是编译进镜像的默认值，不代表设备当前网络状态。

## 4. inittab

`/etc/inittab`（DEP，3 条）：

| id | action | process | procd handler |
|---|---|---|---|
| （空） | `sysinit` | `/etc/init.d/rcS S boot` | `runrc` → 内建 `rcS("S","boot")` |
| （空） | `shutdown` | `/etc/init.d/rcS K shutdown` | `runrc` → 内建 `rcS("K","shutdown")` |
| （空） | `askconsole` | `/usr/libexec/login.sh` | `askconsole` |

procd 支持的 action 集合为 `sysinit`、`shutdown`、`askfirst`、`askconsole`、`respawn`、
`askconsolelate`、`respawnlate`（`inittab.c:244-270`）。本镜像只用了其中 3 个。
`rcS()` 的目录常量是 `rc_d_path = "/etc/rc.d"`（`rcS.c:37`），glob 后按名字排序执行。

## 5. rc.d 启动与关闭顺序

33 个符号链接，全部指回 `/etc/init.d/`。S 链接 24 个，K 链接 9 个。链接编号与脚本内
`START`/`STOP` 变量逐条一致，没有发现编号漂移。

| S 链接 | 服务 | START | K 链接 | STOP |
|---|---|---:|---|---:|
| `S00sysfixtime` | sysfixtime | 00 | `K90sysfixtime` | 90 |
| `S00urngd` | urngd | 00 | — | — |
| `S10boot` | boot | 10 | `K90boot` | 90 |
| `S10system` | system | 10 | — | — |
| `S11sysctl` | sysctl | 11 | — | — |
| `S12log` | log | 12 | `K89log` | 89 |
| `S12rpcd` | rpcd | 12 | — | — |
| `S19dnsmasq` | dnsmasq | 19 | — | — |
| `S19dropbear` | dropbear | 19 | `K50dropbear` | 50 |
| `S19firewall` | firewall | 19 | — | — |
| `S19wpad` | wpad | 19 | `K21wpad` | 21 |
| `S20network` | network | 20 | `K90network` | 90 |
| `S25packet_steering` | packet_steering | 25 | — | — |
| `S35odhcpd` | odhcpd | 35 | `K85odhcpd` | 85 |
| `S50cron` | cron | 50 | — | — |
| `S50uhttpd` | uhttpd | 50 | — | — |
| `S80ucitrack` | ucitrack | 80 | — | — |
| `S94gpio_switch` | gpio_switch | 94 | `K10gpio_switch` | 10 |
| `S95done` | done | 95 | — | — |
| `S96led` | led | 96 | — | — |
| `S98sysntpd` | sysntpd | 98 | — | — |
| `S99bootcount` | bootcount | 99 | — | — |
| `S99ubihealthd` | ubihealthd | 99 | — | — |
| `S99urandom_seed` | urandom_seed | 99 | — | — |
| — | umount | — | `K90umount` | 90 |

`umount` 只有 K 链接，没有 S 链接：它只参与关机路径。

## 6. `S10boot` 在启动中的额外职责

`/etc/init.d/boot` 的 `boot()` 是本镜像里唯一一处把"目录创建 + 模块加载 + 配置生成 +
配置重载"串在一起的地方（`/etc/init.d/boot:33-60`）：

```text
mount_root（若 /proc/mounts 缺失）
  → 建立 /var/{lock,log,run,state,tmp}、/tmp/.uci(0700)、/tmp/resolv.conf.d
  → 按 /proc/filesystems 条件挂载 debugfs、bpffs、pstore
  → [ -f /etc/board.json ] && /sbin/wifi config
  → /sbin/kmodloader
  → uci_apply_defaults      # 逐个 source /etc/uci-defaults/*，成功后删除，然后 uci commit
  → /sbin/reload_config     # 源码注释自称 "temporary hack until configd exists"
```

`/sbin/wifi config` 在 `kmodloader` 之前执行，注释明确说明是为了在 ieee80211 hotplug
事件之前先更新 wireless 配置。这个顺序对无线配置生成路径有直接影响。

## 7. 关机路径

```text
procd STATE_SHUTDOWN → procd_inittab_run("shutdown") → rcS("K","shutdown")
  → /etc/rc.d/K* 按编号执行
procd STATE_HALT     → kill(-1,SIGTERM) → sync → sleep 1 → kill(-1,SIGKILL) → sync → perform_halt()
```

`/etc/init.d/done` 的 `boot()` 会执行 `mount_root done`、删除 `sysupgrade.tgz`/
`/tmp/sysupgrade.tar`、运行 `/etc/rc.local`（若存在）并调用 `set_state done`。
镜像中没有 `/etc/rc.local`，所以该分支在出厂状态不触发。

## 8. 静态证据边界（转入 I0.6）

以下内容本阶段**不下结论**：

- **kernel command line**：设备树 `chosen` 节点只有 `stdout-path = "serial0:115200n8"`，
  没有 `bootargs`。实际 cmdline 由 bootloader 传入，静态镜像无法确定。
  `80_mount_root` 会读 `/proc/cmdline` 里的 `rootfs_mount_options.*`，因此这条未知会
  直接影响 rootfs 挂载选项。
- **实际启动顺序与耗时**：本报告是静态图。procd 的 `rcS` 使用 runqueue，同一编号内的
  实际并发与完成顺序未观察。
- **failsafe 是否被触发**：`30_failsafe_wait` 的 4 秒窗口是否被使用未知。
- **首次启动与后续启动的差异**：`uci_apply_defaults` 会删除已执行的 uci-defaults 文件，
  `82_config_generate` 只在 `/etc/board.json` 缺失时运行。设备当前处于哪一侧未知。
- **`/etc/rc.local` 是否已被用户创建**：未观察。
- **watchdog**：`watchdog_init(0)` 在 `STATE_EARLY` 和 `STATE_UBUS` 各调用一次，实际
  watchdog 设备与超时未观察。
