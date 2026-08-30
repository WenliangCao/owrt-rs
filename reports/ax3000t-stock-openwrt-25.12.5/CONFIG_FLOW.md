# AX3000T stock / OpenWrt 25.12.5：配置链

> I0.5 状态：完成
> 日期：2026-08-31
> 范围：6 个随镜像发布的 UCI 配置、3 个首次启动生成的配置、22 个 uci-defaults、
> 7 个 board.d 脚本、8 个生成器/重载入口
> 设备连接：无。设备上的实际配置内容和迁移进度均未观察。

## 1. 结论

**镜像里的 `/etc/config/` 不是设备上的配置。** 出厂 squashfs 只带 6 个 UCI 文件；
控制面最核心的三个——`network`、`system`、`wireless`——在镜像里根本不存在，
它们在首次启动时由 preinit 和 `/etc/init.d/boot` 生成。

| 配置 | 随镜像发布 | 拥有包 | 顶层 section |
|---|---|---|---|
| `dhcp` | 是 | dnsmasq | `dnsmasq`、`dhcp lan`、`dhcp wan` |
| `dropbear` | 是 | dropbear | `dropbear main` |
| `firewall` | 是 | firewall4 | `defaults`、2×`zone`、`forwarding`、9×`rule` |
| `luci` | 是 | luci-base | `core main`、`extern flash_keep`、5×`internal`（`languages`/`sauth`/`ccache`/`themes`/`apply`） |
| `rpcd` | 是 | rpcd | `rpcd`、`login` |
| `uhttpd` | 是 | uhttpd | `uhttpd main`、`cert defaults` |
| `network` | **否** | — | 首次启动由 `/bin/config_generate` 生成 |
| `system` | **否** | — | 首次启动由 `/bin/config_generate` 生成 |
| `wireless` | **否** | — | 由 `/sbin/wifi config` + ieee80211 hotplug 生成 |
| `fstab` | **否** | — | 需要 `block-mount`，本镜像未安装 |
| `ucitrack` | **否** | — | 本镜像用 `/usr/share/ucitrack/*.json`，不是 UCI 配置 |

任何以"读 `/etc/config/network` 得到接口定义"为前提的替换设计，必须先说明它面对的是
生成前还是生成后的状态。

完整机器记录见
[config-flow.json](../../manifests/ax3000t-stock-openwrt-25.12.5/config-flow.json)。

## 2. 首次启动的配置生成链

```text
/proc/device-tree
  → 02_sysinfo do_sysinfo_generic
        /tmp/sysinfo/board_name  ← compatible 第一项
        /tmp/sysinfo/model       ← model
  → 82_config_generate do_config_generate            （仅当 /etc/board.json 缺失）
        source /etc/uci-defaults/30_uboot-envtools   （让 board.d 能读 U-Boot env）
        /bin/board_detect /tmp/board.json
            └── source /etc/board.d/*                 01_leds 02_network 03_gpio_switches
                                                      04_defaults 05_compat-version
                                                      05_fw_defaults 99-default_network
            └── ucidef_* 累积 JSON
        mv /tmp/board.json /etc/board.json
        /bin/config_generate
            [ -s /etc/config/network -a -s /etc/config/system ] && exit 0
            uci -q batch  →  /etc/config/network、/etc/config/system
  → /etc/init.d/boot boot()
        /sbin/wifi config          （仅当 /etc/board.json 存在，且在 kmodloader 之前）
        /sbin/kmodloader
        uci_apply_defaults         （见 §3）
        /sbin/reload_config        （见 §4）
```

`/etc/board.json` 是这条链的中间真源：`config_generate` 读它，`luci-rpc getBoardJSON`
也读它。它同样**不在镜像里**。

### 本设备在 board.d 中的实际条目

`/etc/board.d/02_network` 对 `xiaomi,mi-router-ax3000t` 有两处命中：

| 行 | 语句 | 含义 |
|---:|---|---|
| 213-220 | `ucidef_set_interfaces_lan_wan "lan2 lan3 lan4" wan` | LAN 为 lan2/lan3/lan4，WAN 为 wan |
| 313-320 | `wan_mac=$(mtd_get_mac_ascii Bdata ethaddr_wan)`；`label_mac=$wan_mac` | WAN MAC 来自 `Bdata` 分区的 `ethaddr_wan` |

同一 case 分支同时匹配 `-ubootmod` 变体。本项目只认 stock profile；两者共用网络定义
这一点必须记录，但不改变镜像身份结论。

`mtd_get_mac_ascii Bdata ethaddr_wan` 说明网络配置生成**依赖 MTD 分区内容**，
不是纯软件推导。这是一条镜像证据不能独立闭合的边。

## 3. uci-defaults（22 个，一次性）

`/etc/init.d/boot` 的 `uci_apply_defaults` 逐个 `source` `/etc/uci-defaults/` 下的文件，
**成功执行的文件会被删除**，然后 `uci commit` + `sync`。因此设备上该目录为空只能说明
它们跑过一次，不能说明跑成功了什么。

| 文件 | 拥有包 | 触及的配置 |
|---|---|---|
| `00_uhttpd_ubus` | uhttpd-mod-ubus | `uhttpd` |
| `05_fix-compat-version` | base-files | `system` |
| `10_migrate-shadow` | base-files | （改 `/etc/shadow`） |
| `11_network-migrate-bridges` | base-files | `network` |
| `12_network-generate-ula` | base-files | `network` |
| `14_migrate-dhcp-release` | netifd | （迁移） |
| `14_network-generate-duid` | base-files | `network` |
| `15_migrate-time-zonename` | base-files | `system` |
| `15_odhcpd` | odhcpd-ipv6only | `dhcp` |
| `30_luci-theme-bootstrap` | luci-theme-bootstrap | `luci` |
| `30_uboot-envtools` | uboot-envtools | （写 `/etc/fw_env.config`） |
| `50-attendedsysupgrade` | attendedsysupgrade-common | — |
| `50-dnsmasq-migrate-ipset.sh` | dnsmasq | `dhcp` |
| `50-dnsmasq-migrate-resolv-conf-auto.sh` | dnsmasq | `dhcp` |
| `50-dropbear` | dropbear | `dropbear` |
| `50-migrate-rpcd-ubus-sock.sh` | rpcd | `rpcd` |
| `50-root-passwd` | base-files | （改 `/etc/shadow`） |
| `50_luci-mod-admin-full` | luci-mod-network | `luci` |
| `51-attendedsysupgrade-owut` | owut | `attendedsysupgrade` |
| `95-luci-app-attendedsysupgrade-housekeeping` | luci-app-attendedsysupgrade | `attendedsysupgrade`、`luci` |
| `99_fwenv-store-ethaddr.sh` | base-files | （写 U-Boot env） |
| `ubihealthd` | ubi-utils | — |

三点值得注意：

1. `12_network-generate-ula` 和 `14_network-generate-duid` 生成**每台设备唯一**的值。
   任何比对两台设备配置的做法必须把它们排除，否则会把正常差异读成偏差。
2. `attendedsysupgrade` 配置由 uci-defaults 创建，不随镜像发布，也不在 §1 的表里。
3. `30_uboot-envtools` 被 `82_config_generate` 提前单独 source 一次，之后又在
   `uci_apply_defaults` 里再跑一次并被删除。它的执行次数与顺序和其他 defaults 不同。

## 4. 配置变更的传播路径

```text
写入方 (uci set / LuCI / rpcd uci.apply / 手工编辑)
  → /etc/config/<pkg>  或  /var/run/uci/<session>
  → ① /sbin/reload_config          （启动时由 /etc/init.d/boot 调用一次）
     ② rpcd uci.apply / uci.commit （LuCI 路径）
     ③ 直接调 /etc/init.d/<svc> reload
  → ubus call service event {"type":"config.change","data":{"package":"<pkg>"}}
  → procd 匹配 config.change trigger（见 SERVICE_GRAPH.md §4）
  → 目标 init script 的 reload / start
  → 执行面（netifd / fw4 / dnsmasq / odhcpd / hostapd）
  → 内核或硬件状态
```

`/sbin/reload_config` 的实际算法（DEP，全文 17 行）：

1. 把 `/var/run/uci/*` 和 `/etc/config/*` 每个文件的 `uci show` 输出写到
   `/var/run/config.check/`（`/var/run/uci/` 优先，同名文件不覆盖）；
2. 与 `/var/run/config.md5` 比对；
3. 对每个 `md5sum -c` 报 FAILED 的文件，发一条
   `ubus call service event '{"type":"config.change","data":{"package":"<name>"}}'`；
4. 重写 `/var/run/config.md5`，删除临时目录。

三个直接后果：

- 变更检测的粒度是**整个 config 文件**，不是 section 或 option。
- 基线保存在 `/var/run`（tmpfs），重启后丢失；因此启动时那次 `reload_config` 会为
  所有配置重建基线，而不是发出变更事件。
- 它比较的是 `uci show` 的规范化输出，不是文件字节。注释和排版差异不会触发事件。

`reload_config` 的源码注释自称 `temporary hack until configd exists`。这是 OpenWrt 自己
标记的一处结构缺口，值得记入候选职责表，但本阶段不做替换判断。

## 5. 配置消费者

工具在 init/uci-defaults/hotplug/board.d/preinit/netifd/rpcd/libexec 等目录内统计了
引用每个 config 名称的语句（带 `uci`/`config_load`/`config_foreach`/`cursor` 上下文）：

| 配置 | 引用语句数 | 主要消费文件 |
|---|---:|---|
| `system` | 40 | `/etc/init.d/system`、`/etc/init.d/log`、`/etc/init.d/sysntpd`、`/bin/config_generate` |
| `dhcp` | 40 | `/etc/init.d/dnsmasq`、`/etc/init.d/odhcpd`、`/etc/uci-defaults/15_odhcpd` |
| `luci` | 22 | `/usr/share/rpcd/ucode/luci`、LuCI uci-defaults |
| `network` | 19 | `/etc/init.d/network`、`/bin/config_generate`、`/etc/init.d/uhttpd`、`packet_steering` |
| `firewall` | 16 | `/etc/init.d/firewall`、`/etc/init.d/packet_steering` |
| `uhttpd` | 11 | `/etc/init.d/uhttpd`、`/etc/uci-defaults/00_uhttpd_ubus` |
| `wireless` | 9 | `/sbin/wifi`、`/etc/hotplug.d/ieee80211/*` |
| `dropbear` | 5 | `/etc/init.d/dropbear` |
| `rpcd` | 5 | `/etc/init.d/rpcd`、`/etc/uci-defaults/50-migrate-rpcd-ubus-sock.sh` |
| `fstab` | 3 | 仅 ucitrack/LuCI 引用；本镜像无实现 |
| `ucitrack` | 3 | 仅名称出现，无 UCI 配置 |

**这些数字不是接口合同。** 它们只说明"哪些文件提到了这个配置"，用来定位消费者，
不用来推断字段级 schema。真正的字段集合必须回到各自源码。

## 6. 未建模字段与提交语义

- **UCI 保留未知字段**：`uci set` 只改指定 option，其余原样保留。任何替换实现如果
  用"解析成结构体再整体写回"的方式，就会静默丢弃它不认识的 option。这是替换 UCI
  读写路径时最容易踩的兼容性坑，必须在 C1 合同里显式约束。
- **临时状态 vs 持久状态**：`/var/run/uci/` 是会话态（tmpfs），`/etc/config/` 是持久态。
  `uci changes` / `uci revert` / `uci commit` 在这两层之间工作。
- **`uci commit` 不发事件**：事件由 `reload_config` 或 rpcd 的 `uci.apply` 发出。
  直接编辑 `/etc/config/` 并 `uci commit` 不会自动触发服务 reload。
- **rpcd `uci.apply` / `uci.confirm` / `uci.rollback`**：提供带确认窗口的应用语义，
  详见 [IPC_CATALOG.md](IPC_CATALOG.md)。这是 LuCI 的实际提交路径。
- **外部写入方与并发窗口**：镜像里同时存在 shell（`uci`）、ucode（`uci.cursor`）、
  C（`libuci`）三种写入方，没有跨进程写锁。并发窗口的实际行为静态不可判定。

## 7. 静态证据边界（转入 I0.6）

- **设备当前的 `network`/`system`/`wireless` 内容**：完全未知。它们由 board.json、
  MTD 分区 MAC、以及可能的用户修改共同决定。
- **`/etc/board.json` 的实际内容**：依赖 `/proc/device-tree` 与 MTD 读取结果。
- **哪些 uci-defaults 实际执行成功**：执行成功即被删除，静态无法回溯。
- **是否发生过配置迁移**：`11_network-migrate-bridges`、`14_migrate-dhcp-release`、
  `15_migrate-time-zonename`、`50-dnsmasq-migrate-*`、`50-migrate-rpcd-ubus-sock.sh`
  的实际迁移结果未知。
- **用户是否手工修改过配置**：未观察（也是 I0.1 记录的既有缺口）。
- **`/var/run/config.md5` 的当前基线**：tmpfs 内容，未观察。
- **并发写入的实际行为**：需要运行态实验才能裁决，且实验本身有副作用，必须单独设计。
