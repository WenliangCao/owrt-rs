# 兼容合同 C8：rpcd 插件对象 `rpc-sys`、`network.rrdns`、`luci-rpc`、`iwinfo`（阶段 8）

> 来源：rpcd @ 28faf640 `sys.c`、`iwinfo.c`；luci `rpcd-mod-rrdns` 20170710 `rrdns.c`；luci `rpcd-mod-luci`
> 20240305 `luci-rpc.c`；libiwinfo @ f5dd57a8 `iwinfo_nl80211.c`/`iwinfo_lib.c`/`iwinfo_utils.c`。只读副本
> `private/stage8/src/`、`private/stage5/src/rpcd/`。决策 [0014](../decisions/0014-rpcd-plugin-objects-and-netlink-read-side.md)。

## 1. rpc-sys

- `packagelist {all}`：读 `/lib/apk/db/installed`（缺失 → NOT_FOUND）；非 `all` 时读 `/etc/apk/world`
  （打不开 → errno 映射；空文件或末尾无换行 → UNKNOWN_ERROR），只列出 world 中出现（以 `\n@~<>=` 结尾匹配）
  的包；`g:openwrt:abiversion=` 后缀从包名剥离后再匹配一次，输出剥离后的名字；`P:`/`V:` 按 `%127s` 取词；
  fgets 516 字节分块语义保留。回复 `{"packages":{name:version}}`。
- `password_set {user,password}`：`/bin/passwd` 缺失 → NOT_FOUND，不可执行 → PERMISSION_DENIED；
  执行 `passwd <user>`，stdin 写入口令两次（间隔 100 ms），不检查退出码，回 0。
- `upgrade_test`：PATH 查找 `sysupgrade`（缺失 → NOT_FOUND），`sysupgrade --test /tmp/firmware.bin`，
  延迟回复 `{code, stdout?, stderr?}`（与 `file exec` 同一 rpc_exec 语义：单流 256 KiB 上限 → NOT_SUPPORTED，
  超时 → TIMEOUT）。
- `upgrade_start {keep}`：2 秒后执行 `/sbin/sysupgrade [-n] /tmp/firmware.bin`，立即回 0。
- `upgrade_clean`：unlink `/tmp/firmware.bin`，失败按 errno 映射（ENOENT → NOT_FOUND）。
- `factory`：2 秒后 `/sbin/jffs2reset -y -r`；`reboot`：sync，2 秒后 reboot(2)。均立即回 0，永不在验证中调用。

## 2. network.rrdns

- `lookup {addrs[], timeout, server, port, limit}`：默认 timeout 250 ms（≤ 5000）、limit 10（≤ 1000）、
  port 53（int16）；越界或缺 `addrs` → INVALID_ARGUMENT；`server` 缺省取 `/etc/resolv.conf` 第一个可解析的
  `nameserver`，没有 → NOT_FOUND；UDP 连接失败 → UNKNOWN_ERROR。
- 最多 `limit` 个查询在途；每个地址（IPv4 → in-addr.arpa，IPv6 → 32 nibble ip6.arpa）发一个 PTR 查询，
  重复地址（16 字节键）跳过；每收到一个应答就补发下一个；应答中每条 PTR 记录追加 `"<addr>": "<name>"`
  （名字无末尾点，多条则重复键）；在途为空或到 timeout 即回复（可能为空表），状态 0。

## 3. luci-rpc（8b）

- `getNetworkDevices`：遍历 `/sys/class/net`（readdir 顺序，跳过目录/普通文件项），每设备：name、
  bridge/ports/id/stp、master、wireless、up、mtu、qlen、devtype（uevent 的 DEVTYPE，缺省 ethernet）、
  ipaddrs/ip6addrs（getifaddrs 顺序：address/netmask/remote|broadcast）、mac（hatype 1）/type/ifindex/
  parent（iflink ≠ ifindex）、stats 十项 u64、flags 七项、link（speed/duplex/carrier/changes/up_count/
  down_count）。
- `getWirelessDevices`：`network.wireless status` 结果逐字段转发（去 `iwinfo`），每 interface 附
  iwinfo 表，radio 级附 phy_only iwinfo。
- `getHostHints`：rtnetlink 邻居表（状态排除 NUD_NOARP 之外全零）、uci `dhcp` host 节、租约文件、
  `/etc/ethers`、getifaddrs，按优先级合并；对非本地地址经 `network.rrdns lookup`（timeout 250）补名字。
- `getDUIDHints`、`getBoardJSON`（`/etc/board.json` 原样）、`getDHCPLeases {family}`：租约文件解析
  （dnsmasq 与 odhcpd 两种格式，含 `ff:`/`01:` DUID 形态、过期时间相对值）。
- R92：畸形 `ff:` 标识在第 14/15 字节切分时不得触发 UTF-8 索引 panic。
  该插件沿用租约文本的有损显示策略（切分片段里的非法字节显示为 U+FFFD），
  不冒称与原版原始字节相同。有效 ASCII DUID 的字节位置和冒号删除规则不变。

## 4. iwinfo（8b）

方法与字段以 `iwinfo.c` 为准：devices、info（phy/ssid/bssid/country/mode/channel/center_chan1|2/
frequency(_offset)/txpower(_offset)/quality(_max)/signal/noise/bitrate/encryption/htmodes/hwmodes/
hwmodes_text/hwmode/htmode/hardware{id[4],name}）、scan、assoclist（含 rx/tx 速率表）、freqlist、
txpowerlist、countrylist（ISO3166 表顺序）、survey、phyname。数值按 libiwinfo nl80211 后端计算。

## 5. 验证

- 8a：`tools/r18_rpcd_plugins_check.py`，精确 rootfs 双沙箱 + 隔离网络中的假 PTR 服务器（127.0.0.1:53，
  含 NXDOMAIN 与静默地址）。
- 8b：沙箱差分 `luci-rpc` 的非无线方法（rtnetlink 读主机接口，两侧同一内核）；`iwinfo` 与
  `getWirelessDevices` 只能在设备上只读差分（遮罩 signal/noise/bitrate/inactive 等瞬时值），`scan`
  各跑一次。
- R92 `r92_compat_probe.py`：所有带 device 的 iwinfo 方法的缺参/不存在设备、100 次失败探测 fd 稳定；
  正确 INT16 端口上的 PTR 正常、截断、坏 additional、压缩指针环、无关 ID/短包后正确回复及后续恢复；
  畸形 DHCP 标识通过实际 `luci-rpc` 调用验证。
