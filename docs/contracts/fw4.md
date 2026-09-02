# 合同 C4：防火墙规则生成器（R09 firewall4）

> 冻结日期：2026-09-02
> 依据：镜像内 firewall4 2025.03.17~b6e51575（`/sbin/fw4`、`/usr/share/firewall4/main.uc`、
> `templates/*.uc`、`/usr/share/ucode/fw4.uc`）；上游 `tests/` 68 个用例（含 uci/ubus/fs mock 与期望输出）；
> 设备 2026-09-02 只读采集：`uci show firewall`、`fw4 print`（203 行）、`network.interface dump`。

## 1. 输入

| 来源 | 内容 |
|---|---|
| UCI `firewall` | `defaults`、`zone`、`forwarding`、`rule`、`redirect`、`nat`、`ipset`、`include` 段，含匿名段序号 |
| UCI `/usr/share/firewall4/helpers` | `helper` 段（CT helper 名称、协议、端口、module） |
| ubus `network.interface dump` | 每个逻辑接口的 `up`、`device`/`l3_device`、IPv4/IPv6 地址与前缀分配、`data.zone`、`data.firewall` 规则 |
| ubus `service get_data {type:firewall}` | 服务与实例声明的防火墙规则 |
| 文件系统 | `/etc/nftables.d/*.nft`（table 内 include）、`/usr/share/nftables.d/{ruleset,table,chain}-{pre,post}/…`（auto_includes）、`/sys/class/net/*`（flow offload 设备解析）、`/proc/version`（内核版本） |
| nft 状态 | `nft -j list sets inet fw4`、`nft -j list flowtables inet fw4`（reload 时判断是否需 `delete flowtable`） |
| 状态文件 | `/var/run/fw4.state`（`start` 写、`reload` 前删除、`network/device/zone` 查询读） |

## 2. 输出

`fw4 print` 的完整 nftables 文本：`table inet fw4` / `flush table inet fw4` / 可选 `delete flowtable`，
然后一个 `table inet fw4 { … }` 块，按模板顺序包含 flowtable、CT helper、set 定义、`define` 区、
limit、用户 include、filter 链（input/forward/output/prerouting/handle_reject/syn_flood、每 zone 的
input_/output_/forward_/helper_、verdict 链）、NAT 链（dstnat/srcnat 与每 zone）、raw 链、mangle 链，
注释格式 `comment "!fw4: …"`。**候选输出必须与原实现逐字节相同**（含空行、制表符与注释）。

子命令语义与 `/sbin/fw4` 一致：`start|reload`（渲染 → `nft -f`，再执行 script include）、`stop`、
`flush`、`restart`、`check`、`print`、`reload-sets`、`network|device|zone` 查询；`-q`/`-v` 标志；
`/var/run/fw4.lock` 排他锁。

## 3. 验证

1. 上游 68 个用例：用同一 mock 输入（uci JSON、ubus JSON、fs 文件）驱动候选，输出与用例期望逐字节一致。
2. 设备配置：候选 `print` 与设备 `fw4 print` 逐字节一致（`--use-state`/实时 ubus 两种输入）。
3. `nft -c -f` 通过。
4. 上线条件：设备差分为空，因此 `enable` 时应用的规则与原实现相同；`nft list ruleset` 前后哈希一致。

## 4. 不在合同内

`fw4` 之外的 firewall 相关组件（`/etc/init.d/firewall`、hotplug `20-firewall`）保留原样，只是它们调用的
`/sbin/fw4` 被 bind mount 到候选。
