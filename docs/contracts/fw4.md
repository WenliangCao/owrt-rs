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

## 5. R92 CLI 与特殊输入

- start/reload 渲染中止后仍按 shell 管线运行 nft 与 includes 阶段；无状态时最终退出 1，print
  中止退出 254。启动/重载的状态存在性按普通文件判定，usage 的空行和文本按镜像 wrapper。
- 一次读取网络/服务 ubus 状态复用同一连接；连接失败只打印一次原版警告。
- `log=0.5` 的规则 action 链选择按 ucode 数值真值判断，不先截成整数位图。
  `any_device`、`monthdays=foo/1.5` 的旧风险假设未复现为新增差异，保留实际生成的规则对照。
- include 被信号终止返回负信号号；超时杀死并等待直接子进程，采用该退出/信号结果。
  不承诺收回任意自行脱离的孙进程；探针的超时脚本 `exec sleep` 验证直接子进程边界。
- 文件打开失败报告该操作的实际 errno。精确 ucode `85922056` 的 fs.open 失败不更新
  fs.last_error，故原版在 ENOTDIR/ELOOP/EISDIR 场景可错误打印旧 ENOENT；有意保留准确诊断，
  不伪造解释器 backtrace。目录成功 open 后读取失败按原版行读取 EOF 处理。

`r92_fw4_probe.py` 用一次性镜像和 nft 记录器对照 16 项 CLI/文件/信号行为，并保留完整 stderr；
它只替代 nft 执行边界，不替代正式回归的上游语料、r29 及实际规则检查。
