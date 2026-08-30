# AX3000T stock / OpenWrt 25.12.5：源码—镜像偏差

> I0.3 状态：完成
> 日期：2026-08-30
> 判定：没有未解释的 source/image deviation；存在 3 条 DT compiler warning 和多次已记录的
> 分析命令失败，它们未被误报为镜像偏差或成功结果。

## 1. 判定规则

本报告分开处理：

1. source expectation 与部署镜像不同；
2. 格式允许且由 build recipe 解释的 padding/conditional output；
3. parser/tool warning；
4. 分析操作自身失败；
5. 静态证据无法回答的 runtime unknown。

只有第 1 类计入 source/image deviation。第 3、4 类必须保留，但不能据此修改镜像结论。

## 2. Expected / observed / delta

| 范围 | source expected | image observed | delta/判定 |
|---|---|---|---|
| profile | `xiaomi_mi-router-ax3000t` stock | metadata、CONTROL、FIT DTB 均为 stock | 无 |
| artifact recipe | `sysupgrade-tar \| append-metadata` | 9,400,320-byte tar + 288-byte fwtool info | 无 |
| fwtool signature | build key/cert 存在时才条件附加 | 没有 signature chunk | 无；合法 conditional output |
| tar members | board CONTROL、kernel、root | 正好 4 项（含目录），无额外 member | 无 |
| tar padding | 512-byte member alignment + 10 KiB record padding | CONTROL 481、kernel 312、末端 8,704 bytes，均为零 | 无 |
| kernel format | AArch64 Linux FIT，LZMA，DTB | FIT totalsize 等于 member size；kernel/DTB hash 匹配 | 无 |
| kernel version/address | Linux 6.12.94，`0x48000000` | 完全一致 | 无 |
| DT compatible | `xiaomi,mi-router-ax3000t` | 完全一致，无 `-ubootmod` | 无 |
| device DT properties | exact DTS/DTSI 的 board、chosen、memory、LED/key、I2C、NAND、Ethernet、Wi-Fi | 148 项语义断言全部通过 | 无 |
| partitions | 10 个 stock fixed partitions | label/reg/read-only 全部一致 | 无 |
| rootfs | SquashFS、默认 256 KiB block、XZ target build | SquashFS 4.0、262,144-byte block、XZ | 无 |
| rootfs device table | `/dev/console c 600 0 0 5 1` | 唯一特殊节点正是该定义 | 无 |
| rootfs xattrs | 非 SELinux build 使用 `-no-xattrs` | superblock：xattrs not stored | 无 |
| root payload alignment | `-nopad` filesystem 后由 artifact/member 对齐 | filesystem 后有 1,010 个零字节 | 无；容器填充 |
| timestamps | `SOURCE_DATE_EPOCH=1782737960` | tar/FIT/1,223 inode 均为 `2026-06-29T12:59:20Z` | 无 |

## 3. 全字节检查

输入的 9,400,608 bytes 已按不重叠区域全部归属：

```text
0 .. 9,400,319         GNU tar
9,400,320 .. 9,400,327 fwtool info header
9,400,328 .. 9,400,591 metadata JSON
9,400,592 .. 9,400,607 fwtool trailer
```

tar 内 header、member、member padding 和 end-of-archive record padding 的总和等于
9,400,320。所有 padding 均验证为零，unknown bytes 为 0。

`fwtool` 正常提取 metadata，CRC 校验通过；signature extraction 返回 `Data not found`。这是
源码中的合法 conditional branch，不是损坏或签名链缺失：发布文件的数字来源已由外部
`sha256sums.asc` 验证，I0.3 只说明 image 内没有嵌入 ucert chunk。

## 4. DT compiler warnings

`dtc 1.7.0` 可确定性地反编译 DTB，退出状态 0，但报告 3 条 warning：

1. `/soc/ice_debug` 缺少或为空的 `reg/ranges`；
2. `/soc/ap2woccif@151a5000` 与 `/soc/syscon@151a5000` unit-address 重复；
3. `/soc/efuse@11f20000/usb3-rx-imp@8c8` 与 `usb3-tx-imp@8c8` unit-address 重复。

这些节点属于完整 MT7981 SoC tree，不影响本设备的 stock compatible、分区、boot console、
Ethernet/Wi-Fi nvmem 或 upgrade mapping。warning 已进入报告，不能被写成“零警告”；同时没有
证据把它们升级为部署阻塞或运行故障。

## 5. 分析失败记录

| attempt | 失败原因 | 影响 | 修正与最终结果 |
|---|---|---|---|
| rootfs extraction 1 | `-e` 被解释为 extract-file，不是 exclude | 尝试创建 `/dev/console`，未完成提取 | 非零结果保留；未用于统计 |
| rootfs extraction 2 | `-excludes` 放在 filesystem 参数之后 | 同上 | 非零结果保留；第三次正确排除 `dev/*` |
| fwtool 探测 | 把 `-i` 误当只读开关，而它实际需要输出路径 | 输入为 0400，写打开失败；没有修改 | 立即复核 size/hash；随后输出到独立 run dir |
| FIT extraction 1 | `dumpimage` 未指定 `-T flat_dt` | `unsupported type`，无 payload 输出 | 指定 type 后 kernel/DTB 成功提取 |
| CRC helper | 当前 coreutils 不支持 `cksum -o 3` | 未得到独立 CRC32 计算 | 使用 FIT 内 SHA-1 + `sha1sum` 做 payload 完整性验证 |
| DT check 1 | Bash helper 覆盖 caller 的全局 path 变量 | 第 51 项路径重复后停止 | 保存 failed log，helper 改用 local variables |
| DT check 2 | 两条 phandle 查询漏传 DTB 参数 | GMAC 引用处停止 | 保存 failed log；第三次 148/148 通过 |

所有失败均发生在派生输出或检查脚本。每次关键操作后都重新计算原始输入 hash；最终仍为
`a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea`。

## 6. 不属于 deviation 的提取差异

普通用户提取树只有 881 files、128 directories、213 symlinks，没有 char device；numeric
image inventory 多一个 `/dev/console`。这不是丢失或 parser 静默失败，而是安全策略主动
排除唯一特殊节点。两边在排除该节点后完全一致。

SquashFS superblock 声明不存储 xattrs，因此 file capability 为空符合格式事实。setuid、
setgid 和 sticky 位也均为空。

## 7. Runtime unknown

下列事项不是 source/image deviation，也尚不能结论化：

- 设备真实 MTD/UBI/NMBM 状态；
- active root、boot flags 和 RD03/RD23 分支；
- 首次启动后 UCI defaults、overlay 和 runtime-generated files；
- DT 中 MT7531/AN8855 节点在具体硬件 revision 上的实际 probe 结果；
- driver、firmware 与硬件的动态行为。

它们进入 I0.6/I0.7，而不是通过继续静态扫描强行解释。

## 8. I0.3 deviation gate

| 项目 | 数量/结果 |
|---|---|
| unexplained bytes | 0 |
| source/image deviations | 0 |
| format/source-explained padding | 4 处，全部为零 |
| DT semantic failures | 0 / 148 |
| DT compiler warnings | 3，已登记 |
| failed analysis attempts | 7，已登记且未当作成功 |
| input hash changed | 否 |

I0.3 不因“能解析”而通过；它因每层结构与精确 source expectation 一致、所有偏差/警告/失败
均已分类且没有未知字节而通过。
