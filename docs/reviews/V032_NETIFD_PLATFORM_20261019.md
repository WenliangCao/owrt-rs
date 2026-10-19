# netifd / platform 后续修复

2026-10-19。**桥属性、GSTRINGS、无线索引、SET_DATA、共享 VLAN ifname 和 PD 长度
共六项均完成四轮红绿验证；最终 netifd green-all 14/14、daemon 单测 175/175 通过。**
所有构建和实验在 Oracle 独立网络、挂载、PID namespace 内执行，没有访问或修改路由器。

## 桥属性 reload

参考精确 OpenWrt 25.12.5 的 C netifd `cbb83a18`：`bridge.c:bridge_reload`
对端口之外的桥属性变更返回 `DEV_CONFIG_RESTART`；`bridge_apply_settings` 将
`multicast_querier` 默认与 `igmp_snooping` 同步，`system_bridge_addbr` 写入内核。

Rust `create_devices` 原先只为不存在的桥发送属性，已有桥只更新内存。
现在复用现有 netlink 属性编码，配置变化时更新已有桥，同时保留端口；querier 默认值
也按 C 跟随 snooping。这是状态正确性修复，不作性能推断。

同一 daemon 内执行 `0→1→0`，读取实际 sysfs `multicast_snooping`、
`multicast_querier`，同时核对配置端口仍在桥中。四轮修前 C 均通过、Rust 均失败；
四轮修后双方均通过。已有协议 exec 恢复、依赖上下线、桥端口删除和最后端口移除
仍通过，连同新增 `bridge_options` 共 6 场景 × C/Rust = 12/12。
netifd daemon 单测 175 通过、0 ignored。

证据目录：Oracle `/home/ubuntu/v032-netifd-platform-20261019/`：
`PLAN.md`、`bridge-red-{1..4}`、`bridge-green-{1..4}`、`green-all/results.json`、
`bridge-unit-bin.log`。首次默认 Cargo test 因独立源码副本未带诊断 example 引用的
`components/rpcd/examples/profile_support/mod.rs` 失败；保留 `bridge-unit.log`，随后明确选择
daemon test target 完成验证。

## GSTRINGS 借用缓冲区边界

C `system-linux.c:ethtool_feature_count/ethtool_feature_index` 先通过
`ETHTOOL_GSSET_INFO` 查询实际特征数，再分配字符串缓冲区。内核的 GSTRINGS
忽略请求中的 `len`，按内核特征数写回；只检查调用者填写的 len 无法保证 Rust
公开 safe 函数的借用边界。

Oracle 四次实测均为 64 项、2060 字节：旧实现把一个 12 字节 slice 交给 ioctl 后，
其后 2048 字节 canary 全部被改写。底层 allocation 故意足够大，本实验只证明
越出借用 slice，没有制造 allocation 越界，也不宣称现有生产调用自然触发过。

修复在 ABI 边界重新查询内核的真实数量，再核对 slice 大小。GSTRINGS 只接受
生产调用使用的固定 `ETH_SS_FEATURES` 表；不接受可能在两次调用之间变化的驱动
统计字符串表。修后四次短 slice 均在 GSTRINGS ioctl 前报错、canary 零改动；
每轮的完整 2060 字节阳性控制均成功。platform 单测 10/10。

同一 Oracle 目录中的 `gstrings-{red,green}-{1..4}.jsonl` 保存原始计数，
`gstrings-unit.log` 保存单测；回归源为 `tools/platform_gstrings_probe.rs`。

## 无线子项索引

无线候选使用同一受控 handler、同一个 radio 下的两个 vif、共享 VLAN 和各自 STA；
参考精确镜像 C netifd 调用的 `wireless-device.uc`。四轮中 C 的三项检查均通过，
Rust 的跨 vif 编号、非字符串 SET_DATA、VLAN ifname 三项均失败。

`wdev_config_init` 的 VLAN/STA 计数器属于每个 vif，Rust 原先跨 vif 累加。
现把两个计数器移入 vif 循环；四轮 `--checks indices` 中双方都输出各自的 `01`，
其余两项仍明确记录失败，没有藏进绿色结果。证据为 `wireless-red-{1..4}` 和
`wireless-indices-green-{1..4}`，回归工具 `components/netifd/tests/wireless_review.py`。

## 无线 ifname 和共享 VLAN 入桥

精确镜像 `wireless-device.uc:wdev_set_data/get_status_data` 以 `父 vif/子 VLAN`
保存共享 VLAN 的 handler data。Rust 原先只用 VLAN section，两个 vif 的同名 VLAN
互相覆盖，且 status 没有输出 VLAN ifname。现在 notify、status 和 NOTIFY_UP 入桥
路径统一使用与 C 相同的键；JSON 和直接 blob 状态投影同步更新。

四轮 `wireless-vlan-red-up-*` 中，C 报告两个独立 ifname 且两个 dummy netdev 均加入
`br-test`，Rust 不报告 VLAN ifname 且只将 `vlan-02` 入桥。四轮
`wireless-ifname-green-{1..4}` 中双方的三项无线检查均通过，两个端口实际入桥。
回归使用同一共享 VLAN 的两个 vif，在 setup 完成前通知 ifname，然后执行 NOTIFY_UP。
只验证控制协议与 Linux 桥行为，没有假装验证物理 Wi-Fi 驱动。

最初 dummy netdev 未设 UP，C 不将它视为可用外部无线设备，早期 exit/held/wait
夹具不能作为入桥正控制；完整原始结果保留，结论只使用 `red-up` 四轮。

## SET_DATA 类型保留

精确镜像 `wireless-device.uc:wdev_set_data` 将 device data 原样传给后续 handler。
Rust 原先只收字符串；现在完整转换并保存整数、布尔、数组和嵌套对象，非法深度在改变
状态前返回 `INVALID_ARGUMENT`。同一 handler 经 notify 注入字符串 token、整数 7、
布尔 true 和含混合数组的对象，再检查实际 teardown argv。四轮 `wireless-red-*`
中 C 均保留所有类型而 Rust 丢非字符串；`wireless-data-green-{1..4}` 中双方均通过。
这些轮次仍显式记录未修的 ifname 失败，不作为完整无线绿色回归。

## PD 长度

精确 C `proto.c:parse_prefix_option` 只接受 `1..64` 的 delegated prefix。
Rust 解析边界现在使用相同范围，避免把 0 或 65..128 交给依赖该范围的分配逻辑。
通过实际 `notify_proto` 逐一送入 0、65..128，另以 56、64 为阳性控制；四轮中 C
均拒绝非法长度而旧 Rust 均接受，修后四轮双方均拒绝，合法长度和 daemon 存活均正常。
没有据此宣称真实配置发生过崩溃。

证据为同一 Oracle 目录 `prefix-red-replace-{1..4}`、`prefix-green-{1..4}`；
回归加入 `proto_spawn_failure.py` 默认集合。早期 `prefix-red-*` 使用 `keep=true`，
C 会保留前一合法前缀，因而“非法更新后表应为空”的夹具判断不成立；这些原始数据保留，
有效对照使用普通 replacement 更新。

## 最终组合验证

`final-green-all/results.json` 包含七个场景 × C/Rust = 14/14，覆盖协议启动失败恢复、
依赖上下线、桥成员移除、桥属性和 PD 长度；`final-unit-bin.log` 为 daemon target
175 passed、0 ignored。最终四轮无线检查同时覆盖局部索引、typed SET_DATA、status
和两个共享 VLAN 的实际内核桥成员。`final-identities.json` 记录参考与候选 ELF、源码
及工具哈希，候选 ELF SHA-256 为
`84b07606b7c2a81fccda040c643f59bb8f3b2d2b3144f242d80c87c304335f5a`。
初次补建因非交互 SSH PATH 没有 cargo 失败，保留 `wireless-ifname-build.log`；
随后使用绝对 Cargo 路径完成构建，日志为 `wireless-ifname-build-cargo-path.log`。
