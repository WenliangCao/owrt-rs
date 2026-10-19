# netifd / platform 后续修复

2026-10-19。**桥属性 reload 的四轮 C/Rust 红绿对照完成：修前 Rust 四轮都未将
`igmp_snooping=1` 写入内核，修后四轮均与 C 一致；默认 green-all 扩展为 12/12 通过。**
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

## 待完成的独立候选

四项静态候选（跨 vif VLAN/STA 编号、SET_DATA 非字符串数据、
无线状态 ifname、协议 PD 长度）仍分别取证；本段不把未测试项记为通过。
下一轮将用实际内核 ioctl 和精确镜像的 C netifd / wifi-scripts 判断边界，
只修改至少四轮重复确认的差异。
