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
`tools/benchmark/profile_support.rs` 失败；保留 `bridge-unit.log`，随后明确选择
daemon test target 完成验证。

## 待完成的独立候选

GSTRINGS 长度与四项静态候选（跨 vif VLAN/STA 编号、SET_DATA 非字符串数据、
无线状态 ifname、协议 PD 长度）仍分别取证；本段不把未测试项记为通过。
下一轮将用实际内核 ioctl 和精确镜像的 C netifd / wifi-scripts 判断边界，
只修改至少四轮重复确认的差异。
