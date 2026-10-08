# 普通 wildcard UDP 的新接口 ACL caller

状态：**仅准备工具与源码接口建议；未访问 Oracle、未构建、未运行测试**。补充门 `tools/dnsmasq/m6b_interface_acl.py` 独立于正在修 tracer 的 `m5_interface_records.py`，不改变原7项期望或完整族资格。工具基 main `2b4015effbb63f80991df30e6ad5db45e349bf27`，使用既有 `m5_listeners.Network` 的真实 veth / 独立 peer netns、`m5_dns_files` 的健康/上游 fixture、精确镜像 rootfs / UBus。产品修改仍由 root 统一整合。

## 3 个普通场景与固定证据

三项都使用 ordinary wildcard：无 bind-interfaces / bind-dynamic，无 listen-address；DNS 15353、cache-size=64、上游 TTL=120、strict-order、关闭0x20和round-robin。peer 仅从 `10.77.0.2` / `lpeer` 向受测 `lan` 的地址发送 UDP。不用同 namespace 的 loopback packet 伪装真实 ingress。

| case | 启动时 | mutation | 首包必须覆盖的 C caller |
| --- | --- | --- | --- |
| `late-device` | `interface=lan`，lan 实际不存在；daemon wildcard 启动并通过正确 loopback host-record 健康门 | 创建 lan/lpeer veth、lan `.1/.3`、peer `.2` | 新的 ifindex 不在启动 snapshot 中；`indextoname → iface_check` 直接按当前 name 接受。 |
| `recreated-device` | lan 存在、`interface=lan` | 删除并重建 veth，明确断言新 actual ifindex 与启动前不同 | 同名新 index 的首包，不能依赖启动时 index / 待下一次查询刷新。 |
| `late-label` | lan 存在，但 `10.77.0.3/24 label lan:0` 实际不存在；`interface=lan:0` | 新增 `.3` / `lan:0` | live name 是 lan，不能直接匹配 lan:0；C 的 actual receive caller 非 CLEVERBIND 枚举，再用 label exception 接受。 |

每项保存：启动/变更前后完整 link、addr、IPv6 flags、wildcard socket inventory、实际运行 ELF/root/maps、syntax stdout/stderr、所有健康原包、两次 peer request/reply、实际 upstream request/reply/source、全部 UBus stdout/stderr 与每次计数采样、失败 traceback 和 TERM / namespace cleanup。

变更前先完成正确健康与 baseline metrics；变更之后、首个 peer request 之前只等待100ms内核状态收敛，**没有 DNS、TCP、HUP 或 UBus 请求**，防止合法其它 caller 恰好更新旧 snapshot。首包是 `cached.acl.test A` 缓存未命中，第二包是同名命中。固定门：

| 相对上一步 | cache inserted | live freed | queries forwarded | local answered | actual upstream |
| --- | ---: | ---: | ---: | ---: | ---: |
| 首次 miss | +1 | 0 | +1 | 0 | 累计恰1个 UDP 请求 |
| 第二次 hit | 0 | 0 | 0 | +1 | 仍累计恰1个 UDP 请求 |

两包都校验 txid、问题、rcode、恰一个 `192.0.2.7 A IN`、reply source 为被查询 local address / 15353、TTL 与实际间隔。没有添加 interface-name/domain 来强迫 existing collector 生效，从而掩盖无发布规则的普通 admission 缺口。健康后的 metrics 只比较增量，启动重试次数不加入正式请求计数。两侧成功之后仍比较回答和计数投影；原始 TTL、时间、upstream wire 不删，TTL 的比较采用按实际时间校验，不能通过任意小 TTL。

## 源码确认与低成本接口

精确 C 同 [NEWADDR 审计](M6B_NEWADDR_PUBLICATION_CONTRACT.md)：`network.c:112–178` 的 `iface_check` 使用 live name；`forward.c:1783–1793` 接收路径先 `indextoname`，失败的 ACL 在非 CLEVERBIND 下才枚举，再验证 `loopback_exception` / `label_exception`（`network.c:190–235`）。ordinary NEWADDR 不应替这些 caller 做事。

Rust `SinglePoll::step_udp` 现把新收到的 `incoming.interface` 交 `listeners::admit`，后者 `.filter(|interface| interface.index == ingress).any(...)` 完全依赖旧 shared snapshot。late / recreated index 旧集合为空时直接 drop，甚至到不了 `process_udp` 的 interface-name 正向枚举；late label 旧地址集合也不能通过 label exception。这个结论来自代码，未冒称实际3个场景已运行。

建议 root 采用两个小边界，不用每请求全 getifaddrs，也不用为名称新建控制 socket：

1. 在实际 wildcard UDP receive caller，以现有 listener fd 做 `net::interface_name(&self.socket, incoming.interface)`。现成函数重用 fd 做一次 SIOCGIFNAME，返回栈 `[u8;16]`，不创建 socket、不分配 Vec。`DnsSocket` 可暴露薄接口 `ingress_name(index) -> io::Result<[u8;16]>`；调用点截到首个 NUL 后，交 pure `iface_check` 对照函数。显式 listen-address 匹配应胜过 excluded-interface；直接 name 匹配和 exclusion 都按现 `name_matches`，不要用旧 ifindex 存在与否 veto name 成功。
2. **只在该 receive caller 的 ACL 失败、且 C 的非 CLEVERBIND 条件成立时**，挂起原 datagram，强制现有 async InterfaceCollector 枚举，完成后重新做 loopback / label exception，再继续该同一包。需要标识是 admission continuation，不能直接复用目前 collector 完成后跳过 admission 的 `pending_interface_udp → process_udp` continuation。loopback 标记只在需要 loopback exception 时通过现 fd 的 SIOCGIFFLAGS 查，label exception 只适用于 IPv4 且 index/destination 匹配新合法枚举列表。

重要接线细节：`enumerate_interface_records` 在无 interface-name/domain 时现早返，仅 `refresh_source_interface_indices`，不更新 shared interface snapshot。上述 admission reason 必须越过该早返并产生真实 collector；只是直接调用既有方法仍不能修 `late-label`。collector begin 的 control socket 失败要保旧代际与本轮 enumerate latch，不能同步 getifaddrs 补偿或绕过 fault-before-clear 合同。

保留既有有效 local-service=net source 检查，以及静态 IPv4 bound socket 的 C 信任规则；不要用这三个 wildcard 场景扩大 static/IPv6 模式。快路径可仅在 wildcard 明确 ACL 或 C 需要定位/例外的 caller 查询 live name；无 ACL 的 UDP hit 不应为了这次修复多做全接口枚举或增加缓冲分配。修后在同源码无 A / A 各补 owner 测试，并对当前正式 CPU 门测出真实增量。

root 已整合的无 A `3d4dbc839c7d7dcf590e207379e40b74442f890b` / A `0d8379b693ca54773a638a0336ee5fbe8658143c` 均保有同一 `DnsSocket` 与 `SinglePoll::step_udp` 接口；下面是可直接移植的薄接口稿，**不是已构建的产品 patch**。在已匹配明确 listen-address、无 interface/exclude 的 ordinary 快路径，不调用 ingress_name，保持原每请求 syscall；只有确实需 live ACL 时调用一次。pure iface_check 不把 loopback 当直接配置匹配，loopback 的特殊许可留给合法 exception caller。

```rust
// listeners.rs: impl DnsSocket，Linux 64-bit 接口
pub fn ingress_name(&self, index: u32) -> io::Result<[u8; 16]> {
    crate::net::interface_name(&self.socket, index)
}

// 与已存在 name_matches/explicit_access 放在同一模块。
// owner 必须先维持已有 local_service_net/source 检查。
pub fn udp_acl_name(config: &DnsConfig, destination: IpAddr, name: &[u8]) -> bool {
    if config.listen_addresses.contains(&destination) {
        return true; // C 的 match_addr 优先于 if_except。
    }
    let selected = config.interfaces.is_empty() && config.listen_addresses.is_empty()
        || config.interfaces.iter().any(|rule| name_matches(rule, name, false));
    selected && !config.excluded_interfaces.iter()
        .any(|rule| name_matches(rule, name, false))
}
```

`step_udp` 只在 actual read 后选择这条路径，不允许 pre-poll 为所有 listener 查询名称。SIOCGIFNAME 失败按 C 立即 drop；成功返回的 NUL 结尾 `[u8;16]` 只借用切片，不转 Vec/字符串。failed live ACL + ordinary 的 continuation 应捕获原 `Incoming`（含源、目的、index）、原包与 listener token/Arc；collector完成后做 exception 判断，成功后再分配 query context / EDNS MAC 查询与 forward，失败就丢原包。不要让 `finish_tcp_accept`、signals 或重复 receive 替这个 pending UDP packet 提供虚假进度。

## 实际执行接口与资格

使用最终候选的 copied feature-off opt3 和 build.json；工具校验实际产品 SHA/bytes、release/opt3/features，并保存全部 driver SHA。`--source-commit` 是源码身份声明，root 仍须把完整源码 / source receipt 与 build.json 外层冻结记录绑定，不能仅凭这个字符串宣称源绑定通过。

```sh
python3 tools/dnsmasq/m6b_interface_acl.py \
  --side both \
  --image-root "$IMAGE_ROOT" \
  --rust-binary "$A_ELF" \
  --rust-sha256 "$A_SHA" \
  --source-commit "$A_SOURCE_COMMIT" \
  --build-receipt "$A_BUILD_RECEIPT" \
  --out "$TOOLS_SOURCE/private/interface-acl-fresh-01"
```

主入口为 C/Rust 各启动独立 run_isolated.sh，再比较；输出必须 fresh private。root 的全局 Oracle 排程、原始证据全量回拷校验后才能 prune 的规则照旧。本门只有3个正常输入，不能代替 full interface/domain、动态/DAD 无 traffic4场景或最终同 ELF 功能资格。
