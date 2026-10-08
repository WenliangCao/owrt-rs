# NEWADDR 的枚举与发布合同

状态：源码审计与独立产品补丁，**未构建、未运行测试、未访问 Oracle**。公共 `main.rs` 由 root 统一整合。补丁基于无 A 的 `0ba856561ad448349de43769590158e9324d3893`；根线程须同样移植到独立 A，分别记录新源码与 ELF 身份。旧 `ae1cdba6` / ELF `e2900727…` 的失败原件保留，不能当修后资格。

## 身份与已观察差异

精确参考为 OpenWrt 25.12.5 `dnsmasq 2.93-r1 nodhcpv6`，镜像 C SHA `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。本地 `private/dnsmasq-rewrite/reference/identity.json` SHA `62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9`，编译参数含 `-DNO_DHCP6`。所有 C 行号是该包参考目录 `dnsmasq-2.93/src/`，不是另找的上游版本。

现有失败汇总 `E/M6B/interface-ae1-failed-01/result.json`（`E=private/dnsmasq-rewrite/evidence`）SHA `ab66514eb673d7637eb724a7d05aaf6aebe38a72f8453f8731a089747f98fda9`。本文处理其中 **7 个正常运行 profile / 17 条失败观测**；35 个 hostsdir 初始化失败和2个 count tracer 收尾失败由其它独立单元处理。

## 精确 C 调用链

| 来源 | 精确 C 边界 | 枚举、发布与失败规则 | Rust 入口与本补丁 |
| --- | --- | --- | --- |
| NEWADDR / DELADDR | `netlink.c:403–410` → event pipe → `dnsmasq.c:1690–1692` → `network.c:1778–1810` | `newaddress()` 仅在 CLEVERBIND、**有效** OPT_LOCAL_SERVICE、DHCP6、relay6 或 RA 时 `enumerate_interfaces(0)`；本镜像后三者禁用。ordinary、local-service=host、只有 interface-name/domain 不枚举。relay4 `iface_index=0` 无条件，不等同重建租约。 | `apply_network_events` 仅 dynamic / 有效 net / 未完初始 DAD 排接口快照；relay4 invalidation 留在条件外。 |
| 显式 ACL 与 host 模式 | `option.c:3485–3492, 6310–6322` | net 与 host 是两个不同标志。if_names/if_except/if_addrs/authserver 清两者；只有 host 转为 loopback + NOWILD。host 不是 NEWADDR 的 net 枚举条件。 | 生产配置先过 `DnsConfig::finalize`。新门读 finalized 的 `bind_dynamic/local_service_net`；不把 host 或 interface-name 规则数当 net。 |
| 初始 IPv6 DAD 未完 | `dnsmasq.c:1222–1231`，配合 `is_dad_listeners()` 的1秒期限 | 每轮 reset latch；存在未完 DAD listener 才枚举并补建 listener，完成后不保永久扫描。地址事件可以提早恢复此已存在的工作。 | 已有 `interface_refresh.retry_at` 表示捕获的未完 listener 或快照失败重试，门仍接受它；dynamic、port0 TFTP、静态 DAD 都不因事件 gate 丢失唤醒。 |
| 正向 interface-name / dynamic-host | `rfc1035.c:2018–2034`；CNAME 同一 `answer_request` 路径 | 仅匹配名字且 QTYPE A/AAAA/ANY 到达原语时枚举。未知名字、TXT、不匹配 class、普通 PTR 不因 interface-name 存在而枚举。 | `process_udp` 的 `interface_forward_name` / cache CNAME preview、pending UDP continuation 保留。 |
| interface-name PTR | `rfc1035.c:1875–1918` | 查询已发布 `int_names.addr`；此分支不枚举。因此新增地址首次 PTR 可仍不存在，正向刷新后才存在。 | 本补丁去掉 NEWADDR 的抢先 publication；PTR 原语本身不动。 |
| TCP accept，首帧之前 | `dnsmasq.c:2025–2048` | accept + getsockname 后，任何 DNS 帧之前先枚举父接口，再检查 admission / fork；child 的枚举被每轮 `done` latch 抑制，保 accept-time 视图。 | `step_tcp_accept` 的 `enumerate_interface_records`、pending accept、`finish_tcp_accept` 保留；新增真实空连接 owner 测试。 |
| server/resolv 成功发布 | `network.c:1564–1584`，`dnsmasq.c:1808–1815` | `check_servers` 在非 NOWILD 下枚举。resolv 真正加载成功才到该 caller；NEWADDR 不调用 `check_servers`。 | `step_dns_files` 的 checks_servers 条件与 continuation 保留；去掉地址快照 changed 路径额外的 server 重新分类及专用 pending flag。枚举内部 server source ifindex refresh 保留。 |
| HUP / INIT | `dnsmasq.c:1570–1594` | 先 `clear_cache_and_reload`。只有 no-poll resolver 或 servers-file caller 才额外 `check_servers`；普通 HUP 本身不枚举。这也决定 hosts/domain 的当前代际。 | file owner 的既定 `checks_servers` / `signal_complete` 条件不动；不以 HUP 合法化此前 NEWADDR 的 eager domain publication。 |
| 启动 | `dnsmasq.c:372–377` | 初始枚举必须先于 `lease_calc_fqdns`，以及接口相关 hosts/domain 初始发布。 | 初始 collector / listener snapshot不动。 |
| 一轮枚举锁存与早期故障 | `network.c:738–750, 775–800` | `done=1` 在 control socket 创建之前；创建失败保旧发布列表，本轮后续 caller 不能再次成功清空/更新。成功创建之后才清 interface-name/conditional-domain/address 列表。 | 现有 `interfaces_enumerated=true` 在 `collector.begin` 前保持；不新增失败后的同轮 fallback。事件 gate 避免本不合法的 snapshot / collector 先消耗 query 的注入故障。 |

参考源码 SHA：`network.c=8229872d…40c9`、`netlink.c=b84884ca…cbd1`、`dnsmasq.c=d4bb7cde…ccd1`、`forward.c=ac05784d…2f95`、`option.c=bdcd4c53…0bed`、`rfc1035.c=231f0b49…722`。

## 主线程整合补丁

完整可应用 diff 随本提交的 `components/dnsmasq/src/main.rs` 和新增 `main_newaddress_tests.rs` 交付。关键统一补丁如下；不能只删第一个条件而保留 ordinary 的事件快照：`listeners::snapshot()` 内部 getifaddrs / if_nametoindex 也可能先消耗控制 socket 故障，然后 query 的 collector 成功，仍得到错误的新代际。

```diff
-                if changed {
-                    if daemon_config.bind_dynamic || daemon_config.local_service_net
-                        || !daemon_config.interface_records.rules.is_empty()
-                        || daemon_config.needs_domain_interfaces()
-                    {
-                        poll.enumerate_interface_records();
-                    }
-                    // 另有 check_server_addresses / pending check 分支
-                }
+                if changed && poll.address_refresh_requires_enumeration() {
+                    poll.enumerate_interface_records();
+                }

                 if events.address {
-                    self.interface_refresh.request();
+                    if self.address_refresh_requires_enumeration() {
+                        self.interface_refresh.request();
+                    }
                     // relay4 invalidation 不在此条件内
                 }

+    fn address_refresh_requires_enumeration(&self) -> bool {
+        self.config.bind_dynamic
+            || self.config.local_service_net
+            || self.interface_refresh.retry_at.is_some()
+    }
```

两条旧 owner 测试显式使用 `bind-dynamic` 后继续验证 port0 和 held-hosts 的实际合法 NEWADDR 唤醒，避免它们固化 ordinary 的错误事件出版。没有改文件读取 owner、tracer、错误注入条件或对照期望。

## 已准备但未执行的 owner 门

| 测试 | 实际路径与断言 |
| --- | --- |
| `ordinary_host_and_acl_address_events_leave_published_generation_and_collector_idle` | finalized ordinary / host / interface ACL / listen-address ACL / excluded-interface ACL 的真实 `SinglePoll.apply_network_events` 后调用 `step`；旧 parent record Arc 与 domain Arc 不变、已存在 collector 仍 idle、listener snapshot不生成、`interfaces_enumerated` 不置真。 |
| `dynamic_net_and_unfinished_dad_address_events_keep_their_real_wake` | dynamic、有效 net、静态未完 DAD 排 refresh，实际 runnable 折叠成 timeout0；DAD 完成后不残留扫描资格。 |
| `ordinary_udp_forward_query_still_starts_and_resumes_its_own_enumeration` | 真实 UDP socket、真实 query 与实际 fd poll；ordinary NEWADDR 不排快照，随后正向 interface-name query 开始 collector，pending query 经真实 dump fd 完成并收到正确有 answer 的响应。 |
| `ordinary_accept_before_first_query_still_refreshes_the_parent_snapshot` | 真实 TCP listener 与仅 connect 的客户端；没有发送 DNS 帧，accept 即开始 collector、park 原连接，完成后父 interface records 已更新且 child 被创建。 |

root 应通过统一 `oracle_build.sh tests` 在新 fresh TMPDIR 上运行原完整入口 tests，不在子分支另建 target。源码与复制 test ELF 前后身份都要记录。以上均没有执行，不能记通过。

## 镜像 C 回归清单

下列7项可先用新输出目录作有界定位，之后须新同 A ELF 重跑完整 ordinary interface/domain 族；partial profile 不能关闭 frozen source row。

| profile | 旧失败位置 | 本修复应保护的合同 |
| --- | --- | --- |
| `domain-interface-publication` | `hup-old-chosen`、`hup-old-fallback`、`old-host-generation-{chosen,fallback}`，4条 | 地址改变不会提早更换 conditional-domain 列表；普通 hosts HUP 使用旧枚举代际，后续合法枚举不改已出版的旧 hosts。 |
| `domain-suffix-interface-publication` | 同上4条 | domain-suffix 的兼容别名同合同。 |
| `interface-udp-ptr-refresh` | `ptr-before-forward` | 新地址先 PTR 使用旧列表，随后正向 query刷新，后续 PTR 才得到新名。 |
| `interface-caller-ordinary` | `before-hup`、`after-hup` | 普通 NEWADDR 与普通 HUP 都不提前枚举；匹配正向 query仍刷新。 |
| `interface-caller-local-service-host` | 同上2条 | host 是静态 loopback，不冒充有效 local-service=net。 |
| `interface-caller-acl-disables` | 同上2条 | 显式接口 ACL 清 net 标志，地址事件不提前出版。 |
| `interface-enum-fault-before-clear` | `faulted`、`ptr-new` | 两侧都实际注入 socket EIO；control 创建失败前保旧 `.9`，不出现 `.10`，保原注入收据与 errno，不重定义期望。 |

关联阳性必须一起跑：`interface-caller-bind-dynamic`、`interface-caller-local-service-net`、`interface-caller-server-file`、`interface-tcp-inherited`、`interface-tcp-removed-cname`、`interface-flag-dad-completion`，以及 `m6b_interface_idle.py` 原4个动态/DAD DNS/TFTP（含 port0）无查询触发的场景。原 count same-cycle tests 保持原计数断言，tracer 的收尾改动由独立工具单元负责。

有界运行沿用当前 source-bound tools、image root、实际产品 ELF、source commit 和同 ELF allocator map，使用 `m5_interface_records.py --side both --mode service` 后重复7个 `--case ID`。完整回归使用 `--ordinary-scope all`，**不能同时加 `--case`**。每次 fresh 输出、实际两个 side、回答内容、注入、cleanup都须入证据。

## 另一个必须守住的 caller 边界

`forward.c:1783–1793` 在 wildcard UDP 的实际 receive caller 内执行 live `indextoname` 与 `iface_check`，只在其失败并需要 loopback/label exception 时非 CLEVERBIND 枚举；localise 的陌生目的地址另有 `forward.c:1808–1810` caller。Rust 目前 `listeners::admit` 使用共享的 listener snapshot；本补丁没有更改该接口。ordinary 显式 interface ACL 在启动后首次出现、或已有接口换了实际 index 的边界，应补一个实际 ingress caller配对，避免此前 eager NEWADDR 快照掩盖 admission 对旧列表的依赖。七失败 profile 的127.0.0.1显式 listener不涵盖这个边界。若配对发现缺口，应在实际 UDP caller 补 live ingress/admission continuation，不能恢复所有普通地址事件的 eager DNS/domain publication 来掩盖它。

本文没有把该未执行边界写成通过，也没有扩展或放宽已有 failure 矩阵。最终资格仍由 root 的新 ELF 功能门决定。
