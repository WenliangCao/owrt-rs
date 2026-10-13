# DNS follow-up audit — 74c6b453

结论限定于 DNS 功能增量：**上一轮 N1 已真正关闭；此次没有确认新的 DNS 功能回归。** 这不代表整分支可合并，持续资源成本由独立性能审计判断。产品代码未修改。

## 身份与方法

- 当前 `HEAD=74c6b453`，main 仍为 `be531cee`；上次报告提交 `5e20291d` 与 `e3a37f55` 的 `components/dnsmasq` 产品内容相同。
- 新 Oracle release：`25b7291d0074b8c7a854aa9f63f7b5edb12bc1315e60dd26f8f6eed36d362fd8`。
- main release：`ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`。
- 上一轮修复分支 release（pre）：`524c327f79080c789f7cdce74125c2af52f6e9c97175414a874ac6e31c9f9c2a`。
- 精确 C：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。

独立审读完整 DNS 增量后，运行原 N1 72 组探针；另写 [boundaries.py](boundaries.py)，比较 C/main/pre/current 四个实际 daemon，针对共享入口的 TTL、OPT、长度、错误码和记录类型顺序补 124 个协议案例。所有服务处于独立 network/mount/PID namespace 和精确镜像 overlay，不使用物理路由器。

[summary.json](summary.json) 保存原始结果路径与 SHA、执行驱动身份、所有分组结果和代表原始包；[collect.py](collect.py) 从原始 JSON 做只读派生，保留 TTL，不使用既有 wire checker 的全 TTL 归一化。大 RR 的全文仍在私有原始结果，派生摘要用字节数和 SHA 替代。

## N1：确认修复

原 [filter_cname_tcp.py](../../../20261012/fix3/dns/filter_cname_tcp.py) 本轮重新执行全部 72 组、216 次进程启动：三轮、普通 `-k`/debug `-d`、SOA/SRV、冷缓存/UDP 预热后新 TCP/同 TCP 持久连接预热，以及开启/关闭 filterwin2k。

**72/72 当前分支和精确 C 的完整 response 字典逐字相同**，包括完整 hex、TTL、flags、AN/NS/AR、长度；上游次数也全部相同，预热响应与次数相同，服务正常退出。没有以“仅 RCODE 相同”代替完整内容检查。

- 旧新增的 24 个 warm + filter 组合：main NOERROR 空答、pre NXDOMAIN，现在 current 与 C 都为 NOERROR + CNAME + SOA。前置 CNAME 优先级修复保留。
- 24 个 warm、无 filter 控制：原 main/pre 的 TCP known-name 缺陷也关闭，current 与 C 一致。
- 冷缓存控制没有被一律改成 NOERROR：无 filter 的真未知名字仍 NXDOMAIN，有 filter 的本地抑制仍为空 NOERROR。

源码链条合理：`main.rs:2715` 在每次非阻塞 upstream step 前从本连接缓存快照或 debug 的当前缓存计算名字存在性；`tcp_service.rs:92` 对当前/挂起问题解析同名查询，`:652` 调用 UDP/TCP 共用 known-name predicate；`reply.rs:308` 包含缓存判断。TCP upstream `tcp_upstream.rs:311-317` 校验响应问题名/type/class，避免把另一个回答名字误用成 query 的缓存存在性。原 `reply.rs` guard 仍限定 RCODE=3、普通 opcode、TC=0。

本轮另外用普通 A 缓存存在性验证新修复：上游后续回 NXDOMAIN，current TCP 现在与 C 一致 NOERROR，main/pre 仍 NXDOMAIN。TC NXDOMAIN、extended RCODE=19 和无缓存名字控制均没有发生误改，四方符合各自既有行为。

## 共享入口、包边界、raw 类型摘要

`daemon.rs:1807-1840` 将 local/cache 选择共用，但 TCP 的 local error→既有 forward/query-error 路径与 UDP 的 error→丢包保留。`service.rs:275-337` 仍区别 TCP local writer 65535 上限与 UDP EDNS 限制、TCP local hit 后 OPT 扫描，以及 address-rule 的 UDP/TCP DO 策略。`cache_engine.rs` 的 transport 限额和 stale/filter EDE 后处理是移动而非删除；接口名与 NXDOMAIN 例外移入共享缓存入口。

新增 124 个边界协议案例的结果：

- 123 个与 pre 的解码响应和上游次数完全相同；唯一改变为上述普通 warm A 名字的 TCP NXDOMAIN 修正，改后匹配 C。
- ordinary 82 案例包含 host/TXT、同类型重复 raw RR、不同 raw 类型、CAA、ANY、缓存 A；EDNS 无/0/512/4096、DO、version=1、截短 Additional、截短 option、重复 OPT。配置 local TTL=37、上游 TTL=120，观察到的 TTL 逐字段保留并与 C/pre 相等，未归一化成空值。
- 12 个极大 raw RR 案例，RDATA 长度 65480/65496/65497，覆盖 UDP/TCP、plain/DO；TCP 能返回 65535 字节，超出时 current 与 main/pre 均 TC 且清空 RR。
- 18 个 local/address CNAME 路由顺序流案例，见下节限制。
- 12 个 warm/cold known-name × ordinary/TC/extended RCODE × UDP/TCP 控制。
- 所有完成记录中的 daemon 均正常退出；普通和超长配置 profile 的 ready/健康检查均通过。

`records.rs:168-182` 的 raw 类型摘要由私有 `push_raw` 维护，dns-rr 和 CAA 两种写入口都使用它，失败解析不会先写摘要；底层 records 声明顺序不变。`local.rs:927-930` 对 ANY 仍扫描全部 raw，具体类型只在确实不存在该类型时跳过。四方运行中的重复 RR 和 ANY 顺序没有变化。该摘要只跳过**无关类型**，同类型大表是否仍有显著成本必须由性能实验判断，不能从功能等值推出性能达标。

## 保留的旧差异、测试失败与覆盖边界

上一轮 O2 的九个 C UDP/TCP 路由差异**未被代码修复为等于 C TCP**。本轮检查 `fix3_repairs/functional/result_checks.py` 与 `wire_compare.py`，它们显式对这九个 case 使用 C UDP 作为共同语义，不是精确 C TCP 等值。不能把其“1852 矩阵通过”写成全部与 C TCP 相同。

本轮 boundary 路由部分是连续查询流，未在每个问题前 HUP 重置；先前请求会改变缓存。因此仅 `route-local / route-6-tcp` 与 `route-address / route-255-tcp` 两个代表重现了原差异：精确 C 本地回答、不转发，main/pre/current 都转发；这两例中当前所有解码字段（包括 TTL）和上游次数均等于 main/pre。其余顺序查询也没有新增字段变化，但不能据此声称九个独立干净缓存场景都已重放。静态增量也未改变 TCP 从原始 alias 选择路由的代码。

极限 65536 字节潜在响应中，精确 C 发出长度为 0 的 TCP frame，main/pre/current 都返回 TC 清空答案。这是原有 C/Rust 差异，不是本轮新增回归。新观察器初版假设收到 reply 至少含 12 字节，遇该 C 空 frame 后在解码阶段退出；之前 90 个已完成案例已保存。没有修改历史结果：保留初版脚本 `R/boundaries.py`、`R/private/dns-boundaries/result.json`，添加短 frame 解码保护和可选 profile 选择后，用 `R/boundaries_v2.py` 在新目录 `dns-boundaries-tail` 完成剩余 34 个案例。当前仓库脚本是可一次运行全部 124 例的修正版。该观察器失败不算产品失败。

未在本轮重新执行：全 14 功能族、所有历史矩阵、TTL 长时老化/stale/max-ttl 组合、上游等待中 HUP/lease 发布、所有 snapshot 竞态、65536 以外随机包 fuzz。相关时间与缓存选择代码做静态增量复核，不能称为全部动态通过。新的功能实验使用 fresh Oracle release，未把这些新探针重跑到 SDK payload。

## 复现

把本目录 `boundaries.py` 上传到新 `R/boundaries_v2.py`；先前 N1 脚本已在冻结源码归档中。输出路径必须不存在。

```sh
R=/home/ubuntu/dnsmasq-fix3-recheck-20261013
OLD=/home/ubuntu/dnsmasq-audit-fix3-20261013
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
sudo -n sh "$R/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$R/source/docs/dnsmasq/audits/20261012/fix3/dns/filter_cname_tcp.py" \
  --tools "$R/source/tools/dnsmasq" --image-root "$IMAGE" \
  --main "$OLD/private/release-main/dnsmasq-rs" \
  --fix "$R/private/release/dnsmasq-rs" --out "$R/private/dns-n1-RECHECK"
sudo -n sh "$R/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$R/boundaries_v2.py" --tools "$R/source/tools/dnsmasq" --image "$IMAGE" \
  --main "$OLD/private/release-main/dnsmasq-rs" --pre "$OLD/private/release-fix/dnsmasq-rs" \
  --fix "$R/private/release/dnsmasq-rs" --out "$R/private/dns-boundaries-RECHECK"
```
