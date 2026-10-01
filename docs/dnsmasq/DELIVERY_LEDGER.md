# dnsmasq-rs 交付账本

日更：2026-10-02。此文件是唯一维护的进度入口；旧 REPORT、CONTINUATION 和细分报告保留作历史证据，不决定当前工作范围。

## 北极星目标已达成

产品源码 `3cfd22e` 使用 AX3000T 实际 UCI 生成的 dnsmasq 配置完整启动，并在隔离环境完成真实 DHCP 租约和 DNS 查询的一轮 C/Rust 端到端对照。8 项主线缺口全部关闭，**当前清单剩余 0 项**。完整 dnsmasq 替换、性能收益和生产验收仍未完成。

原配置没有删除指令或改写语义，737 字节，SHA-256 为 `273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`。它来自已有 AX3000T 运行捕获，连同离线依赖保存在 ignored `private/dnsmasq-rewrite/actual-runtime-20261001/source/`。没有访问物理路由器。

最终流程实际完成：原命令启动、UID/GID 453、UBus注册、DISCOVER/OFFER、REQUEST/ACK、12小时租约文件、FQDN A、短名 A、PTR、一次受控上游 A、原四个 resolver 的首次探测及正常退出。C/Rust 数据和副作用零差异。C参考为匹配 OpenWrt 补丁源码构建的原生程序，实验在构建机命名空间运行，不冒充镜像 ELF、OpenWrt 内核或真机验收。

## 已关闭的八项

1. **原配置与依赖加载。** `read-ethers` 进入启动/HUP，include、账户、hosts等原路径依赖齐备，原配置检查和完整启动均通过。ethers解析与重载29 cases/36 generations一致。
2. **真实 DHCP 标签。** range的`set:lan`、条件广播和忽略名字、实际`dhcp-name-match`规则均已接线。配置C差分114项合同匹配；8项已知未支持边界单列。
3. **DHCP 接口与发送选择。** `no-dhcp-interface`、标签广播和名字策略实包13/13一致。最终E2E发现option28差异，已改为读取实际内核广播属性，保留显式非标准广播地址；修后原闭环通过。
4. **目录 hosts。** 加载`/tmp/hosts`中的实际生成文件，保留文件顺序与排除规则，原配置下租约/本地回答正常。
5. **实际 DNS 策略。** `domain-needed`、`bogus-priv`、`localise-queries`已实现，和目录hosts一起完成UDP/TCP 38/38对照。
6. **接口监听与来源限制。** `bind-dynamic`、`local-service`、IPv6 scope、地址增删和退出清理26/26一致。
7. **进程身份与 PID。** 按原用户/组降权、保留所需能力、PID文件和清理6/6一致。修复了no-ping时多留能力、debug退出不删除PID两处差异。
8. **原配置端到端对照。** 最终`rust-e2e-02`对`c-e2e-06`通过：2个DHCP回复、4次DNS、租约、身份、UBus、各上游端点次数和退出码均一致。

这是一篇大块完成报告，具体范围、身份和失败记录见 [实际配置阶段报告](ACTUAL_CONFIG_STAGE.md)。不再追加逐个复验报告。

## 实现与验证状态

四个大块分别由DHCP网络、DHCP tag/option、配置启动生命周期和DNS负责人交付，主代理已整合进main。相对纠偏起点，产品改动集中在实际配置加载、DHCP规则、网络接口、DNS策略和进程生命周期。没有合入原私有反向缓存或TCP快照实现。

联合源码`f099ffb`已通过native和SDK-musl的库405项、main8项及Clippy/fmt；16项ignored不计通过。之后仅解除已由监听层实现的重复guard及修复广播属性读取；最终`3cfd22e`的相关native/musl解析单元、显式隔离内核检查、Clippy/fmt及musl链接通过。复用已有完整回归，没有为最后两处改动重跑无关全套。

最终功能验证使用的原生调试ELF SHA-256为 `1b0d474ef8c147c1d925a6c7461bed07da6d1375c2dde46e6034293017ea0e3c`。原始结果与所有失败在 ignored `private/dnsmasq-rewrite/northstar-dns-20261002/`；其他模块检查路径在阶段报告中。调试产物只供功能验证，不能用于性能收益结论。

## 失败照实保留

原配置最初因PID选项不支持而不能加载。后续保留的产品失败包括PID能力/退出差异、UDP空闲持锁导致TCP超时、残留接口校验、DHCP option28错误；修复后只重跑受影响部分。fixture的编译器路径、无地址客户端UDP接收、启动身份观察race和四resolver计数假设错误也保留，未当成产品成功或删除。报文和租约等原始数据不进Git。

## 分支已经清理

2026-10-01已归档反向缓存`0eaaef8`和TCP流式导入`dff7a39`，旧分支清除，未合入产品。2026-10-02本轮已完成tag和DHCP网络分支也已清除；当前只保留main，工作树和证据未删除。

| 成果 | 持久引用 |
| --- | --- |
| 反向缓存及中断的未资格化CNAME草稿 | `evidence/20261001/dnsmasq-reverse-cache-retired` |
| TCP流式导入参考 | `evidence/20261001/dnsmasq-tcp-stream-import-retired` |
| 反向缓存工具 | `evidence/20261001/dnsmasq-reverse-cache-gate-retired` |
| 本轮tag/option | `evidence/20261002/dnsmasq-dhcp-tags-options` |
| 本轮DHCP网络/广播修复 | `evidence/20261002/dnsmasq-dhcp-network-actual-config` |
| 本轮DNS与E2E工具 | `evidence/20261002/dnsmasq-actual-config-dns` |
| 本轮启动/监听 | `evidence/20261002/dnsmasq-actual-config-startup` |

用户的`docs/prompts/`修改保持原样。新工作遵循普通修复单元+一次C差分、解析器/租约状态机/缓存一致性完整验证的风险分级；一天只更新本账本一次。

## 尚未交付的范围

实际配置未启用relay/PXE或自定义DHCP option，因此这些能力没有被本次闭环资格化，也没有被从完整重写目标中删除。完整TCP缓存、其他DNS/DHCP/TFTP能力、resolver动态更新、长期运行和OpenWrt全生命周期仍是后续范围。

性能筛选未重启。下一次性能工作须沿冻结协议执行一次，在所测场景功能前置条件成立后开始；不重开旧快照筛选、不挑快窗口或豁免退步。旧SDK阶段包仍是405b7c1，不是本次源码的可替换包。物理设备部署、修改和真机测量仍需另行授权及恢复门。
