# dnsmasq-rs 交付账本

日更：2026-10-01 23:33 CEST。本次按用户纠偏重排任务。此文件是唯一维护的进度入口；旧 REPORT、CONTINUATION 和各阶段报告保留作历史证据，不再决定当前工作范围。

## 当前目标

用 AX3000T 实际 UCI 生成的 dnsmasq 配置，让 dnsmasq-rs 完整启动，在隔离环境完成真实 DHCP 租约和 DNS 查询的一次 C/Rust 端到端对照。清单以外的工作暂停。性能工作停止，达到这个目标后再按冻结协议测一次。

已找到原配置，不需要接触设备。来源为 `private/network-research-20260929/runtime/dns-runtime-files.out` 中的 `/var/etc/dnsmasq.conf.cfg01411c`，capture SHA-256 为 `44d61e552774f9085aee1ab67c6351a9c546af23ede5738bcb29e949a1ead317`。私有提取文件在 `private/dnsmasq-rewrite/actual-runtime-20261001/source/rootfs/var/etc/dnsmasq.conf.cfg01411c`，737 字节，SHA-256 为 `273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`。依赖文件和来源身份记在该目录的 `source/identity.json`；配置、地址、租约不进 Git。

参考仍为 AX3000T / OpenWrt 25.12.5 / dnsmasq 2.93-r1 nodhcpv6，匹配 OpenWrt revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`。已有实际配置、镜像和匹配源码供离线使用。物理路由器访问、部署和配置修改仍需另行授权。

## 按阻塞顺序推进的清单

当前剩余 **8 项：7 项实现阻塞和 1 项最终验收**。以下阻塞已经对照实际配置和源码确认；完整原配置启动尚未执行，不能把源码判断写成已跑的启动失败。

1. **原配置和依赖加载。** 补 `read-ethers` 开关及启动时文件接线，按原路径提供 include、用户数据库等依赖。配置与生命周期负责人负责；DHCP 静态配置输入与网络负责人衔接。
2. **真实配置使用的 DHCP 标签。** 接通 range 的 `set:lan`、条件广播与忽略名字规则，以及 include 中的 `dhcp-name-match`。tag/option 负责人负责。当前配置没有自定义 `dhcp-option`，其余 option 和封装格式暂缓。
3. **DHCP 接口与发送选择。** 接通 `no-dhcp-interface=wan`，把标签匹配结果传入广播回复与发送路径。DHCP 网络负责人负责。实际配置和 include 没有 relay/PXE 项，二者暂不进入本轮实现。
4. **目录 hosts。** `/tmp/hosts` 是目录，当前 `read_hosts` 把它当文件读取；需加载其中实际生成的 hosts 文件。DNS 负责人负责。
5. **实际 DNS 策略。** 实现并接通 `domain-needed`、`bogus-priv`、`localise-queries`，随后解除相应启动拒绝。DNS 负责人负责，不以删除校验代替实现。
6. **真实接口监听与来源限制。** 接通 `bind-dynamic`、`local-service`，保留原配置的接口、地址和端口语义。配置与生命周期负责人主责，网络负责人提供接口上下文。
7. **进程启动退出。** 接通用户/组降权、PID 文件及清理，采用原服务所需的运行身份。配置与生命周期负责人负责；检查真实身份和资源，不能忽略配置后以 root 运行当作完成。
8. **一次完整 C/Rust 对照。** 在私有网络和挂载命名空间重建原配置环境，完成 DORA、租约文件、租约 A/PTR 和一次受控上游 DNS 查询。DNS 负责人组织，网络负责人提供客户端和上游环境，主代理整合验收。现成 resolv 文件先复用已有读取路径；只有实际运行证明必要，动态 resolver 更新才加入阻塞清单。

这 8 项按实际依赖推进，可以并行的实现分开负责。新发现只有确实阻塞当前目标时才加入清单；已实现项要有相应运行证据才关闭。

## 四个大块负责人

- `tcp_stream_resume`：DHCP 网络/PXE/relay。本轮负责清单 3 和端到端网络环境；拥有 DHCP daemon/runtime/service 网络接线。
- `reverse_cache_impl`：DHCP tag 与 option。本轮负责清单 2；拥有 DHCP tag/option 配置与编码。需要 daemon 接口时交网络负责人接线。
- `tcp_stream_review`：配置启动与 OpenWrt 生命周期。负责清单 1、6、7，维护真实配置环境，拥有 main 的相应启动流程。
- `cache_rr_resume`：DNS 剩余缺口。本轮负责清单 4、5、8；拥有 DNS 模块、main 的 read_hosts 和 DNS 策略校验。现有租约发布与 A/PTR 路径复用。

主代理负责阻塞顺序、文件归属、整合、提交和最终对照，不再把多个代理投入同一个 DNS 角落。main.rs 已按函数划分修改区域；用户的 `docs/prompts/` 修改保留。

## 验证规则

普通修复采用单元测试加一次 C 差分，不再逐项冻结参考、双 C、负向对照或独立复核。解析器、租约状态机、缓存一致性仍做完整验证，复用已有有效用例。一次通过只证明已执行的范围；失败、启动未执行和 ignored 检查照实保留。大块完成后才写一篇阶段报告，不再产生细小复验报告。

## 私有分支已清结

2026-10-01 已选择归档反向缓存 `0eaaef8` 和 TCP 流式导入 `dff7a39`，未合入产品；没有等待 48 小时到期。原工作树和所有证据保留，三条旧任务分支已删除。

| 内容 | 持久引用 |
| --- | --- |
| 反向缓存及中断的 CNAME 草稿 | `evidence/20261001/dnsmasq-reverse-cache-retired`，tip `51ed499`；已验证的 `0eaaef8` 另有原证据 tag |
| TCP 流式导入参考 | `evidence/20261001/dnsmasq-tcp-stream-import-retired`，tip `32f8db3`，包含 `dff7a39` |
| 反向缓存工具及原 28 项 before | `evidence/20261001/dnsmasq-reverse-cache-gate-retired`，tip `69d8e73` |

CNAME 草稿的新增单元测试编译停在 E0451，未修复、未通过 after 差分，不能当作已交付功能。原 28 项 before 的 4 处差异、多 PTR 顺序差异及成本退步继续保留。NX、interface-name、反向索引和顺序实验停止；后来已经完成的成本证据另存 `evidence/20261001/dnsmasq-reverse-index-cost-retired`。清结操作记录在 ignored `private/dnsmasq-rewrite/north-star-reprioritization-20261001/retirement.json`。

## 产品起点与当前验收状态

纠偏时最新产品功能提交是 `78f1e81`，只合入独立 DHCP FQDN 接线。该原始产品 ELF 为 `f126a762fbb0f1bcdac0e4e2eb61290bd92361f56fcf712213278ed9ba33e391`，已有原 FQDN 服务 8 项、配置 5 项、恢复与名字冲突 22 项，以及 native/musl 库 391、主程序 7 项验证；16 项 ignored 未计通过。这些证据可复用，但不能代替本轮实际配置端到端验收。

旧 SDK 阶段产物仍是 `405b7c1`，仅安装 `/usr/libexec/dnsmasq-rs`，不是替换包。本轮真实配置完整启动、端到端目标、完整 dnsmasq 等价、性能改善和生产验收均尚未完成。
