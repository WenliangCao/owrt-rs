# hostsdir 事务发布修复独立复核

2026-10-14。`340ed73e83e58ba845e0a645eb21e9ead0d0f108` 的新冻结 ELF
**修复了已复现的无 held TCP、inotify ENOMEM partial publication 边界**。
原反例的全量复跑现在保留 2,000/2,000 个旧名，两个失败新代各 0/6,000，
随后正常 close-write 恢复成功。相邻 held TCP、无压力和失败 HUP 缓存
清除也通过。这是该边界的验收，不是全组件、性能或物理部署放行。

旧 `19bd6162` 的失败证据和两次反例仍保留于
[integrated-reload-review.md](integrated-reload-review.md)，不能以本报告
覆盖旧 ELF 的判定。新的逐执行派生数据见
[inotify-fix-review.json](inotify-fix-review.json)。

## 冻结身份和独立核验

| 项目 | 身份 |
| --- | --- |
| 源码 | `340ed73e83e58ba845e0a645eb21e9ead0d0f108` |
| 新 ELF SHA-256 | `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d` |
| ELF 大小 | 2,089,440 B |
| 精确镜像 C SHA-256 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 原 v2 driver SHA-256 | `a0fd9f5a57188e6459d7e1707e78df59034ac1d647eced953216440581037ade` |
| 原 census wrapper SHA-256 | `cfa0b912752a3d4cb480103a2e592e0ea1b2316ad6a6a7affc8b5d21cefd9da0` |

审计方自行复制新 ELF 至
`/dev/shm/full-audit-resume-20261014/reload-340-inputs/private/dnsmasq-rs`，
实算 SHA 后再启动，每个被测进程再次核验 `/proc/PID/exe` SHA。独立实读
Oracle source 的 647 个文件并实算 SHA，再逐个与 Git `340ed73e:path`
字节对照，全一致；测试后再次核查这 647 个文件无改动。额外只有四个
Python 工具缓存。source 副本没有 `rust-toolchain.toml`；审读 builder
确认显式使用 `+1.98.1`，没有把这项缺失藏在“全文件相同”的表述里。

## 生产路径与分配失败测试

新 `Hosts::try_replace_source(&self, ...)` 从当前 owner 建立工作代，
传播 source 元数据、索引、逐项插入和 ancestor 索引的分配失败；任何
错误都会丢弃工作代，原 owner 保持不变。main 只在完整工作代和第二份
发布副本都成功后切换两个 owner，消除了原路径“忽略 insert 失败、最终
复制却成功”的 partial 发布条件。无需在失败后另行分配来恢复旧代。

独立执行了 peer 新构建的 native Linux `hosts_allocations` 测试 ELF，
SHA-256 `bf2394f348a5ba51ab8d8310abc78ce5f85983403fe469ae9648f9f3dafc82ad`：
**9 passed / 0 failed / 0 ignored**。新增测试直接调用生产 helper 和最后
publication clone，覆盖 shared/exclusive、replacement/deletion、单次及
持续分配失败，并从第一个分配点枚举到首个成功。它检查原 owner 指针、
内容、source 元数据、查询顺序、held 快照及 PTR 所有权。
这项分配器测试与下面的服务级 release ELF 实验分别记数，未混作同一
二进制或重复算作完整 lib/bin 回归。

## 原反例和相邻边界的新运行

8 个新 daemon 执行，C/Rust 各 4 个，均为私有 namespace 和合成
shared DNS/DHCP，初始 2,000 hosts、连续两次替换。每侧使用自身 VmSize
加相同 headroom。没有重新运行上一报告的完整矩阵。

| Rust 模式 | 新行数 | headroom | 两轮 ENOMEM | 源 EOF / hosts 结果 |
| --- | ---: | ---: | ---: | --- |
| inotify，无 held TCP，原反例 + 全量 census | 6,000 | 1,024 KiB | 2 | 每轮 EOF 后 1 次；完整旧代 |
| inotify + held TCP | 6,000 | 1,024 KiB | 2 | 每轮 EOF 后 1 次；完整旧代样本 |
| inotify + held TCP 正控 | 6,000 | 无限制 | 0 | 两个新代完整样本发布 |
| HUP + held TCP + TTL/cache 清除 | 30,000 | 1,024 KiB | 262 | 完整旧代样本；UDP/TCP 缓存清除 |

原反例在解除限制、没有写文件和没有 HUP 的阶段逐个查询全部名字：

| 实现 | old / 2,000 | new / 6,000 | next1 / 6,000 | 错误地址 / 查询错误 |
| --- | ---: | ---: | ---: | --- |
| 新 Rust | **2,000** | **0** | **0** | 0 / 0 |
| 精确 C | 0 | 0 | 6,000 | 0 / 0 |

旧 ELF 在同条件只留下 new 前 3,520 条；新 ELF 保留完整旧代。两轮
inotify 源都确实读到 EOF，随后在客户探针前观测一次 ENOMEM，避免把
“尚未读完整”或探针自身分配失败算成已覆盖发布边界。syscall 层没有
进一步定位 working-copy 与 publication-copy 的具体分配调用点。

四个 Rust case 的配置 DNS、lease DNS、UDP、新 TCP、DHCP ACK 均在
两次压力、解除限制无触发、后续正常触发阶段通过。held TCP 保留接受时
旧 hosts 代；原反例和 held 受限 case 之后的正常 close-write 均成功
替换为 `recovered.test`。解除限制本身没有悄悄加载先前失败的新文件。
无压正控 C/Rust 都依次发布 new/next1 完整样本，说明更新路径本身可用。

HUP case 先证明 TTL=2 到期，再在 TTL=60 答案尚未到期时改变上游并
执行失败 hosts HUP。Rust 的 UDP/新 TCP 均取得新上游地址，held hosts
快照仍稳定。C 的相对限制下新 TCP 仍失败，其 UDP、DHCP、缓存清除与
解除限制后恢复通过；未把 driver 的一般 `passed` 解释为 C 压力 TCP
通过。所有 8 个进程均一直存活并正常停止 exit 0。

## 证据保存与结论边界

原始输出：`/dev/shm/full-audit-resume-20261014/reload-340-*`。
持久备份：`private/full-audit-20261014/resume/reload/fix340/evidence.tar.gz`，
SHA-256 `542f85bfbf0e1b068a46c5658329b80645c2ddeb36788245e5e1cf97628676fe`。
包含冻结 ELF、分配器测试 ELF、构建/测试日志、源码映射、原 driver、
census wrapper、复核器、身份、报文、stderr 和 syscall trace；排除可
重新生成的 staged rootfs。复核器重新解码 903 条已记录 DNS 回复，以及
28,000 对 census request/reply，核对各文件和数据摘要。

本轮可以关闭上述明确反例及已测邻界。除了 census 之外，hosts 原子性
仍按首/中/末样本判定，未声称所有配置、缓存容量、全局 OOM 或任意
allocator failure 都已在服务级覆盖。未操作物理路由器，没有新增性能
结论，也没有把修复方的其他运行加到本报告的独立执行数。
