# FULL-R2 修复与验收边界

基线 `e9d89b17d72a58b723cce88038ceaa1be58d7f8c`，分支
`fix/dnsmasq-full-r2-20261014`，未合 main、未 push、未操作物理路由器。

产品提交：`68f96cf3fb6e0b17f4fc6a9df768c85d1d79a954` 停止并释放失败的 hosts 重载；
`98bc6b58` 保证失败 HUP 仍清除动态 DNS 缓存。复核工具提交 `0dc4df72`。
单独 R2 修复没有包含 TCP hosts 共享，不能代替组合候选的资源验收。

## 制品身份

| 对象 | Oracle 绝对路径 | SHA-256 |
| --- | --- | --- |
| 原 fresh Rust | `/home/ubuntu/full-audit-20261014/private/release/dnsmasq-rs` | `e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0` |
| 68f96cf3 中间 Rust | `/dev/shm/full-r2-fix-20261014/private/release-fixed/dnsmasq-rs` | `b65c06c561a9a852ec42222a5a31be493c742f14d8bc454dbeab22542b26b490` |
| 98bc6b58 最终独立 R2 Rust，2,077,152 B | `/dev/shm/full-r2-fix-20261014/private/release-final/dnsmasq-rs` | `be32a7f3cac5ae9d7ae0df77eb19a07f7d2b41b69779c0302d978868363205c2` |
| 精确镜像 C | `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/usr/sbin/dnsmasq` | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |

源与构建临时文件全部位于 Oracle `/dev/shm/full-r2-fix-20261014/`，没有删除既有证据。
构建采用既定 SDK、musl、release profile 和静态 PIE 参数，没有提高 RLIMIT_AS 或调换 allocator。

## 当前反例与失败路径

首先使用原 `recheck_hosts_limits.py` 对指定 fresh ELF 独立重放：初始 2000 hosts，
各自 VmSize +1024 KiB，HUP 载入 30000 合法新名字。原 Rust 在 23,848 次 ENOMEM 后
SIGABRT(-6)；精确 C 18,036 次 ENOMEM 后存活，解除限制及再次 HUP 后恢复 UDP/TCP。
原始结果为 `private/baseline-repro/result.json`，没有直接沿用旧报告结论。

另用同一基线源码、相同优化参数、仅保留调试符号的诊断构建抓取 gdb 栈：
`HostsReadNotice::Complete → logging::startup::hosts_read:6 → Vec::extend_from_slice → handle_alloc_error → abort`。
诊断 ELF SHA `afbaf0a2c4328db69580c681c264b4b8c1210caf96b2f8172e5a4837206888f3`；
该栈属于诊断 ELF，不冒称给已剥离的交付 ELF 取得了源码栈。原 ELF 中止事实单独实测。

原同步 reader 丢弃 parser 的分配失败标记，又把索引分配失败和重复记录都折叠为 false，
继续读取到内存耗尽，随后格式化完成日志。修复显式传递 parser、索引及祖先节点分配失败，
最迟在当前 8192 B 输入块后停止，释放整个未发布代后再恢复旧视图。正常重复、EOF 和读错误
仍保留既有规则；不把不完整的新代作为成功完成发布。

扩展验收又确认独立差异：失败 HUP 后，原实现保留未过期动态答案 `.12`/TTL58，
C 已重新取得 `.13`/TTL60。`98bc6b58` 将缓存清理移到重载开始，和 hosts 成功发布解耦。
TTL2 的自然过期对照与 TTL60 的失败 HUP 清缓存对照均保留原始请求、响应和上游计数。

## 精确 C 实现参考及语义差异

匹配源码位于 Oracle
`/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/h1-3a/build/openwrt/build_dir/target-aarch64_cortex-a53_musl/dnsmasq-nodhcpv6/dnsmasq-2.93/src`，
OpenWrt revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`。

- `cache.c` SHA `51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`：1494–1532 分配失败跳过名称；1569–1594 先移除旧 HOSTS/CONFIG，保留 DHCP。
- `util.c` SHA `33920165ef3e92f65d1cab75fe8da7772ad7389b37da79ba881957080f12f973`：933–942 的分配失败返回 NULL。
- `log.c` SHA `a205b9cbf9556b01f483b43e732df1ae411c82d622a0e5449f79d43b0267c47c`：文件日志复用启动时分配的 1024 字节缓冲，异步分配失败只记丢失数。

C 在内存不足时可发布新文件的部分可接受记录；Rust 失败时保留完整旧代。
这里只要求进程失败边界、可恢复性及明确的完整代，不声称两者 ENOMEM 后的记录集合相同。
在更紧限制下 C 有 UDP 超时、新 TCP short frame；原始失败均保留，未从分母删除。

## 已执行结果

- 最终独立 `be32…`：原工具 1/2000 初始记录 × +256/+512/+1024 KiB × C/Rust，12 次全部存活、解除限制 HUP 后 UDP/TCP 恢复。
- 中间 `b65…`：2000/+1024、连续两次受限 HUP、DNS 与共享 DHCP 各三重复，12 次 C/Rust 运行存活恢复；Rust 受限 UDP/TCP/DHCP 均健康，C 的受限新 TCP 失败单列。
- 最终独立 `be32…`：shared DHCP、held TCP、自然 TTL 过期、失败 HUP 缓存清除和成功 HUP 恢复均通过。旧 TCP 保持旧代，父视图/新 TCP 的旧新代样本没有混合发布。
- 68f96cf3 的 Linux musl library 784、main 78 通过，20/3 ignored；专用 allocator 测试 7 通过，包含 200 个持续失败切点。98bc6b58 另有失败重载清缓存单元测试；共同源码单元测试由组合报告记录。

独立 R2 的 shared/2000/+256 在 HUP 后 UDP 正常，但首个新 TCP 的原深复制仍可使进程中止，
由 FULL-PERF-TCP 共同修复覆盖。第一份组合 `e2b07561…` 又在 held TCP +256/+512 下发现
回滚旧代的深复制失败、UDP/新 TCP 持续 REFUSED；因此那份组合也不能作为关闭依据。
组合分支另补交互修复并重新验证后，才能认定这些产品修复同时成立。
每项旧/新 hosts 检查包括首、中、尾样本，结合事务代码与分配失败测试；不是 30000 名字全量遍历。

## Oracle 直接重放

OUT 必须是新目录。以下只在 Oracle 隔离 namespace 执行。

```sh
r2_root=/dev/shm/full-r2-fix-20261014/private
r2_tools=$r2_root/source-final/tools/dnsmasq
r2_image=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
r2_elf=$r2_root/release-final/dnsmasq-rs
r2_sha=be32a7f3cac5ae9d7ae0df77eb19a07f7d2b41b69779c0302d978868363205c2
sudo -n sh "$r2_tools/run_isolated.sh" python3 "$r2_tools/recheck_hosts_limits.py" \
  --image-root "$r2_image" --rust "$r2_elf" --rust-sha256 "$r2_sha" \
  --output "$r2_root/reaccept-original" --initial-rows 1,2000 --headroom-kib 256,512,1024
sudo -n sh "$r2_tools/run_isolated.sh" python3 "$r2_tools/full_r2_hosts_recovery.py" \
  --image-root "$r2_image" --rust "$r2_elf" --rust-sha256 "$r2_sha" \
  --source-commit 98bc6b58 --output "$r2_root/reaccept-held-cache" \
  --services shared --repeats 1 --held-tcp --cache-expiry
```

[派生证据](r2-fix-evidence.json) 列出每次结果、工具和构建收据的路径、SHA 及独立判定。
