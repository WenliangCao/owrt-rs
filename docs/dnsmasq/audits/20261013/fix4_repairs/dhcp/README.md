# DHCP 发布后的负缓存对照

初始数据见 [before.json](before.json)。精确镜像 C 为 `097a9e21…`；修复前分支为 raw 扫描优化后的 `cf94126f…`。所有实验通过 `run_isolated.sh` 在 oracle 的独立网络、挂载和 PID namespace 内运行；C/Rust 均使用精确镜像 chroot，真实 DHCP DISCOVER/REQUEST/ACK 和私有 leasefile，没有物理路由器操作。

## 观察及修复边界

用户要求的 NXDOMAIN 矩阵是初始 A/AAAA/TXT × UDP/TCP 预热 × normal/debug × 有 SOA/仅 neg-ttl，共 24 组、504 条回答对。每组先禁用上游回答，以 UDP 和 TCP 重查证明缓存；再恢复上游、完成真实 DHCP，ACK 后不等待立即查 A，然后查询 A/AAAA/TXT/MX/SOA/SRV/CNAME/TYPE65401 的 UDP/TCP 回答及短名 A。

**精确 C 也保留旧 NXDOMAIN。** DHCP A 已发布后，AAAA 和其他没有本地记录的类型仍返回旧 NXDOMAIN，24 组均无上游访问；Rust 在这些回答上与 C 一致。因此没有删除 NXDOMAIN 来迎合预期。C 在 NXDOMAIN 提取时清除地址类型标志，而 IPv4 DHCP 插入只选择 IPv4/CNAME 冲突；`cache.c:1764–1795` 和 `rfc1035.c:1147–1187` 与实测一致。两份源码的 SHA 已逐项匹配既有 patched-source identity。

实际差异是 **带 SOA 的旧 NXDOMAIN 与新 DHCP A 并存时，Rust 的正回答遗漏 SOA Authority**。有 SOA 的 12 组各出现三次遗漏（ACK 后立即 A、后续 UDP A、TCP A），合计 36 条；其余 468 条完整解码字典严格相同，无 TTL 宽容匹配。C 在 `rfc1035.c:1754–1778` 记住负缓存 SOA，并在 `2391–2415` 附加它，即使后续已获得本地正回答。

独立 64 组边界进一步覆盖 direct/cached-CNAME→DHCP A、RD/DO、normal/debug、UDP/TCP，以及足以溢出 EDNS 512 的大 SOA。C 的 direct A 在所有 RD/DO 组合保留 SOA；UDP 溢出时清空 Answer/Authority、设置 TC 并保留 OPT；TCP 保持完整回答。cached-CNAME 路径修复前已经附加一次 SOA，不能因修复再附加一次。

产品提交 `3d5447a9` 在已确定的本地回答写完 Answer 后、Additional 之前复用现有 `append_negative_authority`。普通本地 miss 在此之前已返回，不新增缓存查找或查询解析。缓存 CNAME 的终点拼接只在本地回答尚无 Authority 时补原 SOA，避免重复。三条新增本机单测验证真实 lease publication 对缓存的保留、RD/DO/容量边界、TXT/raw/MX 节顺序和 CNAME 的单一 SOA；最终 ELF/SDK 复跑结果另行追加。

独立源码复核随后发现首版把报文压缩用的 `extra_owner` 当成了 C 的语义名字游标，产生三个新增边界错误：reverse synthesis 错附原 arpa 的 SOA；配置 CNAME 的 CNAME 查询提前停止后仍查目标 NX；raw TYPE 5 的 RDATA 被误当成游标，甚至对有效输出压缩指针 `c00c` 返回错误。三条回归单测均先在首版失败。`12a5a9b3` 改为仅回传实际配置 CNAME 遍历到的名字，direct 回答沿用问题名，并明确传递实际 reverse synthesis 的旧 SOA 排除条件；raw RDATA 保持不透明。另一个已接受的配置目标 `a..b` 不能构造缓存 Name，`8981ed40` 使可选 footer 查找跳过这种名字，保留原有回答；对应单测也先红后绿。本机最新 local 35 条和此前 cache_engine 9 条通过，日志摘要见 [cursor-review.json](cursor-review.json)。这些本机测试不冒充精确 C 的最终验证。

新增 `dhcp_negative_cursor_diff.py` 准备了 12 组 normal/debug 的真实 C 对照，覆盖 raw TYPE 5 压缩指针、目标/原名 NX、配置 CNAME 早停、direct/配置别名的 reverse synth 与显式 PTR 优先级。raw 原名 NX 用 ANY 查询单独验证 SOA 游标，避开 CNAME 查询的独立 NXDOMAIN RCODE 规则；空缓存的压缩指针保留 CNAME/ANY 两种查询。性能窗口结束后须在最终 SDK ELF 上运行；截至此记录尚未运行。原有 `m5_interface_records.py` 的 `synth-reverse-negative-nxdomain` 同时属于受影响回归族。

终点有效性还保持配置 canonicalization 只移除一次尾点的边界。对 `lease.test..` / `..`，canon 后剩余尾点不可被缓存 Name 转换再次移除，否则会误命中真实名字或 root 的 NX/SOA。参数化单测播种了这两种实际缓存记录，先证实错误附加，再以零分配的剩余尾点检查跳过查找；`a..b` 的原检查同时保留。此轮 local 35 条通过，前后日志收据同样收于 `cursor-review.json`。

## 扩展控制和探针修正

首轮工具额外执行了 24 组 NODATA 控制，原始 48 组完整保留，未覆盖或删掉失败记录。其中 8 组 TXT NODATA 在 C/Rust 都不缓存，禁答证明均超时，属于探针错误前提。最终工具默认执行用户要求的 NXDOMAIN 24 组；显式 `--nodata-controls` 可再运行 A/AAAA NODATA 的 16 组有效控制。

另 8 组无 SOA NODATA 控制暴露了既有 SRV TCP 差异：C 转发并返回带 AA 的 NOERROR，Rust 复用前一 UDP 结果、无 AA 且不上游。一组 frozen main `ad103449…` 对照在 `dhcp-nodata-main-control-01` 重现相同 flags 和上游计数差异；不归为本次新增，不以白名单计成全匹配，也不扩成无关修复。

完整 raw 请求/响应、解码字典、ACK、租约、进程退出和上游记录均保留于 `/home/ubuntu/dnsmasq-fix4-repair-20261013/private/`：

- `dhcp-negative-before-01`：原 48 组，包括共同超时。
- `dhcp-soa-boundaries-before-01`：独立 64 组边界。
- `dhcp-nodata-main-control-01`：main 的单组归属控制。

probe 保留全部 TTL，仅允许 SOA Authority 在两个独立实例之间出现经各自 elapsed 上界证明的相邻秒差；DHCP TTL、flags、节、类型、数据、顺序和上游计数始终严格比较。本轮 NX 24 组没有使用该 SOA 时钟宽容。

## 运行

在新的 private 输出目录中执行，`PYTHONPATH` 指向相同冻结源码的 `tools/dnsmasq`；边界工具与主工具放在同一目录。边界的 `--config-evidence` 使用主工具生成的 summary：

```sh
sudo -n env PYTHONPATH="$SOURCE/tools/dnsmasq" sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$DRIVERS/dhcp_negative_cache_diff.py" \
  --image-root "$IMAGE_ROOT" --rust "$ELF" --out "$PRIVATE/dhcp-negative-new"

sudo -n env PYTHONPATH="$SOURCE/tools/dnsmasq" sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$DRIVERS/dhcp_negative_soa_boundaries.py" \
  --image-root "$IMAGE_ROOT" --rust "$ELF" \
  --config-evidence "$PRIVATE/dhcp-negative-new/summary.json" --out "$PRIVATE/dhcp-soa-new"

sudo -n env PYTHONPATH="$SOURCE/tools/dnsmasq" sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$DRIVERS/dhcp_negative_cursor_diff.py" \
  --image-root "$IMAGE_ROOT" --rust "$ELF" \
  --config-evidence "$PRIVATE/dhcp-negative-new/summary.json" --out "$PRIVATE/dhcp-cursor-new"
```
