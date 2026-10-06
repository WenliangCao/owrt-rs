# M5 domain / SRV / synth 极端输入处置

2026-10-06。四个延后边界均已修复或明确保留理由，没有继续延期。新候选 `2522e4a0b84c53b39e6f2fb4d5f3617884d97d3c`（完整身份以[脱敏收据](endpoint-extreme-disposition.json)为准），ELF SHA256 `7f256a35731ae02a5d7d860022587ac3328e1f0ecc81440d199fe926df3ac67d`、1,929,256 字节。镜像 C SHA256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。

同一 ELF 实际执行 6 个语法配对、3 个仅 Rust 的内存安全拒绝、8 个服务配对；服务每侧 104 条观察，最终均零失败。33 项独立负控全拒绝。这里属于极端项处置，最终冻结后的全族统一资格仍须重新运行。两个候选总 ELF 大小相同；同时还有日志改动，不能冒称这是独立的 SYN 体积归因。

| 延后边界 | 实际结果及改动 | 精确 C 位置与处置 |
| --- | --- | --- |
| `domain` / `domain-suffix` 的 `4294967296` prefix | 两 alias 的 `--test` 均接受；分别复用原 `/0` 六地址 hosts expansion 场景、只换 overflow token，全部 DNS 名称、地址、UDP/TCP 与上游副作用严格配对。Rust 显式低 32 位折叠。 | `option.c:750–765 atoi_check`、`:2641–2659`；修复，与 AArch64 镜像行为一致。 |
| 负的 signed IPv6 prefix | 两 domain alias 与 `synth-domain` 的 `4294967295` 均精确退出 1，报 `bad prefix length`。C 危险运行路径未执行。 | `option.c:2679–2697` 只拒绝 `>128`，保留 signed -1；`domain.c:264–279` 调用 `util.c:524–533`，其中 `pfbytes=-1` 被 `memcmp` 转为巨大 `size_t`，且可负索引。Rust 拒绝，避免越界内存读取；该项必须进[账本差异总表](../../DELIVERY_LEDGER.md#与-c-的行为差异)。 |
| 附加 suffix 后的极端 SRV owner / components | owner 两 label 各 63 字节、追加后的总 dotted 长度 253、target dotted 长度 253，以及 port/priority/weight 上界，在 UDP/TCP 严格配对；长度 254 两 alias 精确退出 5，报镜像 `bad srv-host name No error information after domain appended`。 | `option.c:5189–5251`、`:6286–6303` 和 `log.c:476–481`。合法边界保留；非法最终名称的原 Rust 退出码 / 文案已修。该冻结输入的 C errno 为 0，不将 NULL 参数错误说成 `(null)`。 |
| `SYN-PTR/13` 的派生目标长度 | 合法 label 63 / DNS wire 255 与 C 配对。prefix 25 / 47 产生 label 64 / 86；另一输入产生 wire 256。C 实际坏包逐字守卫；Rust 不提交不可编码 PTR，正常向真实上游查询并返回其 NXDOMAIN。仍检查合法 forward、health、单 owner 身份、退出及 FD / PID 回收。 | `domain.c:153–209` 不重新检查派生 target 的 label / wire 长度；`rfc1035.c:1992–2000`、`:1600–1608` 经 `util.c:294–324` 输出 label 64 / 86，或名字终止符令总 wire 达 256。不复制无效 DNS 报文。原 Rust `wire_name(...).unwrap_or(root)` 会伪造 root PTR，现由真实 wire 验证阻止。这项必须进账本差异总表。 |

独立 C 阳性使用合法 SRV profile 中没有 SYN 配置的 IPv4 / IPv6 PTR 查询，真实返回冻结上游的 AA NXDOMAIN (`0x8583`)。坏 PTR 差异守卫要求 C 精确 header、question、RDATA、TTL 0、零上游；Rust 精确 NXDOMAIN 全包、真实且唯一的 `127.0.0.2` 上游、原 question / type，以及两种传输。负控分别改变 C 坏包、伪造 root PTR、删除真实上游、换上游来源、换 question、删除传输行，全部被拒绝；不能靠放宽比较关闭差异。

原 dirty SYN 改动保留在 `evidence/M5/endpoint-closeout-20261006/interrupted-synth-domain.patch`（补丁与 SHA 收据），旧树仍保持 dirty；旧 HEAD 在 `refs/archive/dnsmasq/M5-interface-interrupted-20261006`。实际实现使用 `Name::from_dotted_bytes` 检查可编码性，因为 hosts 的 `canonicalise` 接受某些内部空 label，单用它不能保证不会走 root fallback。

| 实际执行 / 失败记录 | 结果与后续 |
| --- | --- |
| `syntax-before-01` / `2e446f7e` | 6 配对，4 通过；SRV 254 两 alias 的 C 5 / Rust 1 与诊断差异真实红。修复后 `syntax-after-252-01` 6 配对全过。 |
| `service-before-01` / `2e446f7e` | 6 配对；3 合法边界通过，3 不可编码 SYN 的 Rust 假 root PTR 真实红。修复后上述行为已消失。 |
| `negative-v6-before-01` / `2e446f7e` | 3 个仅 Rust 实际语法执行，均拒绝；当时 driver 未强制拒绝断言，不单独当通过。加强精确拒绝守卫后 `negative-v6-after-252-01` 3 项全过。 |
| `service-after-252-01` / `2522e4a0` | 产品已省略无效 PTR 并正常 forward；3 个守卫因误把冻结上游 AA NX (`0x8583`) 预期为无 AA (`0x8183`) 红。保留原红，增加独立 C 阳性，修正夹具。 |
| `service-after-252-02` / `2522e4a0` | 目录已建立，但 catalog 构造的重复 dict keyword 导致未执行任何 C / Rust。原日志与空目录完整归档，失效工具 commit 在 `refs/evidence/dnsmasq/M5-endpoint-driver-fixture-red-20261006`；修正后完整构造 catalog / controls 再运行。 |
| `service-after-252-03` / `2522e4a0` | 6 配对、每侧 32 服务观察；全部通过，6 条明确的坏 PTR 差异（3 场景 × UDP/TCP）严格守卫。 |
| `wrap-runtime-after-252-01` / `2522e4a0` | overflow token 两 alias 的实际 hosts expansion 配对，每侧 72 观察，全部通过。 |

全部 9 份远端目录均完整打包、回拷、逐文件 SHA256 加 metadata 核验后 prune；包括红色、partial 和绿色。metadata 包括类型、mode、uid/gid、纳秒 mtime、链接、设备号、xattr 和 overlay 特殊文件。包 SHA、driver SHA 与逐项结果见[脱敏收据](endpoint-extreme-disposition.json)，完整证据在 ignored `private/dnsmasq-rewrite/evidence/M5/endpoint-closeout-20261006/`。

族清单已将所有这次 endpoint 延后边界标成明确处置，另列 closeout-only cases，冻结的普通 288 required rows、252 syntax profiles、276 service profiles 保持不变。最终 registry 应另跑上述 6 syntax 配对、3 Rust-only 安全拒绝与 8 service 配对，不能把这些处置证据复用为最终统一资格。物理路由器未触碰，未运行 M6 正式性能窗口。

顺带核对的本地记录既有差异属于另一 tester 的最终 replay：`dns-rr=raw.test,65401,gg` 在 `option.c:5091/5103/5116` 将 `parse_hex` 的 -1（`util.c:623–625`）转换为 size_t，再错误比较 32 位 `-1U`，C 报分配失败退出 4，Rust 正常拒绝退出 1；[旧 paired-04](../../../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)有实际原红。CAA 总长 65536 / 65537 在 `dnsmasq.h:403` / `option.c:5144–5149` 先窄化 u16 分配再复制 full strings，既有 `m5_local_records.py --length-only` 的独立语法记录会分类 C SIGSEGV / Rust 安全拒绝。这两个条目必须进最终差异总表；本报告没有重执行它们，也不把历史证据称为新的统一资格。
