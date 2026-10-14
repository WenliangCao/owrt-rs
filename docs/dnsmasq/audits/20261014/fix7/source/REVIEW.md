# FIX7 独立源码复核与 writer 原子性探针

冻结产品 HEAD：`02659da6f35fb60ccc916a28b8abf761bf51913c`；增量基线：`137c2882381109daf3e011f77401cd79524a0221`。本子审查没有修改产品、启动 daemon、修改 Oracle 文件或操作路由器。

**静态复核未发现新增阻断。F3 原例的错误路径已被改成完整 owner 写入；它是否与精确镜像 C 全字段相同，需要主审的实际复现作最后裁定。** 本页的本地探针只证明所用 writer 的边界与原子性，不能代替镜像运行结果。

## 输入及参考

- `137c2882..02659da6` 唯一生产代码变化位于 `append_local_terminal`：新增 14-bit 范围过滤，并在 `record_at` 返回 `InvalidName` 时写完整 owner；另有一项产品测试及 FIX4 补充说明。`wire.rs`、`local.rs` 在区间内没有变化。
- 实际本地四份审阅文件逐字等于 HEAD；[source-identity.json](source-identity.json) 同时记录其基线与 HEAD SHA-256。
- 通过只读 SSH 重新核验 Oracle 匹配 C 源码的全部 148 文件。recipe revision 是 `f0a60eee2fe051741c643ea6118718aae1ef17fb`，`src/rfc1035.c` SHA-256 是 `231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`。
- C `add_resource_record` 在 `1532–1535` 将 `nameoffset | 0xc000` 写入两个字节；raw RR loop 传 `offset=NULL`，`"t"` 分支复制原字节。Additional loop 采用 MX/SRV 保存的 target offset。没有把本机编译 C 当作精确镜像结果。

## 改动逐项检查

1. **14-bit 边界。** 当前 `cache_engine.rs:1795` 保留 `0x3fff`，排除 `0x4000` 及以上；不再把 16-bit 转换成功误当成 DNS pointer 可表示。FIX6 原例的 `16402 / 0x4012` 必然落入完整 `example` owner 分支。它比两字节 owner 多 7 B；按原例布局应返回 16,434 B，而不是要求与 C 的 16,427 B 同字节。
2. **失败后重试原子性。** `wire.rs:684–687` 的偏移及名称解码发生在 append 前；`append_record` 的 section-order `InvalidName` 也发生在任何字节与计数写入前。新增重试不会留下半条 RR 或把计数加两次。`Full` 不重试，继续保留现有 TC 路径。
3. **分节顺序。** 两个调用点都由新的 question/Answer CNAME prefix 进入 helper；helper 固定迭代 Answer → Authority → Additional，补充 negative SOA 也只发生在 Authority。没有发现新 fallback 能从合法此路径触发 section-order 错误。若外部误用 writer，section-order 错误重试仍然失败，不是这里新增的合法输入路径。
4. **span 与 owner 长度。** 完整 owner 成功时 `pointer=None`，`1814–1818` 用 `owner.as_wire().len()` 计算真实 RDATA 起点，后续映射不会继续按两字节 owner 计算。只有 scratch owner 本来就是完整名字时才记录 owner span；不把 scratch 的两字节 pointer 当成与完整名字逐字节相同的区间。
5. **F1/F2 的 raw RDATA。** `record.rdata` 仍直接复制；owner map、scratch question→cached target、已复制区间查找均未改变，未恢复名称游标启发式。正常的小报文 raw RR 的布局走与基线相同的路径。F3 常见的 fallback 在 Additional A/AAAA；这些 RDATA 是地址，不含会因 owner 展开而漂移的 opaque 指针。
6. **旧成功路径。** 固定相同的 scratch 内容和初始 writer，基线若一次 `record_at` 成功，该 offset 必然 `<0x4000`，当前过滤仍保留它，参数与后续 span 相同；基线的 `None→record` 路径也不变。按 RR 次序归纳，基线成功返回的路径不会仅因本次分支改动改变输出。行为变化来自基线曾返回 `InvalidName` 的路径。这是源码推断，不是穷举运行证明。

## 本地实际探针

执行 `python3 docs/dnsmasq/audits/20261014/fix7/source/run_probe.py`，使用 Rust `1.98.1 (48a229cea 2026-09-01)` 直接编译未修改的生产 `wire.rs`；临时程序和 ELF 在执行后删除。**9/9 断言组通过，exit 0**。[探针源码](wire_probe.rs)、[运行器](run_probe.py)、[结果与 SHA](probe-result.json)

- 合法完整名字放在 `0x3fff`，`record_at` 写 `ffff` 并正确解码。
- 同样完整名字放在 `0x4000`、`0x4012`、`0x7fff`、`0xc000`，`record_at` 全部返回 `InvalidName`；完整包字节、header 计数和 flags 均保持不变；随后完整 owner 写入与直接写完整 owner 的结果逐字节一致。
- `<0x4000` 但超出当前包长的 offset 返回 `InvalidName`，不改变包。
- Answer 写在已有 Additional 后的 section-order `InvalidName` 不改变包。
- 指向非法 label type 的 offset 返回独立的 `LabelType`，不改变包。
- 剩余空间只容得下压缩 owner 时，完整 owner 返回 `Full`；没有半条 RR、Additional 计数保持 0，TC 按既有设计置位。

## 限制及不作过度声明

- 新 fallback 只接管 `InvalidName`；`decode_name` 的 `LabelType`、`Truncated`、`NameTooLong`、`PointerLoop` 仍传播。后者是原有行为，不能把本次修改描述为修好所有不可解码 owner。
- 完整 owner 占用更多空间，临近包长上限仍可能触发既有 TC；本地探针没有证明所有这类输入与 C 的 Additional 截断语义相同。主审的 F3 原例/边界、F1/F2 及其余 daemon 回归是独立覆盖。
- 没有重跑性能、OOM/allocator fault、长期 fuzz/soak；本页不能据静态同路径论证声称完整 DNS/DHCP 等价或零性能开销。
- 没有把既有 main 差异重新归类为本次阻断，也没有将 C 自身不可解码的包作为有效语义标准。

## 主审 F3 新运行材料的第二次复核

主审运行完成后，本子审查另外阅读 `root/check_boundary.py`、它实际使用的 FIX6 独立 wire decoder、`root/run_boundary.py`、原始 terminal 驱动及本地 `boundary-checked.json`/`boundary-invocation.json`。重新计算 checker/decoder SHA 并与收据核对，通过 [review_boundary.py](review_boundary.py) 检查矩阵、计数、原例配置及状态；[boundary-review.json](boundary-review.json) 保留输入身份。**本步骤没有新启动 daemon，没有将主审这批运行重复计入覆盖，也没有把派生 JSON 当成另一套独立原始解码。**

- **原例没有被简化。** 独立按 FIX6 正文重建基础配置、3 条 host/MX 配置及 60×255 B + 220 B 的 61 条普通 TXT，SHA 为 `c243542d77c1c7e906b4222950cbbb6a6cb6bfa775202380d555a34adfe9a947`，与新运行四个原例逐一相同。主 checker 还逐字比较原 FIX6 12 例的 `config`、`query` 和 `warm_query`。驱动在同一 TCP 连接发送 warm A 与 final ANY，关闭连接后才测健康；没有 raw 指针、额外 host anchor 或 direct-query 替换混入原 F3。
- **计数准确且无重复。** alias 是 3 个 family × 3 个尾长 × normal/debug × UDP/TCP = 36，direct 是 3 个 family 的 220 尾长 × normal/debug × UDP/TCP = 12；48 个 `(group,label)` 均唯一且矩阵完整，每例正好 `c/main/before/fix` 四方。驱动对每一方实际 `Popen` 新 daemon，故这批是 192 次启动。当前 48/48 为有效回答、全字段等于 C；before 明确保留 6 个 EOF（原 TXT、dual、opaque 各 normal/debug TCP 两个），其余 42 个为回答。
- **没有依赖 driver canonical。** checker 直接消费 `response.hex`；decoder 保留完整 header（包括 ID/flags/counts）、question、各节顺序、owner/type/class、未归零的 TTL 及所有 RDATA，只展开名称压缩。它校验后向 pointer、循环、名称/记录边界、TXT 边界和完整包消费；主 checker 又从配置独立构造 C 的完整期望 Answer/Additional。dual 的 AAAA 字节也必须等于完整 16 B 期望值。F3 C 的 `c012` 实际解码为 question offset 18 的 `example`，与 MX target 及配置期望一致，未把非法 C 名字放行。
- **EOF 是负控制，不是语义通过。** checker 对 `before` 指定场景断言响应必须恰为 `{'status':'eof'}`，随后才跳过其 DNS 解码；它从未给这六个 before 填写 `all_fields_equal_c`。当前 EOF、隐藏 before EOF、TTL、Additional owner 及健康状态五种变异均被拒绝。原 TXT-220 两个 TCP 场景 C 为 16,427 B，当前及 main 为 16,434 B 且二者逐字节相同；当前完整 owner 是 `076578616d706c6500`，C 是合法的 `c012`。两者 flags `0x8580`、64 Answers + 1 Additional 及严格 TTL 全相同。

据上述运行材料及断言审查，**支持主审将 F3 原阻断关闭**；这里未发现计数虚增、canonical 掩盖 TTL/owner 差异、或把修复前 EOF 误算为成功的问题。
