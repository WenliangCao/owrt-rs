# F2 本次新运行及第二套独立解码

**原 F2 已修复。** 本次独立审查重新运行 FIX5 的原始主例，normal/debug × UDP/TCP 共 **4/4** 个四方场景中，当前 `3335a978` 的最终回答与精确镜像 C **逐字节相同**；修复前 `5b914d32`（亦为 `2113d540` 的产品输入）则 **4/4** 重现原来的坏 CNAME。这个结论仅覆盖原 F2，不否定其他审查发现的新回归。

未使用旧的运行结果替代这次运行。实际命令及退出记录见 [invocation.json](invocation.json)；原始输出保存在 Oracle `/home/ubuntu/dnsmasq-audit-fix6-20261014/private/recheck-f2-20261014/result.json`，SHA-256 为 `6fdd20d9df8abac742457fa4f2c333b470e8fb5ff707b916cbed69b8205654dd`。输出目录原先不存在，驱动没有修改：FIX5 `terminal_extended.py` SHA 为 `7ec3edce5f58b098dcadcd05d099fc6fe2ba2eb81358105e5a75e0d5e4017280`，原 `cname-profiles.json` SHA 为 `fd11a9e81a5151f376ab95bd9a1b8b8b15e23cadd05b071b8efce37d549b3084`。

主例没有 host anchor，仍先通过上游预热 `alias.example A → CNAME target.example + A`，然后查 `alias.example ANY`；四条 raw 配置为一个 `c062` 及三个未压缩 `other.example`，顺序与 FIX5 报告一致。TCP 预热与最终查询使用同一个连接。

| 实际 ELF | SHA-256 | 最终长度 | final 上游请求 |
| --- | --- | ---: | ---: |
| 精确镜像 C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 154 | 0 |
| main | `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863` | 223 | 1 |
| before | `7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c` | 196 | 0 |
| 当前 HEAD | `a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66` | 154 | 0 |

这些 SHA 在运行前重新对 Oracle 实际文件计算，驱动亦记录 overlay 内 C 及各 Rust 输入 ELF SHA。完整源码与 ELF 归属由本轮主审的输入核验收据负责；本页不把 ELF 路径本身当成源码身份证明。

本次另写 [decode.py](decode.py)，未导入产品、驱动或之前的审计解析器，也不读取 `canonical` / `checks` 字段。它仅根据原始 hex 解析完整 header、question、各节顺序、owner、TYPE、CLASS、TTL 和 RDATA，名称保存原标签字节且保留重复 RR。客户端语义比较仅展开压缩；HEAD/C 更强的逐字节比较连压缩布局也相同。所有 TTL 严格一致，序列为 `[300,60,60,60,60]`，没有时间容差。原 `fix6/independent/check_f2.py` 亦对这次新结果通过，作为交叉核验。

[完整派生收据](decoded.json) 保留四例原报文、逐 RR 布局、语义、预热/健康/上游数据。C 和 HEAD 的 raw owner 都为 `c02b`，RDATA 位于 `71/98/125/152`；最后的 `c062` 原样保留，offset 98 确实解码为 `other.example`。before 的最后 CNAME 则在 offset 98 读到 `0x70`，第二套 decoder 准确拒绝这一标签；只把这一失败 RDATA 的语义换成正确名称，before 剩下的所有字段都与 C 相同。

main 的最终完整客户端语义与 C 相同，旧有额外转发保留为归属信息。所有四方每例恰有一次预热上游事务；校验 query/reply ID 配对后，仅规范化随机上游 ID，各方预热请求/回答语义一致，main 的最终上游回答亦完整等于 C。全部 **16** 次 daemon 在最终查询后存活、退出 0，预热和关闭 TCP 后的健康回答逐字节等于 C。

独立 decoder 的 [校准](calibration.json) 接受本次原结果，并拒绝用 before 坏回答冒充 fix、修改一位 CNAME TTL、header ID、owner 指针、健康回复 TTL 的五种故意损坏输入。

matching C `rfc1035.c` 重新计算 SHA 为 `231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`，并人工阅读：`:1795–1797` 的真正 CNAME 遍历传 `&nameoffset`，`:1862–1872` 的 raw RR 循环传 `NULL`，`:1610–1617` 的 `"t"` 分支原样复制 bytes。当前修复保留 scratch owner 指针的对应关系，不再让 raw TYPE5 更新 owner 游标；本次观察到的布局和字节与 C 相符。

重跑独立解码：

```sh
python3 docs/dnsmasq/audits/20261014/fix6/recheck_f2/decode.py \
  --input /tmp/fix6-recheck-f2/result.json \
  --output /tmp/fix6-recheck-f2/decoded.json
```

运行完成后按 `/proc/*/{exe,cwd,root}` 检查本次 `recheck-f2-20261014` 目录，无残留 daemon。未修改产品、未接触路由器、未推送，也未删除共享 Oracle 的其他任务进程。
