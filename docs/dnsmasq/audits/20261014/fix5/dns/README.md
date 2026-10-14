# FIX5 DNS runtime evidence

本轮全部 daemon 在 Oracle 独立 network/mount/PID namespace 和精确镜像 overlay 中运行；普通/debug、UDP/同一预热 TCP 连接均独立比较同传输 C。镜像 C 不重新编译。产品冻结于 `5b914d32891a5166f8075d108fc98610abc1f885`。

## 已修复的原 F1

原封不动运行 FIX4 的 `terminal_boundaries.py`，四组 `c00c/c02b × dynamic/host-anchor` 各四例。当前 release 的最终响应与 C **16/16 完整语义相同**，包括 TTL；final 上游计数也 16/16 相同。动态组 main/C 相同，anchor 组 main 的旧 helper 仍错。主审的 [严格收据](original-recheck.json) 从原始 hex 解码，只规范化名称压缩，未采用原驱动省略普通 TTL 的比较结果作为最终依据。

同一原驱动的默认 88 例：62 例有效响应与 C 完整语义相同，8 例 `c0ff` 畸形输出与 C 原始报文相同，18 例 TCP local/address 差异全是 main 与 HEAD 逐字相同的 FIX4 O1。不能把 8 个畸形控制称为有效 DNS 回答。原驱动在 TCP 关闭前查询 UDP 健康；精确 C 的 debug 模式会阻塞该连接，因此 104 个原始场景中的 26 个 C debug/TCP 健康探针超时，全部 daemon 仍存活并正常退出；不是 HEAD 故障。

N1 的原 `n1_fresh.py` 72 例再次运行：HEAD 与 C 最终 response 字典 72/72 **逐字节相同**，48 个 warm 回复同样一致；所有 final 上游次数、进程退出和关闭连接后的健康检查一致。

## 新增 F2：raw CNAME 游标与不透明指针交互

[扩展驱动](terminal_extended.py) 从 FIX4 驱动派生，加入显式 `--before` 四方、JSON profiles、匹配 C 语义的 ANY 上游 CNAME fixture，并把健康请求移到 TCP 关闭后。它不改变产品。正式主例不使用 host anchor：

```text
dns-rr=target.example,5,c062
dns-rr=target.example,5,056f74686572076578616d706c6500
dns-rr=target.example,5,056f74686572076578616d706c6500
dns-rr=target.example,5,056f74686572076578616d706c6500
```

先上游预热 `alias.example A → CNAME target.example + A`，再查 `alias.example ANY`。C 的四个 target CNAME 都指向同一个 `other.example`；未用 CNAME+NS 混用作为主阻断。main 转发时，上游提供 AA 的同语义 CNAME RRset，TTL 为 300/60。fixture 内容与每侧 final/warm 流量均保留。

`cname-dynamic-01/02/03` 三个 fresh 四例矩阵均为 C=main=before、HEAD 无效名称。另以同源码构建方式重新编译 d956 后运行 `cname-same-profile`，排除旧 SDK strip/构建模式造成差异。独立审查者使用新解析器重算首组四例：[checker](independent-cname-check.py)、[完整报文及逐 RR 布局](independent-cname-result.json)、[代码解释](independent-review.md)。它没有使用原比较器，也没有忽略 TTL。

C 的 154 B 报文中，最后 `c062` 指向 offset 98 的完整 `other.example`；HEAD 的 196 B 报文中，同一位置为先前全写 owner 内的 `0x70`，不能作为 DNS 标签。main 的 223 B、修复前的 209 B 报文均合法且与 C 完整语义相同。C/before/HEAD final 上游次数为 0，main 为 1；后者是旧额外转发，不能豁免 HEAD 的新增坏回答。

另有 `candidate-anchor-01` 探索性 NS/CNAME 混用反例；它在 `candidate-anchor-02` 用最终扩展驱动重跑，4/4 同样 C=main=before、HEAD malformed，只作 Local 路径控制。探索性首版驱动 SHA 及原始结果保留在 private，最终收据采用可直接复跑的第二组。

## 其他定向控制

[controls-profiles.json](controls-profiles.json) 的 13 个配置展开为 80 例四方控制：MX/SRV Additional、PTR/TXT、配置 CNAME 后接 raw NS、普通 raw CNAME、raw CNAME 后接 opaque/NS、SOA/SRV/RP 指针、450/500 B raw 数据在 UDP/TCP 的截断。HEAD **80/80** 完整语义和 final 上游次数等于 C；before 64/80，另 16 例是修复改善。全部 320 次 daemon 生命周期与连接关闭后的健康检查通过。此矩阵与正式 F2 主例分开计数，不以通过数冲淡阻断。

## 复跑

- [invocations.json](invocations.json)：原 F1、默认88例和 N1 的实际完整 argv；[执行收据](invocation-results.json)。
- [extended-invocations.json](extended-invocations.json)：主例第2/3组、Local 控制第2组、80例扩展；[执行收据](extended-invocation-results.json)。第一组主例与第2组仅输出目录不同。
- [same-profile-invocations.json](same-profile-invocations.json)：同配置 fresh d956 release 的主例。
- 驱动的 `--source` 使用 frozen source；把本目录的 `terminal_extended.py`、三个 `*-profiles.json` 放到 argv 记录的 Oracle 根目录。每次必须选择新的 `--out`。原始流量、rootfs overlay、ELF 和日志留在 `/home/ubuntu/dnsmasq-audit-fix5-20261014/private/`，不要加入 Git。
- [collect.py](collect.py) 从已下载的 `GROUP/result.json` 生成严格收据：`python3 collect.py --root PRIVATE --out RECEIPT.json GROUP...`。primary 的4个完整报文亦保存在独立派生报告中。

[original-recheck.json](original-recheck.json) 和 [extended-recheck.json](extended-recheck.json) 保存全部逐例判断、上游计数、原始文件SHA和实际ELF身份。单纯 `exit=0` 仅表示测试驱动完成；是否存在差异须读取收据。没有静默丢弃失败案例或用 C UDP 替代 C TCP。未测性能、长期 TTL/stale、并发 reload 或完整 DNS 类型空间。
