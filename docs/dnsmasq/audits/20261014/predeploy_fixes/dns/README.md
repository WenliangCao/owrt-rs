# A / B01、B02 根因隔离与附加 DNS 边界

这里仅记录修复会话新增的最小实验。原审计 focused、日常 DNS、终点/链式
及其它历史回归由相邻 `regressions` 报告记录，不重复计数。

## 根因先于修法

B02 先缩减为：一次外部 alias A 预热 → 直接查询本地终点的 A/AAAA。
删除原复现中的 alias AAAA/TXT/ANY 序列；分别使用 TCP 与 UDP 预热，
预热完成后让所有受控上游丢包。精确镜像 C 的终点 A 均为已学到的
`8.8.4.4`，终点 AAAA 为 NODATA；原审计 Rust 的这 8 次直接查询均为
NXDOMAIN。两个预热回答及四个预热前 NXDOMAIN 控制均一致。

因此后续上游回答替换不是必要条件，TCP 子缓存发布也不是必要条件。
共享 `answer_local_or_cached` 在动态缓存查询前接受了 `local=/lan/`
规则生成的 NXDOMAIN；存在性检查又只看本地配置/hosts/leases，忽略动态
缓存。单测同时断言该终点确实仍在 cache，以区分“缓存被删”与“答案被遮蔽”。
修复将规则答案延迟到实际缓存 lookup 后；本地域名字存在性加入缓存，
且只发送最终答案的规则日志事件。

B01 是另一个调用边界：C `rfc1035.c:1754–1806` 跟随缓存 CNAME 后更改
`namebuff`，TCP `forward.c:2581–2599` 用该名字选路。UDP
`forward.c:2021–2028` 则恢复原问题并交给 `forward_query` 重新提取。
Rust 现在两传输共用同一 cache/local 遍历，只在 miss 后保留这一 C 的
传输差异。TCP 规则、上游组选取及 domain-needed 使用终点，发给上游与
写回客户端的问题仍为原 alias。没有为了使 UDP/TCP 表面相同而改变 C 行为。

## 同功能族扩展

`domain-needed` 在实际捕获配置中已启用。精确 C 增补实验：TCP 预热
`local-chain-dotless.audit.example → auditdotless + A` 后，alias AAAA
及直接终点 AAAA（UDP/新 TCP）均为 NODATA。原 Rust 的 alias 再问上游并学到 AAAA；随后直接终点也返回该 AAAA，
与 C 的 NODATA 不同。B01 首版中间构建虽已停止 alias 上游请求，仍会返回
NXDOMAIN。另用全新 dotless 终点仅 A 预热的控制，原 Rust 的直接
UDP/TCP AAAA 均为 NXDOMAIN，C 均为 NODATA，排除了先前 AAAA 回答的
干扰。这是同一存在性遗漏在 `QueryPolicy` 的分支。

最终实现对原名复用对应 owner/cache view 的只读存在性；对 TCP CNAME
游标显式携带 `ForwardName { name, cached }`，避免在另一个 cache view
重查。源码依据为 `forward.c:2606–2610`、`rfc1035.c:1381–1416` 与
`cache.c:1159–1174`，后者排除 NXDOMAIN、过期及失效 CNAME。

首版 B01 另有被实包证实的构包边界问题：先按短终点构 literal answer、
再替回较长原问题，会使结果超限。已将普通规则与 CNAME 终点共用的
`answer_forward_rule` 直接按原问题构包，不重新执行 hosts 轮转、lease
过期或 cache lookup。配置含 2,332 条 AAAA literal 时，217 B 的原问题
得到 65,513 B 完整应答；2,333 条时，C 返回 217 B 仅问题应答并置 TC。
中间 SDK01 的后一例读到 short TCP frame，证明新增探针能发现错误。
该配置是合成边界配置，不冒称实际 737 B 配置。

## 最终验证结果

被测 Rust 是真实 SDK 源码构建包内 ELF，SHA-256：
`0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`。
产品源码冻结为 `807db8a15e43452414acc048874bf04a4c639bd9`。
精确镜像 C 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。

| 实验 | 原始 / 中间负对照 | 最终 SDK02 |
| --- | --- | --- |
| B02 最小隔离，14 场景/14 交换 | 原审计 Rust 有 8 场景不同 | 14/14 全字段一致，含 TTL、顺序与 flags；各 5 次上游请求均只在预热阶段 |
| dotless，7 场景/8 交换 | 原 Rust 有 5 场景不同；中间 SDK01 的存在性遗漏另保留 | 8/8 交换全字段一致；各 2 次上游请求，均为 A 预热 |
| 长 alias + 2,333 条 literal AAAA | SDK01 short TCP frame，C 返回 TC | 217 B、TC、零 Answer，最终包逐字相同 |
| 长 alias + 2,332 条 literal AAAA | 旧规则选择顺序与 C 不同 | 65,513 B，全部 flags、TTL、地址多重集合及边界相同；记录顺序仍有旧差异 |
| 原审计 Rust 直接 literal 控制 | 同 2,332/2,333 条配置重现相同排序差异 | 证明上一行不是新回退，不将其写成有序/逐字通过 |

上述 daemon 均存活并正常退出 0；最小隔离与 dotless 无 harness error。
本地受影响 DNS 单测族 364 passed、5 ignored；ignored 不计通过，最终完整
单测及历史实包族由总报告和 `regressions` 分项提供。

完整点的排序差异没有被规范化后冒称全字段一致：
[literal-boundary.json](literal-boundary.json) 同时保留有序比较 false、仅排除
RR 顺序的比较 true、双方原始包 SHA、首三条地址，以及原 Rust 直接终点
控制。C 在同域等键 server array 排序后首两条为 `…::91b, …::91c`，
Rust 既有规则遍历为 `…::91c, …::91b`。本任务没有扩展为移植 libc 等键
排序；该合成大规模配置没有出现在实际捕获中。

[summary.json](summary.json) 汇总输入身份和结果；
[observations.json](observations.json) 保存合成名字的逐响应派生观察。
[修复前最小隔离](minimal-before/comparison.json)、
[修复后最小隔离](minimal-after/comparison.json)、
[修复前 dotless](dotless-before/comparison.json)、
[修复后 dotless](dotless-after/comparison.json) 使用原审计严格比较器，
只去掉耗时，不去掉 TTL 或错误类型。

## 执行位置与可复跑入口

Oracle 私有根为 `/home/ubuntu/dnsmasq-predeploy-fixes-20261014/dns/`。
`run.sh` 沿用原审计 actual network/rootfs 包装；`--local-cache-only` 是
B02 最小隔离，`--dotless-cache-only` 是实际 domain-needed 增补。
`predeploy_cname_rule_boundary.py` 直接运行在 `run_isolated.sh` 提供的
loopback namespace，使用镜像 musl 加载精确镜像 ELF。

原始配置、报文、daemon 日志、ELF 均留在 private。此目录只保存散列、
合成名字的派生观察、比较结果与本说明；未触碰物理路由器。

派生报告可用本目录的 `collect.py --root ORACLE_DNS_ROOT --tools
SOURCE_02/tools/dnsmasq --out FRESH_OUTPUT` 重建。`--direct-only` 是追加的
排序前存控制，不把它混作 alias 边界实验；最终两项边界与 actual-config
实验使用冻结 source-02 的工具运行。
