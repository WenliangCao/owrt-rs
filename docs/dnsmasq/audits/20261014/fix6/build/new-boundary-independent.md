# FIX6 新增 14-bit owner 边界：第二名审查者独立核验

**确认新增阻断。** `2113d540..3335a978` 的 scratch owner 映射在一个正常配置的较大 TCP 回答中把合法的 `< 0x4000` scratch 偏移变成 `>= 0x4000` 的最终偏移，当前 HEAD 关闭连接而不返回 DNS 回答。精确镜像 C、main、F2 修复前程序均返回合法且完整语义相同的回答；这不是 main 既有问题，也不是拿 C 自己的畸形包作为标准。

本页没有接受首位审查者的 canonical 或结论作为验证结果。我新写 [new-boundary-check.py](new-boundary-check.py)，仅读取原始响应 hex，独立解码并比较所有 header 字段、question、各节顺序、owner/type/class、**未经归零的 TTL** 和完整 RDATA；只规范化名称压缩。校验器还验证名称长度、向后指针、循环、RR 边界、TXT 字符串边界及完整包消费，并从实际配置独立构造 C 预期 Answer/Additional 记录进行断言。一次 TTL 300→301 变异被检出，非法 question label 和非法 Additional owner 均被拒绝。[严格检查结果](new-boundary-result.json)、[校准和文件身份](new-boundary-invocations.json)

## 普通 TXT 主例

在原驱动默认基础配置上添加：

```text
host-record=target.example,192.0.2.77
host-record=example,192.0.2.20
mx-host=target.example,example,10
```

然后生成 61 条不同 TXT 记录：

```python
for i in range(60):
    print('txt-record=target.example,' + f'{i:03d}' + 'x' * 252)
print('txt-record=target.example,' + 'z' * 220)
```

这里没有 `dns-rr`、手写压缩指针或同 owner 的 CNAME 混用。基础配置包含 `local-ttl=60`、`no-round-robin`，上游只用于预热 `alias.example A → CNAME target.example + A 192.0.2.77`（两条 TTL 300）。随后在同一条 TCP 连接查询 `alias.example ANY`。

| 角色 | normal/debug TCP 最终结果 | 具体语义 |
| --- | --- | --- |
| 精确 C | 16,427 B 合法响应 | 64 Answers + 1 Additional，flags `0x8580` |
| main | 16,434 B 合法响应 | 全字段含 TTL 与 C 相同 |
| `2113d540` 产品输入对应的 FIX5 release | 16,434 B 合法响应 | 全字段含 TTL 与 C 相同 |
| HEAD `3335a978` fresh release | **EOF，无 DNS 响应** | 两种运行模式均复现 |

64 Answers 是 alias CNAME、61 个 TXT、target A、target MX；Additional 是 `example A 192.0.2.20`。CNAME TTL 严格为 **300**，其余 64 条 RR TTL 严格为 **60**。所有最终查询均没有上游转发。UDP 四方均为相同的 31 B TC 回答，没有将该正常截断算成新增问题。

我先独立解析 `private/static-txt-boundary01/result.json`，再使用冻结源码中未修改的 FIX5 `terminal_extended.py`，在全新 `private/build-boundary-txt-independent` 内启动 16 个 daemon，重新获得相同结果。所用精确 C/main/before/HEAD SHA 与本轮构建报告相同；HEAD 为 `a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66`。所有进程存活、连接关闭后健康探针成功、最后 SIGTERM 退出 0。这是特定查询没有回答，不是 daemon 崩溃。

## 独立直接终点控制与原因

我另将驱动的最终问题改为 `target.example ANY`，保留 warm alias 查询与其余所有代码/配置，运行全新 `private/build-boundary-txt-direct-target`。**normal/debug × UDP/TCP 四方全部相同**，TCP 都返回 16,400 B。它直接观察了进入缓存 CNAME 拼接之前的合法终点布局：

| 布局 | MX RR 开始 | MX RDATA 开始 | MX target `example` 开始 | Additional 开始 / owner |
| --- | ---: | ---: | ---: | --- |
| 直接 `target.example`，四方相同 | 16,361 | 16,373 | **16,375 (`0x3ff7`)** | 16,384 / `fff7` |
| `alias.example`，C/main/before | 16,388 | 16,400 | **16,402 (`0x4012`)** | 16,411 / C=`c012`，main/before=完整 `example` |

`append_local_terminal` 的 scratch question 比原 query 长 1 B，但缓存 CNAME 前缀增加 28 B，因此后面的同布局 RR 净移 **27 B**。新代码在 `cache_engine.rs:1785–1792` 找到 MX RDATA span，计算 `16400 + 16375 - 16373 = 16402`。`u16::try_from` 成功，于是 1796 行进入 `record_at`；未改动的 `wire.rs:684–685` 明确对 `name_offset >= 0x4000` 返回 `InvalidName`，1809 行向外传播。以上错误路径由实际直接终点/最终包偏移和冻结源码推得；运行时实际观察是 EOF，日志没有单独打印该内部错误。

修复前按 owner 名称选择写法，Additional 的 `example` 不等于之前的 `target.example`，使用完整 owner，返回 16,434 B 合法包。新代码把这条本来可直接写完整名字的 RR 改走了越界压缩偏移路径。因此归属在本次 `3335a978` 改动，而非原来的 `record_at` 校验或 main。

精确 C 的 `rfc1035.c:1532–1535` 将 `nameoffset | 0xc000` 写入两字节，Additional loop 传入 MX 的 offset。`0x4012 | 0xc000 = 0xc012`，客户端解码 offset 18，恰好是 question 内 **合法的 `example` 标签开头**。独立解码结果与 MX target 和配置的 Additional 地址一致；没有标签越界、跳到 TXT 中间、循环、尾部垃圾或 TTL 差异。这里是 C 的溢出写法碰巧得到正确且合法答案的边界，但按本轮标准，它仍是明确的实际语义基准，不能因 C 的内部实现不理想而豁免 HEAD 的 EOF。

## opaque 控制、执行记录与范围

首位审查者最初用 32 个 raw TYPE65401 记录产生相同字节位置：31 个 500 B、最后 429 B。我也独立解码并 fresh 重跑该配置，随后做了相同 direct-target 控制，结论一致；普通 TXT 主例已经排除了需要 raw 配置的前提。

本页共审阅首位审查者两份原始结果（8 个四方场景），并自己 fresh 运行四组（raw alias、raw direct、TXT alias、TXT direct，共 **16 个四方场景、64 次 daemon 运行**）。全部 raw response 和 config 留在 Oracle private，Git 中保留严格检查器、每份源结果 SHA、语义摘要、TTL、关键布局与可复跑 argv。[执行及 private 路径映射](new-boundary-invocations.json)

直接终点控制驱动仅将冻结 `terminal_extended.py` 中两处 `w.query('alias.example', kind)` 替换为 `w.query('target.example', kind)`；没有改动 warm A 查询或产品。独立复跑 profile 从原始结果的完整配置中去掉驱动固定的前 10 行基础配置生成，记录的配置 SHA 逐一相等。普通测试及构建保护通过的结论仍成立，但不涵盖此新的回答回归。未修改产品、未接触路由器、未推送。
