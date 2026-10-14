# 独立复核 A / B01、B02

日期：2026-10-14。复核分支 `fix/predeploy-20261014`；开始时 HEAD
`aa8f12db`。本分项只判定 DNS 修复和相关回归，不单独批准部署。

**结论：B01、B02 已修好；本轮没有发现新的 DNS 试运行阻断项。**
原问题不是只靠新增单测掩盖：本轮重新运行精确镜像 C 和最终 SDK 包内
Rust ELF，在未改动的实际捕获配置下重新得到客户端包及上游记录。随后
另写查询序列和独立 decoder 扩展缓存、CNAME、本地域、TTL 与 HUP 边界。

| 项目 | 实际影响判定 | 本轮证据 |
| --- | --- | --- |
| A / B01：TCP 缓存 CNAME 终点本地规则被绕过 | 已消除原 P2 阻断 | 原 focused 序列严格一致；断网阶段两版均只向上游发送 A 预热，随后 AAAA 立即空 NOERROR |
| A / B02：缓存终点 A 被本地域规则错答 NXDOMAIN | 已消除原 P2 阻断 | 原 focused 直接 A/AAAA 一致；新三跳链矩阵的 A/AAAA 终点、UDP/新 TCP/既有 TCP 均与 C 相同 |
| 新修复区回归 | 未发现可分级的新缺陷 | 558 对扩展响应：555 对严格一致，3 对只有经时钟区间证实的 TTL 差异，0 个非 TTL 差异 |

## 身份与实现核对

- 精确镜像 C ELF：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
- Rust 包内 ELF：`0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`。
- 实际配置：`273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`。
- 当前 `components/dnsmasq` 对产品冻结 `807db8a15e43452414acc048874bf04a4c639bd9`
  的 Git diff 为空。复用已打包 ELF，本轮没有重建、修改产品或刷机。
- C 用镜像自身 musl/库加载；matching-source native C 只为 UBus fixture。
  本轮直接阅读匹配的 `forward.c`、`rfc1035.c`、`cache.c`；文件散列在
  [closeout.json](closeout.json)。完整参考身份仍见修复报告，不把本轮三个
  文件核对写成重新核验全部 148 个 patched source files。

实现与 C 语义相符：`rfc1035.c:1754–1806` 在可用 CNAME 遍历时改动名字
游标，TCP `forward.c:2581–2610` 用该游标完成本地规则及 domain-needed；
`cache.c:1159–1174` 的存在性排除过期、失效 CNAME 和 NXDOMAIN。

Rust 的对应修复边界是：

- [daemon.rs:1839](../../../../../../components/dnsmasq/src/dns/daemon.rs#L1839)
  保留普通配置/hosts 的先后关系，仅将转发规则结果延迟到动态缓存之后。
- [cache_engine.rs:606](../../../../../../components/dnsmasq/src/dns/cache_engine.rs#L606)
  与 `:632` 保留 CNAME 终点；
  [daemon.rs:1863](../../../../../../components/dnsmasq/src/dns/daemon.rs#L1863)
  仅为 TCP 携带游标，维持 C 的 UDP 原问题选路语义。
- [tcp_service.rs:451](../../../../../../components/dnsmasq/src/dns/tcp_service.rs#L451)
  的 policy 和 `:463` 的选路使用该游标；原始客户端 question 不被改写。
- [cache.rs:420](../../../../../../components/dnsmasq/src/dns/cache.rs#L420)
  的只读存在性与 C 排除条件一致；
  [local.rs:552](../../../../../../components/dnsmasq/src/dns/local.rs#L552)
  将其用于本地域 NXDOMAIN/NODATA 判断。

## 新执行验证

[focused-comparison.json](focused-comparison.json)：原审计工具的 19 场景、
每侧 26 次交换全部严格一致，包含 flags、TTL、记录顺序、内容、客户端
错误类型及存活性。两侧各 16 个上游请求，逐问题/类型/端点/传输计数也一致。
另用新 decoder 重新读取这 52 个原始响应；
[focused-independent.json](focused-independent.json) 保存独立观察。

新增工具 [recheck_dns_local_cache.py](../../../../../../tools/dnsmasq/recheck_dns_local_cache.py)
沿用原审计的 network/rootfs/UBus 生命周期，但独立构造报文、三跳 CNAME
上游回答和查询顺序，不导入产品或原探针 decoder。其 558 对响应包括：

- `.lan`、`.invalid`、无点号终点；UDP 或 TCP 预热 A/AAAA；直接终点与
  alias 查询 A、AAAA、CNAME、TXT、ANY、SOA、HTTPS。
- RD=0、RD=1、CD、EDNS、DO；新 TCP 和在预热连接上继续查询。
- TTL=2 的真实等待 3.1 秒；先直接查询终点，再让 alias 请求重新预热。
  两版既有 TCP 都仍保留接受连接时的缓存/时钟语义，而新 UDP/TCP 已将过期
  终点答为 NXDOMAIN；不是将两种视图强行统一。
- A 预热后 HUP；既有 TCP 仍可确定终点存在并给 AAAA NODATA，新 UDP/TCP
  的缓存已清空并返回 NXDOMAIN，随后 alias 再预热正常。两版相同。

[matrix.json](matrix.json) 保存 TTL 差异、相应原始结果散列和 TTL/HUP
逐响应派生观察。上游请求两侧均为 251，逐名字/类型/传输计数一致。
555 对严格一致。余下 3 对分别为 300/299 秒或 1/2 秒，均保持其它字段
严格一致；每条记录以「上游收到请求至客户端收到预热响应」界定插入时间，
以当前请求发送/响应接收界定查询时间，计算整数秒 TTL 范围。全部落界。
没有用统一“忽略 TTL”冒充严格通过。

[collect.py](collect.py) 在收集时独立解码全部 1,168 个原始响应，验证
完整包消费、请求 ID、question 关联、保存的派生解码及语义比较。
[checker-calibration.json](checker-calibration.json) 记录 14 个 TTL+2
变异和 flags 变异均被拒绝。两个测试组 daemon/upstream 均正常退出 0，
无 harness error，UBus fixture 无失败。

## 证据、复跑与范围

Oracle 独占根：`/home/ubuntu/dnsmasq-recheck-dns-20261014/`。
`run.sh` 使用原 actual network/rootfs 包装，`run-matrix.sh` 仅将末级工具
替换为新脚本。四个最终目录是 `private/{c,rust}-focused-02` 与
`private/{c,rust}-matrix-02`。具体二进制、配置、工具及证据清单身份见
[identity.json](identity.json)。复收集命令：

```sh
python3 collect.py \
  --root /home/ubuntu/dnsmasq-recheck-dns-20261014 \
  --tools /home/ubuntu/dnsmasq-recheck-dns-20261014/source/tools/dnsmasq \
  --out /home/ubuntu/dnsmasq-recheck-dns-20261014/derived
```

首轮 bootstrap 因复制后的工具不在 `source/tools/dnsmasq` 层级，fixture
寻找源文件路径错误，在启动 daemon 前失败；保留 `private/c-focused`，
不计产品缺陷。初版矩阵的 TTL 观察先查 alias，会重热终点，最终矩阵已调成
先直接查终点；初版保留但不重复计入上述 558 对。

收尾重读 3,558 个最终原始证据文件散列，无变化；本任务无遗留测试进程
或宿主挂载，见 [closeout.json](closeout.json)。Git 仅提交合成测试工具、
散列及派生报告；完整包、配置、ELF 和原始运行记录留在 Oracle private。

本分项没有重跑 DHCP 全族、所有历史 DNS 矩阵、B03 异常 TCP 边界、OOM、
长期 fuzz 或路由器性能测试。新增查询仍是原实际配置上的受控合成流量；
不证明实际流量触发频率，也不替代其它分项对 hosts、日志、部署回退与
1,000 qps REFUSED 的验收。本分项未接触物理路由器。
