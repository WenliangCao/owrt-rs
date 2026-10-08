# PTR 目标配置 CNAME 的正式缓存族回归

2026-10-08。工具基线 `b93b9ef938b64688d15a47b6a0d3072a44ec6da5`；本提交只修改 driver、manifest、final recipe、qualifier和本审计，未改产品或公共账本。仅静态阅读和 `git diff --check`，未运行 Oracle、测试或构建。

主线程实际最小服务对照见 [M6b报告](../M6B_REPORT.md)：修复后的无A `1bd9436c/30141ffe…` 与A `ae1cdba6/e2900727…`，在精确镜像C `097a9e21…` 上逐一跑 IPv4/IPv6 PTR × UDP/TCP，8组均原 `case_equal` 精确语义/metrics相等，各组仅1上游、插入1，后两次父UDP命中。该证据只关闭普通caller；最终缓存族同ELF仍要fresh全跑。

本次把 ignored/private driver中 `SCENARIOS=[]` 后添加的4项直接注册到正式 `m5_dns_cache.py`，最终运行不再依赖该monkeypatch：

| case | 种子传输／后续请求 | boundary |
| --- | --- | --- |
| `reverse-cname-v4-udp` | IPv4 PTR，UDP→UDP→UDP | REVERSE |
| `reverse-cname-v4-tcp` | IPv4 PTR，TCP→UDP→UDP | REVERSE、TCP-CALLERS |
| `reverse-cname-v6-udp` | IPv6 PTR，UDP→UDP→UDP | REVERSE |
| `reverse-cname-v6-tcp` | IPv6 PTR，TCP→UDP→UDP | REVERSE、TCP-CALLERS |

配置原字节仍为 `host-record=Local.case.test,192.0.2.2` 与 `cname=Alias.case.test,Local.case.test`；上游PTR返回Alias.case.test，metrics打开，其余transport、TTL、容量、客户端和时间控制沿用原正式driver。复用既有网络schedule、镜像identity、query/reply raw保存和public ubus metrics。C先定义 expected行为，candidate身份仍由最终qualifier绑定。

独立窄守卫只用于新4项：精确config/labels、正常exit、无upstream错误、仅1实际上游且地址/传输正确，以及每个query的 `dns_cache_inserted=1`。旧 `case_equal`、DNS归一、TTL窗口、PTR顺序变化策略和全部旧cases/limits不改；新case的payload、TTL、全部metrics和upstream语义仍由原comparator逐一比较。

普通 `compare_family` 和完整 `m5_dns_cache_qualify.py` 都覆盖该守卫；增加 missing-insertion/zero-insertion/missing-upstream三个窄负控（每个新case各3个），不能把再次转发或未导回当缓存命中。完整qualifier新增 `reverse_cname_caller_guard`，final recipe要求为true。缺任何新case仍由完整集合检查拒绝。

固定inventory同步：C/Rust完整run各增4项；unique boundary required `512→516`（两项TCP映射不会重复计数），完整executed/passed `536→540`。旧8次 C reverse-order重复只覆盖其原4项不变；没有扩顺序矩阵或测试限额。manifest自己的required_count同步516。

下一步由主线程freeze本工具版本，并在同一个最终产品ELF上执行已有 `m5_dns_cache` 完整final-family recipe；本提交不把静态接线或既有8组最小caller证据当作新540项全族资格。原语receipts也不替代这道实际镜像服务门。
