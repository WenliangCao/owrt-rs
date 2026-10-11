# DNS / hosts 独立复核记录

本记录供主审报告引用；未修改产品代码。测试均在 Oracle 的 `run_isolated.sh` 新网络／挂载／PID namespace 中运行，使用合成配置、地址和报文。最终对照产物：

| 实现 | SHA256 |
| --- | --- |
| 精确镜像 C 2.93 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| main 新构建 | `18a692e088bb67a730c809c9eb2263f1eb9cedaa044e6c9b0e579e64ce1010f7` |
| fix 新构建 static PIE | `6ef1857c385c277ee00a186312e2bfb4400abd2eeb4c2a3a7ade9e16219c5c84` |

## F-DNS-01：P2，TCP 缓存 CNAME 被 alias 本地 TXT 抢答，新回归，已复现

**影响**：原来能正确遵循已缓存 CNAME 返回目标 TXT 的 TCP 请求，现在直接返回 alias 的另一个 TXT 值，并将 AA 从 0 改为 1。这改变实际 DNS 内容，不是压缩方式或日志顺序差异。无需恶意报文，常规 DNS 查询与受支持配置即可触发。建议作为合并前修复项。

**配置与步骤**：使用 `cache-size=32`、`cache-rr=TXT`、`txt-record=alias.test,alias-local`、`server=127.0.0.1#15354`。隔离上游首先对 UDP A `alias.test` 返回 `alias.test CNAME target.test` 和 `target.test A 192.0.2.77`，TTL 均为 600；随后对 UDP TXT `target.test` 返回 `"target-upstream"`，TTL 600。两个填充查询完成后，使用新建 TCP 连接查询 TXT `alias.test`。

| 实现 | Answer | flags | 上游请求总数 |
| --- | --- | --- | --- |
| 精确 C | `alias.test CNAME target.test`；`target.test TXT "target-upstream"` | `0x8180`，AA=0 | 2 |
| main | 同 C，整个 TCP DNS payload 逐字相同 | `0x8180`，AA=0 | 2 |
| fix | `alias.test TXT "alias-local"`，丢失 CNAME | `0x8580`，AA=1 | 2 |

普通 `-k` 和调试 `-d` 分别完成上述三方对照，结果一致。三方 A/TXT 填充回复相同，直接查询 `target.test` 的 TCP TXT 也相同，排除了 stub、TXT 编码和缓存未填充的解释。三方进程均继续存活。旧 main 的 UDP 已有同类差异，本分支将错误扩展到了 TCP；不能把现有 UDP 行为当作兼容性 oracle。

**代码依据**：`components/dnsmasq/src/main.rs:2790-2803` 和 `2808-2836` 把 TCP 顺序改成先 `local_tcp_answer` / `tcp_view_local_answer`，仅在本地未回答时检查动态缓存。`components/dnsmasq/src/dns/local.rs:239-270` 的 CNAME 判断只看配置 CNAME，随后能直接回答 alias 的 TXT。因此尚未进入缓存 CNAME 处理就结束了查询。匹配 C `src/rfc1035.c::answer_request` 在约 1754 行先查 `F_CNAME | F_NXDOMAIN` 并替换 name，再在约 1809 行查 TXT；main 原 TCP 顺序在本用例中与 C 相同。修复 DHCP 新 A 被旧 NXDOMAIN 覆盖，不能用“所有本地记录先于所有缓存”替代具体记录优先级。

**证据**：[执行脚本](dns_hosts_cname.py)、[完整报文／日志／三方身份](dns_hosts_cname.json)、[解码、flags、full hex 与因果断言](dns_hosts_cname_summary.json)。执行命令（先把脚本与 `dns_hosts_probe.py` 放到同一私有目录）：

```sh
sudo -n sh /home/ubuntu/dnsmasq-fix-independent-20261011/source/tools/dnsmasq/run_isolated.sh \
  python3 /home/ubuntu/dnsmasq-fix-independent-20261011/private/dns_hosts_cname.py \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust /home/ubuntu/dnsmasq-fix-independent-20261011/private/release/dnsmasq-rs \
  --main /home/ubuntu/dnsmasq-fix-independent-20261011/private/main-release/dnsmasq-rs \
  --out /home/ubuntu/dnsmasq-fix-independent-20261011/private/dns_hosts_cname-fresh
```

## 低影响差异

- **P3，stale 元数据兼容性，已复现，未证实新引入**：使用 `neg-ttl=1,use-stale-cache=30` 先缓存 `client AAAA NXDOMAIN`，等待 2.1 秒，经 DHCP ACK 发布 `client A 127.0.0.30`，随后带 EDNS 的 TCP A 查询。C 和 fix 都正确返回 DHCP A；C 的 OPT 含 EDE 3（stale answer），fix 无 EDE。`-k/-d` 均一致。新 TCP 顺序在 local answer 成功时没有 `CachedAnswer.stale` 来源（`main.rs:2802,2835`）。这是旧 NXDOMAIN stale 位在 C 先行查找中的可见副作用，不应夸大为 DHCP A 解析失败。该实验上游仅监听 UDP，**没有验证 TCP stale-refresh 成功、连接关闭或最终缓存内容**。证据：[脚本](dns_hosts_stale.py)、[结果](dns_hosts_stale.json)。
- **P3，addn-hosts 错误诊断遗漏，既有问题，已复现**：普通 `--addn-hosts` 中 100,000 字节的非法名称，C 报 `bad name ... line 6`，fix 仅报 accepted names 数；相同文件经 `--hostsdir` 读取时两者都报错。`Hosts::read_from` 在 `hosts.rs:312` 丢弃 invalid 回调。合法记录仍正常加载，故不是本次流式读取功能的阻塞项。证据：[脚本](dns_hosts_probe.py)、[结果](dns_hosts_probe.json)。
- SIGUSR1 配置 host 的 flags 中 C 为 `4FRI   HC`，fix 为 `4FRI    C`；来源仍显示 config，未发现业务计数或解析影响。non-terminal、C allocator pool 数字未输出属于原报告已公开的表示差异，不计为新缺陷。

## 已确认有效及覆盖范围

- 全量原 DNS corpus **368** 个 UDP/TCP 组合重新运行，**366** 逐字相同；仅 `forward-pointer` 的 UDP/TCP 两项不同，C 保留的压缩指针形成环，Rust 展开名称，属于原报告已记录差异。原工具带 `--require-match` 的退出码为 **1**，不能把本次运行直接写成工具全绿。证据：[结果](dns_hosts_dns_matrix.json)。
- 独立 hosts parser 与缓存开启的 malformed 查询：普通文件、hostsdir，VT/FF/CR、embedded NUL、100 KiB 超长 token／comment、缺末尾换行；QD=0/2、非法 label；cache=150 时五种畸形 additional；共 **62** 个 UDP/TCP 查询组合，C/fix wire 相同且存活。扩展 malformed 检查弥补原 corpus `cache-size=0` 的局限，但不等价于完整状态化 DNS fuzz。
- 48 MiB 短注释 hosts 文件：无地址空间限制启动、32 MiB RLIMIT_AS 启动、32 MiB RLIMIT_AS SIGHUP 三组均保持 A 记录与正常退出。fix VmHWM 为 1888/1996/2012 KiB，C 1116/1128/1116 KiB；流式读取确实消除了按整个输入文件分配的旧问题。这是特定边界内存验证，**不是**完整真实 hosts 记录规模性能比较。证据：[结果](dns_hosts_memory.json)。
- SIGHUP/USR2/USR1/ALRM × C image/C native/fix 共 12 组继续服务；真实 cache/queries/server/NXDOMAIN 两次 dump 一致；注入租约文件 EFBIG 后恢复限制，ALRM 在 60 秒自动重试前重新持久化租约，USR1 可见租约。沿用已审阅 harness，结果 [dns_hosts_signals.json](dns_hosts_signals.json)。C native 仅辅助，精确镜像 C 为行为 authority。
- 独立 DHCP retained NXDOMAIN 交互：没有 stale 时，新发布 DHCP A 的 TCP 回答在 `-k/-d` 都与 C 逐字匹配，验证原修复目标。stale 时 A 内容仍正确，见低影响差异。

没有覆盖全部动态 CNAME/本地记录组合、各种上游 server retry/撤销/loop-detect 后 SIGUSR1 计数、hostsdir 非阻塞 FIFO 的全部信号与 IO 错误排列、32 位或非 Linux。未触及物理路由器。性能比较由主审独立执行，不能用这里功能测试结果推断无性能退步。
