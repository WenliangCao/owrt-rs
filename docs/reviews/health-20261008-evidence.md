# 2026-10-08 体检原始证据复核

复核日期：2026-10-09。这里只记录独立读取原始数据与精确版本源码所得的结论。修复、CLI oracle、netifd 内核回放及发布判断由总报告汇总，不将旧 GPT 报告作为行为权威。

全部操作为本地文件读取或 oracle 源码读取；未修改路由器。主会话一次只读 SSH 请求得到 `No route to host`，因此没有新增生产观察窗口。原始内容不入 Git。[派生 JSON](health-20261008-evidence.json)保存 56 项证据的 SHA-256、逐窗口九组件身份、重新计算的计数，以及限制。

## 原始材料完整性

- 体检目录 `/Users/USER/Documents/OpenWRT/diagnostics/2026-10-08`：重新计算 `evidence-manifest.json` 列出的 33 个文件的 SHA-256 和长度，全部一致。
- `private/stack-20260929/windows/stock-2-failed-output` 和 `stock-2-retry-failed-output`：分别重新核对 `measurements/live.sha256` 的 59 个文件，均一致。
- 两个 C2 窗口的 `measurements/running-hashes.txt` 各有九个组件；逐项对照 `packaging/image/native-25.12.5.json` 的 `stock_sha256`，18/18 匹配。其中 netifd 是 `8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90`，fw4 是 `c240b413a4cf80617ac1a71f601d2e0edae46b0493e3c00fbe883b2446e4a1a6`。原始 `boot.log` 也记录 stock 模式及九组件身份验证。

这验证了“全 C 栈”前提，不能仅凭目录名 `stock-2` 下结论。

## WAN6：原版栈也有公网地址撤回与恢复

以下都是 `ubus network.interface dump` 原始 JSON 重新解析的 `wan6` 数据；不保存地址本身：

| 原始文件（相对 `private/stack-20260929`） | WAN GUA | WAN ULA | 路由 | PD |
|---|---:|---:|---:|---:|
| `windows/stock-2-failed-output/measurements/live/network.json` | 1 | 5 | 18 | 1 |
| `c2-failure-diagnostic/network.stdout` | 0 | 5 | 16 | 1 |
| `c2-failure-diagnostic/repeated/00-network-before.stdout` | 1 | 3 | 22 | 1 |
| `c2-failure-diagnostic/repeated/06-network-after.stdout` | 1 | 3 | 22 | 1 |
| `c2-failure-diagnostic/repeated/07-network-before.stdout` | 1 | 5 | 18 | 1 |
| `windows/stock-2-retry-failed-output/measurements/live/network.json` | 1 | 5 | 18 | 1 |
| `c2-failure-diagnostic/after-retry/network.stdout` | 1 | 5 | 18 | 1 |

第一次 C2 的事后 `fw4.diff` 仅改变 `wan_subnets` 一行：公网 `/64` 消失，ULA 顺序改变。重试后的 `fw4.diff` 则只改变相同集合成员的顺序，没有公网成员删除。13 轮 repeated 的 26 个快照都带 GUA，但在第 06/07 轮之间 ULA 和路由成员发生变化。

2026-10-08 的 `raw/ubus-monitor.txt` 中只解析客户端进入 ubusd 的 `<- ... invoke`，避免将转发的 `->` 同一请求重复计数。`notify_proto` 且 `interface=wan6` 共 13 次；第 2、3、5、9、11 次不带公网地址，分别只有 5 个 ULA 地址和 16 条路由；其余是 6 个地址和 18 条路由。13 次都带 PD。省略地址发生于 netifd 的输入边界之前，这一报告条目成立。

**分类：上游网络方向证据较强，但排除 Rust→内核→odhcp6c 反馈仍须看本轮独立内核回放。** 全 C 栈历史中的相同症状反驳“Rust 独有”，却没有 RA 报文或时间关联足以指认某个上游发送者、租期参数或恶意广播。不能用 ifupdate 去重掩盖成员变化。

## odhcp6c 为何可以使查询读端提前消失

oracle 上精确源码根为 `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components`：

| 组件 / 文件 | 已核对 git HEAD | 文件 SHA-256 |
|---|---|---|
| `odhcp6c/src/script.c` | `07d324ee7222c0e15b9975281f18236fdccc11bd` | `c3251b23ebef2f565e0554fb9ab511e513aae9a117446ea757f04aa652f936b9` |
| `procd/signal.c` | `58eb263d5abe03f8c1280bdfa65a3b052614215d` | `b209cf27025ebaad20df43c18a5c5e788491d7abc7235b22bdc8fc170235ddd6` |

两个 checkout 的 `git status --porcelain` 均为空，版本与镜像 `sources.json` 一致。odhcp6c 配方没有补丁。`private/upstream-ref/dhcpv6.script` 的 SHA-256 为 `7b5208d7bad126359061bc1c2e6e1e75bab40ac9779070b3064ae4bada9d4de9`，与配方 overlay 哈希相同。

- `script.c:444` 的 `script_call()` 由状态通知调用。第 452–456 行发现 `running > 0` 就 `kill(prev, SIGTERM)`；随即在 469 行 fork 新处理者，477–479 行把 `running` 指向它。没有等待前一脚本完成，也没有杀整个进程组的 `killpg`。SIGCHLD 的 48–57 行只负责非阻塞回收。
- 新子进程第 490 行将 **SIGTERM** 设为默认；没有恢复 SIGPIPE。延迟后构造环境，571 行 `execv()` 执行脚本。
- 匹配 `dhcpv6.script:174` 执行 `ZONE=$(fw3 -q network $INTERFACE 2>/dev/null)`。脚本被 SIGTERM 终止会关闭这个命令替换的管道读端；还活着的 fw3 写端之后可能得到 EPIPE。这是源码确认的可行机制，现有 core/日志没有逐进程信号轨迹来证明每一次事故都由这一条路径触发。
- C `procd/signal.c:90` 忽略 SIGPIPE，匹配 C netifd `main.c:328–329` 也显式忽略它。Rust `components/procd/src/proc.rs` 保留这个 exec 继承行为。体检 `raw/processes.txt` 的 procd、netifd、odhcp6c 均有 `SigIgn=0000000000001000`（SIGPIPE 位）。原版链路下 EPIPE 可见，而非进程被 SIGPIPE 立即终止。

**分类：脚本替换、SIGPIPE 忽略及 shell 的 `cat: write error: Broken pipe` 属原版行为。Rust fw4 把 EPIPE 转成 panic/SIGABRT 才是我们的缺陷。** 不应修改 odhcp6c 的调度或 procd 的继承约定来掩盖 fw4 问题。

## core 与其它体检项目

| 项目 | 分类 | 独立核对与结论 |
|---|---|---|
| `/tmp` core 积累 | 我们的缺陷之结果 | `cores.txt` 有 90 个文件，逻辑长度合计 22,560,768 字节，`final-snapshot.txt` 另有 `du` 汇总 10,128 KiB；`core-classification.txt` 有 90 条 broken-pipe 扫描记录。本地只有 first/latest 两个 ELF 原件；两者都含 `failed printing to stdout: Broken pipe (os error 32)` 和 `fw3 -q network wan6`，独立按 ELF64 PT_NOTE 解析 NT_PRSTATUS 的 `pr_info.si_signo` 与 `pr_cursig` 均为 6。修复输出路径；不新增轮转。 |
| WAN IPv4 60 秒租期 | 上游网络 | 原始日志有 288 次原版 udhcpc 的 `lease ... obtained ... lease time 60`。没有九组件自行缩短租期的证据。 |
| 外部 IPv4 TCP/53 超时 | 上游网络方向，精确位置证据不足 | `dns-tcp-tests.json` 中三个直接外部 IPv4 目标 exit 9；本地 TCP DNS、随后本地外部解析及直接上游 IPv6 TCP DNS成功。conntrack 记录 router-originated SYN_SENT/UNREPLIED，原始 nft output/forward-to-WAN 是 accept，没有观察到 DNS 专用拦截。支持外部 IPv4 TCP 路径异常，不足以声称已证明运营商哪一跳封锁；没有修九组件的依据。 |
| 某 2.4 GHz 终端 TX failed | 证据不足 | `wireless.txt` 原始驱动累计计数为 32,202 / 315,374，信号约 −34 dBm。只是单台终端累计比值；没有前后增量、同负载 C 对照或无线驱动因果轨迹，不能归责九组件，不能当全网丢包率。 |
| mt7530 探测超时 | 原版行为 | `dmesg.txt` 中 2.639700 秒的 reset timeout / −110 随后伴随 AN8855 成功初始化，15.204238 秒 WAN 1Gbps/Full。发生在保留的内核/驱动边界，没有证据关联九组件；闲置 LAN 口没实测。 |
| 日志窗口短 | 原版配置行为 | `cores.txt` 明示 log_size=128 KiB；`logread.txt` 为 1,273 行，15:10:02–17:33:53，共 143.85 分钟；其中 594 条 wan6 防火墙 reload、288 条短租期、28 条 cat Broken pipe。建议经另行批准配置远程日志并设接收端容量/保留期；可按内存余量扩大 RAM 环形日志，避免持续写设备 flash。本轮不改配置。 |

日志中的 594 / 143.85 = **4.129 次/分钟是 WAN6 firewall reload 行的平均速率**；它不是精确的所有地址写入计数。短观察中的 13 次 notify_proto / 45 秒是另一种事件口径，不应混用。

## 不成立或不能扩大解释的条目

1. **“90 份 ELF 都在本地 raw 中，并已逐份重新分析”不成立。** 本地实际只有两个 ELF；90/90 只获得当时的路径列表与签名扫描记录支持。最早/最新两份独立解析为同类 SIGABRT，生产当前不可达，未补取其它 88 份。
2. **“C2 每次失败都确证为公网撤回”不成立。** 首次事后快照与 diff 确有公网成员撤回；重试事后 diff 只有成员顺序变化。两次 `live.log` 都只有 stdout byte validation failure，`1-fw4.json` 是空文件，失败 invocation 的实际 stdout 没保存。历史材料能证实状态漂移并支持解释，但无法还原该失败瞬间的精确字节。
3. **“LAN 前缀顺序问题在 r2 一定仍未修”不是事实前提。** 必须检查 `a4053dd5` 的实现/历史和本轮测试；这份原始证据审计不把旧报告的未关闭状态当作当前状态。
4. **“4 次/分钟就是所有地址内核改动速率”“TX failed 比值是全网丢包率”“多个 ULA 是恶意 RA”“超时已定位到运营商封锁”均没有现有证据支持。**
5. **“shell Broken pipe 是 Rust procd 错误”不成立。** 精确 C procd/netifd 本来就忽略 SIGPIPE；执行面会替换脚本。修复边界是 Rust 一次性 CLI 的输出失败处理。
6. **“21.5 MiB 的 core 逻辑大小等于 RAM 实占”不成立。** 逻辑大小已独立复算；`raw/final-snapshot.txt:4` 的分配汇总是 10,128 KiB（约 9.9 MiB），应明确区分稀疏文件逻辑大小与实际分配。

## 可复算命令

以下命令只读本地原始材料；不会调用生产 fw4 或改变设备：

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json, ipaddress
r = Path('/Users/USER/Documents/OpenWRT/diagnostics/2026-10-08')
for f in json.loads((r / 'evidence-manifest.json').read_text())['files']:
    b = (r / f['file']).read_bytes()
    assert len(b) == f['bytes'] and hashlib.sha256(b).hexdigest() == f['sha256']
updates = []
for line in (r / 'raw/ubus-monitor.txt').read_text().splitlines():
    if not line.startswith('<- ') or '"method":"notify_proto"' not in line:
        continue
    d = json.loads(line.split('invoke: ', 1)[1])['data']
    if d.get('interface') == 'wan6':
        updates.append(any(ipaddress.ip_address(a['ipaddr']).is_global for a in d.get('ip6addr', [])))
print('inputs', len(updates), 'without global', updates.count(False))
PY
```

源码复核（oracle 只读）：

```sh
ssh oracle 'git -C /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/odhcp6c rev-parse HEAD'
ssh oracle 'sha256sum /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/odhcp6c/src/script.c'
ssh oracle 'nl -ba /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/odhcp6c/src/script.c | sed -n "444,494p"'
```
