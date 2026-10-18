# odhcpd-rs 独立审计：配置、ubus 与运行期边界

初审结论：发现 **2 项 P1、1 项 P2**，原冻结产物不应继续发布/部署。
后续定向复验已在 `e33fa56c` 闭合 CR-1/2/3，证据见末节；这不构成发布或部署许可。
本审计不修改产品、不访问物理路由器、不刷机、不发布，也不涉及性能或 PGO。

## 范围与证据身份

- 独立审阅 `components/odhcpd/src/{config,control,main,netio}.rs`；这四个文件与
  `d0ef9f04` 无差异。审计进行期间其他代理对 DHCPv6 的新提交不属于此处基线。
- 精确 C 源码：`5d7be43f8b9dec0eb47e245cfab81108bb131273`，Oracle 路径
  `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/odhcpd`。
- 实验 C ELF SHA-256：`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
- 实验 SDK Rust ELF SHA-256：`79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`。
- `/home/ubuntu/odhcpd-image-v024-20261018/rootfs` 只读复制；每例使用新的
  mount/net/PID namespace、复制后的 rootfs 和私有 ubusd/provider/veth client。
- 所有新文件位于 `/home/ubuntu/odhcpd-audit-control-20261018-QOfzrV`，下文简称 `E`。
  未使用或修改 dirty `/home/ubuntu/owrt-control-plane-rs`，未操作其他运行目录。
- 新结果直接来自本次反例；以前的 passed 结果未当作审计证据。

## CR-1 / P1：事件队列判空后清理通知，存在丢唤醒竞态

位置：`control.rs:107-127`，消费者 `main.rs:505-513,768-773`。

`Bus::try_event` 先 `events.try_recv()`，随后读 wake socket。判空分支最多消费
64 字节通知，却不再检查事件队列。以下合法交错会丢掉新事件唯一的通知：

1. owner 的 `try_recv()` 返回 `Empty`。
2. worker 的 `emit` 成功入队 `Network` 或 `Request`，然后 `notify` 写入一个字节。
3. owner 读走这个字节，仍返回先前计算的 `None`。
4. `bus_events` 停止 drain。后续主循环只有 wake fd readable 才重进 `bus_events`；
   一秒协议定时器、数据包活动均不会主动检查这个事件队列。

因此网络快照可能一直不生效，ubus 调用可能超时；只有后续新通知等外部事件才能解救。
队列容量、generation 校验和 worker 的周期 poll 不会恢复 owner 丢掉的通知。

**验证与确定性：** Oracle 上编译运行 `E/odhcpd_lostwake.rs`，使用真实
`sync_channel(8)`、非阻塞 `UnixStream::pair()` 和 rendezvous 强制上述交错。
它提取原实现的判空/读通知顺序，结果为：

```text
returned=None wake_read=WouldBlock event_still_queued=true
```

这是确定性的并发反例模型，**不是**声称在未修改 SDK ELF 上概率命中了该调度窗口。
模型只增加交错控制，不依赖时间测量。现有 `control.rs` 私有总线测试直接循环调用
`try_event`，会绕过生产主循环的 fd-ready 条件，因此不能排除此反例。

修复目标：通知清理与队列检查顺序必须保证返回 `None` 后，队列中新到事件仍有可见通知；
回归测试应包含这个交错以及生产的 readiness 驱动消费方式。

## CR-2 / P1：新增接口局部 bind 失败导致全部既有服务退出

位置：`main.rs:245-266,303-304`，上抛链为 `reload:218` →
`bus_events:542` → `run:773` → `main:812-815`。

输入：`br-lan` 已正常提供本机 RA/DHCPv6；新建另一条 running veth `broken0`，
由私有测试进程在该设备独占绑定 IPv6 UDP 547；netifd 完整 dump 新增：

```json
{"interface":"extra","up":true,"l3_device":"broken0","data":{"ra":"server","dhcpv6":"server"}}
```

这是另一个接口的服务冲突，没有修改既有 `br-lan` 的配置、地址或链路。
精确 C `config.c:reload_services` 对各接口调用 setup，局部失败不结束进程；
Rust 的 `Socket::open(...)?` 直接结束整个运行循环。

| 本次结果 | 精确 C | 冻结 Rust |
| --- | --- | --- |
| 新接口日志 | `bind(): Address in use` | `Address in use (os error 98)` |
| 原 daemon 状态 | 仍运行 | exit 4 |
| 原 br-lan DHCPv6 Information-request | 有回复 | 超时 |
| 原 br-lan RS | 有 RA 回复 | 超时 |
| `dhcp.ipv6leases` | 成功 | object Not found |

**验证与确定性：** `E/c-conflict`、`E/rust-conflict` 的 `results.json` 和
`odhcpd.log`，各一次精确 ELF 实包对照。两边故障注入前都已验证 DHCPv6 和 RA 可用。
独占 socket 生命周期覆盖整个故障观察窗口；结果与明确的 `EADDRINUSE` 错误链一致。
没有运行 procd 自动重启，因此不推断真机重启次数；可确定的是原进程及全部协议服务退出。

修复目标：将新增/重开服务失败限制在相应接口，并保留无关活动接口，安排明确重试。
不能只在 `reload` 外层吞掉错误：`services` 先 `mem::take` 旧集合，早退还会丢掉
尚未迁移的服务。启动时明确拒绝不支持模式的要求应继续保留。

**保留的阴性结果：** 最初预测“新接口 `disable_ipv6=1` 会令 socket setup 失败”被
`E/c-secondary`、`E/rust-secondary` 推翻：两者均保持原接口服务，均未退出。
该输入不构成本报告缺陷；之后用独占端口产生可观察、确定的局部错误。

## CR-3 / P2：合法 `ra_preference=default` 被拒绝

位置：`config.rs:495-500`；UCI 与 netifd.data 共用 `apply_pool`。

精确 C `config.c:config_parse_interface` 明确把 `medium` **或** `default` 映射为 0；
Rust 只接受 `medium/high/low`。这不是未实现的 relay/hybrid/NDP 功能。

输入：运行期 netifd dump 把现有 LAN 的 `data.ra_preference` 设为 `default`。
`E/c-default` 中 C 保持运行，原接口 DHCPv6、RA 和 ubus 均可用；
`E/rust-default` 中冻结 Rust 记录 `invalid ra_preference` 后 exit 4，三项服务均不可用。
同一 UCI 字符串也会进入此拒绝分支；本轮直接实测的是 netifd 输入。

**确定性：** 各一次精确 ELF 实包对照，加上两个解析分支的直接源码证据。
修复目标：接受 C 的 `default` 别名；同时避免一个运行期配置校验错误撤销全部已生效服务。

## 已核对且未另立缺陷的边界

- `maindhcp=0` 下 `dhcpv4=server/start/limit` 保持 dnsmasq 共享含义；本次三个
  C/Rust 对照输入均包含它们，故障注入前均可启动、响应 DHCPv6/RA。
- `add_host` 使用完整有序 DUID 字节列表和 MAC 列表作为 key，保留旧 IAID 与
  `ignore_v6`，与精确 C `lease_cfg_cmp/lease_cfg_change` 的对应分支一致。
  C 的完整配置 reload 会通过 vlist flush 移除仅由 `add_lease` 添加的配置；不能把
  Rust 的同类移除单独判为缺陷。本轮未另跑静态 host 全组合或非法 blob fuzz。
- worker 对新连接重建对象/订阅，reply 按 generation 过滤，Network 满队列时保留
  待交付最新快照；未在静态审阅中发现 CR-1 之外的具体反例。本轮未以既有重连 passed
  结果替代新的重连验证，也未新增重连矩阵。
- `ipv6-prefix` 字段缺失在本机 server 范围内不构成反例：精确 C 唯一
  `ubus_has_prefix` 调用是 `config.c:2142` 的 master hybrid 判断；前面明确跳过非 master。
  该模式本次明确拒绝，实际本机地址来自 rtnetlink。
- `netio` 有目标 ABI/布局约束、OwnedFd 错误路径释放，检查 datagram/control 截断、
  pktinfo 重复或缺失、ifindex/scope 与 RA hop limit。每轮收包有预算，丢包后的剩余队列
  仍保持 fd readable。未找到可报告的 ancillary 越界或 fd 泄漏反例；未进行 syscall
  故障全覆盖或资源耗尽注入。
- 信号 handler 只写原子标志，主循环有最大一秒 poll 界限；ubus Linux Poller 重试 EINTR。
  本轮没有证明所有信号交错、异常退出和下线 RA 发送错误组合均正确。

## 复现与实验边界

开工前已读 `docs/RESEARCH_GUIDANCE_FROM_FABLE.md`。本轮模型是“队列非空必须仍可唤醒
owner；运行期单接口失败不能扩大为无关接口失效”。每个实验在执行前选择了可推翻的结果：
竞态模型应留下无通知的排队事件；配置/局部 socket 反例应使 C 保持原接口而 Rust 退出。
这是功能审计，判据为进程状态、明确 errno、请求是否得到协议回复；一秒 DHCPv6/两秒 RA
窗口仅为有限等待，不用于性能结论。未做性能地板、负载、PGO 或真机实验。

Oracle 复现命令（每次使用新的 `--out`）：

```sh
cd /home/ubuntu/odhcpd-audit-control-20261018-QOfzrV
/home/ubuntu/.cargo/bin/rustc --edition 2024 odhcpd_lostwake.rs -o lostwake
./lostwake
sudo python3 odhcpd_control_audit_case.py \
  --rootfs /home/ubuntu/odhcpd-image-v024-20261018/rootfs \
  --daemon /home/ubuntu/odhcpd-validation-20261018/sdk-d0ef9f04/odhcpd-rs \
  --out /home/ubuntu/odhcpd-audit-control-20261018-QOfzrV/replay-rust-conflict \
  --case secondary_port_conflict
```

精确 C 对照替换 `--daemon` 为
`/home/ubuntu/odhcpd-validation-20261018/c-baseline-06/rootfs/usr/sbin/odhcpd`。
别名反例使用 `--case ra_preference_default`；阴性反例使用 `secondary_socket_failure`。
脚本导入私有复制的 `odhcpd_baseline.py`，没有修改共享工具或被测产品。

| 保留工具 | SHA-256 |
| --- | --- |
| `odhcpd_baseline.py` | `69b852e8e9d4cdaede130f42540d36f2c4892a36e1974fb4a07f432d6d5b44ef` |
| `odhcpd_control_audit_case.py` | `fff9ca0a3c3931f0434605b0192b010582b2169d18326efbef5d58ead97a7191` |
| 阴性轮原始 `secondary-disabled-instrument.py` | `6ff0a6296e6c463a778d47e57eca794aafbf6b1a20900a55e20b12c960609db8` |
| `odhcpd_lostwake.rs` | `ba6995a26600e96ff2ae4c956a9b5382266f5ec9056a57e510efcebb4091467a` |

本范围审计到此停止。下一轮只裁决 CR-1/2/3 的修复是否满足上述可观察条件，
不把此报告当成部署许可，也不扩大为性能或全功能重新验证。

## 定向修复复核（2026-10-18）

本节只复核上述问题。修复提交为 `fa882f1c`（CR-1）和 `e33fa56c`
（接口错误隔离、`default` 别名及运行期无效配置处理）。新独立目录为
`/home/ubuntu/odhcpd-control-recheck-20261018-uvanh1`，下文简称 `R`。
原始失败证据 `E` 未修改。

### CR-1：源码顺序与直接模块回归

修复将 `try_event` 改为先读最多一个通知，再检查队列：若新事件在读取通知前进入，
后面的队列检查能看到它；若在队列判空后进入，则通知仍留给下一次 readiness 等待。
只消费一个通知也避免在 owner 达到处理预算时，把剩余队列的通知全部清掉。

`before_wake_read` 测试 hook 强制在通知读取前完成新事件入队和通知。
原实现的相同 hook 位置处于 `try_recv(Empty)` 之后，故该交错会触发原失败。
新回归先等待实际 Poller readiness，再调用真实 `Bus::try_event`；
`partial_owner_drain_leaves_remaining_events_readable` 则每消费一个事件都重新等待
readiness，覆盖部分消费后剩余事件的可唤醒性。

从 `e33fa56c` 的 `git archive` 在 R 编译直接产品模块，
`cargo test --locked --lib control::tests::` 得到 **4 passed、1 ignored**，包括
两个新增并发目标及已有 absent/dump 测试；日志 `R/control-target-tests.log`。
再单独运行 ignored 的完整私有总线测试，覆盖对象调用、对象重建、满队列最新快照和
ubusd 重启后的 generation/订阅恢复，得到 **1 passed**；
日志 `R/private-stock-bus-root.log`。使用复制到 R 的 stock launcher，只读加载精确
C ubusd，ELF SHA-256 为
`cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88`。

保留的夹具前提：首次以普通 ubuntu 身份运行 ignored 测试，在 `Bus::start` 之前的
`netifd.add_object` 返回 `StatusError(2)`；日志 `R/private-stock-bus.log`。
以 root 身份运行同一已编译测试及同一 launcher 后通过。该首轮未进入被审修复路径，
没有将其记为产品通过或隐去。

### 运行期无效配置与待应用配置

源码核对：`reload` 的配置解析失败分支在替换 `self.config` 或变更 socket 集合之前
返回，并清空 `pending_config`。因此无效的新请求不会让上一次因 snapshot 暂错而待应用
的配置随后覆盖当前活动状态；启动路径仍由 `App::new` 拒绝不支持的配置。

在 R 直接运行
`tests::invalid_runtime_config_keeps_active_state_and_cancels_older_pending_reload`，
得到 **1 passed**；日志 `R/runtime-invalid-target.log`。该测试注入 ENOBUFS、提交
有效待应用配置，再提交无效 relay 配置，恢复 snapshot 后验证仍是原配置；它验证
状态转换，未把没有启用协议 socket 的单测等同于活动 LAN 的实包证据。

### CR-2/CR-3：canonical SDK 实包与恢复路径

只使用 CI `39112918594` 对应的 canonical SDK，源码
`e33fa56c426f51931251df022228cd7ab905b63d`，Oracle 路径
`/home/ubuntu/odhcpd-validation-20261018/sdk-e33fa56c/odhcpd-rs`。
本代理再次核对 SHA-256 为
`c4a7c2731e02cb14fca5f94e4cbe940e0f9c91f64ca45be2e98ab19281250048`。
未替换最初的 SDK/C ELF，未构建中间 SDK 产物。

复验沿用原来的两个反例，增加必要的故障解除验证。两个场景均在新的 namespace 和
rootfs 复制件执行一次，原基线失败证据保留在 E，没有重跑全协议矩阵。

| 场景与阶段 | 同一原进程 | 原 LAN DHCPv6 / RA / ubus | 额外验证 |
| --- | --- | --- | --- |
| 新接口 UDP 547 被独占 | 仍运行 | 全部响应 | 新接口 DHCPv6 超时，日志明确为 `EADDRINUSE` |
| 关闭占用 socket，再发 netifd notify | 仍运行 | 全部响应 | 新接口收到相同 XID 的 DHCPv6 Reply，源为 `fe80::3` |
| netifd 设置 `ra_preference=default` | 仍运行 | 全部响应 | 不再触发配置错误 |
| 随后设置非法 `invalid-audit-value` | 仍运行 | 全部响应 | 日志明确拒绝 reload 并保留活动服务 |
| 再改为合法 `high` | 仍运行 | 全部响应 | 新 RA preference 位为 `0x08`，证实后续有效配置生效 |

端口冲突场景额外配置第二个真实 veth 客户端，新接口恢复由实包确认，不只根据 ubus
对象或 socket 列表推断。每个场景的原进程在其独立 PID namespace 内始终为 PID 35；
夹具没有 procd 或其他自动重启器。证据分别为
`R/sdk-conflict-recovery/{results.json,odhcpd.log}` 和
`R/sdk-default-recovery/{results.json,odhcpd.log}`，两者均正常完成全部断言。

复验脚本 `R/odhcpd_control_recheck.py` 仅扩展私有夹具，没有修改产品或共享 baseline。
复现时为 `--out` 选择新的目录；另一个场景替换 `--case ra_preference_default`：

```sh
cd /home/ubuntu/odhcpd-control-recheck-20261018-uvanh1
sudo python3 odhcpd_control_recheck.py \
  --rootfs /home/ubuntu/odhcpd-image-v024-20261018/rootfs \
  --daemon /home/ubuntu/odhcpd-validation-20261018/sdk-e33fa56c/odhcpd-rs \
  --out /home/ubuntu/odhcpd-control-recheck-20261018-uvanh1/replay-conflict \
  --case secondary_port_conflict
```

| 新证据 | SHA-256 |
| --- | --- |
| `odhcpd_control_recheck.py` | `162c66d22e10ca0784f425f459ec6da4a9c29be5e3ff62702ccf4b128e97deb0` |
| `sdk-conflict-recovery/results.json` | `ab87412f7a9d30d663ad9bb849304714a9fbac83ba96739c76c0e2f74e77a3a1` |
| `sdk-default-recovery/results.json` | `d0b69032fb170e64c363cabfeac53f4844d8a195706ba413b19a2d9c5f5ebf81` |

本次定向复验结论：**CR-1、CR-2、CR-3 闭合，未出现新的具体阻断**。
闭合仅覆盖已报告交错、局部接口 bind 故障及别名/配置失败恢复；不宣称所有并发调度、
全部接口错误或所有 runtime 配置组合均已验证。没有物理设备、发布、刷机或性能操作。

## Fable 最终候选的原场景重跑（2026-10-18）

针对 Fable 修复后的新 ELF，只重跑上节冻结的两个 SDK 目标场景，确认 CR-2/CR-3
没有回退。候选源码为 `e2adbe1c2bc32cdfbaef5ea4fa01acc81e9385ba`，ELF 路径
`/home/ubuntu/odhcpd-validation-20261018/sdk-fable-e2adbe1c/odhcpd-rs`，本代理再次核对
SHA-256 为 `c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30`。
私有复验脚本及导入 baseline 的 SHA-256 与上节完全相同，没有改动判据。

两例各执行一次，全新 namespace/rootfs 复制件及输出目录，全部断言通过：

- `R/sdk-fable-conflict-recovery`：新接口独占 UDP 547 时原 LAN DHCPv6、RA、ubus
  仍响应；日志明确为该接口 `EADDRINUSE`。关闭占用 socket 并 notify 后，新接口
  收到相同 XID 的 DHCPv6 Reply，源为 `fe80::3`，原 LAN 持续响应。
- `R/sdk-fable-default-recovery`：`default` 被接受；非法值只产生
  `netifd lan data skipped: invalid ra_preference`，符合新逐接口隔离行为，原 LAN
  服务持续。随后改为 `high`，新 RA flags 为 200，其中 preference 位为 `0x08`。

两例中原进程各自在独立 PID namespace 内始终为 PID 35，没有自动重启。
结果文件身份如下；同目录的 `odhcpd.log` 保留局部错误证据。

| 新候选证据 | SHA-256 |
| --- | --- |
| `sdk-fable-conflict-recovery/results.json` | `3f2d23354c866e8fadfb40eb72b494c9d12e8c57bd8db477aef2a79c515df838` |
| `sdk-fable-default-recovery/results.json` | `d498378985e14ce4b6b7febdb384dbd1958b0ae4c4347106a5f46120a7d8639d` |

结论：**最终 Fable 候选保留 CR-2/CR-3 的闭合结果**。本轮不重新编译控制模块，
不替代统一验证负责的其他夹具；没有新审计范围、性能、物理设备或发布操作。
