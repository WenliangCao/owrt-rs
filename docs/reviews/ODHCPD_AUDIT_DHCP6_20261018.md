# odhcpd-rs DHCPv6 / lease 独立审计（2026-10-18）

复验结论：**两项 P2 已闭合，最终 Fable 源码 `e2adbe1c` 的 SDK ELF 定向回归也通过。**
原五个目标事件的 IA 完整内容均与既有精确 C 证据一致，见文末闭合及最终 ELF 回归记录。

初审结论（旧 ELF `79f1349e`）：2 项 P2，未发现 P0/P1。
两项均由精确 C ELF 与旧冻结 SDK ELF 的真实 UDP 请求独立复现，审计未修改产品代码。
没有刷机、发布、访问物理 router、性能/PGO 实验或 Mac Rust 构建。

## 身份与方法

- Rust 产品源码：`d0ef9f04`；本次读取的 `dhcpv6.rs` / `leases.rs` 与该提交无差异。
- SDK ELF SHA-256：`79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`。
- 精确 C 源码提交：`5d7be43f8b9dec0eb47e245cfab81108bb131273`。
- C ELF SHA-256：`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
- C 源码：Oracle
  `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/odhcpd`。
- rootfs 原件：`/home/ubuntu/odhcpd-image-v024-20261018/rootfs`，只读复制；实验只修改
  `/home/ubuntu/odhcpd-audit-dhcp6-20261018/{c-01,rust-01}/rootfs`。
- 独立场景工具：[tools/odhcpd_audit_dhcp6.py](../../tools/odhcpd_audit_dhcp6.py)。
  复用已阅读的 `odhcpd_baseline.Fixture` namespace/veth/ubus 仪器，新增自己的输入与判断，
  不将旧报告的通过结论作为证据。两次运行均 `complete=true`，没有重跑筛选。

预实验判断：Rust 缓存默认 lease time 会使已存在租约保留旧值；按 `/128` 分支选择
地址选项类型会把 PD 撤销编码为 NA。预测分别是 C/Rust `1200/600` 秒与选项 `26/5`。
这是确定性的功能差异实验，判断依据为回复字节；不涉及成本、噪声或性能代理指标。

## P2-1：修改默认 leasetime 后，现有动态租约续租继续使用旧值

位置：`components/odhcpd/src/dhcpv6.rs:210`、`:221`、`:808`。

新租约把 `pool.lease_time` 缓存到 `Lease.lease_time`。`refresh_host()` 对无 host 配置的
动态租约直接返回；有 host 配置但没有独立 leasetime 时，也只有 host 本身变化才更新该值。
修改 pool 的默认 leasetime 后，Renew/Rebind 的共同路径继续使用创建时的值。

输入与实测：

1. LAN `leasetime=600`，获取 IA_NA IAID=1，Request 绑定。
2. 修改同一配置为 `leasetime=1200`，发送 SIGHUP。
3. 同一 DUID/IAID 发送 Renew，再发送 Rebind；随后用新 IAID=9 Request。

| 回复中每个 IAADDR 的 preferred/valid | 精确 C | 冻结 Rust |
|---|---:|---:|
| 初次 Request | 600/600 | 600/600 |
| reload 后原 IA 的 Renew | 1200/1200 | 600/600 |
| reload 后原 IA 的 Rebind | 1200/1200 | 600/600 |
| reload 后新 IA 的 Request | 1200/1200 | 1200/1200 |

新 IA 使用 1200 排除了配置 reload 失败。精确 C `src/dhcpv6-ia.c:612` 的 `build_ia()`
每次在没有独立 `a->leasetime` 时读取 `iface->dhcp_leasetime`。

影响：管理员对默认租期的缩短或延长不会作用于持续续租的已有客户端。独立实包验证了
动态 NA；共享字段和刷新路径也覆盖 PD 与未单独设置 leasetime 的静态 host，后两者是
代码推导，未另外实包验证。

建议：在现有租约的有效配置刷新/回复路径重新解析 host override 或当前 pool 默认值，
保持已经承诺的当前 deadline，令下次续租使用新策略。验收至少覆盖默认值增减、NA/PD、
带/不带 host override。

## P2-2：IA_PD 的旧 /128 前缀撤销被编码为 IAADDR

位置：`components/odhcpd/src/dhcpv6.rs:1035`、`:1051`、`:1074`。

Renew/Rebind 会把客户端不再适用的 IAPREFIX 放入零寿命撤销回复。
`encode_address()` 仅凭 `length == 128` 选择 IAADDR，而没有保留所属 IA 类型。
因此合法长度为 128 的 IAPREFIX 被转成 code 5，嵌套在 IA_PD 中。

输入：先绑定 IA_PD IAID=2 `/62`，然后 Renew 的同一 IA_PD 带旧 IAPREFIX：
`fd12:3456:789a:4::1234/128`，preferred=valid=600。

| IA_PD 回复中的撤销子选项 | 精确 C | 冻结 Rust |
|---|---|---|
| 类型 | IAPREFIX（26） | **IAADDR（5）** |
| 原前缀长度 | 128 | 无此前缀长度字段 |
| preferred / valid | 0 / 0 | 0 / 0 |

两者都同时回复当前 `/62` IAPREFIX；差异仅在旧 `/128` 的撤销类型。
精确 C `src/dhcpv6-ia.c:795` 根据原选项 `otype == DHCPV6_OPT_IA_PREFIX` 构建
`dhcpv6_ia_prefix`，保留 `/128`。

影响：客户端得不到该旧 PD 前缀的正确撤销选项；严格解析器可能忽略非法子选项。
未对具体客户端实现的后续行为作实测，也不声称造成了服务中断。

建议：序列化时显式携带 IA_NA/IA_PD 或子选项种类，不能用前缀长度判断种类；
验收 Renew/Rebind `/128` 撤销与普通 IA_NA `/128` 回复。

## 已检查范围与边界

逐段阅读 `dhcpv6.rs` 与 `leases.rs`，同时追踪 `main.rs` 的 handle/reconcile/写文件调用。
核对精确 C 的 IA 查找与分配、Confirm、Renew/Rebind、Release/Decline、有限/无限期限、
`build_ia()` 与 `statefiles.c` 的 hosts/trigger 边界。

- TLV 长度检查、1024 option 上限、全 IA header/suboption 预验证、短 DUID、未知消息、
  server-id、unicast 与忽略 host；没有找到未经长度检查的网络索引或可由报文引发的 panic。
- NA 保留 IID/配置 IID、PD 对齐/重叠/空间上界、4096 lease 上限、512 字节 IA 回复预算。
  多 IA 的畸形头/子 TLV 在状态变更前验证；预算检查前的候选 PD 路由由未使用路由清理覆盖。
- Confirm 无地址/未知绑定的静默路径、Renew 无绑定、Rebind、新旧前缀撤销、Release、
  动态 Decline 一小时隔离与固定 IID 立即释放。
- 路由新增先 ACK 后发布；部分新增失败会清理已成功的新路由，删除失败保留追踪；
  reconcile 重新导出/安装并重试。此项做源码路径核对，**未独立注入 netlink ACK 故障**。
- lease/hosts 输出有效期过滤、hostname 转义与校验、PD 不进入 hosts、状态文件先写后
  rename、映射未变不触发脚本、所启动子进程的回收。没有新增的已确认出口缺陷。

没有把已接受差异列为问题：无 Reconfigure、Release 槽位立即复用、拒绝畸形整包、
到期立即清 export、修复 C 的无效 PD route/旧 route 泄漏。

本次不是穷尽 fuzz 或完整客户端互操作验证，也没有重新执行此前所有单测或性能套件。
没有验证任意外部长时间阻塞 trigger 脚本的资源上界。无 P0/P1 的结论限于上述检查范围。

## 重放与原始证据

在 Oracle 自建目录复制本工具和 `tools/odhcpd_baseline.py`，以 sudo 执行；`--out` 必须全新：

```sh
sudo python3 odhcpd_audit_dhcp6.py \
  --rootfs /home/ubuntu/odhcpd-image-v024-20261018/rootfs \
  --daemon /home/ubuntu/odhcpd-validation-20261018/c-baseline-06/rootfs/usr/sbin/odhcpd \
  --out /home/ubuntu/odhcpd-audit-dhcp6-20261018/c-replay
```

Rust 重放只将 `--daemon` 换成
`/home/ubuntu/odhcpd-validation-20261018/sdk-d0ef9f04/odhcpd-rs`，并另选新的 `--out`。
工具会核对两种已知 ELF 哈希，保存请求/回复十六进制和解码数据。只读原件不被修改。

原始目录：Oracle `/home/ubuntu/odhcpd-audit-dhcp6-20261018/{c-01,rust-01}`；本地副本在
ignored `private/odhcpd-audit-dhcp6-20261018/{c-01,rust-01}.json`。

| 文件 | SHA-256 |
|---|---|
| 初审 `audit.py` / `4a8b2077` 中的场景工具 | `e9c8cb5882a56a48c279302dc312a6658b174aa09dab9b94ae0b351a04e918f1` |
| C results.json | `1aed5311e7e2f801d7f37562f5f7c72ca61a25f2f736659209199b509014fee1` |
| Rust results.json | `bf749b1f3ed9aa27ec4e4fa00d4254c02bfdca63eb5dd5ace7bdba2668604850` |

关键事件键：`na_request_600`、`na_renew_after_1200_reload`、
`na_rebind_after_1200_reload`、`fresh_na_after_1200_reload`、`pd_renew_old_128`。

## 修复后的独立定向复验

修复提交 `9be8f5fc`，统一源码 `e33fa56c426f51931251df022228cd7ab905b63d`。
复验对象是 canonical CI run `39112918594` 的 SDK 产物，不是中间 native ELF：

- Oracle：`/home/ubuntu/odhcpd-validation-20261018/sdk-e33fa56c/odhcpd-rs`。
- SHA-256：`c4a7c2731e02cb14fca5f94e4cbe940e0f9c91f64ca45be2e98ab19281250048`。
- 场景工具提交 `4908d026` 添加显式 `--candidate-sha`，不改变原场景输入。
  未指定该参数时仍只接受原 C/Rust 两个哈希；指定后严格要求该哈希，并在 namespace 内
  再次核对。未知 ELF、错误 SHA、非法 SHA 格式均已在 Oracle 验证为 exit 2，且不创建 out。

独立静态复核：成功候选的共同回复路径在计算新期限之前重新解析 host override 或当前
pool 默认值，覆盖 NA/PD 的 Renew/Rebind；不会在 pool reload 时单独改写已承诺的
lease deadline。地址编码显式传入 `LeaseKind`，NA 保持 IAADDR，PD `/128` 保持 IAPREFIX。

预实验预测是修复后与旧 C 一致：既存 NA Renew/Rebind 为 1200 秒，PD 撤销类型为 26。
只运行原场景一次，沿用初审 `c-01/results.json`，不重新运行 C、不扩大矩阵、不做性能测量。
新 `rust-e33fa56c-01` 返回 `complete=true`；比较器同时核对候选身份及五个事件的整个
IA 对象，包括 IA payload 十六进制、T1/T2 和全部子选项。

| 原目标事件 | 修复后 SDK 与既有 C 的 IA 完整内容 |
|---|---|
| `na_request_600` | 一致；preferred/valid 为 600/600 |
| `na_renew_after_1200_reload` | 一致；preferred/valid 为 1200/1200 |
| `na_rebind_after_1200_reload` | 一致；preferred/valid 为 1200/1200 |
| `fresh_na_after_1200_reload` | 一致；preferred/valid 为 1200/1200 |
| `pd_renew_old_128` | 一致；旧 `/128` 为 IAPREFIX（26），preferred/valid 为 0/0 |

**P2-1、P2-2 均闭合。** 本结论只关闭这两项 DHCPv6 发现；前述未实测范围仍然保留，
不代替其他组件审计、部署验证或发布决定。

原始数据：Oracle
`/home/ubuntu/odhcpd-audit-dhcp6-20261018/rust-e33fa56c-01/results.json`；
本地 ignored `private/odhcpd-audit-dhcp6-20261018/rust-e33fa56c-01.json`。
比较器及结果分别保留于同一 private 目录的 `compare_closure.py`、`closure-e33fa56c.json`。

| 复验文件 | SHA-256 |
|---|---|
| `tools/odhcpd_audit_dhcp6.py` | `38021c65a7795809b22a25830a7a2d54e01e252717b90ed01f9e78aa626ca27d` |
| 候选 results.json | `5ac5b307b110f7d3a516cfd121bf4c29742c49864ae58e297cb6187b33c1050b` |
| `compare_closure.py` | `25928ae0168cb4af7314f83ad716e201c927af560881976048db6455496f2c31` |
| `closure-e33fa56c.json` | `d50adec80b1f41cb07d3cc1d86c7226906a284e656aa28f744f735c34db18f9c` |

重放使用前述命令，将 `--daemon` 换成 `sdk-e33fa56c/odhcpd-rs`，加
`--candidate-sha c4a7c2731e02cb14fca5f94e4cbe940e0f9c91f64ca45be2e98ab19281250048`，
并指定全新 `--out`。原 C、旧 Rust 和初审数据均未覆盖。

## 最终 Fable ELF 定向回归

按新 ELF 重新执行原场景一次，检查 F3 host parser 变化是否回归已闭合的两项 P2。
预期仍为既存 NA Renew/Rebind 1200 秒、PD `/128` 撤销为 IAPREFIX（26）；
未增加场景、重跑 C、做性能实验或访问物理 router。

- 源码：`e2adbe1c`。
- ELF：`/home/ubuntu/odhcpd-validation-20261018/sdk-fable-e2adbe1c/odhcpd-rs`。
- 严格 `--candidate-sha`：`c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30`。
- 新目录：`/home/ubuntu/odhcpd-audit-dhcp6-20261018/rust-fable-e2adbe1c-01`。
- 工具与比较器沿用上节版本及哈希；C 数据继续沿用未修改的 `c-01/results.json`。

**结果：5/5 原目标事件的 IA 完整内容均与 C 一致，`complete=true`，两项 P2 未回归。**
比较包含 IA payload 十六进制、T1/T2 和全部子选项，范围与上节相同。

本地 ignored 证据在 `private/odhcpd-audit-dhcp6-20261018/`：

| 文件 | SHA-256 |
|---|---|
| `rust-fable-e2adbe1c-01.json` | `3620db08acf15181e6888194baf589f53e04f975871009caa832908dfa81e613` |
| `closure-fable-e2adbe1c.json` | `06c72b5c49ffaeeb08862128fd449312384d9899e0305151a3200bd651aee9dd` |
