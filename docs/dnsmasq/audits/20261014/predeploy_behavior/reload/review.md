# 重载、文件更新与本地名字：独立行为复核

2026-10-14；冻结产品源码 `58365e8c8ebe1805573baa02543baf1c9d45be68`。
本分项未发现阻止上线的行为差异。实际配置实验的 **60/60 行比较一致**，
包括 24 次 HUP 期间的 160 个 IPv4/IPv6 UDP/TCP 查询，两边均 160/160 成功。
另以精确镜像的 init/procd/rpcd/odhcpd 运行合成 UCI 生命周期，流程结果相同；
旧工具的 pidfile 布尔字段不计作生命周期证明，见后文。
这不是整个 DNS/DHCP 审计的最终上线结论。

## 权威与隔离

- C 是精确镜像 `/usr/sbin/dnsmasq` ELF，在 Oracle aarch64 原生运行，
  通过同镜像 musl 加载器加载同镜像库；没有换成 native 重编译 C。
  SHA-256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
- Rust 是本轮冻结源码的 release ELF，SHA-256
  `5931b2d114ae5c3e911775e8fd529dcf83ef8718e2c11b50916ce1164dab0966`。
- 原始配置 SHA-256
  `273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe`，
  与 `ACTUAL_CONFIG_STAGE.md` 的 737 字节捕获相同。
  原接口名、53/67 端口、include、resolver 路径及四个上游地址保持原样；
  最后标记为配置修改的阶段才追加一条合成 `host-record`。
- 运行在 `run_isolated.sh` 的 network/mount/PID namespace。
  `actual_config_network.py` 创建独立服务端、LAN 客户端及受控上游；
  `actual_config_rootfs.py` 只向私有 tmpfs 复制捕获文件。
  实际运行捕获未包含的 `/etc/passwd`、`/etc/group`、`/etc/hosts`、
  `/etc/ethers` 从精确镜像补入。未修改源证据、产品代码或物理路由器。
- LAN 增加合成 ULA 用来测客户端 IPv6 DNS 传输；hosts 和预置持久租约均为
  合成数据。该租约的恢复检查不宣称完成真实 DHCP 获取/续租，后者由 DHCP 分项负责。

## 本轮结果

派生数据见 [summary.json](summary.json)，原始报文、进程日志、命令和租约
留在 Oracle 的 ignored `private/`；对应散列见
[evidence-manifest.json](evidence-manifest.json)。比较保留 DNS flags、问题、
记录次序、类型、数据及 TTL；只有显式 cache 用例的 TTL 按 110–120 秒窗口
验证后归一化。每条查询的实际到达上游端点及次数也参与比较。

| 范围 | 本轮观察及对客户端的含义 |
| --- | --- |
| 原始 hosts 数据 | 镜像 `/etc/hosts` 与捕获 `/tmp/hosts` 的 10 条名字/类型查询一致；未将真实名字带出 private |
| 本地 hosts/租约名字 | 短名、扩展 FQDN、A、AAAA、PTR，UDP/TCP 一致；另测 IPv6 客户端 UDP/TCP |
| 原子替换 addn-hosts 成员 | HUP 前两边仍答旧地址；HUP 后新查询答新地址，旧 PTR 被清除、新 PTR 生效 |
| 删除及重建 hosts 成员 | 删除后 HUP 返回 NXDOMAIN；重建后 HUP 正常解析；进程均存活 |
| 已有 TCP 连接跨 HUP | 两边均保留连接建立时的旧 hosts 视图，新连接看到新视图；这是 C 的连接生命周期语义，并非 Rust 独有陈旧答案 |
| HUP 与缓存 | 正常缓存命中不访问上游；HUP 后同名重新访问上游，两边一致 |
| 四个实际 resolver 单独生效 | 每次原子替换 resolv-file 留下一个实际端点；每端点 A/AAAA 查询成功，包含 IPv6 上游；每次只访问该端点一次 |
| resolver 丢失与恢复 | 写空后新外部查询返回 REFUSED；随后删文件仍 REFUSED；恢复原四端点后成功并首次各探测一次。两边一致，不能将上游配置为空造成的共同失败算 Rust 回归 |
| resolver 更新与缓存 | 实际配置没有 clear-on-reload；更新 resolver 保留有效正缓存，两边均不重新转发 |
| 主配置变更 | 追加 host-record 后，仅发 HUP 两边都不读新主配置；正常 TERM/start 后新记录生效 |
| 租约持久化 | 合成既有租约 A/PTR 在 HUP、TERM/start 后仍可解析，最终租约文件仍保留该条目 |
| bind-dynamic | 给 br-lan 增加第二 IPv4 地址后该地址上的 UDP/TCP 能服务；移除后原地址继续服务 |
| 高频 HUP | 24 次 HUP 同时运行 160 个查询，IPv4/IPv6 × UDP/TCP 各 40 个；两边零超时、零错误答案、无崩溃。最大本机观测延迟 C 1.66ms、Rust 1.72ms，仅为此次连续性观察，不是性能验收 |
| 正常退出 | 初始进程与重启后进程，C/Rust 均 TERM 后 exit 0，无强杀 |

## 实际 init/procd 调用边界

仓库 `packaging/openwrt/owrt-dnsmasq/files/dnsmasq.init` 与精确镜像脚本
逐字节相同，SHA-256
`610f043921f86083ef8e28f34acc2f853145469c6ae4f2994670916bb4062a7f`。

- 第 1249–1250 行原子替换生成配置与 hosts 文件。
- 第 1267–1268 行注册 `dnsmasq -C ... -k -x ...` 及 procd `file` 配置监测。
- 第 1320 行注册 dhcp/system 的 reload trigger。
- 第 1377–1380 行 `reload_service` 先 `rc_procd start_service`，再发信号。
  因而用户经 UCI/LuCI 修改配置时，不能把“仅发 HUP 不重读主配置”误报为缺陷。

本轮另复跑 `m2_lifecycle.py`：精确镜像 C 与 Rust 均在镜像 rootfs 的
ujail/procd 内运行，经历 init start、直接 HUP、未变配置的 init reload、
rpcd UCI staged edit/apply、真实 odhcpd DHCPv6 租约发布、init stop。
合成 UCI 配置启用本地 DNS/DHCP 与 IPv6；它用来验证真实调用链，
**不是原 737 字节配置的重放**。嵌套隔离环境使用工具既有
`--jail-procfs` fixture，仅为 jail 加入 procfs。

[lifecycle-summary.json](lifecycle-summary.json) 保留 18 个相同结果字段，
其中两个 pidfile 相等字段不作为有效生命周期证据。实际业务结果为：
UCI apply 前记录未生效，apply 后新地址能解析；C 内层 ELF PID 从 271
变为 601，Rust 从 273 变为 603，说明两边实际重启。随后镜像 odhcpd 经
真实 DHCPv6 Solicit/Request 建立租约并更新 hosts，dnsmasq 的 AAAA 回答
与租约相同；最后服务、内层进程及 pidfile 均清理。

旧 lifecycle 工具的 `uci_apply_restarted` 只比较 pidfile 中的 namespace-local
PID，两次都为 1，因此原字段误报 false；不能用该字段或
`sighup_keeps_pid` / `init_reload_keeps_pid` 的同类 pidfile 比较证明生命周期。
此处重启结论来自已校验 ELF SHA 的 **外层可见 inner_pid**。该工具观察限制
已明确写入派生结果，不列为产品缺陷。

## 源码复核与发现分级

没有本分项的确认 P0/P1/P2 产品发现，也没有仅凭源码推测的疑似阻塞。
源码检查与实测相符：

- 匹配补丁 C `dnsmasq.c` 的 `EVENT_RELOAD` 调用 `clear_cache_and_reload`，
  后者重新读 hosts、DHCP 数据文件、ethers 并重建租约 DNS，不重读主配置。
- Rust `main.rs::process_reload_before_dns` 经 `reload_data` 更新这些数据；
  `DnsFiles::schedule` 区分 Signal 与 Notify/Route，实际 polling resolver 更新
  通过文件变化触发；这次原子替换/清空/删除/恢复均已实包验证。
- Rust 的 DHCP 文件重载完成前 admission gate 与初始 hosts 发布 gate 有明确
  状态；本轮只检验普通小文件和连续 DNS，不以源码检查声称所有并发时序正确。

## 复跑与未覆盖

主实验工具为 `tools/dnsmasq/predeploy_audit_reload.py`。
Oracle 审计根目录为
`/home/ubuntu/dnsmasq-predeploy-behavior-20261014`；最终原始目录是
`private/reload/c-05` 与 `private/reload/rust-03`，其中 `command.json`
保留完整命令（含私有 CIDR，不进 Git）。将命令中的输出目录改为新目录后
执行即可复跑。结构如下：

```text
sudo -n sh run_isolated.sh
  python3 actual_config_network.py --source-root <captured-root> --router-cidr <captured-cidr> --output <fresh-private-network> --
  python3 actual_config_rootfs.py --source-root <captured-root> --
  python3 predeploy_audit_reload.py --side <c|rust> --out <fresh-private-run>
    --image-root <exact-image-root> --reference-build <native-ubusd-fixture-build> --rust <frozen-release>
python3 predeploy_audit_reload.py --mode compare --c-out <c-run> --rust-out <rust-run> --out <derived-output>
```

`reference-build` 仅提供私有 UBus fixture；DNS 对照始终是精确镜像 C。
完整 init/procd 实验的复跑命令在
`private/reload/lifecycle-{c,rust}-01/command.json`。

未覆盖：真实物理 Wi-Fi/交换芯片、断电/flash 写入、reload 中的 DHCP 地址获取
或续租竞态、巨型 hosts/FIFO/文件权限损坏、长时间负载、实际 UCI 全部字段的
变更组合、配置修改重启期间的 DNS 丢包窗口，以及原配置上的完整
procd/odhcpd 联合链（本轮联合链使用合成 UCI）。没有据此扩大上线保证。

准备阶段失败记录保留：c-01 为人为预置租约所有者触发 Oracle
`protected_regular`，c-02 为 runtime 捕获缺省账户文件；均未进入客户端测试，
不是产品失败。c-03/rust-01 与 c-04/rust-02 是补齐镜像 hosts/ethers 前的
中间通过结果，最终结论只用 c-05/rust-03。
