# FULL-PERF-TCP 修复交付

基线 `e9d89b17d72a58b723cce88038ceaa1be58d7f8c`，独立分支
`fix/dnsmasq-full-tcp-20261014`。产品提交为 `936514cd` 和 `22fe5dd9`。
第二个提交补回审阅发现遗漏的 `/etc/hosts` 默认日志来源及空表查询早退；
以下最终结果全部使用包含该补充的产物，未使用中间产物代替最终验收。
未合并 main、未 push、未操作路由器。

## 身份与原因

| 输入 | SHA-256 |
| --- | --- |
| 原 Rust ELF | `e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0` |
| 最终 Rust ELF（2,089,440 B） | `0ac4ad216c071ae708af52f5d4d4cd6e4c2130b451655033efc463888bff0834` |
| 精确镜像 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |

原 ELF：`/home/ubuntu/full-audit-20261014/private/release/dnsmasq-rs`。
最终 ELF：`/dev/shm/full-tcp-fix-20261014/private/release-final/dnsmasq-rs`。
精确 C rootfs：`/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`。
最终源码提交完整值为 `22fe5dd9a6539ef7381b0bab43b39786b0bceae7`；构建目录与本地提交的
184 个 dnsmasq/ubus/packaging 输入逐文件 SHA 相同，收据为 `private/source-identity.json`。
原始证据、ELF、构建 target 全部在 Oracle 私有 tmpfs，Git 只记录工具及派生报告。

`finish_tcp_accept` 每次深复制 hosts 与 DnsConfig；配置文件中的 host-record 也会重复占用内存。
对应 patched dnsmasq 2.93 的 `dnsmasq.c:2124,2197` 在普通 `-k` 模式 fork 后处理 TCP，
旧连接保持接收时的内存视图。`cache.c:1174–1260` 的轮转只改变匹配组的顺序。
实现参考仍是 OpenWrt recipe revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`，
此次读取的 `cache.c` SHA 为 `51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`，
`dnsmasq.c` SHA 为 `d4bb7cde522376200a0293427b0812625ebc457f10dc9d3e2bef243ccba8ccd1`。

修复在首次 TCP snapshot 时共享 hosts records/indexes。只有实际查询的多地址名字需要私有轮转顺序，
查询单地址名字不会复制全表；后续 HUP/hostsdir 结构变更保留既有连接的代。
加载期间仍使用 owned 存储，`try_clone` 继续是可失败的完整复制，不向原加载路径添加 Arc 分配。
DnsConfig 用 Arc 共享；接口枚举没有改变 domain 内容时保留同一个配置代，避免每次 accept 又复制直接配置。
配置或域内容真实变化时使用独立代，lease/interface publication 的既有快照机制保持不变。

## 独立原反例与最终资源结果

均为精确 rootfs 内 `-k`、cache-size=1000、每连接查一次后保持；PSS 为进程树总和，单位 KiB。

| hosts 路径 | 记录数 | 原 Rust 0/20 TCP | 最终 Rust 0/20 TCP | 最终 C 0/20 TCP |
| --- | ---: | ---: | ---: | ---: |
| addn-hosts | 0 | 2,040 / 2,552 | 1,884 / 2,352 | 387 / 3,333 |
| addn-hosts | 10,000 | 6,808 / 51,440 | 6,796 / 7,260 | 1,391 / 4,091 |
| addn-hosts | 50,000 | 24,032 / 227,604 | 23,964 / 24,428 | 5,436 / 8,261 |
| 直接 host-record | 10,000 | 11,808 / 80,740 | 11,708 / 12,168 | 2,589 / 5,355 |

每组还保存了 1、10 连接与 drain 后的采样。50k 的 20 TCP 增量从 203,572 KiB 降到 464 KiB；
直接配置路径增量从 68,932 KiB 降到 460 KiB。共享映射的 PSS 会受同机其它精确镜像测试影响，
因此同时保留了下述独立 cgroup 硬限制门。

原反例在父/子同一个 `memory.max=67108864`、`memory.swap.max=0` cgroup 中独立复现：
C 完成 20 连接并继续 UDP，peak 10,481,664 B、无 OOM；原 Rust 第 5 连接失败，整个 daemon
`SIGKILL(-9)`、UDP 失效、peak 67,108,864 B、`oom_kill=1`。

最终同门限完成 20 连接、UDP 正常，peak 23,846,912 B、所有 OOM 计数为 0。
相邻边界在同 64 MiB 下保留 20 个连接后 HUP 新的 50k hosts，再保留 10 旧+10 新连接：
Rust peak 46,518,272 B、无 OOM；20 个旧连接都看到旧 `.1`，10 个新连接都看到新 `.2`，UDP 正常。
C 对照同样通过，peak 15,806,464 B。测试 cgroup 均清理完成。

这没有声称 Rust 的单代常驻内存与 C 相等；最终仍有约 24 MiB 的 50k hosts 基线，
HUP 有旧连接时会保留旧代。本修复关闭的是连接数乘以完整 hosts/config 的内存放大。

## 行为边界与检查

- 最终 ELF 的 42 个精确 C wire/语义观测完全一致：两个既有连接与父进程的独立 IPv4/IPv6 轮转、
  HUP 前后旧/新 TCP、直接配置记录、hostsdir/inotify 更新前后旧/新 TCP。
- 原 `m5_dns_cache.py` 的 7 个独立 C 对照均 `case_equal=true`：cache TTL 到期重取、TCP 固定时钟 TTL、
  HUP 替换 cache、DHCP add/rename/release 后既有 TCP 的 lease 视图、既有 lease TTL。
- 额外 3 个真实 DHCP add/rename/release 场景在既有 schedule 后新建 TCP，查询旧/新 lease 名；
  与 C 完全一致，避免仅检查旧 TCP/父 UDP。
- 最终匹配源码的 Linux musl 测试：786 library 通过、20 ignored；78 main 通过、3 ignored。
  本地 hosts 分配失败测试和新增 hosts/config 快照测试通过。中间一次 main 测试因其它任务遗留
  `/tmp/dnsmasq-ready-log-1` 导致 mkfifo 失败；未删除该残留，使用专属 TMPDIR 后最终测试通过。
- 两个产品提交与 FULL-R2 保持独立；本报告的 ELF 不包含 R2 修复，组合门另由集成分支验收。

详见 [机器可读派生证据](tcp-hosts-fix-evidence.json)，其中保留每份原始结果/构建收据的绝对路径及 SHA。
中间结果保留在 `fixed-*`，最终结果为 `final-*`，最终 ELF 始终以完整 SHA 核验。

## Oracle 可直接运行的复核命令

以下在 Oracle shell 执行；输出必须为未存在的新目录，不覆盖旧证据。所有脚本也已随本分支提交到
`tools/dnsmasq/full_tcp_*.py`。cgroup 脚本使用随机目录名，允许多个 PID namespace 同时验收，
并在输出中冻结 `driver.py`；原先已完成的脚本仍保留为 `full_tcp_hosts_cgroup-v1.py`。

```sh
perf_root=/dev/shm/full-tcp-fix-20261014
perf_tools=/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq
perf_image=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
perf_elf=$perf_root/private/release-final/dnsmasq-rs
sha256sum "$perf_elf"
sudo env PYTHONPATH="$perf_tools" sh "$perf_tools/run_isolated.sh" python3 "$perf_root/full_tcp_hosts_cgroup.py" --image-root "$perf_image" --rust "$perf_elf" --output "$perf_root/private/reaccept-cgroup" --budget-mib 64
sudo env PYTHONPATH="$perf_tools" sh "$perf_tools/run_isolated.sh" python3 "$perf_root/full_tcp_hosts_cgroup.py" --image-root "$perf_image" --rust "$perf_elf" --output "$perf_root/private/reaccept-cgroup-hup" --budget-mib 64 --hup
sudo env PYTHONPATH="$perf_tools" sh "$perf_tools/run_isolated.sh" python3 "$perf_root/full_tcp_hosts_memory.py" --image-root "$perf_image" --rust "$perf_elf" --output "$perf_root/private/reaccept-memory" --rows 0,10000,50000
sudo env PYTHONPATH="$perf_tools" sh "$perf_tools/run_isolated.sh" python3 "$perf_root/full_tcp_hosts_memory.py" --image-root "$perf_image" --rust "$perf_elf" --output "$perf_root/private/reaccept-direct" --rows 10000 --config-hosts
sudo env PYTHONPATH="$perf_tools" sh "$perf_tools/run_isolated.sh" python3 "$perf_root/full_tcp_hosts_snapshot.py" --image-root "$perf_image" --rust "$perf_elf" --output "$perf_root/private/reaccept-snapshot"
for side in c rust; do
  sudo env PYTHONPATH="$perf_tools" sh "$perf_tools/run_isolated.sh" python3 "$perf_root/full_tcp_lease_snapshots.py" --side "$side" --image-root "$perf_image" --rust "$perf_elf" --out "$perf_root/private/reaccept-new-leases-$side"
done
```
