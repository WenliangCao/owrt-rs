# 综合分支 hosts reload 独立验收

2026-10-14。冻结对象为 `19bd6162e1b33c92a1e5ea26e864497800c7cfed`，
ELF SHA-256 `fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b`。

**不能全关闭：失败 HUP 的缓存清除及旧 hosts 保留通过，但无既有 TCP 的
inotify 更新仍会在 ENOMEM 下发布不完整 hosts。** 两次独立执行均复现；
第二次全量扫描确认只发布了新文件的前 3,520/6,000 条。配置 DNS、DHCP、
进程存活和随后恢复均正常，不能将这些健康信号替代 hosts 发布正确性。
本报告只判定上述冻结 ELF，不替 main、其他组件或后续修复 ELF 宣告通过。

## 身份和方法

- Rust：上述 ELF，2,089,440 B；每个执行过程均核验 `/proc/PID/exe` 身份。
- 精确 C：OpenWrt 25.12.5 提取的 `/usr/sbin/dnsmasq`，SHA-256
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
- 原 v2 driver SHA-256：
  `a0fd9f5a57188e6459d7e1707e78df59034ac1d647eced953216440581037ade`；
  与集成源码中 `tools/dnsmasq/full_r2_hosts_recovery.py` 字节一致。
- 40 个新 daemon 执行，C/Rust 各 20 个；全部私有 network/mount/PID
  namespace、合成 hosts 和 loopback DHCP，未操作物理路由器或改产品代码。
- 初始均为 2,000 hosts；每次先完成启动 DNS 和 DHCP，再相对该进程自身
  VmSize 设置 RLIMIT_AS。held TCP 情况在测 VmSize 前建立并查询连接。
  每个 case 连续更新两次，然后解除限制但不触发更新，最后再次正常更新。
- `--hostsdir` 只用 close-write，没有 HUP。HUP 测试另有 TTL=2 到期正控，
  每次 HUP 前缓存 TTL=60 的上游地址并改变上游，验证 HUP 后立即取到新地址。

逐 case 派生数据、哈希、失败探针和发布样本保存在
[integrated-reload-review.json](integrated-reload-review.json)。复核器重新读取
原报文，确认 4,078 条已记录 DNS 回复的解码、问题和正向地址与 raw 一致；
另重新解码 census 的 28,000 对 request/reply，验证全量计数。所有成功的
正向样本均只有一个正确 A 答案，未靠“任何一个地址碰巧匹配”通过。

## 阻断：无既有 TCP 的增量更新发布 partial

条件：`--hostsdir`，shared DNS/DHCP，无 held TCP，2,000 → 6,000 hosts，
该 Rust 进程 VmSize 3,528 KiB，加 1,024 KiB，RLIMIT_AS 为 4,661,248 B。

| 独立执行 | 第一轮源 EOF | EOF 后 ENOMEM | 第二轮 ENOMEM | hosts 结果 |
| --- | ---: | ---: | ---: | --- |
| 原 v2 driver | 1 | 2,472 | 126，未 EOF | old 消失；new 首/中存在，末条缺失 |
| 原流程加解除限制后 census | 1 | 2,480 | 126，未 EOF | 同样 partial；全量结果如下 |

第一轮的 ENOMEM 切片在客户探针前采集，发生在源文件 EOF 后。第二次执行
只在原 driver 的 release-no-trigger 探针后追加全量 UDP 查询；之前的
RLIMIT_AS、两次文件写入、采样和故障过程未改变。没有借助 HUP 或新文件
事件修复状态。解除限制后的全量结果：

| 实现 | old 存在 / 2,000 | new 存在 / 6,000 | next1 存在 / 6,000 | 错误地址 / 查询错误 |
| --- | ---: | ---: | ---: | --- |
| Rust | 0 | **3,520** | 0 | 0 / 0 |
| 精确 C | 0 | 0 | **6,000** | 0 / 0 |

Rust 的 `new000000` 至 `new003519` 存在，`new003520` 至 `new005999`
缺失；old 和第二轮 next1 全部缺失。原始首/中/末样本在 UDP 和新 TCP 上
一致。两次 Rust 运行配置 DNS、lease DNS、DHCP ACK 均健康，正常停止
exit 0；解除限制本身没有重新装载缺失记录，随后一次 close-write 成功
发布 `recovered.test` 并清掉旧代。C 同一相对限制没有 ENOMEM，两轮完整
发布，故不能将该结果写成“和 exact C 相同的受限行为”。

源码对应位于冻结 `main.rs::publish_hosts_source`：无共享记录时直接修改
local hosts；循环对每条 `local.hosts.insert(...)` 丢弃返回值，后续只以
`try_clone()` 成功为发布条件。分配失败的插入可以被忽略，已消费输入的
释放又可能使最终复制成功。这与观察相符；syscall trace 本身没有标出
Rust 分配调用点，本报告不把推断冒称为 allocator 栈证据。

## 已通过的同 ELF 边界

下表为 Rust，两次受限更新的 ENOMEM 总数；除注明者外，UDP/新 TCP 都
保留完整旧代的首/末样本，新代首/中/末均不可见。样本通过不等于全量证明。

| 模式 | 新行数 | 256 KiB | 512 KiB | 1,024 KiB |
| --- | ---: | ---: | ---: | ---: |
| HUP + held TCP + cache purge | 30,000 | 95 | 277 | 262 |
| HUP，无 held TCP + cache purge | 30,000 | 284 | 277 | 262 |
| inotify + held TCP | 2,000 | 2 | 2 | 2 |
| inotify，无 held TCP | 2,000 | 2 | 2 | 0，完整更新 |
| inotify + held TCP | 6,000 | 215 | 262 | 2 |
| inotify，无 held TCP | 6,000 | 215 | 262 | **2,598，partial 阻断** |

HUP 的六个 Rust case 均证明未过期转发缓存被清除：UDP 和新 TCP 都返回
更新后的上游地址；配置 DNS、lease DNS、DHCP ACK、解除限制后的健康和
下一次 HUP 恢复均通过。held TCP 一直保留接收时的旧 hosts 代。无 held
TCP 的三个 case 也验证了 `19bd6162` 对独占旧视图的保留，没有将该修复
仅凭静态修改算作成功。

inotify 2,000 行的 held 三档和 no-held 256/512 档，每轮都读到 EOF，
随后一次 ENOMEM，并保留旧代。6,000 行 held 1,024 档同样读到 EOF 后
失败而保留旧代；256/512 档在 staging 阶段失败，没有读到 EOF。这些
EOF 证据区分了早期读取失败，但不能进一步区分 working-copy 与
publication-copy 的确切失败分配。

无压力的 held inotify 2,000 → 6,000 正控，C/Rust 都零 ENOMEM，UDP/新
TCP 依次完整发布 new、next1 样本，held TCP 保持旧代；配置 DNS、DHCP
和最后恢复均通过。所有 Rust case 的进程、配置 DNS、lease DNS、新 TCP
和 DHCP 健康检查均通过，**仍有两个 partial case 未通过发布正确性**。

C 压力结果单列保留：HUP 六个 case 的新 TCP 均失败；无 held 的
256/512 档各有一次 `ready.test` UDP 300 ms 超时，DHCP 和缓存清除仍
成功，解除限制后恢复。inotify 6,000 行的 held/no-held 256 档也出现 C
部分 hosts 和新 TCP 失败。没有把 driver 的一般 `passed`（不包含 C
pressure TCP）解释成 C 所有服务正常，也没有把限时探针超时直接扩大
成持久进程故障。

## 保留证据和复现

Oracle 原始输出都在 `/dev/shm/full-audit-resume-20261014/reload-*`。
本地持久备份为 `private/full-audit-20261014/resume/reload/evidence.tar.gz`，
包含原 driver、census wrapper、派生数据复核器、报文、身份、stderr 和
syscall trace；排除可重新生成的 staged rootfs。
SHA-256：`c79f7b269df72a7a031870b692b029267cd5c631a6526d9a782ca6b6ccd4e7b4`。

原始阻断单点可在 Oracle 使用全新 private 输出路径复现：

```sh
TOOLS=/dev/shm/full-integrated-fix-20261014/private/source-final/tools/dnsmasq
sudo -n env PYTHONPATH="$TOOLS" sh "$TOOLS/run_isolated.sh" \
  python3 /dev/shm/full-integrated-fix-20261014/private/tools/full_r2_hosts_recovery_v2.py \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust /dev/shm/full-integrated-fix-20261014/private/release-final/dnsmasq-rs \
  --rust-sha256 fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b \
  --source-commit 19bd6162e1b33c92a1e5ea26e864497800c7cfed \
  --output /dev/shm/full-audit-resume-20261014/reload-repro/private \
  --services shared --initial-rows 2000 --new-rows 6000 \
  --headroom-kib 1024 --repeats 1 --hostsdir
```

没有覆盖全进程的任意单次 allocator failure、其他缓存容量、所有配置或
全局 OOM。没有新的部署或性能结论。后续修复必须换用明确的新冻结身份
重新执行阻断反例及相邻 held/no-held 边界，不能复用本报告宣告全关闭。
