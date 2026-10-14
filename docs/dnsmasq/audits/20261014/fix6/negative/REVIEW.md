# FIX6 DHCP negative cache / terminal SOA regression check

对冻结产品 HEAD `3335a978` 的 fresh release 重跑 NX24 + SOA64 + cursor12：**100/100 场景通过，本范围没有发现新的回归。** 840 对 DNS 响应中，819 对全部字段严格相同；21 对仅有按各实例 elapsed 约束的 authority SOA 相邻秒 TTL 差。180 对 DHCP 解码回复的 header、options、lease timers，以及逐请求上游行为相同。

精确镜像 C 是本轮语义标准；本矩阵当前版本直接对齐 C，因此无需用 main 或基线结果豁免任何当前差异。本子审计不单独裁定 F2 主复现。

| Suite | 场景 | DNS 响应对 | 全字段相同 | 有界 SOA TTL | DHCP 回复对 |
| --- | ---: | ---: | ---: | ---: | ---: |
| NX24 | 24 | 504 | 485 | 19 | 48 |
| SOA64 | 64 | 256 | 254 | 2 | 128 |
| cursor12 | 12 | 80 | 80 | 0 | 4 |

对象是本轮 fresh release ELF，SHA-256 `a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66`；精确镜像 C 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。程序在 Oracle 独立 network/mount/PID namespace、精确镜像只读 lower + 私有 overlay 内运行；C 使用镜像加载器和库，没有 diagnostic probe 或重编宿主 C。逐 suite 的环境身份、驱动 SHA、实际 argv、200 个侧结果 SHA 与每次 daemon argv 见 [checked.json](checked.json)。镜像 provenance 字段缺失情况在环境收据中保留为 null；没有将其冒充为已单独验证完整固件身份。

流量矩阵与 FIX5 相同，覆盖 direct/cached-CNAME、RD/DO、normal/debug、UDP/TCP、EDNS512 大 SOA 截断，以及 raw/configured-CNAME/reverse-synthesis 名字游标边界。既有 `negative_final.py` 的独立 wire decoder 从原始 hex 检查全部 DNS header 字段、question、section 边界、owner/type/class/TTL、完整 SOA 两个名称和五个整数、其他 RDATA/OPT，以及请求和响应的 ID/question 对应关系；仅规范化名称压缩。此次没有改产品或流量驱动，额外明确断言每个 daemon 都有 exit=0、资源释放且无强制 kill 的记录，并将这些断言的输入写进收据。200 个 daemon 的全部请求时存活检查与退出检查通过。

TTL 豁免仅针对 authority SOA，并同时要求差值不超过 1、两侧 TTL 分别落在 `[3600 - floor(elapsed) - 1, 3600]`，其余字段严格相等。本轮 21 处均为 3599/3600，允许区间均为 `[3599,3600]`：

- NX24 的 `rcode3-soa1-debug0-q1-tcp` 占 19 处，C=3599、Rust=3600；是同一缓存实例跨墙钟秒界后的连续响应，不是 19 个独立失败。
- SOA64 的 `large1-debug0-alias-udp-rd0-do1` 中 `ack-visible-a`：C=3600、Rust=3599。
- SOA64 的 `large1-debug1-alias-udp-rd1-do0` 中 `ack-visible-a`：C=3599、Rust=3600。

每一处的双方 elapsed 和精确上下界都已保存在 `checked.json`，未忽略任何非 SOA 的 TTL 或 RDATA 差异。另在已观察到的 C 响应副本上做独立 checker 负控制：rcode、question、owner pointer、A TTL、SOA TTL（差 2）、SOA RDATA、section count、上游行为八类人工损坏全部被拒绝；原响应自比较 21/21 严格通过。见 [checker_calibration.py](checker_calibration.py) 和 [calibration.json](calibration.json)。该校准只在内存副本中改包，未向 daemon 发送损坏流量。

原始 DNS/DHCP 报文和 daemon logs 留在 Oracle `/home/ubuntu/dnsmasq-audit-fix6-20261014/private/negative-01`。本轮结束后按该目录的 `/proc/*/{root,exe,cwd}` 归属检查，没有遗留进程或宿主 mount；fresh release SHA 未变化。见 [closeout.json](closeout.json)。未触碰其他 Oracle 任务。

复现（OUT 必须不存在；先将本目录的 `negative_final.py` 复制到 DRIVER）：

```sh
SOURCE=/home/ubuntu/dnsmasq-audit-fix6-20261014/source
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
FIX=/home/ubuntu/dnsmasq-audit-fix6-20261014/private/release/dnsmasq-rs
DRIVER=/home/ubuntu/dnsmasq-audit-fix6-20261014/private/negative_final.py
OUT=/home/ubuntu/dnsmasq-audit-fix6-20261014/private/negative-NEW
sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" python3 "$DRIVER" \
  --source "$SOURCE" --image "$IMAGE" --fix "$FIX" \
  --fix-sha256 a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66 \
  --out "$OUT"
```

可在同一个实际输出目录追加 `--collect-only` 独立重新解析全部侧结果，无需重启 daemon。

本子审计未测性能、未重跑完整 DHCP lifecycle/relay/PXE/helper 故障矩阵、全部 TTL/stale/时钟交错或长期并发；未运行 main/2113 的本矩阵副本，当前所有有效场景直接满足 C 语义。不能把这 100 个场景外推为完整 DNS/DHCP 等价。未修改产品、未碰物理路由器、未部署或推送。
