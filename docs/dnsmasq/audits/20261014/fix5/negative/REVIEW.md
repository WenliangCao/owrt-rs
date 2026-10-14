# FIX5 DHCP negative cache / terminal SOA regression check

对当前产品 HEAD `5b914d32891a5166f8075d108fc98610abc1f885` 的 fresh release 运行 NX24 + SOA64 + cursor12，100/100 场景通过。840 对完整 DNS 响应中，838 对全字段相同，2 对仅有经单实例 elapsed 约束的 authority SOA 相邻秒 TTL 差；180 对 DHCP 解码回复（header、options、lease timers）及逐请求上游行为相同。本范围没有发现新的功能回归。

对象是本轮 fresh release ELF，SHA-256 `7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c`；精确镜像 C 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。这组测试没有使用 diagnostic probe 或此前 SDK ELF。程序在 Oracle 独立 network/mount/PID namespace、精确镜像只读 lower + 私有 overlay 内运行；C 使用镜像的加载器和库。见 [运行环境派生身份](environment.json)。

| Suite | 场景 | DNS 响应对 | 全字段相同 | 有界 SOA TTL | DHCP 回复对 |
| --- | ---: | ---: | ---: | ---: | ---: |
| NX24 | 24 | 504 | 502 | 2 | 48 |
| SOA64 | 64 | 256 | 256 | 0 | 128 |
| cursor12 | 12 | 80 | 80 | 0 | 4 |

复用了产品仓库现有流量驱动，另用上一轮 `negative_final.py` 的独立 wire decoder 从原始 hex 解码检查 DNS header 所有字段、question、完整 section 边界、名称、owner/type/class/TTL、SOA 两个名称和五个整数、其他 RDATA/OPT，以及请求与响应的 ID/question 对应关系。不只读取驱动 `passed`，也不只核对 rcode。此次仅参数化 ELF 身份，并把 TTL 允许范围和 elapsed 逐项写入收据；没有改变产品或流量矩阵。

覆盖 direct/cached-CNAME、RD/DO、normal/debug、UDP/TCP、EDNS512 大 SOA 截断，以及 raw/configured-CNAME/reverse-synthesis 名字游标边界。每场景重启 daemon；所有请求时 daemon 存活，DHCP 驱动的退出与资源释放检查通过。

两处时钟差均在 `rcode3-soa1-debug0-q28-tcp`：

- `after-ack-65401-udp`：C TTL 3599，Rust TTL 3600；各自首次查询开始至本响应结束 elapsed 为 0.034532727 / 0.031451741 秒。
- `after-ack-65401-tcp`：C TTL 3599，Rust TTL 3600；elapsed 为 0.034964051 / 0.031876105 秒。

检查要求 TTL 差不超过 1，且各自必须落在 `[3600 - floor(elapsed) - 1, 3600]`，这两处均为 `[3599, 3600]`。只允许 authority SOA 这一字段的墙钟相邻秒差；其他记录 TTL、flags、数据、次序及上游行为均严格相等。逐场景计数、TTL 范围、驱动/ELF/summary SHA 和 200 个侧结果 SHA 见 [checked.json](checked.json)。原始报文、DHCP 报文和 daemon logs 留在 Oracle `/home/ubuntu/dnsmasq-audit-fix5-20261014/private/negative-01`。

复现（输出目录必须不存在）：

```sh
SOURCE=/home/ubuntu/dnsmasq-audit-fix5-20261014/source
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
FIX=/home/ubuntu/dnsmasq-audit-fix5-20261014/private/release/dnsmasq-rs
DRIVER=/home/ubuntu/dnsmasq-audit-fix5-20261014/private/negative_final.py
OUT=/home/ubuntu/dnsmasq-audit-fix5-20261014/private/negative-NEW
sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" python3 "$DRIVER" \
  --source "$SOURCE" --image "$IMAGE" --fix "$FIX" \
  --fix-sha256 7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c \
  --out "$OUT"
```

先把 [negative_final.py](negative_final.py) 复制到上述 DRIVER。可在相同输出目录追加 `--collect-only` 重新独立解析所有侧结果，无需重启 daemon。

本轮该子审计未测性能，未重跑全 DHCP 生命周期/relay/PXE/helper 故障矩阵；没有把这 100 个场景外推为所有 DNS/DHCP 行为均等于 C。
