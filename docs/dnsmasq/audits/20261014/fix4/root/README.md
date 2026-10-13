# 独立原始 DNS 边界复跑

使用当前源码树未修改的 `tools/dnsmasq/audit_20261011_dns.py`。本轮实际命令如下；复跑时必须给 `OUT` 新路径。两组都直接执行精确镜像 C，因此 C 自身的可重复性也受检查。

```sh
SOURCE=/home/ubuntu/dnsmasq-fix4-repair-20261013/source-final
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
OUT=/home/ubuntu/dnsmasq-audit-fix4-20261014/private/root
FINAL=/home/ubuntu/dnsmasq-fix4-repair-20261013/private/sdk-verify-final/payload/usr/sbin/dnsmasq
MAIN=/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs
sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$SOURCE/tools/dnsmasq/audit_20261011_dns.py" \
  --image-root "$IMAGE" --rust "$FINAL" --out "$OUT/dns-final"
sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$SOURCE/tools/dnsmasq/audit_20261011_dns.py" \
  --image-root "$IMAGE" --rust "$MAIN" --out "$OUT/dns-main"
python3 collect_dns.py "$OUT/dns-main/result.json" \
  "$OUT/dns-final/result.json" boundary-summary.json
```

每组 368 个协议案例：116 个本地记录/畸形问题/EDNS 边界，转发、RR 过滤、rebind 各 84 个。两组共观察 1,472 个请求结果。配置 `cache-size=0`；此探针不覆盖缓存老化和 DHCP 发布。

[boundary-summary.json](boundary-summary.json) 精确保留改变项与剩余差异的请求和客户端响应字节。完整原始结果留在上述 Oracle private 目录，本地副本在 `private/dnsmasq-audit-fix4-20261014/root/`。比较不归一化 TTL、flags 或返回状态；上游只比较次数，避免把每次随机 transaction ID 误判成语义差异。

所有改变的 7 个 TCP 案例从 main 的 EOF 修复为 C 的 REFUSED：两个多问题包、零问题包、自引用/越界指针、bitstring label、过长名字。368 个最终 SDK 案例中 366 个与 C 完全一致。余下 forward-pointer UDP/TCP 两项在 main 和分支逐字相同，是旧 parser 差异；客户端分别收到 C 的本地 A 答案，而 Rust UDP 丢包、TCP 返回 REFUSED。所有上游计数一致、16 次 daemon 生命周期均健康。
