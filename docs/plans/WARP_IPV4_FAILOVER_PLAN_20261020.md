# 楼宇 IPv4 故障时自动切换到 Cloudflare WARP（方案）

2026-10-20。状态：**待用户批准，路由器尚未改动。**

## 背景与证据

- 2026-10-19 约 22:37 和 2026-10-20 约 22:20，楼宇 IPv4 出口（CGNAT）故障。
  - 10-19 WAN 抓包：110 条 IPv4 TCP 流只有 31% 收到 SYN-ACK。
  - 10-20：路由器 ping 楼宇网关 0% 丢包，ping 外网 223.5.5.5 100% 丢包，IPv4 新建连接成功率 5/20。
- 两次故障期间 IPv6 都正常。
- 上游网络属于固定输入，只能在路由器侧处理（见记忆 `upstream-is-student-apartment-wall-port`）。

## 目标

- 平时所有流量照常直连，不经过 Cloudflare。
- 检测到楼宇 IPv4 故障时，家里设备的 **IPv4** 流量自动改走 WARP 隧道（隧道本身经 IPv6 连接）。
- IPv4 恢复后自动切回直连。
- IPv6 流量在任何时候都直连，不受影响。

## 组成

1. **软件包**：从本固件对应的官方源安装 `kmod-wireguard`（必须匹配 6.12.94 内核的 kmods 源）和 `wireguard-tools`。
2. **WARP 账号**：在 Mac 上用 `wgcf` 注册免费 WARP，得到私钥和隧道地址。
   - 私钥只保存在路由器和 `private/`，不进 Git。
   - 对端为 Cloudflare 公钥，端点为 `[2606:4700:d0::a29f:c001]:2408`（IPv6）。
3. **隧道接口 `warp`**：由切换脚本用 `ip link` + `wg setconf` 直接创建，MTU 1280。
   - 平时保持空闲：只有每 25 秒一次的保活包，不承载任何业务流量。
   - 不使用 netifd 的 wireguard 协议，避免依赖 netifd-rs 尚未验证的 proto 路径。
4. **防火墙**：在 wan 区域加 `list device 'warp'`，沿用 wan 区域已有的 masquerade、MSS 修正和 LAN→WAN 放行规则。
   - fw4-rs 已支持区域的 `device` 列表（`components/fw4/src/sections.rs`）。
5. **切换方式**：策略路由，只作用于 IPv4。
   - 启用：`ip -4 rule add iif br-lan lookup 100 priority 1000`，表 100 只有一条 `default dev warp`。
   - 关闭：删除这条规则。
   - 路由器自身的流量始终走原 WAN，所以探测测到的永远是楼宇原生 IPv4 的真实状态。
6. **探测与切换逻辑**：一个 procd 服务 `warp-failover`（shell 脚本），每 10 秒运行一次。
   - 每轮从路由器原生 WAN 对 4 个 IPv4 目标发起 TCP 连接，例如 Cloudflare、Google、Apple、Fastly 的 IP 字面地址，超时 3 秒。
   - **切到 WARP**：连续 3 轮（约 30 秒）中每轮至少 3 个目标失败。
   - **切回直连**：已切到 WARP 后，连续 12 轮（约 2 分钟）中每轮至少 3 个目标成功。
   - 两侧阈值不对称，用来防止来回频繁切换。
   - 探测必须用 TCP，不能用 ping：10-19 那次故障期间 ping 外网是通的，坏的只有 TCP。
   - 具体用哪个探测工具（BusyBox 或 uclient-fetch），先在设备上实测后确定。
   - 每次切换写一行 syslog，例如 `warp-failover: switched to WARP (native ipv4 0/4)`。
7. **DNS**：dnsmasq 的上游同时有 IPv4（62.220.18.8 等）和 IPv6（2001:1438:2:1::8 等）服务器，故障期间可以继续用 IPv6 上游解析。上线前在故障中实测确认。

## 已知副作用

- 切换的瞬间，已经建立的 IPv4 连接会断开一次。故障期间这些连接本来就基本不通。
- 走 WARP 时，网站看到的是 Cloudflare 的出口 IP，个别网站可能弹验证码。
- 走 WARP 时，IPv4 流量经过 Cloudflare。内容本身仍是 HTTPS 加密的。
- 软件流量卸载（flowtable）对 warp 设备的行为需要在上线时验证。
- 只有路由器下的设备会受益。

## 恢复门（上线前）

1. 核验离线备份存在，并备份 `/etc/config/network`、`/etc/config/firewall` 和 `apk info` 列表到 `private/`。
2. 上线后启动一个分离运行的定时回滚：3 分钟内如果没有从客户端确认健康，就自动删除策略规则和 warp 设备、恢复 firewall 配置、重载 fw4。
3. 客户端健康检查（经 Wi-Fi）：
   - IPv4 和 IPv6 的 HTTPS 正常；
   - 强制切到 WARP 后，`curl -4 https://www.cloudflare.com/cdn-cgi/trace` 显示 `warp=on`；
   - 切回后显示 `warp=off`；
   - B 站可以打开。
4. 手动回滚命令（一条）：`/etc/init.d/warp-failover stop && /etc/init.d/warp-failover disable`。
   - 停止服务时会删除规则和隧道，并恢复 firewall 备份。
   - 如需彻底移除，再执行 `apk del wireguard-tools kmod-wireguard`。

不刷固件、不重启路由器，只通过 Wi-Fi 管理。

## 验证计划

1. **白天**：装好以后保持直连，确认网速与之前一致（networkQuality 下载约 560–650 Mbit/s）。
2. **白天，手动强制切换**：
   - 确认 B 站视频能流畅播放，WARP 吞吐可以接受；
   - 确认 IPv6 仍然直连；
   - 确认切回直连后一切正常。
3. **晚上故障复现时**：
   - 确认约 30 秒内自动切换，syslog 里有切换记录；
   - 确认 B 站可以打开；
   - IPv4 恢复后，确认约 2 分钟内自动切回。
