# native-eleven 开机功能夹具

扩展后的 `tools/native_boot_check.sh` 在 Oracle 自测通过；原 native-ten
IPv4/DNS/HTTP/七个运行进程身份路径也通过。未访问物理路由器，没有性能采样或门槛。

- 镜像 `release.json.layout=native-eleven` 才启用 IPv6 分支，保留镜像原
  `S35odhcpd`/`/etc/init.d/odhcpd`，由真实 procd 启动 `/usr/sbin/odhcpd`。
- netifd 建立带 GUA `/64`、ULA `/60` 的 LAN 和 IPv6 默认路由；独立 veth
  客户端验证 hoplimit 255、M/O/A/L、两个 PIO、内核实际生成的两个 SLAAC 地址。
- 客户端完成 IA_NA Advertise/Request（两个地址）及 IA_PD（一个 `/62`）；
  核对 `dhcp.ipv6leases`、`dhcp.ipv6ra`、实际租约文件、hosts 文件和内核 PD 路由。
- 配置原 `/usr/sbin/odhcpd-update`，新租约名称的 DNS AAAA 答案必须出现并
  等于 IA_NA 地址；同时核对该脚本、原 init 的字节身份及 procd 实际 argv/PID/ELF。
- 客户端 veth 保留至服务器状态采集完成，避免清理动作导致桥 down 后误判空 RA。

自测输入是 v0.2.3 解包 rootfs 的独立副本，加 SDK odhcpd ELF
`79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`；
仅自测副本的 manifest 标为 native-eleven。**它不是最终十一组件镜像资格**。
最终镜像须对其精确解包 rootfs 运行同一命令：

```sh
sudo sh tools/native_boot_check.sh EXTRACTED_FINAL_IMAGE NEW_OUTPUT_DIRECTORY
```

Oracle 自测输出：`/home/ubuntu/odhcpd-native-boot-20261018/check-eleven-04/`
及 `check-ten-01/`。本地原件与工具 SHA：
`private/odhcpd-20261018/native-boot-selftest/receipt.json`。早期夹具准备失败和
客户端提前清理导致的采集失败已保留，不计作产品失败或最终镜像通过。
