# v0.3.0 真机部署：续租通过，撤销报文与精确 C 一致

**v0.3.0 已刷入，初始连续客户端健康通过 187.711 秒；真实客户端自然
DHCPv6 Renew 通过。一次获准的 20 秒 WAN6 断开已自动恢复，路由器撤销报文
经离线对照与精确 C 一致；用户接受 Mac 处理延迟，不再作为发布阻断。**
没有重复断开、额外重启或性能轮次。

最终 ELF 的[完整十项 A/B](ODHCPD_FINAL_FULL_AB_RESULT_20261018.md)与
[固件守卫资格](ODHCPD_V030_GUARD_20261018.md)已通过。本报告记录同一产物的
部署结果；不会用隔离夹具代替用户新增的真实客户端验收。

| 发货身份 | 值 |
|---|---|
| 镜像源码 | `6fb236a3d3cae4c1fa2e0c80e8f0aae552437bd2` |
| 镜像 CI | [39124795974](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39124795974) |
| 镜像 SHA256 | `75c55bd57fd5908b89dce4e0239e1ec1cada36f3b94ae6d141a69b0a83472cfd` |
| manifest SHA256 | `85baf34ed4f912b2c8355478361b4b839241e220fa64480ee8a2fe4145d688ad` |
| odhcpd ELF SHA256 | `589226a178668c0e53fa8db5ff726e2b4e69464f9521355fad229b1862c3043e` |

执行了一次 sysupgrade。十一组件的安装文件、ROM 和运行身份相符，没有可执行
文件 bind mount；其余十个 ELF、内核和集成文件与 v0.2.3 一致。客户端取得
新的 RA、IPv6 地址与默认路由，直接向 RA 提供的 RDNSS 查询 TCP DNS，双栈
HTTPS 和 LuCI 均通过。这里只验收实际软重启，没有声称做过物理断电测试。

真实 Mac 客户端的 Renew(5) 与 Reply(7) 是捕获记录 18→19：MAC、DUID、
事务、Server DUID、IAID 一致，客户端收到了同一 Reply；无 NoBinding 或
UseMulticast。回复保留两条正寿命地址，T1/T2 为 1118/1788 秒。UTC
12:31:20.190–12:31:36.666 的 12 个状态样本和两次完整健康检查通过，地址、
路由、DNS 与候选进程身份正常。最终捕获 113 帧，无丢包、截断或配额耗尽；
关闭收据补足早期 proof 的 `capture_complete:false`，原证据未改写。

整段较长观察并非零失败：UTC 12:35:43.301、样本 418 有一次 `dig exited 9`，
在已验证的 Renew 窗口之外；样本 429 恢复通过。健康探针未记录具体失败的 dig
命令，原因未知，不能把它归因于客户端 UDP DNS 限制，也不因此改写续租窗口。

获准的 WAN6 操作只通过独立守卫请求该接口 down/up：设备 uptime 2576 秒
断开，2596 秒请求恢复，2600 秒确认 WAN6 与委派前缀恢复。WAN IPv4、LAN、
Wi-Fi 和 UCI 未作变更；约七分钟内 295 个样本的 WAN4/LAN 均 up，59/59
IPv4 HTTPS 探测成功，恢复后三次完整客户端健康通过。恢复获得同一委派前缀。

前缀撤销目前的证据边界：路由器在断开后约一秒已发出旧 PIO
preferred/valid=0/0、router lifetime=0 的 RA；**发出不等于客户端已收到**。
Mac 的已收 RA 在断开窗口内仍是旧记录，到恢复开始的样本 92 才记录另一条
0/0 PIO，样本 93 两条 SLAAC 地址首次出现 deprecated；样本 94 同一前缀
恢复后重新 preferred。窗口内没有该客户端对旧 IA_NA 的 Renew 撤销交互，
DHCPv6 地址仍保留。另一真实客户端在断开期间发出 Renew，服务器两次回复
明确将旧 GUA IAADDR 的 preferred/valid 设为 0/0，并保留正寿命 ULA；这证明
服务器撤销回复路径，但没有该客户端的地址状态，不能证明它已经清除旧地址。
45 帧撤销观察抓包完整、无丢包或截断；这是路由器抓包
完整性，不能证明无线客户端接收无丢失。现有证据不能确定首包未及时反映在
客户端状态中的原因，也不能据此认定 odhcpd 未发通知或实现缺陷。

发布裁决：用户明确接受 Mac 未及时标记属于客户端行为，不将其作为阻断；
新增发布条件是离线确认同一 WAN6 断开输入下 C 与 Rust 的撤销报文一致。
[精确 C 对照](ODHCPD_WITHDRAWAL_C_PARITY_20261018.md)已满足该条件：旧 PIO
0/0、router lifetime 0、保留的 ULA、RDNSS、RIO 及其寿命均一致，事件通知
均约一秒后触发。这个结论来自精确源码、已有夹具和已保存的本次抓包，没有
再次操作 WAN6。客户端记录和孤立 dig 失败仍原样保留；没有将同前缀恢复
描述为永久换前缀后的旧地址删除，也未认定无线首包未及时反映的具体原因。

WAN6 守卫和两次有限抓包均已退出；配置哈希未变、守卫锁不存在。完整材料已
归档后删除本次两个临时目录，没有留下自动恢复进程或持久启动项。

刷机前核验了 46 成员配置备份和 v0.2.3 离线回滚镜像，完整自动回滚守卫已
通过离线资格。初始客户端验收后，部署守卫明确 disarm、自行退出并归档，
临时启动项、目录及 RAM 暂存已清理；早期结果中的 armed=true 仅是当时状态。
干净备份 9,666 B、46 成员，原文件内容不变、无 trial 成员。离线材料持久化于
ignored `private/backup/release-v0.3.0/`，未随报告公开。

| 恢复材料 | SHA256 |
|---|---|
| 刷机前配置 | `b8702654472e3aec26c233e30f1ad2192e351d4d572965768c880c945562b650` |
| 刷机后干净配置 | `2f3f6661ff3fa3a930da0fa8db927a1e00d37e3216a0b634555862e83caf2022` |
| v0.2.3 回滚镜像 | `02b6a3283140126a9c7d3ccc0404afe42077924b6b1229b3b96859cf449d8606` |

私有原始证据分别保留于 `private/odhcpd-20261018/` 下的 `deploy-v030/`、
`postflash-prefix-renew-01/` 与 `wan6-withdraw-live-01/`。发布仅使用表中已测
CI 字节，v0.3.0 标签指向实际镜像源码；之后的工具或报告提交不改变发货 ELF，
不触发替代镜像构建。[v0.3.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/v0.3.0)
于 **2026-10-18 13:28:52 UTC** 发布为正式 Latest，release ID `416466158`。
十三个附件全部回读，逐文件字节数和 SHA256 与冻结清单一致；公开校验清单的
十二项也全部通过。十一件原始 CI 附件保持原字节，仅四个中文 APK 名称的
`~` 改为 `.`；另外两件是发布说明和公开 `SHA256SUMS`。原 manifest 的
`flashed:false` 保留构建时语义，不回写原始资产。

[PR #1](https://github.com/WenliangCao/owrt-control-plane-rs/pull/1) 的 host-tests、
host、target 三项 CI 通过后合并，提交 `948126206bc730874894fed0529a90e1ed436566`。
推标签短窗口停用 `release-image`，`finally` 恢复并核验为 active；发布后检查
未见延迟 tag 构建，未生成替代镜像。已合并任务分支本地及远端均删除，完整
证据提交仍由 main 历史保留；用户原有十二个未提交文件及无关工作树保持原样。
公开附件不含配置备份、密钥、抓包或原始设备状态。
