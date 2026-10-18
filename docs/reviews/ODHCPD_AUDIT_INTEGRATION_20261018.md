# odhcpd 安装、恢复与验收证据独立审计

2026-10-18：本范围发现 **1 项 P2，0 项 P0/P1**。最终十一组件镜像的恢复清单
若漏掉 odhcpd，恢复工具仍返回成功，留下 Rust odhcpd。必须处理该结论后再讨论
上线。v0.2.4 继续不刷、不发布；本审计不构成部署许可。

审计者未参与组件实现。审读安装配方、原 init/update 调用合同、试运行生成器/
守卫/自测/客户端观察器及现有功能资格工具；只增加一个 Oracle 隔离负控和一项
原件一致性复核，不修改产品或现有工具。不访问物理路由器，不构建 Rust，不做
性能或 PGO。协议实现细节由并行独立审计负责。

输入绑定：组件 source `d0ef9f04`，SDK ELF
`79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`；最终镜像
source `4acf1c80e2dfeab7247b6de85694977ae2873894`、image SHA256
`eb96dd90d23f4f35f8ccdee2ec01b1c2f5cf828b47ebb87671fe297caa7f9ed3`。
最终 rootfs 仅从 `/home/ubuntu/odhcpd-image-v024-20261018/rootfs` 复制读取。

## P2：恢复集合未绑定镜像布局，遗漏 odhcpd 会误报完整 C 恢复

位置：[owrt-recover-c:9](../../packaging/image/owrt-recover-c#L9) 的 12/13 行选择，
[第 17 行](../../packaging/image/owrt-recover-c#L17) 的条件 odhcpd 要求，以及
[第 65 行](../../packaging/image/owrt-recover-c#L65) 的成功说明。

`stock.sha256` 自己的行数决定恢复范围。工具不读取同目录 `release.json` 中的
`layout`、组件集合或已存在的 `stock_manifest_sha256`。因此真正 native-ten
镜像的兼容路径，也接受 native-eleven 镜像中缺少 odhcpd 的旧/不完整清单。

实际失败顺序：

1. 复制精确最终 native-eleven rootfs。保持 `release.json`、11 个活动 ELF、
   13 个 stock 恢复文件和恢复脚本不变。
2. 仅删除 `stock.sha256` 的 `/usr/libexec/owrt-stock/usr/sbin/odhcpd` 一行。
   剩余 12 行正好是工具要求的历史集合，所有剩余文件哈希均正确。
3. 在新 mount/net/PID namespace 中运行副本的原 `/usr/sbin/owrt-recover-c`。
   实测退出 **0**，旧十个组件变为 C；odhcpd 仍为 SDK Rust ELF。
4. 输出仍为 `All 10 C programs ... Reboot to activate the complete C stack.`。
   若操作者因 odhcpd 故障调用完整 C 恢复并据此重启，故障组件没有被恢复。

这不影响完好清单的正常恢复，也不是物理路由器已遭遇的故障；它破坏的是已有
“损坏恢复材料必须在任何替换前拒绝”的保证，且会给出错误的恢复完成信号。

期望修复：恢复前把集合绑定到当前镜像的布局/组件清单，并验证已经存储的
`stock_manifest_sha256`；native-eleven 必须要求 13 项，真正 native-ten 仍允许
12 项。不应靠本次待验证清单的行数推断镜像代际。

只需扩展 [native_image_check.py:134](../../tools/native_image_check.py#L134)
的 recovery 场景：native-eleven 副本去掉 odhcpd 行，期望非零退出，11 个活动
ELF 和两个 integration 文件全部保持 Rust 状态。现有
[test_native_image.py:67](../../tools/test_native_image.py#L67) 的 `missing` 删除
fw4，未覆盖“恰好退化成合法旧集合”；保留真实 native-ten 正控。

负控一次执行，无失败重试。Oracle 原件：
`/home/ubuntu/odhcpd-audit-integration-20261018/missing-odhcpd-01/result.json`。
本地 ignored 目录 `private/odhcpd-20261018/audit-integration/` 保存独立脚本与结果：

| 对象 | SHA256 |
|---|---|
| `recover_missing_odhcpd.py` | `2e7d828bac5456afd975418c7e714d9017a9949399f188fbdc95ed36b152e5b2` |
| `recovery-result.json` | `7ba85af06443c164a947d01a9fbd55a67aeaa9a17dc4edcb5454d461035138b5` |
| 原镜像恢复清单 | `8ec4cc70c2025836138d2ea84a4e848bc9f00717dffd8afeeb9631d7157557b4` |
| 缺 odhcpd 的输入清单 | `d36e8549ac163eb464945662bcfad733963a3d3447970d86b49341e800019922` |

运行前后核对共享源 rootfs 的清单、恢复脚本、11 个 ELF 和各 C 副本，全部未变。

## 已核对的集成与证据边界

- [native_image.py:39](../../tools/native_image.py#L39) 按固定名字、路径、binary、
  owner 验证十/十一组件；odhcpd 的 SDK 引用哈希、stock 哈希和
  `odhcpd-ipv6only` owner 均已绑定。最终 rootfs 的原 odhcpd init/update 与原
  `15_odhcpd` 保留，原 init 使用 `/usr/sbin/odhcpd`、respawn、SIGHUP reload。
  此范围未发现正常打包将错误 ELF、init 或 owner 放入镜像的路径。
- `native_apk_fixtures.py` 加入 odhcpd 原 owner；它明确只重建未签名 payload，
  重装使用 `--no-scripts`。这些证据证明文件所有权与缺失文件修复；不把它解释为
  原始签名 APK 的完整生命周期资格。
- 试运行守卫自身执行 bind 和 restart，先建立脱离调用者的进程再改服务；确认后
  必须停止候选、卸载可归属 bind、恢复并核对 C，再写 `restored-confirmed`。
  健康回执由可信外部观察器生成，守卫验证其 digest/token/boot/候选身份；守卫
  本身不重算外部网络证据，合成回执自测不能替代真实客户端验收。
- 对 `trial-live-01` 原始 JSONL、客户端回执与设备 tar 重新计算摘要：事件顺序为
  start、13 次 pass、complete；同一候选 PID/start/ELF 和 boot，连续
  **124.986447 秒**；5 个不同激活后 RA 接收时刻。设备 `accepted` 同时匹配回执
  摘要和原始 JSONL 摘要，归档状态是 `restored-confirmed`，候选/C 文件身份正确。
  配置前后 tar SHA256 相同。没有发现这次试运行假通过的证据。
- 最终镜像 boot 原件含新客户端 SLAAC、IA_NA/IA_PD 四次交换、ubus/lease/hosts
  内容及新名字的 DNS AAAA，所用原 update 会通过 procd 通知 dnsmasq。
  真实 Mac trial 的现有地址/缓存 DHCPv6 不单独证明新 DHCPv6 交换；报告已明确
  这个边界，不能把 120 秒连通性等同于全生命周期资格。

原件复核输出：Oracle `.../live-evidence/audit-result.json`，本地
`private/odhcpd-20261018/audit-integration/live-evidence-result.json`。
原始健康 JSONL SHA256 为
`c9ce4f3cf35edb5cc582ac6e31a09a3094753827b032349d7a437d1c35c6b0d1`；设备归档
SHA256 为 `24eab4a77e16c1ab862c0bb0d274e02516b8da1498102c3c2cf9321b71633401`。
报告未写入真实地址、DUID、MAC、PID、boot ID、token 或配置。

## 应定向扩展的必要功能资格

82 项是 baseline 20 加四组扩展 62 个断言，不能代替所有本机调用链。
这里的空白是测试结论的边界，不额外计作已复现的产品缺陷：

| 现有场景及空白 | 最小扩展 |
|---|---|
| `odhcpd_baseline.py:432` 直接发 HUP，但未修改 UCI；control 的 DNS 改动来自 netifd `data`。`native_boot_check.sh:168` 调用 reload_config，也没有修改后验证配置生效 | 在已有完整 boot 夹具的绑定完成后，修改 LAN DNS/租期，调用原 init reload 或真实 reload_config；验证新 DHCPv6 参数、旧绑定的续租期限及 PID/start 不变。重复空 HUP 无法覆盖这个合同 |
| `native_boot_client.py:91` 直接检查租约文本，未调用实际 LuCI 消费者；`odhcpd -h` 功能列表也未经过消费者检查 | 在同一夹具增加 `luci-rpc.getDHCPLeases` 和 `luci.getFeatures` 查询，分别核对本次 NA/PD 导出和 `ra/dhcpv6/ubus=true, ndp/dhcpv4=false`。无需新增客户端或扩大物理试运行 |

现有真实 trigger 的首次名字注册、普通续租不重复 trigger、纯 PD 不重复 trigger
已有不同层次证据；不要求为了补计数再跑这些场景。尚无主动物理 DHCPv6 续租的
证据应保留为限定说明，不能在本次只读审计中自行补做路由器操作。

本范围完成。后续只需处置上述恢复缺陷并把必要的配置 reload/调用方断言纳入
受影响功能门；是否继续上线还须合并其余独立审计结论。

## 定向复验：恢复 P2 在修复脚本上关闭

2026-10-18 独立复核修复 commit `974cfee55de072468b7c4cd9c572e88b54213566`：
脚本先读取 `release.json.layout` 决定必需数量，再核对已有
`stock_manifest_sha256`，之后才检查恢复集合与写入文件。该 P2 **closed**。
修复后的 `/usr/sbin/owrt-recover-c` SHA256：
`96d6677abebc2a14012f1ab43f885cf614c96f73bcc189005674bfbda0d81abc`。

复用原负控的输入变更与真实 BusyBox/jsonfilter、mount/net/PID namespace，
独立新脚本在每个新 rootfs 副本仅替换修复后的恢复脚本。三个场景一次通过：

| 输入 | 实测结果 |
|---|---|
| 精确 native-eleven，仍只删除 odhcpd 恢复清单行 | 退出 1，报 `stock recovery manifest identity mismatch`；11 个活动 ELF 和两个 integration 文件的哈希全部未变，无 staging 文件 |
| 精确 native-eleven，完整清单 | 退出 0，13 个目标的内容和模式全部匹配 stock 副本，无 staging 文件 |
| 精确历史 v0.2.3 native-ten rootfs，source `0a925bcc2ec065eebaae51811c1a6252007b9d56` | 退出 0，12 个目标的内容和模式全部匹配 stock 副本，无 staging 文件 |

两份共享源 rootfs 的活动/stock 文件、清单与原恢复脚本在运行前后均未变化。
Oracle 原件为 `/home/ubuntu/odhcpd-audit-integration-20261018/recovery-fix-01/`；
本地 ignored `audit-integration/` 保存 `recover_recheck.py` 和
`recovery-fix-result.json`。未构建产品、访问路由器或采集性能。

关闭的是该脚本修复，不把旧 v0.2.4 镜像重新认定为已修复；最终新镜像仍须包含
上述脚本并运行受影响恢复门。配置 reload 与 LuCI 消费者的新增夹具结果等待
最终新 SDK/镜像后另核，不在此次定向复验中重跑。
