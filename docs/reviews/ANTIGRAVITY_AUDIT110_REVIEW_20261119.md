# Antigravity audit-110 对抗性审查（2026-11-19）

这轮有可取的修复和契约测试，但**不值得整轮合入**。120 个原提交逐条裁决：**20 采纳、6 修改后采纳、61 拒绝、33 无法判定**。建议拿回的是 **9 个功能修复及17个测试提交**；40 个 perf 全部未通过采纳门槛。建议已整理在从 `0cbc328d` 起的本地 `candidate/audit110-20261118`，并保持与 main 分离。待定不是断言补丁错误；它表示缺少足以承担部署风险的证据，具体缺口逐条写入同名 JSON。

| 组件 | 采纳 | 修改后采纳 | 拒绝 | 无法判定 |
|---|---:|---:|---:|---:|
| dnsmasq | 5 | 2 | 19 | 15 |
| fw4 | 6 | 0 | 2 | 0 |
| httpd | 2 | 1 | 8 | 1 |
| logd | 0 | 1 | 2 | 1 |
| netifd | 4 | 1 | 4 | 10 |
| odhcpd | 1 | 0 | 7 | 0 |
| platform | 0 | 0 | 1 | 1 |
| procd | 1 | 0 | 9 | 0 |
| rpcd | 1 | 0 | 5 | 3 |
| ubus | 0 | 0 | 1 | 1 |
| ubusd | 0 | 0 | 3 | 1 |
| uci | 0 | 1 | 0 | 0 |

组件表按原提交归属计数，ubus单列，platform是被链接库。关键证据：netifd四组修复有真实C/基线/候选差分；DNS根域与合成域名判断、启动失败日志有镜像对照；httpd EINTR与TLS虚假就绪有基线反例；odhcpd队列容量有确定性失败输入。fw4六项锁定完整渲染输出，uci测试需修正宿主配置污染。procd/rpcd/logd可拿回的是契约测试，不是这轮大范围生命周期和IO改写。

审查基线为 `v0.3.3 → 1e25d61d`，部署固件SHA256 `5b4e7511b228f97b477b875ebfca4c93117e84e450d5c0f5178725e8bab3b151`；`0cbc328d` 与它的 `components/` 净差异为空。归档端点 `983269e5`，完整区间120条，58 fix /40 perf /21 test /1 revert。行为权威为OpenWrt25.12.6镜像及匹配源：netifd cbb83a18、odhcpd 5d7be43f、uhttpd 373145f7、dnsmasq2.93，以及各组件记录的libuci/libubus/procd/rpcd/firewall4版本。

## 值得拿回的修复（按影响范围排序）

| 原提交 | 候选方式 | 真实问题与复核 | 范围限制 |
|---|---|---|---|
| `1435c839` netifd | 修改后采纳，`6862500e` | UCI scalar空白、list形状和dump wire type错误；原版C与最终候选逐字段一致，等价配置不重启、空白编辑会重启，基线相反。原audit仍把不匹配的list拼成scalar，不能照搬。 | 任意外部handler重名异型属性仍是既有单值映射限制；极值扩展覆盖单列。 |
| `c82b7416` netifd | 与 `ad2e816d` 合组，`49991fb6` | 协议IP过期后旧用户态节点不移除。IPv6重装基线NEWADDR/NEWROUTE=1/0，C与候选1/1并有addresses更新标志；重复重装均零写入。 | 不是声称基线最终内核路由缺失；旧路由可能还存在。内核快照相等不能掩盖事件差异。 |
| `0cf26d48` netifd | `5bb77351` | `proto none`错装遗留静态地址；`defaultroute=0`仍安装IPv4/IPv6网关。最终候选与C内核观察一致，reload重新开启后均恢复网关。 | 不覆盖另一个offlink reload补丁。 |
| `44bef059` netifd | `e056d39a` | auto从0改1后reload不启动。基线start_seen=false，C/候选true；手动down后reload三方均继续保持down。 | 已审Down/Normal/remove_pending条件；不是全无线生命周期认证。 |
| `e1dc55f4` odhcpd | `5c7aaf6b` | refresh占据8槽回复队列的一个位置，第8个回复在基线WouldBlock；候选把refresh合并为标志并保留在途permit，8个回复全部保留。C并发8请求均成功，私有C ubusd断连恢复测试通过。 | 内部确定性交错与C wire实验分别记录，未声称两者内部线程结构同构。 |
| `4f0a0591` httpd | 修改后采纳，`1e8c3bd5` | 直接调用基线生产resume，空队列的就绪回调后连接计数1→0；MSG_DONTWAIT版本保留连接。C空读回调同样保留，随后GET/repark/close验证。 | 删除原“<15ms”调度阈值，改为状态和进展断言；C空读为完整源函数加受控依赖。 |
| `5736a005` httpd | `b57c5882` | 请求体/CGI遭EINTR时不应丢失剩余数据。主代理重跑：base两个body/CGI测试失败，候选通过；C函数注入EINTR/短写仍完整送出13字节。 | HEAD读测试base也通过，未把它算回归证明。 |
| `819d705c` dnsmasq | 修改后采纳，`4fb96656` | 根域仅含host/CNAME时错误NOERROR，以及合成IPv4名的AAAA错误NXDOMAIN。精简候选9场景13探测与镜像C一致。 | 剥离前序大型CNAME/cache改写；并未证明所有DNSSEC/stale组合。 |
| `f5974e3b` dnsmasq | 修改后采纳，`1e89cd8a` + `13e41b52` | 前台重定向后退出5却丢失日志。发布ELF可复现，候选和C的前台/调试/后台派生结果相符。 | 修正原测试错误文本并固定root/group以隔离drop权限；未注入所有helper/netlink启动失败。 |

可直接复现的主代理验证命令如下，输出目录必须使用未存在的新名字。Rust命令先在oracle设置PATH并检查 `cargo -V` 包含 `huacnlee/cargo`，进入仓库以使用1.98.1工具链；不使用mbx、target-dir或clean。

```sh
# 真实内核/ubus/typed配置三方；proto-fix在此目录实际指最终组合netifd ELF。
ssh oracle 'sudo -n python3 /var/tmp/a110-chief.9YihOB/resume-net/focused-net.py /var/tmp/owrt-qual/rootfs /var/tmp/a110-replay-net-20261119 --cases autostart static-none proto-shape --sides c before proto-fix'
# 48个续租/过期/重装场景，43个内核状态对照。
ssh oracle 'sudo -n python3 /var/tmp/a110-chief.9YihOB/candidate/tools/netifd_renewal_keep.py --rootfs /var/tmp/owrt-qual/rootfs --candidate /var/tmp/a110-chief.9YihOB/combined-bins/netifd-rs --out /var/tmp/a110-replay-renewal-20261119'
# HTTP EINTR：base预期失败，candidate预期通过。
ssh oracle 'export PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN=1.98.1; cargo -V | rg huacnlee/cargo && cd /var/tmp/a110-chief.9YihOB && cargo test --locked --manifest-path candidate/components/httpd/Cargo.toml --bin httpd-rs interrupted_ -- --test-threads=1'
# DNS根域、合成域、TTL的镜像C/Rust对照。
ssh oracle 'sudo -n sh /var/tmp/owrt-a110-dns.2dL5o7/src/tools/dnsmasq/run_isolated.sh python3 /var/tmp/owrt-a110-dns.2dL5o7/src/tools/dnsmasq/m5_option_matrix.py --image-root /var/tmp/owrt-a110-dns.2dL5o7/stock-root --rust /var/tmp/a110-chief.9YihOB/combined-bins/dnsmasq-rs --rust-sha256 1156cba368d0371f3cc1cdf966f50b03f2bec892684ad786b92087a55515cf76 --source-commit 6862500e --manifest /var/tmp/a110-dns-review.MFJkia/candidate-owner-matrix.json --output /var/tmp/a110-chief.9YihOB/private/dns-replay-20261119'
```

启动三模式命令、队列容量、TLS虚假就绪及每个提交的基线/端点测试名在JSON的 `reproduce`。证据中的固定测试ELF已从会自动清理的Cargo缓存复制到独立scratch。`combined-bins`记录的源快照是6862500e；后续DNS与netifd生产代码不变，后续HTTP生产补丁使用另外记录的最终产物。不要用原目录中名为candidate的audit端点冒充精简候选。

17个测试提交的采纳范围是：fw4六项（`d1062961 fbf15547 8aa14c82 c9e7b781 88c12321 74fc6365`）；DNS五项（`33162d2a 1146e24d 6898407e 3a552d6b e76a2b17`）；procd watchdog `c2f9d8bf`；rpcd timeout `e67f9ba5`；logd oneshot `381a56cd`（用较小有界测试替代）；uci revert `4ee06746`（加隔离修正）；netifd `ad2e816d`；httpd PATH_INFO `974f925d`。它们验证已有契约，基线通过是合理的，不把test-only提交冒充bug fix。

- fw4六场景完整stdout与镜像ucode相同；两场景有既有mock stderr差异，未声称全部输出字节相同，更未声称nft内核能接受所有C产生的规则。
- procd无watchdog设备仍提交5000ms timer、rpcd timeout八个边界，由匹配C函数/表达式受控执行验证；没有拿计时睡眠做断言。
- logd真实C与发布版均完成1条即时记录后EOF，以及700条积压+1条实时记录后EOF；积压超过实际pipe容量，确实经过排队路径。
- UCI原测试受 `/run/uci/pkg` 和 `/tmp/.uci/pkg` 污染，主代理各复现退出101；禁用override、唯一包名后相同污染场景退出0。这个修正以 `20e2b8b4` 保存，不能遗漏。

## 性能三方与重建控制组

**以下全部在oracle Linux VM上测量，未经设备验证。** 为区分构建配方和代码效果，实际测了四方：原版C、实际发布v0.3.3 ELF、同路径重建基线、同路径重建audit端点。新的80窗按四轮轮换顺序交错（16联合+64隔离），CPU3固定、一次仅一个计时所有者，耗时419秒。旧70窗另存，不与新样本混算。开始/过程/结束进程快照没有Rust编译，但普通后台服务存在；不声称整个VM无噪声。

模型：端到端时间=服务CPU+CLI/内核+调度+缓存。预注册预测RSS增加300–350KiB、anon增加60–90KiB、reload CPU降10–20%但墙钟可能仍在噪声内。观察分别是+330KiB、+70KiB、-15.875%；墙钟+4.152%且区间重叠。模型支持“少了一些周期轮询/处理CPU，同时增加常驻成本”，不支持“用户体验已显著提升”。

下面每格为窗口中位数[min–max]，每侧n=4；每个相同二进制的四窗区间就是同批噪声校准，所有原始样本与span/median保存在JSON。RPC每lane1000次、DNS/DHCP各400测量请求、reload10为10周期；fw4每窗1次、uci5次、logd/ubusd100次。小样本CLI不用于宣布普遍加速。

| 指标（每侧 n=4） | C 原版 | 实际发布 v0.3.3 | 同路径重建基线 | audit端点 |
|---|---:|---:|---:|---:|
| 空闲总RSS KiB | 10284.000 [10252.000–10348.000] | 8658.000 [8652.000–8672.000] | 8616.000 [8492.000–8620.000] | 8946.000 [8944.000–8948.000] |
| 空闲匿名内存 KiB | 1968.000 [1964.000–1976.000] | 1234.000 [1228.000–1248.000] | 1260.000 [1252.000–1260.000] | 1330.000 [1328.000–1332.000] |
| 约10秒空闲CPU ms | 2.166 [2.147–2.232] | 0.246 [0.237–0.264] | 0.243 [0.230–0.257] | 0.000 [0.000–0.000] |
| 10次reload守护进程CPU ms | 22.256 [21.846–22.708] | 24.650 [23.995–27.538] | 25.698 [24.144–26.933] | 21.619 [21.118–22.223] |
| 10次reload墙钟 ms | 528.998 [521.576–541.923] | 177.265 [171.441–199.062] | 169.893 [167.590–192.848] | 176.947 [173.289–182.485] |
| HTTP JSON-RPC p50 µs | 351.103 [347.443–352.602] | 247.082 [245.482–248.922] | 248.302 [245.442–249.762] | 248.642 [247.202–257.282] |
| rpcd UCI get p50 µs | 420.744 [412.604–426.803] | 344.222 [342.723–345.243] | 348.343 [346.123–360.763] | 348.663 [341.843–365.803] |
| procd service list p50 µs | 338.983 [334.443–354.563] | 278.142 [276.482–283.842] | 283.102 [277.922–295.043] | 279.382 [270.362–293.443] |
| netifd dump p50 µs | 389.343 [381.163–397.724] | 282.262 [281.642–283.482] | 289.382 [286.322–292.443] | 286.602 [278.843–301.202] |
| DNS p50 µs | 50.901 [43.120–61.601] | 39.960 [37.440–44.201] | 45.180 [40.200–52.600] | 40.700 [39.080–43.481] |
| DHCPv4 p50 µs | 95.560 [87.080–123.241] | 76.361 [62.000–87.761] | 84.441 [75.601–101.161] | 83.520 [71.240–94.721] |
| fw4 print p50 µs | 20933.855 [20560.852–21059.736] | 1223.830 [1134.529–1290.931] | 1210.830 [1151.090–1303.091] | 1156.350 [1131.290–1159.010] |
| uci export64 p50 µs | 998.929 [984.328–1055.969] | 630.106 [620.565–694.806] | 662.946 [640.165–686.486] | 615.525 [601.925–631.725] |
| log read100 p50 µs | 371.203 [361.123–409.443] | 117.521 [116.001–121.281] | 115.461 [112.041–121.761] | 117.001 [112.921–127.361] |
| ubus invoke p50 µs | 57.021 [52.081–57.840] | 45.740 [44.721–48.601] | 46.001 [44.600–46.960] | 46.680 [46.480–47.281] |

新批次未复现旧窗“rpcd p50回退”的暗示：+0.092%、区间重叠；reload墙钟也由旧窗负变化转成+4.152%，因此撤回旧窗对这两项的方向性判断。UCI export64出现-7.153%、四配对同向且区间分离，保留为窄负载筛选线索；UCI自身没有perf提交，不能据此归因任意共享库改动。reload CPU的改善不能抵消内存/体积代价，也不能代替设备体验。

内存单位KiB，每格“RSS中位数[min–max] / 匿名内存中位数[min–max]”，每侧n=4：

| 守护进程 | C RSS / anon | 发布 RSS / anon | 重建基线 RSS / anon | audit RSS / anon |
|---|---|---|---|---|
| dnsmasq | 1250.000 [1188.000–1252.000] / 240.000 [240.000–240.000] | 2568.000 [2568.000–2572.000] / 640.000 [640.000–644.000] | 2588.000 [2588.000–2588.000] / 660.000 [660.000–660.000] | 2578.000 [2576.000–2580.000] / 650.000 [648.000–652.000] |
| netifd | 2016.000 [2016.000–2080.000] / 612.000 [612.000–612.000] | 1240.000 [1240.000–1244.000] / 184.000 [184.000–188.000] | 1242.000 [1240.000–1244.000] / 186.000 [184.000–188.000] | 1314.000 [1312.000–1316.000] / 258.000 [256.000–260.000] |
| odhcpd | 1112.000 [1112.000–1112.000] / 100.000 [100.000–104.000] | 804.000 [804.000–804.000] / 76.000 [76.000–76.000] | 804.000 [804.000–808.000] / 76.000 [76.000–80.000] | 880.000 [880.000–884.000] / 88.000 [88.000–92.000] |
| httpd | 1040.000 [1036.000–1040.000] / 120.000 [120.000–120.000] | 1146.000 [1144.000–1148.000] / 82.000 [80.000–84.000] | 1082.000 [1080.000–1084.000] / 82.000 [80.000–84.000] | 1080.000 [1080.000–1084.000] / 80.000 [80.000–84.000] |
| procd | 1082.000 [1056.000–1084.000] / 132.000 [128.000–132.000] | 792.000 [792.000–792.000] / 64.000 [64.000–64.000] | 792.000 [792.000–792.000] / 64.000 [64.000–64.000] | 920.000 [920.000–920.000] / 64.000 [64.000–64.000] |
| rpcd | 1960.000 [1960.000–1964.000] / 548.000 [548.000–552.000] | 1128.000 [1128.000–1128.000] / 64.000 [64.000–64.000] | 1128.000 [1000.000–1128.000] / 64.000 [64.000–64.000] | 1192.000 [1192.000–1192.000] / 64.000 [64.000–64.000] |
| ubusd | 960.000 [960.000–964.000] / 116.000 [116.000–116.000] | 538.000 [536.000–540.000] / 82.000 [80.000–84.000] | 540.000 [536.000–540.000] / 84.000 [80.000–84.000] | 540.000 [536.000–540.000] / 84.000 [80.000–84.000] |
| logd | 892.000 [828.000–892.000] / 100.000 [100.000–100.000] | 442.000 [440.000–444.000] / 42.000 [40.000–44.000] | 442.000 [440.000–444.000] / 42.000 [40.000–44.000] | 440.000 [440.000–444.000] / 40.000 [40.000–44.000] |

每组件空闲CPU及上下文切换的n/median/min/max均在JSON `performance.summary`。主要空闲变化来自procd和netifd：合计约10秒12次上下文切换降为0，约0.243ms CPU降为0；0表示窗口没有新增计费CPU，不表示永远不唤醒。CPU时钟声明1ns分辨率不代表实际准确度；上下文切换也不等同于精确timer唤醒次数。fw4、uci、reload-config是短命CLI，无空闲常驻进程，idle RSS/anon/CPU为不适用，峰值内存未采。platform随调用者计入，无独立C/ELF可比较。

| 组件 | C入口字节 | 发布字节 | 重建基线字节 | audit字节 | 增量字节 |
|---|---:|---:|---:|---:|---:|
| fw4 | 2965 | 1051347 | 1051347 | 1071843 | +20496 |
| httpd | 58322 | 1620727 | 1620727 | 1641207 | +20480 |
| logd | 16905 | 432819 | 432819 | 436915 | +4096 |
| netifd | 232827 | 1105976 | 1105976 | 1142840 | +36864 |
| procd | 97697 | 897016 | 897016 | 901112 | +4096 |
| reload-config | 591 | 465643 | 465643 | 465643 | +0 |
| rpcd | 62043 | 1280803 | 1280803 | 1293107 | +12304 |
| ubusd | 32962 | 524280 | 524280 | 524280 | +0 |
| uci | 16395 | 490251 | 490251 | 490251 | +0 |
| dnsmasq | 269305 | 2321243 | 2202459 | 2235227 | +32768 |
| odhcpd | 111865 | 807032 | 807032 | 823432 | +16400 |

重建端点总ELF增加147,504字节；reload-config两侧465,643B，低于512KiB（524,288B），余量58,645B。C的fw4和reload_config入口是脚本，表中的入口大小不含解释器/共享库，不能拿来当整个执行栈的大小。

22个归档MD5与历史清单均匹配，但22个重建产物都不同。差异已查到：路径remap、build-id、sstrip/section headers、httpd中ring的clang21与SDK GCC14编译器、DNS归档ET_EXEC与发布/重建static PIE。fw4/odhcpd的±4096B进一步定位为4080B填充+16B Cortex-A53 erratum843419链接桩。两侧源快照各477个tracked文件匹配相应提交，但这不证明历史编译时所有环境都已重现。

重建基线也不与发布ELF逐字节相同：DNS比发布少118,784B，冻结PGO有3099/3128条缺数据诊断。故表中始终保留实际发布列；不可把重建before称为线上原样产物。CPU负载只是Oracle筛选，没有单perf隔离，也没有独立odhcpd DHCPv6/RA update、大型fw4、HTTP parked、DNS TCP/反向缓存/TFTP、rpcd exec完整性能矩阵。**40项perf拒绝的是本轮采纳资格，不是证明40项都没有收益。** 当前没有达到申请设备验证门槛的最小组合，因此不请求上传或运行候选。

## 这轮自述里不成立的部分

1. “reload比C快约65%、RSS比C低约15%”大部分是v0.3.3已经具有的收益。新窗发布reload墙钟177.265ms、audit176.947ms，C528.998ms；不能把相对C的优势记成audit新增功劳。
2. “修复”不等于C兼容：odhcpd小数租期、DNS地址优先级、PIO时钟、RA停用lifetime；httpd根docroot、HEAD错误body、目录index边界，均有与C不一致的实测或完整C函数证据。安全/标准方向值得另议，不能伪称恢复旧合同。
3. 原DNS启动回归测试在audit tip仍失败，错误文本/权限路径没有隔离；UCI测试则能被宿主配置稳定污染。绿色命名不构成可靠测试。
4. “renewal before/after kernel无差异”不足以证明没有缺陷。旧harness按C/Rust使用不同NEWROUTE期望，掩盖过期用户态节点未更新。严格统一断言后，基线确有可观察差异，候选修正。
5. `9589e337`只修回本轮perf把getHostHints改坏的名字；`8af090f4`只补回本轮先删掉的PID1上限。DNS neighbor、lease、suffix索引和netifd/HTTP索引反复引入再删除，应按组看净diff，不能累计宣传收益。
6. TLS“大正文截断”在普通512KiB附带测试和实际4MiB三方传输没有复现；带raw junk的TLS超时测试虽区分两侧，缺同条件C截止点，所以291d0017仍待定。

## 净差异、未决风险与验证边界

净diff已按组件复核：DNS包含缓存/CNAME/DHCP/异步reload广泛交互，仅选两项最小功能修复；netifd包含设备消失、桥删除、无线队列、前缀分配、重启清理、route gate等多个生命周期边界，未以四项通过背书其余代码；HTTP未带入HEAD/docroot/TLS drain/parked索引整串；odhcpd未带入语义重设计和大表优化；procd/rpcd/ubusd/logd/platform保留ACL、信号、FD归属、队列与respawn未决项。

33个无法判定均有具体缺口。例如DNS CNAME过期链缺同缓存时间线C实测，DHCP relay缺真实跨接口内核发送；netifd bridge拆分尚无完整候选，wireless缺精确ucode回调对照；ubus额外FD附带测试在base也通过，rpcd query-id碰撞缺确定性随机源；logd极端ring输入debug失败但C边界与生产可达性未闭合。此报告不会把这些项目写成“审过所以安全”。

odhcpd前缀移位guard虽能消除debug测试的shift overflow，却会丢弃精确C接受的PD前缀，整提交拒绝。主代理复核了release与实际发布ELF：同输入C回3个PD前缀，发布版回2个且进程存活，audit只回1个。release测试失败来自len=2与测试期望1不符，不是移位处panic；不能用debug panic外推生产必崩。当前无立即重启/修改线上配置的依据。实际设备未运行任何候选。

本次使用Microsoft Rust Guidelines的失败边界、unsafe/FFI、可控IO、非同义反复测试和静态验证规则；没有宣称全仓库重新逐行认证。Rust只在oracle用PATH中的huacnlee/cargo运行。候选每组按独立提交保留，main只提交本报告和账本。

指令冲突按本次明确边界处理：

- `AGENTS.md` 的“可设共享CARGO_TARGET_DIR并cargo clean”例外不适用；没有使用。
- `docs/RUST_GUIDELINES.md` 的“using mbx for every Cargo…”以及Makefile/旧driver的mbx调用过时。本轮在scratch用ci-plain.py仅把命令入口改为cargo，保留仓库manifest、locked参数、feature矩阵和namespace runner。
- 提示同时写“main只读”和“报告按路径stage提交到main”。以具体交付条款为报告文件的唯一写入授权；功能代码候选不合入main、不push、不移动归档标签。
- 子代理路由沿用中断会话最后明确选择的 `xingchi/gpt-6.1-sol`。子代理结论均作为线索，采纳项与新的实质发现由主代理复核。

## 交付与复现索引

候选分支：`candidate/audit110-20261118`，当前HEAD `1e8c3bd5d516f13c2ad3c59561bd882b645daa03`。全部候选提交顺序见同名JSON的 `candidate_commits`；按依赖顺序可cherry-pick，不能只拿最后一个提交。

最终 `1e8c3bd5` 组合门禁日志明确 `GATES-COMPLETE`：fmt覆盖15 crates及fuzz；check/clippy/test覆盖14组件crate的默认/声明的all-features、examples、doctests；benchmark默认/all-feature及9组Python检查、C语法检查。被忽略测试不计执行；显式补跑DNS TFTP partial bind与syslog连接恢复、odhcpd私有broker恢复。门禁日志位于 `oracle:/var/tmp/a110-chief.9YihOB/ci.log`，旧6862500e与0c82bd58日志单独保留。最终HTTP musl ELF SHA256 `7610df0dbd2e405637f253136fc141fb24a7aedf16753bb70b83b62aeaf11db0` 的49场景/39精确项复验也通过。

主代理新执行的C功能证据包括HTTP 49场景（39精确项零差异）、PATH_INFO四场景、目录index反例、netifd三场景/续租48场景、DNS 9场景13探测和三种启动模式、fw4六个渲染场景、UCI12步事务/两类污染反例、logd即时/排队EOF、C watchdog/timeout、odhcpd队列与C前缀函数。完整执行命令及哪些是源码受控依赖、哪些是真进程/镜像，逐条写入JSON。

原始日志、上游提取文件、脚本与输入身份保存在忽略目录：
`/Users/wenliang/Developer/owrt-audit110-review-20261118/private/audit110-review-20261119/`。
账本中的 `private/audit110-review-20261119/` 相对这个独立review worktree；远端原始目录继续保留。性能新批次在 `oracle:/var/tmp/a110-repeat.ctAqA1`，构建在 `oracle:/var/tmp/owrt-audit110-build.dNUabP`。`primary-review-manifest.json`及各分项identity文件用于追溯输入与日志；重放使用新输出目录，不覆盖旧观测。

最终自检：120/120原提交一条且仅一条；分类总数与git一致；26项建议采纳有主代理复核记录及本地候选；性能明确全部未经设备验证；未合入功能代码、未push、未触设备状态。后续需要用户决定的是是否另行把这个候选合入main，以及是否为待定安全/兼容变更开单独任务；本报告不代替设备验收。
