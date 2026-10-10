# dnsmasq-rs 交付账本

## 当前状态与下一步

**M6b最终交付完成。** UDP／TFTP授权修复后，从 `889fe4f5` 重新冻结并从第1步完整验收；全部普通／targeted、资源／压力、135、guard、APK生命周期、报告与清理已关闭。产品继续冻结，没有在验收中修改。完整结果见 [M6B_REPORT.md](M6B_REPORT.md)。

| 最终产物 | 字节 | SHA256 |
| --- | ---: | --- |
| feature-off opt3 | 1,966,120 | `791a7c33987fbb21887c51041f27722b9cc1bd8bd4cffab0fc03a292517fb10f` |
| 同源 feature-off s | 1,642,536 | `d8d3c1ea2ed0a3c29ab260aea21534e6c326a371342a15442a540d62cd3539dc` |
| 精确镜像 C | 269,305 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 可替换r3 APK | 1,085,625 | `8df2e454151ac09aad64630bf4d8b5f95fcf415c6f65a96a010e923ad0c59a01` |

最终源码 `889fe4f5c59da514529e31173d346ec93bae03a9`；172项产品／包输入、157项编译输入及实际ELF/build/link map核验见 [冻结记录](audits/M6B_FINAL_FREEZE.md)。后续main工具／文档提交不改变产品身份。s只完成性能对照，未继承opt3功能／APK资格。

| 统一验收 | 最终状态 |
| --- | --- |
| M5／M2 | 同opt3完整44族／68步、169选项CLI/file；完整M2十jobs（7DNS profile、4DHCP profile套件、C/R生命周期）；全通过 |
| 独立targeted | 16jobs：route basic/clears、accept snapshot、lease-held-import C/R/compare，same-wake、interface-idle、netlink membership、interface ACL；全通过 |
| 资源与压力 | 43jobs、15collector；public11×C/R、内部8项warm+10批及pin150、交错3项十批、S8recover十批／TERM、layout／六controls、mixed300／fullcache300、ENOSPC／EMFILE；全通过 |
| 正式性能 | 9场景×C/R3/Rs×5轮=135，全部attempt1，controller/watcher退出0，authoritative/formal_complete=true；普通错误0，故障各600timeout只在预定故障期；归档全核验 |
| perf guard | 已按事前固定算法从135冻结；UDPp50≤1ms、idle60CPU≤10ms、TCP峰PSS≤6144KiB；实际23.48µs／0／4880KiB，全通过；[工具计划](../../tools/dnsmasq/m6b_perf_guard.final.json) |
| APK | 载荷等于最终ELF，不重新codegen/strip；14阶段真实安装、升级、卸载、降级和移除后回滚，variant互斥及cleanup全通过；体积目标原红保留 |
| 报告与卫生 | [最终报告](M6B_REPORT.md)已提交；43树／9任务branch已archive/tag及原始资料验证保全后退役；Git剩6树／18branch；四dirty、health、11项prompts保持 |

**未达标与未执行：** TCP miss稳态PSS约C3.386倍，饱和4.671倍，排空后约10.9MiB仍未达到3–6MiB；ELF约C7.30倍、APK约stock7.00倍，均超原体积预算。UDP-hit、DHCP、reload相对C存在CPU／延迟退步；TCP-local稳态CPU相对原Rust增加19.65%。fullcache300仍有resource_review_required。详尽分类与原始Rust同opt比较见报告；不以吞吐收益抵消差距。M7真机、第4包未执行，物理路由器没有dnsmasq-rs。本轮结束，后续s／M7／第4包由用户另行决定。

历史身份与失败保留：原冻结284376c4后，无关health合并16ac3cea没有触及dnsmasq输入；之后授权UDP/TFTP修复才改变ELF，旧13步没有导入。UDP回退由M6b e8b1d6c4新live-name caller漏隐式loopback，3492bbde提取复用admit规则；TFTP普通IPv6旧名路径始于M5 86e31143，M6b2c28df78删除扫描使rename错误持续，8bd80024复用既有共享collector续步修复，约13分钟内通过，889仅修测试字节转义。DNS-TCP／DHCP审查已结束、未扩大；归因没有历史ELF bisect。见 [UDP历史](audits/M6B_UDP_LOOPBACK_REGRESSION_HISTORY.md)、[准入复核](audits/M6B_INTERFACE_ADMISSION_REVIEW.md)。

方法红与唯一原参数确认、fresh完整修订资格、归档恢复错误、APK体积红均保留原判定，见 [方法记录](audits/M6B_FINAL_METHOD_CORRECTIONS.md)。既有故意行为差异及C参考位置见 [M5差异表](M5_BEHAVIOR_DIFFERENCES.md)，169普通合同已闭合，历史逐项结果见 [M5报告](M5_REPORT.md)。

`E = private/dnsmasq-rewrite/evidence`；最终证据 `E/M6B/final-889fe4f5/`。[交付总索引](../../private/dnsmasq-rewrite/evidence/M6B/final-889fe4f5/final-delivery-index.json) SHA `81ea618a1c5ed5d5d8ecdce379ad30f82930dbc2becd51a0e3b9588d455dfc59`；[退役保全索引](../../private/dnsmasq-rewrite/evidence/M6B/final-889fe4f5/cleanup-archives/retirement-index.json) SHA `f7008b55bdeb21a29e983a6f60d87e666b34f09c943656a1ace77f35e38c1293`。前置10目录与最终两目录、135原PAX tar、原始latency／wire／smaps／CPU／FD、source／ELF／build/map、APK及cleanup证明全部private。43 exact tags在 `archive/dnsmasq/m6b-final/20261009/`，原raw和四个target保全共1,482,019,483B／36,621条目。

## 工作规则

- 精确OpenWrt镜像是部署规格，匹配C源码是实现参考；保留真实失败和未测范围，不换身份、不挑最好attempt。
- 产品已冻结；新普通产品缺陷先停止告知用户，不边测边改。任何新ELF须重新冻结并实际验收，s不能借opt3资格。
- 每批先本地整批夹具／路径／权限／见证预检及相关单测，再一次上传。原参红只确认一次；不新增门、不扩矩阵，生成器受限只写≥X。
- Oracle由主线程串行；正式窗口独占，其他会话／health-*存在就等，不停用户服务。后台等待每20–30分钟检查，无新结果不重复汇报或准备。子代理最多4个、继承主模型、仅本地读码／报告。
- 按明确路径暂存、每个有意义单元小提交。保留docs/prompts用户修改、hotfix/health-20261008-r3和owrt-health-r3、四棵dirty树及active任务；退役前exact archive refs和完整private证据必须验证保全。
- 原始资料、固件、dump、秘密、ELF/APK只放ignored/private，Git仅工具／无秘密清单／派生报告；未回拷验证不删远端raw。Oracle构建统一oracle_build.sh和唯一共享Cargo target，镜像使用共享只读基底与临时overlay。
- 不修改／刷写物理路由器；M7／部署需用户另行明确授权及恢复门。当前没有真机性能或生产替代结论。
