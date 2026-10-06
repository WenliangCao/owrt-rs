# M5 fixture6fb65：17族最终ELF正式复跑通过

2026-10-06。产品source dc1b740d7973838e2ae7f098d0726b0484e55074、最终ELF37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b（1,929,256B）不变；工具source6fb65d96390e46bb84f2d623b8ca4e653120888e的fixture revision上17族全部实际fresh执行并通过。每族独立--family attempt1，原所有checks/inventory保持，未借之前35或dc1b旧绿。这里关闭这一分工的统一复跑，整体验收/M2/资源/APK仍以root账本为准。

| 功能族 | 正式结果 |
| --- | --- |
| m5_script_arp | 通过；全部冻结步骤实际执行，0失败 |
| m5_pxe | 通过；全部冻结步骤实际执行，0失败 |
| bridge-interface | 通过；全部冻结步骤实际执行，0失败 |
| dhcp-device-binding | 通过；全部冻结步骤实际执行，0失败 |
| dhcp-files | 通过；全部冻结步骤实际执行，0失败 |
| dhcp-identities | 通过；全部冻结步骤实际执行，0失败 |
| dhcp-proxy | 通过；全部冻结步骤实际执行，0失败 |
| dhcp-range | 通过；全部冻结步骤实际执行，0失败 |
| dhcp-reply-delay | 通过；全部冻结步骤实际执行，0失败 |
| dhcp-tags-options | 通过；全部冻结步骤实际执行，0失败 |
| m5_boot | 通过；全部冻结步骤实际执行，0失败 |
| m5_dump | 通过；全部冻结步骤实际执行，0失败 |
| m5_leasequery | 通过；全部冻结步骤实际执行，0失败 |
| m5_relay | 通过；全部冻结步骤实际执行，0失败 |
| m5_tftp | 通过；全部冻结步骤实际执行，0失败 |
| shared-network | 通过；全部冻结步骤实际执行，0失败 |
| tftp-errors | 通过；全部冻结步骤实际执行，0失败 |

旧两处fixture红已在新same-ELF运行上闭合：ARP实际C78/R78、missing0、9负控全拒绝，malloc/realloc实际断点使用已冻结link.map，三个Rust ENOMEM caller都执行而非豁免；生产没有globalallocator跟踪。PXE61syntax/260packet、协议字段/同侧kernel received_ns witness均通过，保留真实包、计数和顺序，未比较跨侧绝对clock。TFTP30普通+5reference+6配置syntax、dump70、delay25、DHCP device27以及relay37/174+40grammar/4binding均在本ELF通过；relay额外frozen --recheck实际11报文+4语法负控也全拒绝，input SHA470c3ea7d3a43bba5c4368393834b4aa838ea7769c66a31e3727d962db8f272c保持。

17原始功能叶全部SHA+mode、uid/gid、nanosecond mtime、链接、设备节点、xattr验证后prune；17controller/phase当前目录另完整快照回拷验证且保留远端原路径。所有locked leaf JSON及phase receipts保持，成功input SHA逐份复核。完整身份、每一步实际退出/时长、34批归档与relay额外控制见[收据](final-seventeen-fixture-6fb65.json)。首次本地launcher误将flat TOOLS当作嵌套目录，remote attempt/产品未开始；失败日志保留后更正，不计作任何产品执行或通过。

原dc1b阶段15绿/2fixture红仍保留在[旧正式收据](FINAL_SEVENTEEN_FAMILIES_DC1B.md)，原未控制DAD/跨FD顺序与修复证明见[relay因果记录](RELAY_FINAL_FIXTURE_REPAIR.md)。这一新收据没有覆盖或删掉之前的失败。物理路由器未触碰，M6正式性能窗口未运行。
