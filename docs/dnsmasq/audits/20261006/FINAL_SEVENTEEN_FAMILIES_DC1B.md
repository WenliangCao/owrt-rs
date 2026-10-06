# M5 dc1b 最终 ELF：17族正式复跑收据

17族均在source dc1b740d7973838e2ae7f098d0726b0484e55074 / ELF37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b（1,929,256B）实际重新执行；不复用此前资格。15族通过，2个夹具缺口保持红色，等待fixture-only sidecar严格冻结后fresh复跑。这里不是M5整体验收完成。每族独立controller --family attempt1，所有冻住的checks/inventory保持。

| 功能族 | 正式结果 |
| --- | --- |
| bridge-interface | 通过；全部冻结步骤实际执行 |
| dhcp-device-binding | 通过；全部冻结步骤实际执行 |
| dhcp-files | 通过；全部冻结步骤实际执行 |
| dhcp-identities | 通过；全部冻结步骤实际执行 |
| dhcp-proxy | 通过；全部冻结步骤实际执行 |
| dhcp-range | 通过；全部冻结步骤实际执行 |
| dhcp-reply-delay | 通过；全部冻结步骤实际执行 |
| dhcp-tags-options | 通过；全部冻结步骤实际执行 |
| m5_boot | 通过；全部冻结步骤实际执行 |
| m5_dump | 通过；全部冻结步骤实际执行 |
| m5_leasequery | 通过；全部冻结步骤实际执行 |
| m5_pxe | 失败保留；共享actor timestamp被当成协议字段 |
| m5_relay | 通过；全部冻结步骤实际执行 |
| m5_script_arp | 失败保留；未传allocator map，3个Rust故障caller未执行 |
| m5_tftp | 通过；全部冻结步骤实际执行 |
| shared-network | 通过；全部冻结步骤实际执行 |
| tftp-errors | 通过；全部冻结步骤实际执行 |

新error文案的DHCP tags/options、25行reply-delay、70行dump、30普通+5reference+6配置syntax TFTP、95场景TFTP errors、27 caller DHCP设备绑定均已在这一ELF正式通过。relay37/174、40语法与4绑定模式通过；另外在同frozen工具上actual --recheck补完11报文+4语法负控，全部拒绝，原input SHA保持1d04e15ba28b488c27ec2c0ae3efb29776d162f1b80c874cdbcf98d34fac8b60。recheck不是新产品执行，也没有替代paired运行。

ARP的C侧78行全部执行；Rust只有positive-record-enomem、negative-record-enomem、helper-buffer-enomem-reference三行因缺--allocator-map未执行。它们保持失败与缺项，不能把其余75行记为完整族资格。缺失资产是已绑定实际release的link.map，修复只补registry argv，未加入global allocation tracing。PXE假红保留原始字段，修复由独立logging owner负责，最终receipt须指向affected新sidecar运行。

17个功能叶的全部原始内容已全SHA+mode、uid/gid、nanosecond mtime、链接、设备节点和xattr校验后prune；原controller/phase/locked结果JSON保留原路径，成功结果SHA逐个复核。17个controller/phase目录另完整打包回拷并验证，远端后置门保持。详见[完整脱敏收据](final-seventeen-families-dc1b.json)。原80a721源码/ELF下14绿与3红不计入这一新正式收据；relay诊断失败与严格修复另见[因果报告](RELAY_FINAL_FIXTURE_REPAIR.md)。
