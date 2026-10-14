# 最终 SDK 产物：协议与缓存独立复核

冻结组合源码 `b587282081b72ea0f96cf909e0f70b0bc8de9372`；真实 SDK 包内
ELF `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c`，
2,124,571 B。APK `880050e82f81ad3dff27dac9716f15f7e167346750a4c8c197e9fe8ce6001742`。
以下实际执行由主审对这一 ELF 新跑；没有继承修复方 Oracle ELF 的通过计数。
[派生结果](final-sdk-protocol-review.json) 保存身份、比较器与原始证据 hash。

| 范围 | 最终产物实测 |
| --- | --- |
| 普通协议/异常输入，精确C与Rust新配对 | 368对，366完整字节相同；两条forward-pointer仍为C名称压缩循环、Rust合法展开答案。8个daemon健康退出，5类检查器负控全部拒绝 |
| 有状态缓存与TCP调用 | Rust新跑110场景，337个客户端观察、150个上游报文，全部进程身份和原始wire重新解码一致。复用已留档的相同输入精确C及固定PTR顺序控制，110/110、452负控通过；未声称整个cache family已全跑 |
| F10具体合同 | Rust新跑13场景、704观察，逐条从raw wire重新解码核对。缺名、地址集、TTL、header、count、TC与A/AAAA顺序均无差异；44条PTR初始顺序差异按下述限定规则判定，没有全局排序或抹除差分 |

F10复用原精确C参考及控制。主审独立执行最终检查器，得到0个未获资格差异：
16条匹配既有C完整查询轨迹，28条符合四个明确的源码合同。批准清单 SHA
`57da7fe59de8de504cb77f5982b8e15a3d599a083b1387e1a7451936f64a8f78`；
主审另运行24项检查器单测，全部通过。原observed-only失败保留，不改写为字节全等。

## PTR顺序合同的独立依据

主审实读并核对精确镜像匹配源码的 `cache.c`、`rfc1035.c`、`dnsmasq.c`、
`inotify.c`、`lease.c` SHA，与[批准清单](f10-contract/qualifier/approved/report.md)
一致。C的name hash混入已重定位的指针，PTR枚举依赖bucket/chain顺序；两进程
初始顺序可能不同。另一方面，查询诱发的链变化必须正确保留，不能只比较无序集合。

主审还独立解析精确C ELF的DT_RELR：`typestr` VA为`0x3e388`，前四个字符串
addend为`0x32862/0x3509a/0x31c6c/0x31b68`。将匹配C的hash算法应用于原26份
C进程身份记录的实际load bias，得到两种x/y初始bucket顺序；六条host-record
用例的两份C记录预测分别为bucket11/21、84/91，与各自8条实际应答一致。
这是对既有运行地址的源码/ELF推导，没有新跑C碰随机顺序，也没有把模型预测冒称
该fixture新增反序运行。先前仅用256个低位变化的模型bias没有覆盖两序，未用其
支持结论；最终采用已有真实映射地址并明确推导边界。

四个声明仅覆盖：六条host-record、单文件初始hostsdir、互不重叠租约名字的DHCP
fixture，以及固定IPv6碰撞fixture。每项绑定完整配置/文件/查询序列、来源hash、
问题名和状态；一项内UDP/TCP及before/after必须始终选同一初始排列。DHCP项另
绑定request、发生位置与decoded结果，依据是DHCP节点移除/插入不交换这两个
不相交静态名字的相对位置。五行查询诱发变化、其它名字/输入、A/AAAA、TTL或
截断均不在初始顺序规则内。新增主机名、缺记录与跨阶段拼接仍失败。

## 证据与边界

Oracle新目录 `/dev/shm/full-merge-final-protocol-20261014/`；本机持久归档为
主仓库 `private/merge-acceptance-20261014/protocol/raw-evidence.tar.gz`，SHA
`c134ff3d4b7f690d00c9ba5c3eb15b0fa70eda29332bf4754c2319785ced67c8`。
1,361个普通文件逐一重哈希通过；不归档可重建rootfs/overlay。主审派生脚本、
新运行收据和本地比较结果另存同一private目录。归档首次读取root日志权限失败，
之后用授权sudo读取归档并回拷验证；未重跑产品场景或覆盖原结果。

全部daemon已退出，自有namespace结束；没有操作物理路由器。本页证明明确的
协议/缓存合同，资源、包激活、管理恢复与回退分别见同ELF专项。不外推任意报文、
全部配置或长期硬件运行的零缺陷保证。
