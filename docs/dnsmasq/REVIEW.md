# 独立复核记录

复核针对本轮新增模块；不把模块正确性推广为完整服务等价。

| 复核方/对象 | 深度与结论 | 后续 |
|---|---|---|
| 主代理 / DNS wire | 对照 rfc1035 extract_name、skip、EDNS与writer，核读binary标签、长度、pointer resume/hop、有界记录；未见确定偏差 | C oracle无OPT时原先遗漏signed结果比较，已要求补TKEY/TSIG差分 |
| 主代理 / DHCP packet+lease | 对照rfc2131 option扫描与lease.c:621–702、846–1008、1062–1170；核对CLID顺序、唯一expiry索引、prune顺序、名称抢占；未见确定偏差 | 完整状态机/恢复/脚本与lease指标仍待实现验证 |
| DNS代理 / TFTP实现与oracle | 核读netascii线性算法、ACK/绕回恢复；发现测试器max block+header越界 | 已修buffer并加六项极限回归、ASan/UBSan通过；完整传输差分未完成 |

所有解析器的C抽取oracle仅作测试，不进入产品依赖。测试器必须保留成功/失败校准，
差分中的预期由精确C或独立固定报文提供。C自身未定义行为单独记录，不复制到Rust。
