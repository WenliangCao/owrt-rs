# FIX6 回归材料的独立重算与 fresh 控制

本子审计完成于 2026-10-14。对象是冻结 HEAD `3335a978` 的 release，SHA-256 `a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66`；精确镜像 C 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。这里仅裁定正常/链式回归矩阵，没有将这些通过结果用于否认其他边界反例。

## 执行完成情况与证据来源

接手时 `dns/early-recheck.json` 只收录 9 组，但 Oracle 的 `dns/all-results.json` 实际已有 **13/13 组 exit=0、432 个场景**。未收进 early 收据的四组是 full-terminal、N1、chain-dynamic、chain-anchor；不是四组未执行。全部 13 组现在从原 `private/<group>/result.json` 重新独立解码和汇总。原始 driver log SHA、driver/profile SHA、C/main/before/fix 身份均重新核验，前 9 组的重新计算结果与仓库 early 收据逐字段一致。

保留材料的重新计算结果见 [retained-recheck.json](retained-recheck.json)。这些运行是本次接续的既有 FIX6 数据，**不是本子审计新启动的 daemon**；同样没有用 FIX5 旧 ELF 的结果替代当前 ELF。比较器沿用 FIX5 的完整 wire decoder，保留 header、question、RR 顺序、owner/type/class、RDATA 和所有 TTL，只规范化名称压缩。

| 保留数据 | 独立重算结果 |
| --- | --- |
| F2 两次主例、anchor 和 candidate-anchor | 16/16 当前合法答案全语义等于 C；F2 独立主复现另有专门报告 |
| F1 `c00c/c02b` Dynamic/Local | 16/16 全语义等于 C |
| 13 配置 extended-controls | 80/80 全语义及 final 上游次数等于 C |
| 原 terminal 矩阵 | 62 个合法答案等于 C；8 个 C 自身畸形控制 raw 相同；18 个 O1 既有差异 main 与当前完整 response 字典逐字相同 |
| N1/filterwin2k | 72/72 全语义和 final 上游次数等于 C，48/48 warm 答案相同 |
| 10 配置链式矩阵 Dynamic/Local | 160/160 全语义、final 上游次数和 warm 答案等于 C |

所有 432 个场景的 daemon 存活和退出检查通过。原 terminal 驱动中，F1 的 4 个及 full-terminal 的 22 个 C debug/TCP 健康请求在 TCP 连接关闭前发出，仍有预期的 C 阻塞/超时；不是当前 Rust 新差异。没有把这 26 个非 reply 隐去。N1、extended 和 chain 的关闭连接后健康检查全部通过。

## 本子审计 fresh 重跑

使用原 driver 和原 profile，仅替换 `--out` 为新的私有目录，通过三个独立 network/mount/PID namespace 并发重跑 **240 个场景**。原始材料没有覆盖。实际命令见 [fresh-invocations.json](fresh-invocations.json)，运行时间、log/result SHA 和完整逐例检查见 [regression-recheck.json](regression-recheck.json) 的 `fresh` 部分。

| 新运行 | 场景数 | 当前结果 |
| --- | ---: | --- |
| extended-controls | 80 | 全字段及 TTL、final 上游次数、全部 warm 响应均等于 C |
| chain-dynamic | 80 | 同上 |
| chain-anchor | 80 | 同上 |

全部 fresh 回答可解码，daemon 存活、退出 0、TCP 关闭后健康均通过。链式配置覆盖 configured CNAME→CNAME→MX（单/多记录及 Additional）、SRV、MX+SRV、TXT/PTR、A/AAAA、空终点、raw NS、重复 raw CNAME、raw MX；每组覆盖 normal/debug × UDP/TCP 和对应类型/ANY 查询。当前与 FIX5 before 的这 240 个最终答案也全部相同；main 在 extended 的 72 例、chain-anchor 的 12 例仍偏离 C，当前已对齐 C，因此不构成本轮新增回归。

## 负缓存材料重新核验

读取原 `negative-01/checked.json`，逐一重新验证三个 suite summary 和 **200 份侧结果的 SHA**，再调用独立 wire decoder 的 `strict_pair` 重新比较全部输入，没有重写旧收据或重启这批 daemon。仓库 `negative/checked.json` 的文件 SHA 与 Oracle 原文件一致。

重新计算为 **100/100 场景通过，840 对 DNS 响应中 819 对严格相同、21 对仅有有界 authority SOA 相邻秒 TTL，180 对 DHCP header/options/timers 相同**，与原收据逐字段吻合。每例上游行为、全部存活检查、exit=0、资源释放且无 forced-kill 也重新检查。这里没有增加 TTL 豁免；仍要求仅 SOA authority、差值不超过 1，且双方值分别在各实例 elapsed 算出的界限内。逐例重算和精确时间界限位于两份 recheck JSON 的 `retained_negative`。

## 范围与收尾

本范围没有发现新增回归。保留和 fresh 两种证据明确分开，未把 8 个 C 自身畸形控制统计为合法答案，未将 main 既有 O1 作为阻断。未重新运行性能、长时间并发/soak、全部 DHCP lifecycle、ignored tests 或内存故障注入；本矩阵不能证明所有 DNS 行为等价，也不覆盖 14-bit 指针大报文边界的独立结论。

[closeout.json](closeout.json) 重新确认 18 个 O1 的 main/current response 字典逐字相同、本次 fresh 私有目录无归属进程或宿主 mount、release SHA 未变化。未修改产品、未操作物理路由器、未推送或干预其他 Oracle 任务。新文件仅工具和派生收据；daemon 日志、overlay 和原始运行结果保留在 Oracle `private/recheck-regression`。

可复跑本子审计（`OUT` 必须不存在，`negative_final.py` 使用相邻 `negative/` 中的原文件）：

```sh
python3 recheck.py \
  --root /home/ubuntu/dnsmasq-audit-fix6-20261014 \
  --out /home/ubuntu/dnsmasq-audit-fix6-20261014/private/recheck-regression-NEW \
  --negative-checker negative_final.py
```
