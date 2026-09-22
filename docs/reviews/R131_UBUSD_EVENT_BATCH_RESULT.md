# R131 ubusd event fanout 实机结果

R131 是从精确 R124 ELF 源码分支出的同一 owner 连续事件帧批量发送实验。只有连续发往同一连接、没有 monitor 的事件帧进入 batch；跨 owner、monitor、已有队列、短写和大帧路径保留逐帧语义。候选 ELF SHA256 为
`c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a`，源提交为
`4e45d2ecc41d8548916c2f92f30c7ac4d2bb65dc`。

路由器只运行了临时命名空间中的候选，生产 `/sbin/ubusd` 始终是 C 版。`router-04` 完成六个 C/R124/R131 交错 block、18 个窗口，每个窗口 5000 次、20 次 warmup；daemon 固定 CPU1，事件 caller 自身固定 CPU0，argv0 固定为 `/sbin/ubusd`。54 个 lane 的 payload、接收数、处理器身份、候选/工具 SHA、boot/config/production/mount 和清理门全部通过。末态仍为 C SHA
`cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88`，PID 869，boot id 未变，未留下临时目录。

相对 R124，同一 block 配对的 `user_8_1` 主 lane 六块全部下降：

| 指标 | 中位变化 | 六块范围 |
| --- | ---: | ---: |
| wall time/op | −20.22% | −13.07% 至 −24.17% |
| daemon CPU/op | −21.78% | −18.48% 至 −22.96% |
| caller CPU/op | −11.40% | −6.16% 至 −14.14% |

相对 C 的同一主 lane，中位变化为 wall `−14.96%`、daemon CPU `−19.62%`、caller CPU `−7.46%`，同样六块全降。两个 guard lane 没有触发“六块全升且中位超过 5%”的回退门：`user_1_1` 的 wall/daemon/caller 中位分别为 `+0.89%/+1.39%/+0.19%`，`user_1_0` 分别为 `+1.07%/+1.36%/+0.08%`。

更正：R131 的均值 wall/CPU 子项显示收益，但原冻结计划还要求尾延迟门；本批未采集 p95/p99，所以完整验收应记为 **pending**，不能事后另定义只有均值的接受门。R131 保留为待补齐的事件 fanout 性能候选。该结果没有证明所有事件模式都优于 C，也没有证明整个 ubusd 或九组件组合已完成最终验收；目前应保留 R124 作为可回退基线，只有在组合矩阵中复核后才决定是否采用 R131。

本次精确事件 caller 只输出整个循环的 wall/process CPU 累计值，没有逐次延迟样本，所以 p95/p99 没有测量，也没有从总计时推导。原始窗口与离线复核结果保存在忽略的 `private/r131-event-batch/router-04/`；复核器为 [`tools/r131_event_report.py`](../../tools/r131_event_report.py)，结果文件为 `router-04/report.json`。此前 `router-01`、`router-02`、`router-03` 的失败分别是 benchmark 模式、daemon/event helper 混用和 harness 证据记录问题，均已保留，不能算作候选功能失败。
