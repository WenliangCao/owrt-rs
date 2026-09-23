# R141：固定 PGO 训练通过

[冻结工具与计划](R141_TRAINING_PLAN.md) 于 `20fd3fb` 提交后执行；八类均首次通过，
没有失败后重跑、补样本或按耗时调权。每类使用独立 namespace 和输出目录，受测 ELF
均为 `9452594e10f36ea2008382ea513525e5bdadfa7f32bf954031f1fca36a7451c9`。
所有 daemon 经 SIGTERM 正常退出 0，每类产生唯一非空 raw；namespace 内 PID 均为 35，
以类别目录＋PID 标识归属，不将相同 PID 数值误作同一进程。

| 类别 | 固定命令数 | raw bytes | LLVM Total count |
| --- | ---: | ---: | ---: |
| registration | 4 | 60,632 | 4,935,796 |
| lookup | 9 | 61,608 | 32,462,226 |
| invoke | 5 | 60,760 | 719,818 |
| object_events | 3 | 60,904 | 2,805,433 |
| user_events | 3 | 60,680 | 1,840,579 |
| ownership | 3 | 60,888 | 6,527,586 |
| transport | 3 | 61,640 | 2,239,088 |
| lifecycle | 6 | 61,768 | 28,526 |

全部 raw 由 pinned LLVM profdata 22.1.8 解析，均为 322 functions、3,892 blocks。
八个明确 raw 按冻结顺序只合并一次，无额外权重；合并 Total count **51,559,052**，
精确等于八类之和。产物 95,640 bytes，SHA256 为
`566a73250308a19e97715b40ff2b2f4043f07ed836b89b205d50d810ef07c4f8`。
独立能力 smoke 验证环境覆盖及正常退出落盘，未进入合并；默认输出目录没有 raw。

冻结计划 SHA256：`1c7611cc90a925300c540352eb7c08b2349bb8239775ad901beaec9a25dce9ed`。
训练结果 SHA256：`81059d6cc19d3845f39654f1075f4cb904822ca5d92f881354339ee6678b05dc`。
私有归档 SHA256：`eb3d955031225fb7a12948dbc2ff7e896e9c156ff34063c72ee8a8dee9335f2c`。
下载后复核归档、全部 raw 与合并文件身份。[脱敏结果](r141-training-results.json) 保留
逐类身份、计数和 smoke 摘要；原始进程环境只留 private。

文档纠正：冻结计划总述的 caller/provider CPU0–1 表述不精确。实际冻结命令固定
daemon CPU1、provider CPU0；Rust caller 默认允许 CPU0–1，原生 event caller CPU0。
本次保持已冻结脚本与采集内容，没有因文字修正重新训练。

这是计数及 fanout 不同的固定组合，并非八类等权或真实设备流量权重。故障恢复、
crash/restart、OOM 等未覆盖项继续保留在原计划中。训练通过只证明 profile 可用；
profile-use 候选仍须独立通过正确性与未插桩性能筛选，R140 及早前否决结论不变。
