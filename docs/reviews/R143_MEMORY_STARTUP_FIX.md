# R143：内存夹具的本地执行权限修正

原 `memory-01` 三窗采集在第一窗、C 侧启动 caller 时退出，stderr 为
`benchmark INVALID: Permission denied (os error 13)`。caller JSONL 为空，
R136 侧尚未开始，**零份内存快照**；不是 daemon、协议或性能测量失败。
失败目录、原 plan、日志和归档均保留，不把原系列改为通过。

本地下载的 helper 模式是 `0644`，上传保留该模式，因而不能执行；Oracle smoke
使用的是构建机上可执行的原产物，所以没有暴露下载后的元数据错误。
仅把本地 helper 设为 `0755`，字节未改，SHA 仍为
`2db999c1d14c641eb689c161c444a6355c617694eb6acaa20aaf4bd142f7b62a`。
原 driver 的清理、同 boot、配置、生产 C 身份和挂载检查全部通过。

后续 `memory-plan-02` 单独冻结并从第一窗开始：仍为原定三配对窗、正/反/正顺序、
相同 C/R136、相同八阶段和 1s/5s 快照，未看过任何内存测量结果。
这是零样本启动错误修正，不追加窗口挽救性能方向；已完成的十窗 monitor 系列
及其冻结工具/输入不改。私有 `memory-permission-fix-01.json` 记录修正前后模式、
原失败日志/结果的哈希与零样本断言，新计划绑定该记录及本文。
