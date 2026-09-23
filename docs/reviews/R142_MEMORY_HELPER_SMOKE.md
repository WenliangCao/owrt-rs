# R142：内存探针三方功能 smoke

同一 `monitor-memory` ELF `2db999c1d14c641eb689c161c444a6355c617694eb6acaa20aaf4bd142f7b62a`
在 exact C、R136 和 R142 `367badc11…` 各执行一次 `smoke`，均通过。daemon 固定 CPU1，
原 `0ca42fb…` helper 使用 `exec-cpu 0` 启动探针；ELF、argv、PID/starttime、CPU、退出和
空对象表均校验。每方输出 16 条阶段 snapshot＋COMPLETE，完整验证 10 条镜像；最后
FD 回到各自 baseline，caller 与 daemon 均退出 0，日志为空。

覆盖 empty、connected、monitored_small、32/256/768 KiB、大消息后 stopped_connected、
disconnected。smoke 的 `delay_ms` 均为 0，不是正式 1/5 秒驻留测量，不能用其内存值或
运行时间判断接受或性能。[完整派生结果](r142-memory-helper-smoke.json) 保留逐方证据 SHA。

首个 `memory-helper-smoke-01` 在启动等待处失败：镜像 BusyBox 不接受 `sleep .01`。
这时探针尚未执行，C daemon 由 trap 清理。保留完整原目录，仅把等待改为整数 `sleep 1`，
在全新 `memory-helper-smoke-02` 执行相同 ELF 和三方命令；没有替换数据或修改探针。

两次尝试和脚本的私有归档 SHA256：
`e219cc30e3c24dac57df698ea264c6efc9488bf4d7bc91d6fc313ab79559df54`。
成功原始结果 SHA256：`f95b26d843abc70846b25e2260d45fe0c53b9b8d756d3dd4723a18a1b45e8468`。
下载后校验归档、结果及所有逐方证据身份；未进行路由器操作。
