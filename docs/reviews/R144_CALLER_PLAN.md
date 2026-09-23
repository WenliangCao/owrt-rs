# R144：独立 shared caller 回复借用候选

本实验只优化 `owrt_ubus::Connection::request_until` 的匹配回复消费。daemon 保持精确 C/R136，provider 始终使用旧固定 caller ELF；不改正式 shared runtime，不继承旧 caller 下的 daemon 性能结论，不混入 PGO/A53，不自行执行性能或路由器任务。

优先复现 R135 `85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d`，原大小 720968 bytes。Oracle 历史规范路径保留 18 个编译输入，包括当时的 benchmark manifest/main；与当前多了 phase feature 的主树不同。其 shared conn SHA 为 `3b8a0df7a5c6c3e87655803fd2a308f410037e61d30101dfa1d277e5f72d6c7b`，与当前基线一致。私有 `base-01` 清单 SHA `46e1f79c01e685e3b92017b0983a3a105c159cd0d80bc6607734a9b8f6ed58c2`。主机绝对路径只保留于私有构建记录。

构建复用原 `tools/r135/build_benchmark.sh`（SHA `1fb454a9c3ce2e8973c160e1a1184679f693790f976fe2f2a2aa3f8ca08b4167`），只改输出目录。私有 mount/PID namespace 将 snapshot bind 到历史规范路径，宿主源码不改；Rust1.98.1、LLVM22.1.8、SDK linker、release profile、六项 RUSTFLAGS 与原 Cargo fingerprint 一致。先单独构建控制，必须报告能否逐字复现；不匹配时只可作为两个同源新 caller 的独立系列，不借旧 ELF 混比。

唯一候选：request_until 直接取得现有 take_frame 的 header/FD/body；seq、peer 都匹配的 DATA 直接从 body 复制最终 Reply payload，STATUS 借用 body 调用现有 attrs_from/as_u32 规则；其他消息仍通过 blob_of 成为拥有数据的 pending Message。recv_until、HELLO、公开 Reply API、接收状态机、Owned 大帧分配/复制、deadline 和错误处理保持原样。不引入前缀移动、缓存池或公共 API。

已有小帧流程为 rx→Message Vec→Reply Vec，STATUS 的 Message Vec 则解析后丢弃。候选最多去掉每个小 DATA/STATUS 的一个临时 Vec；典型 ADD+REMOVE cycle 为四次分配/释放、约64字节复制。最终 Reply、请求编码、往返和 daemon 工作不消失；实际端到端收益尚未测量。

匹配 revision `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` 的 C libubus [接收层](https://raw.githubusercontent.com/openwrt/ubus/24864e7840b3a02a9ef76284a373f6b2f00b8a9b/libubus-io.c) 复用消息缓冲区；[请求层](https://raw.githubusercontent.com/openwrt/ubus/24864e7840b3a02a9ef76284a373f6b2f00b8a9b/libubus-req.c) 对非 blocked DATA 直接调用 callback，blocked 才建立拥有副本，STATUS 直接解析。Rust 返回拥有数据的 Reply，因此保留最终 payload 复制，不改为借用公共返回值。

必须保持 pending FIFO、错seq/peer与同标识异类帧的拥有语义、匹配 DATA FD 关闭、STATUS FD 转移、重复状态最后项覆盖、1/2/4-byte数值兼容和缺失/非法状态默认 INVALID_ARGUMENT。复用所有 shared library 单测与 doc-tests，另加入真实 socket transcript：合包/碎片回复、异步pending和FD、独立STATUS FD、重复/缺失状态、大帧及后续小帧所有权、错误与超时边界。单测是独立 test ELF，记录完整测试命令/flags/数量及结果，不称测试 ELF 等于计时 caller。

实验设计另冻旧/新 caller × C/R136 daemon，provider 固定旧ELF；报告每个 daemon 内的新/旧 caller变化及caller CPU，不将其归为 daemon 优化。原0ca42/85dd系列旧负项继续有效。这里只授权源码快照、构建和正确性，不授权计时、部署或路由器访问。
