# 精确 SDK 布局原型的栈帧核对

仅本机只读 SDK ELF、同次 link map 和 build receipt；未访问远端、构建、
执行目标程序或计时。完整 SHA、输入节范围、PT_LOAD 转换、指令字节及
调用地址见 [`SDK_LAYOUT_FRAMES.json`](SDK_LAYOUT_FRAMES.json)。

四份 ELF 都是无 section headers 的 AArch64 `ET_DYN` static PIE。
先按各自 build receipt 验 ELF/map，再用现有 `LoadElf/input_sections`
将 map 输入节限定到对应可执行、文件支持的 PT_LOAD；按该映射提取字节，
使用本机已安装 Capstone 5.0.7 解码。直接 `BL` 的指令类别及有符号偏移
另按 AArch64 编码复核。没有复用旧 Rust-bundled-musl `ET_EXEC` 地址。

| SDK 产物 | 入口帧 | 原 local 分派帧 | general 分派帧 | 地址 helper | finish helper |
| --- | --- | --- | --- | --- | --- |
| F `b7926bcf…` | 848 B | 1408 B | — | 512 B | — |
| reply-layout `afc32ddc…` | 656 B | 1408 B | — | 512 B | 608 B |
| address-dispatch `77dca9fe…` | 848 B | 无独立定义 | 1376 B | 512 B | — |
| udp-read-one `5216c41d…`（布局对照） | 848 B | 1408 B | — | 512 B | — |

F 的入口从 `0xe65b8` 开始，`str d10,[sp,#-0x80]!` 加
`sub sp,sp,#0x2d0`，合计848 B；local分派为128+1280=1408 B，
地址 helper 为96+416=512 B。普通地址调用链的这三帧合计2768 B。

address-dispatch 的普通 A/AAAA、无同类型配置 raw 记录分支，在
`0xe8384` 与 `0xe9548` 直接 `bl 0xeb284` 地址 helper。
入口848 B加helper512 B，所列两帧合计1360 B，比F少1408 B。
general分派仍有定义，并在其他分支被调用；它不是删除通用处理逻辑。
这个结果是精确SDK的重新确认，不能只凭旧ET_EXEC的同一数值替代。

reply-layout 的入口从 `0xe6588` 开始，128+528=656 B。
地址查找阶段仍调用1408 B分派和512 B地址helper，三帧合计2576 B，
相对F该阶段少192 B。正回答阶段则在 `0xe8048` 用普通 `BL` 调用
`0xed74c` 的608 B `finish_local_records`；调用后 `0xe805c` 才恢复
入口的局部栈空间，因此不是尾调用。该阶段两帧合计1264 B，相对旧入口
848 B多416 B；不要将查找阶段和输出阶段所有帧相加。

这些数字只表示所列同时存活帧的预留空间，不是每查询读写字节数、
整个daemon的动态栈峰值、缓存miss、IPC或速度。未计入祖先及更深callee。
两个布局原型是独立产物，未据此推算未构建组合或宣称G验收通过。
