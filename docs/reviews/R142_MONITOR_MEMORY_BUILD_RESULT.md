# R142：独立驻留 helper 构建完成

使用固定 Rust 1.98.1、OpenWrt 25.12.5 SDK/musl 和原 generic 链接参数，只构建
`owrt-benchmark` 的 `monitor_memory` example，原性能 caller 和 daemon 不变。
helper 为 **397,264 字节**，SHA-256
`2db999c1d14c641eb689c161c444a6355c617694eb6acaa20aaf4bd142f7b62a`。
17 项输入逐字节校验，构建后未变；实际 Cargo dependency flags、compiler 版本与日志保留。

本地复核了构建证据归档与 ELF。归档 SHA-256 为
`4a6d79c91d8197c1f1cebc118bf06cb372e9d717ad4fa4ae56a815583389e629`，
原始数据在 ignored `private/r142/memory-helper-build-*`。
[C/R136/R142 的功能 smoke](R142_MEMORY_HELPER_SMOKE.md)已通过；它跳过驻留等待，
不能作为路由器内存结论。该 helper 尚未在路由器上运行。
