# M5 与 C 的行为差异

完整交付总表维护在 [交付账本](DELIVERY_LEDGER.md#与-c-的行为差异)，包括每条差异的精确C源码位置、Rust行为、理由和对照边界。收尾仍在逐族核对；未执行的最终复测不算通过。

`log-malloc`按用户2026-10-06更正仅要求accept/start/--test，逐次分配内容不要求一致。全局分配跟踪实验已从生产撤下，保存在 `archive/m5-malloc-trace-experiment-20261006`；普通路径不保留allocator包装/开关检查或128KiB事件缓冲。首次实验ELF增量180,224B；限制内联的独立控制省143,360B。实验身份和混合阶段生产撤除成本见 [体积归因](M5_SIZE_ATTRIBUTION.md)。
