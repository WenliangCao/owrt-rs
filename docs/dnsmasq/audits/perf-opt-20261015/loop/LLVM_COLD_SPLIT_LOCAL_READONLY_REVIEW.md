# LLVM cold split：本地报告只读核对

核对作者报告 `764a4022` 与独立实验源
`d5e97d78edee12eec45e3addffa7fab237a1a09f`。相对精确 9e，唯一 recipe 变化是
`-Cllvm-args=--hot-cold-split`；两者 `components/dnsmasq` Git tree 均为
`c0540ee972156ac0d4aa5032943a3b8f2742146d`，没有 c95 section 属性或产品源码改动。
保留的 control receipt `0478e80d3a58ba5bdfae56a0078771ede69f9c97fc38d2bc44236ed787e5d5ca`
与 variant receipt 的 codegen flags、除 linker 路径外的 rustc `-C` 参数只差该 flag。

使用既有 `Elf` 读取器重读两个本地 ELF，核对全部 ALLOC 段、LOAD 文件字节、
所有报告所选函数的地址/大小/代码哈希，以及既有日志和五份私有收据。

| 身份 | 9e control | cold split |
|---|---|---|
| ELF SHA256 | `fd2fa9ffe57ae5b3b1c3ac596b9508ae31a54ce58508104c8a6d47d725884a77` | `88ef2a68111f98ba8206dacebe0d814c8947aec96eee79845f7715c1f2d8c4d4` |
| 15 个 ALLOC 段的内容及元数据指纹 | `e10603674a0a368c088dc3a13f5cb3f2418abe5e10f595e37f44bd11332c52da` | `f9858537d6734b5e268a503ccc8959dbcbb13eae23fc0535eab8e8095ce85218` |

ALLOC 指纹为每段 `(name,type,flags,address,size,alignment,sha256)` 元组排序后，
以 `json.dumps(rows,separators=(',',':'),ensure_ascii=True)` 编码取 SHA256；
NOBITS 内容哈希为 null。这是本次只读内容绑定，不是新增验收门。

| 本地 ELF 指标 | control | variant | 差值 |
|---|---:|---:|---:|
| `.text` | 1,824,680 | 1,807,768 | −16,912 B |
| `.eh_frame` | 96,992 | 126,472 | +29,480 B |
| `.eh_frame_hdr` | 18,932 | 28,444 | +9,512 B |
| `.gcc_except_table` | 5,640 | 5,688 | +48 B |
| File-backed PT_LOAD | 2,090,032 | 2,112,160 | +22,128 B |

上述四个段的差值合计正好解释 LOAD 文件字节增加 22,128 B。810 个 `.cold.`
符号合计 19,636 B。整个 ELF 为 5,024,648→5,211,920 B，包含符号/字符串表，
不能当作 shipping SDK 体积或原 release 预算结果。

`answer_udp_prepared_with_local` 原为 2,484 B；variant 是 **主段 2,468 B 加独立
`.cold.1` 28 B，合计 2,496 B，比原来多 12 B**。不能把 helper 的 28 B 显示为整个
方法。首次按逻辑名覆盖显示的记录 `19e692ac5efab57d589ac4127e99853e0d69152db5c2584a6c57108f1d2b9f15`
及说明 `949ada94216952decd5e2c611f5e20b19b6157dae6d74cb9358d019e869517df` 均保留且哈希匹配；
旧同名汇编输出曾被覆盖，不能声称旧汇编字节也已归档。现有 ELF 与修正后的两个独立范围可核。

原日志确为 729 passed / 8 ignored / 0 failed，哈希
`79739ba5505d82764e333c4c5d8b3c3cdf691c8ca3fd62caed3525f1ad2e53d6` 匹配。
本次没有构建、重跑测试、执行原检查脚本或访问远端，也没有新增脚本/JSON框架。
该实验继续未选；没有运行时收益、实际 SDK 资格或 CPU/IPC 结论。

[作者报告](LLVM_COLD_SPLIT_LOCAL.md) · [原证据清单](llvm-cold-split-local.json)
