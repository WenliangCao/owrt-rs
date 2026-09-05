# httpd/ring 可重复性：第一处分叉的证据

日期：2026-09-05。基线 `5b79d94`。按 `R34_HTTPD_RING_ONESHOT.md` 的方法执行：先取证再改代码。
**本轮没有改任何构建参数**，因为证据还不足以证明单一根因。

## 1. 同宿主是确定的

构建主机上两次独立 clean 构建（A1、A2）：APK sha256 都是 `29d35930…`。
所以"构建不确定"不成立，问题**只发生在跨宿主**。

## 2. 发货产物：不是打包层

| 产物 | CI | 构建主机 |
| --- | --- | --- |
| owrt-httpd-0.1.1-r4.apk | `b529ef48…` | `29d35930…` |
| APK 内提取的 httpd-rs | `8cc07af3…` | `1c5d345c…` |

两个 ELF **大小完全相同**（1465087），差异在内部：767080 字节、446 个簇，从 `0x214` 到 `0x1659d9`。
反汇编看是 branch 立即数与 `add` 偏移变化——布局位移传播，不是 76 万字节的逻辑差异。
发货 binary 是**完全 strip 的（没有 section header table）**，无法再细分，所以做了诊断构建。

## 3. 诊断构建：第一处分叉在 ring 的 C/汇编对象

`tools/repro_diag.sh` 在两边跑打包配方的同一条 cargo 命令并保留中间产物。
两边工具身份一致：`rustc 1.98.1 (48a229cea)`、LLVM 22.1.8、同一 SDK gcc、`-fuse-ld=bfd`，
只有 host triple 不同（x86_64 vs aarch64；构建主机通过 qemu 跑 x86_64 SDK）。

40 个收集产物逐一比对：

- **纯 Rust 的 rlib 基本一致**：cfg_if、once_cell、owrt_ubus、rustls_pki_types、subtle、untrusted **全部字节相同**。
  → 该 target 的 Rust codegen 是宿主无关的。
- **ring 的全部 20 个 `.o` 与两个 `.a` 都不同**。
- **`.o` 的文件名两边完全一致**（`c322a0bcc369f531-sha256-armv8-linux64.o` 等）。
  → 指导里怀疑的 "cc 的源目录哈希导致对象名不同" **被排除**。
- `libzeroize-8df4440f4f2f9a27.rlib` **不同**，而它是纯 Rust 且**没有 build.rs**。**这一项未解释**。

## 4. 纯汇编对象里差的是什么：宿主路径

`c322a0bcc369f531-sha256-armv8-linux64.o`（由 pregenerated `.S` 汇编而来），两边大小相同，**只差 20 字节**：

```
off 0x1612: CI   ...\x02\x01\x00\x01\x01/home/runner/.cargo/registry/s
            HOST ...\x02\x01\x00\x01\x01/home/ubuntu/.cargo/registry/s
```

前缀的 `\x02\x01\x00\x01\x01` 是 DWARF line program 的头，后面是目录表。也就是说：
**差异是嵌进调试信息里的 `CARGO_HOME` 绝对路径**（`/home/runner` vs `/home/ubuntu`）。

原因清楚：配方的 `--remap-path-prefix=$CARGO_HOME=/cargo` 只作用于 **rustc**；
ring 的 C/汇编由 SDK 的 gcc 编译，**没有拿到任何 `-ffile-prefix-map` / `-fdebug-prefix-map`**，
于是把真实路径写进 DWARF。这正是指导 §3.A 列的候选，现在是证据而不是猜测。

## 5. （已被 R35/E0 更正，见 R35_RING_E0_RESULTS.md）原措辞：路径不是唯一原因

三条反证，说明"加个 `-ffile-prefix-map` 就完事"还不能承诺：

1. **`a4019cc0736b0423-mem.o` 两边大小不同**（CI 64616 / HOST 64512，差 104 字节），
   而 `/home/runner` 与 `/home/ubuntu` **等长**。等长的路径替换不会改变文件大小，
   所以这个对象里还有别的东西不一样。它的 section 大小两边一致，差异在别处（对齐/表区），未定位。
2. **最终 ELF 的 `.text` 真的不同**：诊断构建（`-C strip=symbols`，输出里没有任何 `.debug_*` 段）
   两边 `.text` 差 655830 字节、`.rodata` 差 41686、`.eh_frame` 差 64222、`.data.rel.ro` 差 1350、
   `.got` 差 1、`.data` 差 2。调试信息在链接后已经不存在，光靠路径字符串解释不了代码段的差异。
3. `libzeroize` 的差异同样没有解释。

## 6. 下一步（一次受控实验，不是猜）

给目标 CC 加 `-ffile-prefix-map=$CARGO_HOME=/cargo`（以及 `/tmp/owrt-build` 的映射），
**只作为诊断构建**在两边各跑一次，然后重新逐层比对：

- 若 ring 的 `.o`/`.a` 全部一致而 `.text` 仍不同 → 存在第二个原因，继续从 rlib / LTO / 链接输入顺序找；
- 若 `.o` 一致且最终 binary 也一致 → 再按正式参数重跑，并做 A1/A2 与 CI/构建机双重验收。

在拿到这个结果之前，不改发布配方，也不宣布修好。

## 7. 影响范围的界定

这是**发布来源可核验性**问题：两台机器重建不出相同产物，就不能用哈希直接证明设备上的 binary 与被审源码一致。
但目前的证据只是"不一致"，并且已知其中一部分来自**调试信息里的路径**——
这既不能推出 TLS 有缺陷，也不能推出性能或稳定性问题。设备侧的 r14 差分 38/38、
r27 零新增偏差、TLS 与 8.97 MiB 上传验证都是另外独立通过的。

## 证据位置（Git 外）

构建主机 `~/diagwork/diag/collect/`（40 个产物 + `collect-sha256.txt` + `tools.txt`）；
CI 侧为 `repro-diag` 工作流 run 33990586855 的 artifact。仓库里只有配方、工具与本报告。
