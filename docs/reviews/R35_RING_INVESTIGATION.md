# httpd 跨宿主字节不一致：完整调查结果

日期：2026-09-06。基线 `6c352a8`，Rust 1.98.1，锁定 ring 0.17.14 / rustls 0.23.43 / cc 1.4.4。
本文替代 R34/R35 系列中的阶段性结论，是这条线索的最终交付。E0–E8 共 8 组实验，
其中 4 组是空结果。全部实验在 CI（x86_64 GitHub runner）与构建主机 `oracle`（aarch64，
经 qemu-x86_64 跑 x86_64 SDK）两侧进行，未修改发布配方，未影响设备行为。

---

## 1. 最终根因

**Cargo 为"依赖图中经过 build script（Host-kind unit）的 crate"计算出的 `-C metadata`
在两台宿主上不同；该值进入 `StableCrateId`，成为 v0 符号里的 crate 消歧串；符号名长度变化
改变 LTO 的排布，最终产出布局不同、语义相同的 ELF。**

证据链从输入到最终哈希是完整的，四个环节各有直接证据：

### 环节 1：输入 —— `-C metadata` 按 build script 分裂

由两侧 rlib 文件名直接读出（`-C extra-filename` 即该值）：

| crate | 构建主机 | CI | 结果 |
| --- | --- | --- | --- |
| cfg_if | c940dcd0d43ea356 | c940dcd0d43ea356 | 相同 |
| getrandom | c60e273676307c42 | 01e053837fa6807e | **不同** |
| libc | 02b1ad336ca43929 | 7df1fd0eefa9aa4f | **不同** |
| once_cell | 5e977ab56168bf42 | 5e977ab56168bf42 | 相同 |
| owrt_ubus | f8fc7a2647916635 | f8fc7a2647916635 | 相同 |
| ring | ce38e6235afbbc44 | 06b40896dc713810 | **不同** |
| rustls | 1769321dc3c4ee79 | 18bc029a86f70054 | **不同** |
| rustls_pki_types | 91e17267bf74e221 | 91e17267bf74e221 | 相同 |
| subtle | ebbcbf205c506fe2 | ebbcbf205c506fe2 | 相同 |
| untrusted | 864a8f7c2aa29be5 | 864a8f7c2aa29be5 | 相同 |
| webpki | 5436ba3d893c47d1 | a7bcfa086a506edc | **不同** |
| zeroize | 8df4440f4f2f9a27 | 8df4440f4f2f9a27 | 相同 |

分裂线与 build script 完全吻合：`libc`、`ring`、`rustls` 自带 `build.rs`；`getrandom`
依赖 `libc`、`webpki` 依赖 `ring`，沿依赖边传播。7 个"相同"的 crate 依赖子树里没有任何
build script。Host-kind unit 的哈希包含宿主三元组，因此两侧必然不同——这不是配置错误，
是 Cargo 的设计。

### 环节 2：`-C metadata` → 符号名

v0 mangling 把 `StableCrateId` 编码成 base-62 消歧串，直接出现在每个符号里：

```
ring    构建主机 Cskia6MYFH9dt_4ring     CI Csd2U2ioFfwR_4ring      ← 长度不同
rustls  构建主机 Cs7PLbKArcbwf           CI Cs3NKtuc6iWHl
```

### 环节 3：符号名 → LTO 位码

差异出现的 crate 与环节 1 的表完全一致，且位码尺寸变化量与符号长度变化吻合：

| crate | 构建主机位码 | CI 位码 |
| --- | --- | --- |
| ring | 531732 | 530072 |
| rustls | 3002224 | 3002324 |
| webpki | 423188 | 424312 |
| libc | 7804 | 7800 |
| subtle / zeroize | 逐字节相同 | 逐字节相同 |

### 环节 4：单变量实验闭环（E8）

**同一台宿主、同一份源码、只改 `-C metadata`**，得到三个不同的发货二进制：

```
control（不改）  04eb7b0b2e3e8e1b   ← 与 A0 完全一致，说明手工调用等价于配方
-Cmetadata=AAA   2e3228118ece6ecf
-Cmetadata=BBB   f8c64f29983d8c58
```

这一步把"metadata 差异足以单独造成最终哈希差异"从推断变成了实测。

---

## 2. 被证伪的假设，以及杀死它们的实验

| 曾经合理的假设 | 证伪它的实验 | 直接证据 |
| --- | --- | --- |
| 嵌入的绝对路径（CARGO_HOME）导致最终差异 | **E1**：只给目标 CC 加 `-ffile-prefix-map=$CARGO_HOME=/cargo` | 11 个纯汇编对象跨宿主收敛（对象内 CARGO_HOME 字符串 6→0，`/cargo` 0→6），但 A0==A1、B0==B1 **逐字节相同**——路径变了，二进制没变 |
| 路径经 rustc 侧 target/OUT_DIR 泄漏 | **E2**：只加 `--remap-path-prefix=<target dir>=/target`，先验证该 flag 在 `cargo-vv.log` 出现 16 次 | A0↔A2、B0↔B2 只有 `tools.txt` 不同；A2↔B2 仍有 33 个产物不同 |
| 发货二进制里残留宿主路径 | 直接扫描最终 ELF | 只含 `/cargo/...`、`/rustc/<commit>/...`、`/dev/null`，**零个宿主相关路径** |
| rustc 对 aarch64-musl 的 codegen 与宿主有关 | **E3/E4**：无依赖最小 fixture 两侧各构建一次 | 两侧 `f564e0d2ad2e84cd` **逐字节相同** |
| build script 输出了不同的 cfg | A0/B0 build-script `output` 逐行比对 | `cargo:rustc-cfg` **完全一致**；只有 `cargo:warning`（CI 的 STAGING_DIR / 构建机的 LD_PRELOAD）和 `rerun-if-changed` 顺序不同 |
| ring 的链接顺序 / ar 成员顺序 | E0 逐成员比对 | 成员名、顺序、archive 元数据一致 |
| metadata 差异不足以改变最终二进制 | **E5**（最小 fixture + no-op build script）曾给出这个结论：metadata 不同（`c2aa5dc5…`/`fe6bb2d0…`）但二进制相同（`ffbe79bf…`）。**E8 表明 E5 是功率不足，不是结论正确**——单 crate 平凡程序的布局本来就不依赖符号名 | E8 在真实 httpd 上做同一变量，得到三个不同哈希 |

我自己在 R34 写过的"路径不是唯一原因"和"部分 rlib 相同即证明 codegen 与宿主无关"两句
都超出了当时的证据，已按 R35 的意见收紧，本文不再沿用。

---

## 3. 哪些差异只是中间产物噪声

已证明**不传播**到发货二进制：

1. **ring 的 C/汇编 DWARF 路径差异**。E1 让 11 个对象收敛，二进制不变（A0==A1）。
2. **ring 全部对象的非调试段**：零差异。差异只在 `.debug_line_str` / `.rela.debug_line`。
3. **build script 的 `rerun-if-changed` 顺序与 `cargo:warning` 行**：不进入编译输入。
4. **zeroize 的 `lib.rmeta`**（本轮新查清）。metadata 哈希两侧相同、`.rcgu.o` 位码
   **逐字节相同**，但 rmeta 有 338 字节、42 段差异。精确解码后：
   - 两侧 rmeta **总长相同（529880）**，**可打印字符串多重集完全相同**，字节直方图总偏差
     只有 20；
   - 差异形如构建主机写 `00`、CI 写 `01 <varint>`，即某张表的"索引/内联"判别位不同，
     后续条目整体位移。属于编码层差异，不是内容差异；
   - 三次同宿主构建 rmeta 完全稳定（`fd31c0ea7ec89b51` ×3），所以不是运行间非确定性；
   - 位码相同 ⇒ 不可能到达 codegen；rmeta 不参与链接。
   结论：与宿主相关但**不传播**，归为噪声。这是本轮唯一一处"已定性、未彻底解释成因"的差异，
   边界已被位码相同这一条硬证据封死。

**真正传播**到发货二进制的只有环节 1–4 那一条：build-script 相关 crate 的 `-C metadata`。

---

## 4. 最终两个二进制到底差在哪

构建主机 `04eb7b0b2e3e8e1b` vs CI `a56ef06727148b14`，767008 / 1466512 字节不同。
但结构比对显示这是**同样的代码、不同的排布**：

```
文件总大小            1466512 / 1466512      相同
section 表（名/地址/大小）                    完全相同
program headers                              完全相同
.text 指令条数        261898 / 261898        相同
.text 助记符直方图                            完全相同（每一种助记符计数都一致）
.gcc_except_table     0 字节不同             异常表逐字节相同
```

各段差异分布：`.text` 62.60%、`.eh_frame` 68.21%、`.rodata` 15.48%、
`.data.rel.ro` 4.75%、`.data` 2 字节、`.got` 1 字节。字节直方图偏差极小
（`.text` 0.41%、`.rodata` 0.035%），符合"同一批指令重新排布 + 分支位移/立即数重新编码"，
不符合"生成了不同的代码"。`.rodata` 中 6277 个不同的 8 字节字长里，**没有一个**两侧
都落在映像地址区间——即差异是字符串重新打包，不是指针重定位。

---

## 5. 最小修复

**只有一条：正式发布固定在单一 canonical 宿主上构建。**

没有任何配方 flag 能抹平这个差异。`-C metadata` 由 Cargo 在 unit graph 层面计算，
Host-kind unit 的哈希包含宿主三元组；`--remap-path-prefix`（E2 已证伪）、
`-ffile-prefix-map`（E1 已证伪）、ar/链接顺序（E0 已证伪）都作用在下游，够不到这个输入。

支撑这条修复的两个事实已经拿到：

- **每台宿主内部已经可重复**：CI 三次 `a56ef06727148b14`（A/B 变量分别是 none、
  cc_map、rustc_map），构建主机三次 `04eb7b0b2e3e8e1b`。也就是说"同源码同宿主 → 同字节"
  这条验收本身是成立的，缺的只是宿主唯一性。
- **两个二进制行为等价**：CI 产物对 stock uhttpd 跑 r14 差分 **38/38 全过**（
  `/tmp/r14-ci.json`，`passed: true`, `different: []`），与构建主机产物此前结果相同。

唯一没做成的对照是：在构建主机上用 qemu 跑 x86_64 rustc，让 Cargo 看到与 CI 相同的
host 三元组。失败于 `Could not open '/lib64/ld-linux-x86-64.so.2'`——需要在构建主机装
multiarch 运行库，属于系统级安装，未经你同意我没有做。这条对照如果做成，会把
"宿主三元组是唯一自变量"从强推断变成实测；它不改变修复方案，只增强证据。

### 修复是否影响运行行为

不影响。差异是符号命名与排布：指令条数与助记符直方图完全一致、异常表逐字节相同、
段表与 program header 完全一致，ring 全部对象的非调试段零差异，无 build script 的
crate 位码逐字节相同。行为侧 r14 38/38 在两个二进制上都通过。

### 修复后 A/B 是否逐字节收敛

按定义收敛：固定宿主后 A/B 就是同宿主两次 clean 构建，而同宿主可重复性已由
三次构建各自复现。跨异构宿主的字节一致**不是**这条修复能达成的目标，也不应作为验收项——
除非你要求原生 x86_64 与原生 aarch64 构建也一致，那需要 Cargo 上游改变
Host-kind unit 的哈希输入，不是本项目能修的范围。

---

## 6. 需要你决定的一件事

按既定规则，改动正式发布配方要先问你。可选：

- **A：以 CI 为 canonical**。发布产物哈希变为 `a56ef067…` 一系；构建主机降级为诊断/对照用途。
  好处是 runner 环境由 workflow 固定、可审计。
- **B：以构建主机为 canonical**。设备当前跑的 r5 就是这一系（`04eb7b0b…`），不需要重新刷。
  代价是宿主是一台长期机器，环境漂移要靠自律。

两者都能达成"同源码 → 同字节"，差别只在谁是可审计基线。我倾向 A，因为发布来源核验
本来就要能被第三方重跑。在你定之前配方不动。

---

## 附：实验索引

| 编号 | 变量 | 结果 |
| --- | --- | --- |
| E0 | 无（拆已有 A0/B0 产物） | 定位到 metadata/符号层，排除 ar/顺序 |
| E1 | 目标 CC 加 CARGO_HOME 映射 | 空结果（对象收敛，二进制不变） |
| E2 | rustc 加 target/OUT_DIR 映射 | 空结果（flag 已验证生效） |
| E3/E4 | 无依赖最小 fixture，两侧各一次 | 空结果（两侧逐字节相同） |
| E5 | 最小 fixture + no-op build script | 假空结果（功率不足，被 E8 推翻） |
| E6 | 逐 crate 位码/rmeta 归类 | 分裂线与 build script 吻合 |
| E7 | zeroize rmeta 精确解码 + 同宿主三次复现 | 归为不传播噪声 |
| E8 | 同宿主只改 `-C metadata` | **闭环**：三个不同二进制 |
