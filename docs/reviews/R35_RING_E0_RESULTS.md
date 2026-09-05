# R35 / E0：拆已有产物的结果 —— 差异全部落在"嵌入的绝对构建路径"

日期：2026-09-05。基线 `758df09` + 取证修正。按 R35 §E0 执行：**先分析已有 A0/B0 产物，不重编**。
E1（受控重编）尚未执行。

## 先更正 R34 的措辞

R35 的批评成立，采纳：

- R34 写的**"路径不是唯一原因"过头了**。正确说法是：**已定位一处（实为一类）路径差异，最终 ELF 的差异尚未解释完**。
  "存在第二个独立根因"当时没有证据，现在 E0 的结果也**不支持**这个说法。
- "同宿主两次相同"只证明这两次相同；"若干 rlib 相同"只证明这些产物相同。两处已改。

## E0-1：mem.o 多出的 104 字节，定位到了

| | CI | 构建主机 |
| --- | --- | --- |
| 文件大小 | 64616 | 64512 |
| section headers 起点 | 59432 | 59328 |
| `.debug_line_str` | **1121** | **1021** |

差的 100 字节在 `.debug_line_str`。原因是对象里嵌了 **SDK 的绝对路径**，两边长度差很多：

```
CI  : /home/runner/work/owrt-control-plane-rs/owrt-control-plane-rs/work/openwrt-sdk-…/staging_dir/toolchain-…/include
HOST: /home/ubuntu/release/25.12.5/openwrt-sdk-…/staging_dir/toolchain-…/include
```

**逐 section 比对 mem.o：只有 `.debug_line_str` 与 `.rela.debug_line` 不同，没有任何可装载 section 不同。**
也就是说 ring 的 C 对象**机器码两边完全一致**，差的只是 DWARF 里的路径数据。

（纯汇编对象 `sha256-armv8-linux64.o` 早先测到的 20 字节差异同理，是 DWARF 目录表里的 `CARGO_HOME`。）

## E0-2：zeroize 的 rlib，差的是 `.rmeta` 不是机器码

```
成员名与顺序：完全相同
lib.rmeta                                    DIFFERS
lib.rmeta-link                               same
zeroize-….zeroize.….rcgu.o                   same     <-- 机器码对象
整个文件差异字节数：338
```

**目标机器码对象逐字节相同**，只有 Rust 元数据 `lib.rmeta` 不同（338 字节）。
所以之前"zeroize 未解释"的部分，现在归到同一类：**元数据里的绝对路径**。
R35 的提醒是对的——不能把整个 rlib 不同直接叫作机器码不同。

## 目前的统一解释（一个原因，三类路径）

到 E0 为止，**每一处已定位的差异都是"没有被 remap 的绝对构建路径"**，且两边长度不同：

| 路径 | 谁嵌进去 | 现状 |
| --- | --- | --- |
| `$CARGO_HOME` | rustc **已** remap；ring 的 C/汇编经 SDK gcc，**没有**任何 `-ffile-prefix-map` | C/汇编对象的 DWARF 里是真实路径 |
| SDK / toolchain include 路径 | SDK gcc | 两边长度差很多（CI 的 workspace 路径长得多） |
| target / `OUT_DIR` 路径 | 两侧都可能 | 配方的两条 `--remap-path-prefix` **不覆盖**它 |

最终 ELF 的 `.rodata`（差 41686）与 `.text`（差 655830）**仍未解释**，但一个自洽且尚未被证伪的机制是：
长度不同的路径字符串改变 `.rodata` 布局，随后所有 PC 相对引用跟着位移。
**这是待验证的假设，不是结论**——E1 就是用来判它的。

## E1 的范围需要按证据调整（并说明为何偏离指导）

R35 要求"这一轮只加 `-ffile-prefix-map=$CARGO_HOME=/cargo` 一个因素"。
但 E0 已经证明**同一个对象里还嵌着 SDK include 路径**，只映射 CARGO_HOME**必然不足以让 `.o` 收敛**，
那一轮的结果会是"对象仍不同"，读不出更多信息。

建议把"一个因素"定义为**"给目标 CC 补齐构建路径映射"**这一件事（CARGO_HOME + SDK 根 + target 目录），
仍然不动 LTO、linker、strip、profile、源码路径。若你更希望严格照原文只加 CARGO_HOME，
我可以先跑那一轮作对照，代价是多一轮构建。**等你定，不擅自决定。**

无论哪种范围，都会按 R35 保存四组比较：A0↔B0、A0↔A1、B0↔B1、A1↔B1，
并先从 `cc-commands.txt` 确认参数**实际落到了** C 与 `.S` 的编译命令上。

## 取证脚本的修正（已提交，未改构建语义）

按 R35 §"先修取证"：

1. build-script 输出路径修正为 `.../build/ring-<hash>/output`（原来多退一层且被 `|| true` 吞掉，**一直没收到过**）；
   同时收 `root-output`/`stderr`/`invoked.timestamp`；**所有 ring build 目录按 hash 分别收集**，不再只取第一个；
   一个都找不到就**显式失败**。
2. rustc 身份改为从 `cargo -vv` 日志里解析**实际被调用的 rustc 路径**再问它 `-vV`，并记录日志里出现过几个不同的 rustc。
3. `httpd-rs.unstripped` 改名为 `httpd-rs.release`（release profile 本来就 strip），并另存实际 section 列表。
4. 增记：git revision 与工作区是否干净、Cargo.lock 哈希、SDK 目录、CC/AR 的**文件哈希**与 `file` 输出、
   qemu 版本（构建主机用 QEMU 跑 x86_64 SDK 编译器）、以及逐个具名的编译器覆盖变量。
5. 新增 `cc-commands.txt`：从 `-vv` 日志里抓**真实的 C/汇编命令行**，用来证明 flag 确实生效。
6. 不再原地删除上一轮 diag，先归档带时间戳的副本；A0/A1 仍用同一物理构建路径。

## 与安全性无关

这是发布产物可核验性问题。已定位的差异全部是**调试信息与元数据里的路径**，
目标机器码在对象层面**逐字节相同**。不构成 TLS、性能或稳定性问题的证据。
