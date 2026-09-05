# R35 / E1：只加一个因素的受控对照结果

日期：2026-09-05。基线 `5d64e50`。按用户选择的**选项 2** 严格执行：
这一轮**只**给目标 CC 加 `-ffile-prefix-map=<本机 CARGO_HOME>=/cargo`，其余一律不动
（源码路径、OUT_DIR、strip、LTO、linker、profile、容器全部保持原样）。

因为 A0/B0 是用有 bug 的取证脚本收的，**两条基线都用修正后的脚本重收了一遍**，
四组产物才能按名字对齐。四次构建：A0/A1（构建主机）、B0/B1（CI），每组 47 个产物。

## 先确认因素真的生效了

R35 强调"先核对参数实际落到 C 与 `.S` 上"。这一步差点被我漏掉：
`cc-commands.txt` 里 `ffile-prefix-map` 出现 **0 次**——但这不是因为 flag 没生效，
而是 **`cargo -vv` 根本不打印 cc crate 自己的编译命令**（只打印 rustc 的）。该文件已改名
`rustc-linker-commands.txt` 并写明它**不能**用来证明 C flag 落地。

改从产物取证，结论明确（`mem.o`）：

| | A0（none） | A1（cargo_home） |
| --- | --- | --- |
| 文件大小 | 64512 | 64440 |
| `/home/ubuntu/.cargo` 出现次数 | **6** | **0** |
| `/cargo` 出现次数 | 0 | **6** |
| `openwrt-sdk` 路径出现次数 | 2 | **2** |

映射确实生效，且**只**替换了 CARGO_HOME；SDK 路径原样留着（本轮没映射它）。

## 四组比较

| 比较 | 相同 | 不同 |
| --- | --- | --- |
| A0 ↔ B0（跨宿主，映射前） | 9 | **33** |
| A1 ↔ B1（跨宿主，映射后） | **20** | **22** |
| A0 ↔ A1（同宿主，前后） | — | 30 个中间产物变了 |
| B0 ↔ B1（同宿主，前后） | — | 30 个中间产物变了 |

### 收敛的：11 个纯汇编对象，全部

```
c322a0bcc369f531-{aesv8-armx, aesv8-gcm-armv8, armv8-mont, chacha-armv8,
  chacha20_poly1305_armv8, ghash-neon-armv8, ghashv8-armx, p256-armv8-asm,
  sha256-armv8, sha512-armv8, vpaes-armv8}-linux64.o
```

这些由 pregenerated `.S` 汇编而来，**只嵌了 CARGO_HOME**，映射后跨宿主逐字节一致。

### 没收敛的：11 个 C 编译对象 + `.a` + build-script 输出

C 对象里除了 CARGO_HOME 还嵌着 **SDK toolchain include 路径**，两边长度差很多，本轮没映射它。
`ring-output` / `ring-root-output`（build-script stdout，**正是 R35 修好取证后才第一次收到的证据**）同样含绝对路径。

## 本轮最重要的一条：**最终二进制对这个因素完全不敏感**

```
A0 httpd-rs.release = 04eb7b0b…      A1 = 04eb7b0b…   （同宿主，映射前后逐字节相同）
B0 httpd-rs.release = a56ef067…      B1 = a56ef067…   （同上）
A1 ↔ B1 仍然不同
```

也就是说：**改掉 ring 对象里的调试路径，发货二进制一个字节都没变。**
它们在链接时被 strip 掉了，从来就没进过最终产物。

这直接**证伪**了我在 R34/E0 里提出的假设——"长度不同的路径串移动 `.rodata` 布局、
PC 相对引用跟着位移"——**对 ring/DWARF 这一类路径不成立**。
按 R35 的要求，这句话现在有实验支撑，不再是"自洽假设"。

## 结论与下一个因素

对照 R35 的决策表，本轮落在"**ring 对象仍不同**"这一格，但多了一条它没预期的信息：
最终 ELF 与这个因素**无关**。所以剩下两条线索是独立的：

1. **让 ring 对象跨宿主收敛**：还差 SDK toolchain 路径这一个映射。这条线索**对发货哈希没有帮助**
   （已证明），只影响中间产物的可比性。
2. **让发货二进制跨宿主收敛**：得从别处找。现在最具体的线索是
   `libzeroize-….rlib` 的 `lib.rmeta`（338 字节，机器码对象逐字节相同）——
   rmeta 参与 LTO，且配方的两条 `--remap-path-prefix` **不覆盖 target/OUT_DIR 路径**，
   而该路径在两台机器上长度差别极大。

**建议下一个单一因素（E2）：给 rustc 增加 target 目录的 `--remap-path-prefix`。**
仍然不动 CC 映射、LTO、linker、strip。理由：它直接命中 §2 这条线索，而 §1 已证明与发货哈希无关。
是否要先把 SDK 路径映射也单独跑一轮作为对照，等你定。

发布配方**依然没有改动**。这一轮全部是诊断变量。

## 与安全性无关

已定位的全部差异仍是调试信息与元数据里的路径；目标机器码在对象层面逐字节相同
（收敛的 11 个汇编对象是直接证据）。不构成 TLS、性能或稳定性问题的证据。
