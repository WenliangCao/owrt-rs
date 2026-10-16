# Static LLVM cold splitting: independent local experiment

Source `d5e97d78` changes only the recipe's addition of
`-Cllvm-args=--hot-cold-split` on exact 9e product code. It excludes c95's
section attributes and all other local prototypes. All heuristic defaults,
optimization level, fat LTO, codegen unit count and target remain unchanged.
Pinned rustc1.98.1/LLVM22.1.8 accepts the option. The same option was used in
local library and final Linux linking; 729 local release-mode library tests
pass, with 8 ignored. These do not replace the Linux/SDK qualification.

The [LLVM22 implementation](https://github.com/llvm/llvm-project/blob/release/22.x/llvm/lib/Transforms/IPO/HotColdSplitting.cpp)
uses static coldness analysis alongside available profile information and a
profitability check; it skips functions carrying noinline/alwaysinline.
This experiment supplies no PGO profile and changes no threshold. These
implementation references motivate the experiment, not a speed prediction.

| Local final Linux artifact | 9e control | Cold split |
| --- | ---: | ---: |
| `.text` bytes | 1824680 | 1807768 |
| File-backed PT_LOAD bytes | 2090032 | 2112160 |
| `.eh_frame` bytes | 96992 | 126472 |
| Whole ELF bytes | 5024648 | 5211920 |
| Emitted `.cold.` functions | 0 | 810 |

Cold functions total19636B. The whole file includes symbol/string tables;
it is not the shipping ELF size. File-backed loads still grow22128B despite
text shrinking16912B. Unwind metadata grows, including its header. Original
release size budgets remain unmeasured and unchanged.

The principal entry ranges barely change: process_udp4660→4652B,
step4692→4596B, wait_for_files7192→7048B, and the prepared-query main body
2484→2468B plus a separate28B cold helper. Fresh writer1028B and shared
local/cache answer3848B are unchanged. Source/module placement and additional
cold calls may affect other paths; these sizes establish no CPU/IPC benefit.

The first local display collapsed identical logical names and showed a cold
helper's28B as the prepared method. Raw inspection retained both symbols.
The corrected inspection uses separate cold-helper assembly filenames and
reports all ranges; the initial display and explanation are retained. No
source, build, measured window or acceptance comparator was rerun for that fix.

This remains an unselected local experiment, below c95's actual SDK layout
validation. No parameter sweep, remote preparation or performance run follows.
[Artifacts, tests, complete selected ranges and retained diagnostics](llvm-cold-split-local.json).
