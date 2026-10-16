# 2b4f8b16 independent local review

**PASS: no product-semantic blocker identified.** The actual change retains
partial-block lengths, Entry/Record identity and COW ownership. Shared clear
detaches each block once; unique clear preserves backing. The new fully
populated0/1/63/64/65/1000 cases exercise the final partial block, and existing
partial8 snapshot mutation/Record-sharing coverage remains. Parent1721e5a1
changes only a cfg(test) hosts fixture plus its report; production hosts
source before the test module matches G.

The [independent receipt](content-slice-local-independent.json) binds all20
command/log results,16 raw count outputs, Mac722 pass/8ignored and musl check
logs. The current snapshot-count.rs was compared byte-for-byte with the old
cold-metadata-review copy, both SHA`c43d5a93…59bc07`. All count errors and
final live-byte deltas are zero; population drops balance construction.

At capacity1000, ctor99→83 allocations and requested/live93248→93120B are
confirmed. Twenty snapshots request332800→335360B. Filled800 with one real
content detach per snapshot gives80→60 lookup allocations but
423955→426195B peak extra requests. This retains the adverse root/peak cost.

Both final local ELFs and all12 selected function bodies were independently
rehashed and disassembled, matching the retained assembly byte-for-byte.
get160B, invalid232B, is_valid176B and the three selected caller sizes remain
equal. The get instruction sequence removes the wrapper-dependent address
load and instead indexes16B roots, retaining the final Arc-header offset.
The full local ELF grows200B. No cycle or A53 benefit is inferred.

No product/test/probe execution, remote action or qualification-tool edit
occurred during this review. Existing full-gate wrapper coupling remains;
the independent prototype is not full-gate ready or selected for deployment.
