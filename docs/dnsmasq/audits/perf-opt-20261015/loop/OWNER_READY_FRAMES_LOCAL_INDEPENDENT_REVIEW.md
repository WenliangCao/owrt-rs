# Independent check of existing 5c owner-frame codegen

PASS for existing local source and ELF evidence. Candidate
`5c995a8564ce04b81e42c7f1c581bb06e691d87a` includes 025's ready-DHCP
extraction and adds the gate-admitted cache-dump extraction. It is not bare
6ab. No source, compiler, test or remote task was run during this review.

| Function | 6ab bytes / frame | 5c bytes / frame |
|---|---:|---:|
| `SinglePoll::step` | 17,608 / 2,400 B | 4,692 / 640 B |
| `process_ready_dhcp` | inlined | 4,408 / 2,016 B |
| `dump_requested_cache` | inlined | 8,884 / 1,072 B |
| `wait_for_files` | 7,192 / 352 B | 7,192 / 352 B |

ELF symbols, full selected-function disassembly and hashes were independently
reproduced from existing bytes. Frame sizes follow actual prologues: step
`0x60+0x220`, DHCP `0x60+0x780`, dump `0x60+0x3d0`. Wait function size and
frame are unchanged; its relocated machine bytes are not identical.

The dump call at `0x295ad0` occurs only after the original atomic decrement:
`0x295aac` skips directly to `0x295ad4` on zero, and the CAS retry remains at
`0x295abc/0x295ac8`. ALARM processing still precedes that gate. The sole DHCP
call at `0x295c5c` remains after helper processing, `dhcp_packet_work_allowed`,
input detection or the original due-maintenance test. False admission and
not-due paths skip it. Source locations are frozen `main.rs:4538–4579` and
`main.rs:6424–6456`; neither gate introduces state or changes work order.

Active frames nest: step plus DHCP is 2,656 B, which is 256 B above the former
6ab shared step frame alone; step plus dump is 1,712 B. The two helpers run
sequentially, not inside each other. These sums exclude deeper callees and do
not establish whole-program peak stack or CPU improvement.

The local bundled-musl/lld ELF is 5,022,096 B: 144 B smaller than 6ab and
280 B larger than 025. Candidate ELF SHA-256:
`5f6d7274a09577d074704df3016a9ee2501883e7cfab05a7c6f91ca024bad88b`.
The [compact audit receipt](owner-ready-frames-local-independent-review.json),
SHA-256 `696ce151356a8156bb9478762b8e858f52b9e52a155455d236812f842a1902e2`,
binds both ELFs, symbols/code/assembly hashes, source, conditions and frame
arithmetic. This is local codegen evidence, not canonical SDK, physical-device
or runtime-performance qualification. Bare 1df's active queue is unchanged.
