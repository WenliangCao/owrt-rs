# Contiguous query-name copying: local-only

The 9e child `365d80d6` validates an ordinary consecutive-label name before
copying it once into an already large enough UDP scratch buffer. Growth,
compression pointers and rejected inputs use the original walker. No unsafe
code, retained metadata or API change is introduced. A second focused commit,
`cbb631bd`, outlines that original walker to keep its code off the common entry.

All 730 local library tests pass (8 ignored), including 46,606 new comparisons
against the original walker for bytes, cursor, errors, retained partial scratch
and buffer identity. Both versions pass the musl all-target check. The first
implementation changed long-name allocation growth; the unchanged original
daemon test caught it. Its failed log is retained. Restricting the fast path to
existing capacity restores the original growth path without changing tests.

| Local final musl code | 9e control | 365 fast path | cbb outlined |
| --- | ---: | ---: | ---: |
| UDP prepared entry bytes | 2484 | 2840 | 1968 |
| Own frame bytes | 688 | 720 | 672 |
| Whole local ELF bytes | 5024648 | 5025016 | 5024984 |

The exact previous local 9e control is reused, with the same toolchain/flags.
Code inspection confirms the normal path makes one memcpy instead of copying
each label. The outline adds a separate 640-byte helper with a 112-byte frame;
its nested total is 784 bytes, above the previous 688. Fallbacks also pay the
new failed eligibility scan before the original walk. These tradeoffs remain
explicit: no runtime CPU, instruction or A53 cache improvement is inferred.

Source review is separate. Neither prototype is remotely qualified or selected
for timing; immutable 9e and accepted G remain unchanged.
[Exact artifacts, test logs and emitted ranges](contiguous-query-name-local.json).
