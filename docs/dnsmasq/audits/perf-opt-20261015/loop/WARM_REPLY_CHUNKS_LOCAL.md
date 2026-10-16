# Warm reply chunks: local-only prototype

Source `4348b6d3` is an independent child of frozen `9e8459dd`. It replaces
whole-packet zeroing followed by overwrite with four initialized chunks:
12-byte header, original name, 16 fixed fields and the selected address bytes.
Capacity, length, logging and fallback guards and send/recycle ownership remain
unchanged. No unsafe code, new persistent state or public API was added.

The existing 18,432 reply comparisons remain unchanged. All 729 local library
tests passed (8 ignored), and the musl all-target check passed. Independent
source review `2bc0f64b` checked byte layout, capacity and ownership; these are
local checks, not the original Linux/SDK correctness qualification.

The exact previous local 9e ELF was reused without rebuilding. Local musl
ELF size changes from 5,024,648 to 5,024,112 bytes. The fresh writer changes
from 1,028 to 704 bytes, with its own 160-byte frame unchanged. Its direct
memset disappears, but the four chunk writes call an out-of-line 128-byte
`Vec<u8>::append_elements` helper, with a 48-byte frame and a memcpy call.
Its guarded reserve branch remains emitted; the original capacity guard
prevents growth on this path. The parent had one direct memset and two direct
memcpy calls. Smaller code does not establish fewer calls or lower CPU cost.

Two append helper monomorphizations exist. The first local inspection rejected
an incorrect uniqueness assumption before producing a final receipt. That
failure is retained; the corrected inspection selects the helper actually
called by the fresh writer (0x314e34), without rebuilding or rerunning tests.

This prototype has not been selected for remote qualification or timing.
Accepted delivery remains G; the separate 9e screen remains immutable.
[Exact artifacts, checks and function evidence](warm-reply-chunks-local.json).
