# Reuse a question the writer has already validated

Independent185 childb65e9a9c skips only a redundant name scan in `record_at`:
when offset isHEADER_LEN and the writer contains a completed question, those
bytes came from a valid `Name`. Writer methods can append but cannot mutate
that question. Bounds, arbitrary offsets, no-question cases, record append
ordering, truncation and atomic overflow remain on their original paths.
No unsafe code, new API or retained metadata is added.

Mac722passed/8ignored and musl all-target checking pass. The new independent
wire-byte test covers root, mixed case, maximum-length and every single-byte
label, plus invalid offset, absent question and multiple-question boundaries.
Existing writer golden packet and atomic/sticky truncation assertions remain.

Final local AArch64 code confirms the fresh writer branches around the name
walk after reading its nonzero question count. Static code still retains the
fallback: writer1088→1092B, record_at368→384B; writer frame remains288B.
This is a mechanism check, not a CPU benefit. No SDK/Linux runtime or timing
has run, and this is separate from185 and the a15 small combination.
[Exact code ranges, local build commands and validation](written-question-owner-local.json).
