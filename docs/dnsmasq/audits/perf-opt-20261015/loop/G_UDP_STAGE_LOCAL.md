# Current G cumulative-path diagnostic source, dormant

Accepted G remains the delivery candidate. This independent excluded source
reuses the original E four-mode diagnostic, with no new measurement framework.
It is only a possible next attribution step if bare1df remains inconclusive;
no SDK build, Linux execution, router plan or timing has been selected.

58f96e8e places the original receive, before-answer, skip-local and full hooks
on G. The skip-local hook is at the shared LocalAnswerer entry and retains
inspect_name. The old patch context failed there because G moved record
assembly; that failure remains and the original hook was inserted explicitly.
Putting it in answer_local_records would miss normal G cached hits.

Separate a34e7310 preserves G's buffer lifecycle at before-answer: take the
existing local cached_reply_buffer, clear and reserve128 as the original writer,
then use the unchanged synthetic bytes. Mark the result cached so the original
send completion returns it through recycle_cached_reply. The old E helper's
fresh128B allocation would otherwise introduce5000allocations/releases per cut
window and confuse interpretation. No production service visibility/API changed.

The original1600synthetic replies, rejected fixtures and1000-entry threshold
pass locally, with added pointer/capacity assertions across returned buffers.
Musl all-target compilation passes. Actual Linux fixture, SDK identities and
size, source review, full-mode calibration, original raw count/traffic/health
and restoration gates would still be required if selected. Synthetic TTL120,
changed control flow/prologues/cache state and writer work remain limitations;
stage contrasts are not additive function costs or performance acceptance.

[Source and local check receipt](g-udp-stage-local.json).
