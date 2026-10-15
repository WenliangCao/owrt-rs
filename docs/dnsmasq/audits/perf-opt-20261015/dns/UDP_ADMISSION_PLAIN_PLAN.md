# UDP admission fixed plain screen

Candidate `c1ea66f6` versus exact E `4f869c88`. Run the committed
`udp_admission_plain.py` once after all Oracle research builds and counters
are quiet. No PMU, tracing, allocator instrumentation or concurrent workload.

Five alternating pairs for each of hit, hit-upper, miss, host and malformed,
in that order: 50 windows, two million operations each plus the existing 800
priming operations. Odd pairs use E first; even pairs candidate first. CPU2,
ordinary priority, same native release artifacts already counted; artifact
hashes and expected whole-answer checksums are asserted by the script.
CPU is child user plus system time for the complete process, including setup.
Wall time is retained separately. No repeats, tuning or replacement windows.

Report median and full range on both sides, paired directions and W, the
larger within-side full range divided by its median. A screen improvement or
regression requires magnitude greater than W and at least four concordant
pairs. This focused screen does not replace the frozen daemon acceptance
thresholds or device comparison. Malformed's counter increase stays visible;
an adverse control prevents automatic selection.
