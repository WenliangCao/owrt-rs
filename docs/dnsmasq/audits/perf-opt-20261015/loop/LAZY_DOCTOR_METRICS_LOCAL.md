# Conditional UDP doctor metrics: local prototype only

Independent6ab childa2c2cabe captures the original120-byte Metrics snapshot only
when a DNS UBus subscriber exists. Its capture point stays before query work;
the doctor callback retains its per-result DNS-counter update. Ordinary UBus,
cache-dump and DHCP-probe snapshots remain unchanged. Counter getters copy
values without resetting them or performing I/O. The redundant second copy
of the same DNS counters was removed.

The existing ParentEvents exclusive borrow prevents subscription processing
between capture and the original polling decision. Interface-enumeration work
returns or recurses after dropping that borrow and rechecks the condition.
Subscriptions can change inside doctor_dns; that original per-callback handling
is retained. Loop independently reviewed these source boundaries. Mac23binary
tests and default/m6b musl all-target checks pass; real Linux UBus lifecycle and
nested-doctor gates have not run.

The local final Linux ELF has an actual branch around the metrics call for
absent/unsubscribed UBus. This is not a CPU measurement. process_udp grows
4660→4880B, poll_udp_completions1432→1496B, metrics remains416B. Their stack
frames are1056→1056B and624→656B respectively. Both favorable call skipping and
adverse code/frame growth are retained. The local linked ELF is not an SDK
artifact.

Earlier L07 rejected this direction based on a small instruction share. The
new G profile's process_udp cycle share includes other work and does not prove
metrics became expensive. Keep this isolated prototype without a dedicated
remote screen now;6ab qualification, actual G allocation counts and the
separate opt2 experiment have higher priority. No new performance claim,
behavior fix, test-tool expansion or stopping conclusion follows.

[Source, checks and local codegen receipt](lazy-doctor-metrics-local.json).
