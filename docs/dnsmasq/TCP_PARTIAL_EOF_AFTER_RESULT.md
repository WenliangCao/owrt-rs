# Private incremental receiver partial-EOF result

The private streaming receiver matches the frozen exact-C baseline in **27/27
state observations across all nine cases**, with zero differences or execution
failures. This closes the five observed state differences in the
[whole-frame reference](TCP_PARTIAL_EOF_BEFORE_RESULT.md). The former C-only
partial end-sentinel case now has an explicit typed end-marker counterpart;
its three states are included in the 27 paired observations.

Source `dff7a39` contains runtime change `ab98013`. The actual receiver consumes
a one-byte Begin, length-prefixed records and a four-byte End marker. Begin
starts insertion and clears previous pending state. Every complete record is
imported immediately with the existing insertion rules; only End commits the
pending transaction. Abnormal EOF drops the import cursor without restoring
removed records, undoing eviction counters or clearing the applied pending
prefix. The public whole-transaction import API retains its existing behavior.

The gate uses the real anonymous pipe, encoder, receiver and record importer.
For each selected cut it first verifies the complete encoding produces the
expected Begin/Record/End/EOF sequence. Then it closes the writer at the selected
valid semantic prefix and compares before, after-receive and after-next-start
states. All lookups, expiry values, pending/failure state and counters are exact.
The frozen C output is hash-verified and reused, rather than rerun here.

| Case family | Cases | Paired states |
| --- | ---: | ---: |
| No operation or Begin only | 2 | 6 |
| Partial first scalar, name or address | 3 | 9 |
| Complete first record; partial second under pressure | 2 | 6 |
| Partial End; complete transaction control | 2 | 6 |

Identical traces pass calibration; changed pending counts, changed insertion
counts and missing states are rejected. The original C pressure calibration
failure, C negative control and failing whole-frame result remain retained.
No previous failed observation has been removed or counted as a pass.

The probe SHA-256 is
`0a0f97d7829065d1348a9c8bd64cabf9b7e49b71f9c3db7367ed6e06304beadc`.
The [sanitized JSON](TCP_PARTIAL_EOF_AFTER_RESULT.json) pins the complete source,
tool, baseline, probe, result and archive identities. Raw evidence and source
archives are ignored under `private/stream-after-evidence/` in the independent
gate worktree. The executed source and evidence remain on oracle at
`/home/ubuntu/dnsmasq-tcp-stream-import-20261001/first-source/private/after-01/`.
Execution used the Linux isolation wrapper; no router was accessed.

This is a bounded cache primitive/receiver gate, not full daemon, OOM, arbitrary
malformed-input, target-musl, native-wire saturation or performance acceptance.
The typed wire is not the C native ABI. The sender still captures a transaction
and encodes its complete byte vector before writing; the receiver now buffers
one record, but no memory-cost improvement is measured here. Record length has
only the existing minimum validation and can request very large buffers;
allocation failure and C/Rust ENOMEM/ENOBUFS behavior remain unqualified.
The deep accept-time cache clone also remains private and unaccepted.
