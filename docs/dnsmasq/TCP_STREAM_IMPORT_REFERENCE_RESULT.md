# Private incremental TCP cache import regression

Private source `dff7a39` preserves the existing TCP functional gates after
changing the parent receiver to apply complete records before the transaction's
End marker. The separate [partial-EOF gate](TCP_PARTIAL_EOF_AFTER_RESULT.md)
matches exact C in 27/27 states; the fresh daemon and import regressions below
also pass. This remains a private correctness reference, with no product merge
or resource/performance acceptance.

| Gate on the frozen source | Result |
| --- | --- |
| Ordinary TCP inheritance, writeback, accepted clock and HUP | 32/32 paired observations |
| Stale TCP close/refresh/writeback | 41/41 paired observations; C 164/164, Rust 154/154 auxiliary checks |
| TCP request CD, raw reply CD, pressure and independent bogus transaction | 65/65 paired observations; 152/152 auxiliary checks on each implementation |
| Native UBus daemon integration | 69/69 paired observations; 581/581 checks |
| Real EMFILE listener recovery | 17/17 paired observations |
| Shared TCP capacity and queued admission | 31/31 paired observations |
| Doctor-held writeback, indexed slot order and drained release | 12/12 paired observations |
| Frozen typed cache transaction primitive | Native 307/307 and aarch64-musl 307/307 |
| Namespace-isolated Linux unit tests | 398 library + 7 main passed; 17 ignored |
| Native and aarch64-musl all-target Clippy; formatting | Pass, warnings denied |

The native release executable was freshly built in a new target directory and
has SHA-256
`79479efd1a6efb3c35b4abed87caaa91f98190eae56d9e6ddeadc0f209680786`.
The exact native C executable remains
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
All service gates run C first inside the Linux isolation wrapper. Unit binaries
were built outside the wrapper and executed inside it as the build user. The
transfer gates verify the frozen C baseline identities and output hashes before
comparison. No physical router was accessed.

The first writeback attempt failed during tool identity validation because the
source sync omitted its existing `tcp_writeback_subscriber.c` dependency. No
daemon had launched. Its log and empty output directory are retained; copying
the frozen dependency and using a fresh `writeback-12-02` directory produced
the 12/12 result without changing the candidate or fixture. No passing window
was rerun. The UBus report retains the known C bus-restart object-type defect.
The ten C process-shape checks excluded from the stale Rust total and all 17
ignored unit tests are not candidate passes.

The parent pins the indexed slot and entry clock from Begin through End or EOF.
It waits outside parent locks and defers other parent dispatch while the current
transaction is partial. It consumes one transaction per drain event; slot
release still requires joined worker completion plus drained pipe EOF. The
12-observation service gate preserves the existing doctor/backpressure and slot
ordering coverage; it does not add an arbitrary-exit-order proof.

The sender still captures and encodes the complete transaction into vectors.
The receiver buffers a record and applies it before reading its successor;
these functional checks measure no memory, latency or throughput improvement.
Deep-clone admission costs, allocation failure, large or arbitrary malformed
record lengths, C/Rust ENOMEM/ENOBUFS differences and exact native-wire pipe
saturation remain unqualified. The musl primitive/Clippy results do not imply
actual image-musl service qualification. No production acceptance follows.

The [sanitized JSON](TCP_STREAM_IMPORT_REFERENCE_RESULT.json) pins source,
artifact, gate, tool, log and archive identities. Raw packets, configurations,
traces, executables, failed attempt and measurements are ignored under
`private/stream-import-evidence/` in this private worktree. The complete executed
source and evidence also remain at
`/home/ubuntu/dnsmasq-tcp-stream-import-20261001/dff7a39/` on oracle.
