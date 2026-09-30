# TFTP dedicated socket listener phase

The pinned `tftp.c:626-665` event loop only calls `handle_tftp` after comparing
the actual `recvfrom` peer with that specific transfer's peer. A nonempty
foreign datagram receives error code 5 from the socket it reached. This check
also applies when the foreign sender owns another active transfer.

The Rust listener previously substituted the socket owner for the actual
sender, permitting foreign ACK/ERR packets to complete or abort its transfer.
It also returned on an idle server/transfer socket before processing other
transfer sockets and retransmission timers. `handle_transfer_datagram` now
preserves both addresses; replies retain the receiving socket's source TID;
idle reads no longer block transfer/timer progress. No extra transfer socket
is allocated for a foreign sender.

`tools/dnsmasq/tftp_listener_diff.py` compares the exact C daemon with
`tftp_listener_probe.rs`, which directly drives the production Rust listener.
It requires `run_isolated.sh`, loopback, isolated lease/network state and
matching source/ELF identities. It calibrates comparison with one equal case
and six deliberately unequal cases before starting services. Packet bytes,
error codes, source-TID equality, success/error cleanup and process exit are
compared; only ephemeral port numbers and diagnostic error text are normalized.
Raw packets, process logs and binary/source hashes stay under ignored private/.

The 2026-09-30 run used exact C ELF SHA256
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431` and
`tftp.c` SHA256
`a6971bf4ce77c0ca4c7ebf0194a2ee9c2ad702b1b8a882d46de87c6c6f5e63f3`.
Both IPv4 and IPv6 passed 14 checks: initial DATA for two peers, distinct
transfer sockets, foreign short/ACK/ERR/RRQ and cross-transfer ACK errors,
ignored owner RRQ/empty foreign packet, subsequent correct ACK progress,
baseline FD restoration after final ACK/client ERR, and clean exit.

One additional ignored-by-default Linux test exercises idle polling, both
address families, foreign-peer isolation, retransmission, timeout, and socket
closure verified by rebinding the released addresses. It passed under the
same namespace gate. The socket-independent runtime suite passes 13 tests.

Evidence: `private/dnsmasq-rewrite/tftp-listener-tid-20260930/run-01/`.

The second unit closes request-error response and descriptor ownership for
the covered branches of `tftp.c:367-375,501-529,538-624,700-724`. ENOENT emits
ERR_FNF (1); EACCES and root/world-read or secure-owner policy emit ERR_PERM
(2); other open/fstat/read errors emit ERR_NOTDEF (0). WRQ and malformed RRQ
emit ERR_ILL (4). A rejected new request sends from a temporary socket and
releases it, preserving an existing dedicated socket for the same peer.
Runtime permission and I/O failures no longer escape as fatal listener errors.

The expanded differential has 27 checks for each address family, 54 total,
with zero mismatches in `run-03/`. It adds missing/private/non-directory/
directory-read/malformed/WRQ/traversal requests while a healthy transfer from
the same peer stays active. Each checks the error code, temporary source TID
and zero FD delta. It also truncates an already-open file after OACK and
compares C's exact `DATA 1, DATA 2, ERR 0, ERR 0` window before FD restoration.
The failed intermediate `run-02/` is retained: an initial read-failure event
incorrectly removed the peer's older socket. The final code distinguishes
server-request cleanup from transfer/timer cleanup, and the unchanged
scenario now passes. Runtime tests additionally inject EPERM and EMFILE and
check secure-owner rejection. All 30 host TFTP tests pass; the additional
Linux namespace listener test passes on the final source snapshot.

The differential fixture can be rebuilt with native `cargo build --lib` and
`rustc --edition 2021 tools/dnsmasq/tftp_listener_probe.rs --extern
dnsmasq_rs=components/dnsmasq/target/debug/libdnsmasq_rs.rlib -L
dependency=components/dnsmasq/target/debug/deps -o private/tftp_listener_probe`.
Run the Python tool under `run_isolated.sh`, supplying `--c`, `--rust`,
`--source` (the matching `tftp.c`), and a fresh `--out` under private/. Its
summary records both executable hashes and the Rust source hashes.

These are host functional results, not router performance results. They do
not close interface admission/pktinfo source selection, transfer port ranges,
repeated successful same-peer RRQ in separate-port mode, full single-port
service equivalence, PXE/helper scripts or package integration. Capacity,
socket allocation/send failure and complete resource-pressure behavior also
remain outside this gate.
