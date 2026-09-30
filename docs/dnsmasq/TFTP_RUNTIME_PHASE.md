# TFTP transfer runtime phase

`src/tftp_runtime.rs` is the file and transfer state boundary below the
event-loop listener. It opens real files with `open` followed by `fstat`, checks
the C root/secure permission rules, shares an already-open descriptor by
`(st_dev, st_ino, path)`, and reads blocks with position-independent `read_at`.
The caller supplies a packet callback and a transfer ID for dedicated sockets;
this module does not bind port 69, inspect pktinfo/interfaces, or run PXE/helper
scripts.

`handle_socket_datagram` adds the small transport-role gate below that state
machine: in separate-port mode, `SocketRole::Server` admits RRQ/WRQ and
`SocketRole::Transfer(id)` admits the non-RRQ transfer path (ACK/ERR are the
stateful opcodes; a foreign peer receives `ERR_TID`). The caller still binds port 69 or a
configured transfer range, validates interface metadata and supplies the peer
TID; this is not a listener implementation.

The runtime preserves the existing `tftp::Transfer` state machine: OACK is
retransmitted while block 0 is outstanding, windows begin only after ACK, a
partial window cannot complete until its final ACK, exact multiples and empty
files send a zero-length DATA block, and `>120s` cleanup is explicit. Foreign
peers receive TID errors without changing ACK/wrap state. Read failures emit a
failed cleanup event and release the active file reference.

| C source | Behaviour / invariant | Rust | Evidence |
|---|---|---|---|
| `tftp.c:543-624` | Open then `fstat`; enforce root world-readable and secure owner policy | `RealFileOpener`, `OpenedFile` | real opener and permission predicate tests |
| `tftp.c:242-271,671-735` | Existing peer/TID admission plus separate port-69 versus transfer-socket opcode ownership | `TransferRuntime::handle_datagram`, `handle_socket_datagram`, `SocketRole` | TID/replacement/capacity and socket-role tests |
| `tftp.c:724-850,916-1028` | OACK, DATA/ACK progression, block wrap, netascii carry and final empty block | `TransferRuntime` using `tftp::Transfer` | 12 focused runtime tests; netascii oracle is recorded separately |
| `tftp.c:671-735,852` | Retransmit on deadline and release on error/timeout/completion | `tick`, `RuntimeEvent::{TimedOut,Failed,Completed}` | retransmit, timeout and cleanup tests |
| `tftp.c:625-668` | Same `(path, st_dev, st_ino)` file may be shared by active transfers | `SharedFile` with `Arc<dyn FileReader>` | active-transfer lookup and descriptor test |

Focused tests cover real `File`/`fstat`/`read_at`, octet DATA, netascii carry,
OACK retry, partial windows, timeout/retransmit, TID validation, WRQ rejection,
exact-multiple/empty-file completion, and descriptor sharing. The runtime test
fixture uses isolated temporary files; no production or physical-router state
is touched. Full UDP listener/pktinfo and PXE/helper integration remain outside
this phase.

The focused module suite passes 16/16 with `cargo test --lib tftp_runtime`.
`handle_transfer_datagram` receives the dedicated transfer ID and the actual
sender: even a sender owning another active transfer receives
ERR_TID before any ACK/ERR state changes. Empty datagrams are ignored, matching
the C `recvfrom() > 0` boundary; a foreign one-byte datagram still gets ERR_TID.
The Linux listener consumes idle `WouldBlock`/`Interrupted` reads and returns
TID errors on the receiving socket. IPv4/IPv6 UDP differential and resource
evidence for that narrow contract is in `TFTP_LISTENER_PHASE.md`; complete
TFTP daemon and OpenWrt helper compatibility remain unverified.

The error paths preserve C wire codes: missing files return 1, access/owner
policy failures return 2, other open/fstat/read failures return 0, and WRQ or
malformed RRQ return 4. A file shrinking mid-window retains earlier DATA and
subsequent per-block ERR packets in C order before `Failed` releases the
transfer. These failures return protocol events rather than aborting the
listener. `TFTP_LISTENER_PHASE.md` records the exact-daemon differential and
the separate temporary-error-socket cleanup contract.

Dedicated RRQs now keep distinct `TransferId`s throughout Send, completion,
error and timeout events. A repeated RRQ from the same address/port creates
another instance, matching C; an ACK/ERR can only change the instance whose
socket received it. Single-port mode retains peer-based replacement. The
dedicated listener follows C's `active <= tftp_max` admission test and stops
receiving when false, leaving queued requests available after completion.
This exact C boundary permits `max + 1` active transfers for one listener.
