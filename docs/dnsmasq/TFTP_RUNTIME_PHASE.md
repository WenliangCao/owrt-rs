# TFTP transfer runtime phase

This phase joins the reviewed TFTP path and transfer state machine with real
Unix files. It still does not claim the daemon listener or OpenWrt helper
integration.

| C source | Behaviour / invariant | Rust | Evidence |
|---|---|---|---|
| `tftp.c:543-624` | Open then `fstat`; enforce root world-readable and secure owner policy | `RealFileOpener`, `OpenedFile` | real opener path and permission predicate; memory opener tests |
| `tftp.c:242-271` | Existing peer/TID admission, repeated RRQ replacement and transfer cap | `TransferRuntime::handle_datagram` | wrong-peer/TID and replacement paths |
| `tftp.c:724-850,916-1028` | OACK, DATA, ACK progression, block wrap, netascii carry and final empty block | `TransferRuntime` using `tftp::Transfer` | six runtime tests, including negotiated block bound |
| `tftp.c:671-735,852` | Retransmit on deadline and release on error/timeout/completion | `tick`, `RuntimeEvent::{TimedOut,Failed,Completed}` | retransmit and cleanup tests |
| `tftp.c:625-668` | Same `(path, st_dev, st_ino)` file may be shared by active transfers | `SharedFile` with `Arc<dyn FileReader>` | active transfer lookup; opening still occurs before identity sharing |

`TransferRuntime` emits packets through `RuntimeEvent::Send`; the caller owns
the UDP socket, source TID and interface pktinfo. It uses `pread`-equivalent
`FileExt::read_at`, so concurrent transfers do not share a mutable file cursor.
Malformed requests are converted to TFTP error packets, and a packet from a
different peer receives `unknown transfer id` without changing transfer state.

The current module does not yet bind UDP port 69, allocate the configured
separate transfer port range, validate Linux pktinfo/interface changes, invoke
PXE/helper scripts, or expose lease/DHCP integration. Those are explicit
OpenWrt delivery gates. The netascii path is bounded to the negotiated DATA
block size; a larger temporary expansion buffer would violate the C packet
boundary and is intentionally avoided.
