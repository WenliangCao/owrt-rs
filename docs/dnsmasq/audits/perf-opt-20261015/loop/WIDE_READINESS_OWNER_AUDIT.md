# Wider readiness aggregation: actual ownership boundary

Read-only follow-up while candidate E runs its full correctness gates. No
remote command, workload, new tool, registration framework or product change
was made. The reviewed root source includes E's hosts-initialization repair;
that change does not alter the wait/descriptor interfaces inspected here.

There is **no safe drop-in persistent cache for the current `PollFd` arrays**:
they expose only numeric fd, wanted mask and returned mask. A descriptor can
close and a different owner can reuse its number between waits without a
changed array shape. Object addresses, vector indices, path names, peer
addresses and netlink request sequences do not repair that missing identity.

There is a bounded hybrid hypothesis: retain the explicit arrays, existing
deadlines and dispatch order; aggregate only entries whose owner has an
existing lifetime token or a proved fixed descriptor lifetime; leave all
unidentified/reopening/file entries on direct ppoll. It needs explicit owner
keys and reconciliation, but need not initially add registration hooks to
every subsystem. Whether that subset is large enough to matter is presently
unknown, because the recorded six baseline entries are not fully identified.

## Actual owners and available identities

"Fixed" below means the inspected production construction/Drop boundary,
not the object's address. A key is scoped to the owning `SinglePoll` lifetime.
Any future replacement must advance an explicit epoch or leave the group.

| Owner / source | Identity already available | What must be preserved or added |
| --- | --- | --- |
| DNS UDP/TCP listeners, `main.rs` `PollListener` | `SocketToken` allocated from `next_listener` for each added listener | Use token **plus transport role**; one token can identify both UDP and TCP. Removal may leave a deferred `Arc<DnsSocket>` alive. The existing increment is not a general reusable registration allocator. |
| Signal pipe, `main.rs:1526` | Owned read fd installed once for the owner lifetime | A reserved owner-role key is sufficient only while this single-install invariant holds. Probe wait excludes it; pending signal counters remain independently runnable. |
| RouteWatch, `dns/filewatch.rs:61` | One File-owned netlink fd, fixed until RouteWatch Drop; `raw_fd()` exists | Startup assigns it once. Retry state suppresses interest without replacing the socket. Normal wait only; no netlink sequence is a lifetime token. |
| DNS InterfaceCollector, `dns/interface_collect.rs:65` | One OwnedFd netlink socket fixed for the collector lifetime | The optional control fd changes per enumeration but is **not** appended to the wait set. The polled socket switches IN/OUT and is omitted when idle. Collector request `sequence` is not fd identity. Initial/lazy construction must share one owner-scoped lifetime key. |
| NeighborCache, `neighbors.rs:85` | One OwnedFd netlink socket, installed once when enabled | Interest exists only during a dump. Request sequence changes do not change fd identity. Both normal/probe use it with different timer/activity context. |
| DNS inotify FileWatch, `dns/files_runtime.rs:210`, `dns/filewatch.rs:267` | Fixed watch fd within a DnsFiles instance; `watch_fd()` exists | Watch descriptor numbers name inotify watches, not open-fd generations. DnsFiles instance replacement requires an epoch; its read job/lookup fds below cannot inherit this key. Probe excludes the watch. |
| DHCP/PXE sockets, `dhcp/service.rs:244` | Fixed main socket and optional PXE socket within SocketListener | Listener enum names a role, not a unique lifetime. An owner-scoped instance/role key could cover fixed construction; pending replies add OUT. Admission and interface-file gates can suppress the entire interest. Probe excludes DHCP input. |
| DHCP IPv4 snapshot and directory watch | Each owns a fixed netlink/inotify fd within its instance | `Ipv4Snapshot.sequence` and `DhcpFiles.Generation` describe work/data, not replacement of an open fd. Fixed owner scope or explicit instance epoch needed; keep existing conditional masks/file gates. |
| UDP upstream, `dns/upstream.rs:299,1141` | Checked-increment `SocketToken` per owned socket | A genuine lifetime token exists, but `append_poll_fds` currently drops it. A narrow identity-bearing append interface would be needed, scoped to resolver lifetime. Empty-error suppression and POLLOUT probe references remain unchanged. |
| Downstream TCP, `main.rs` `PollTcpClient` | No socket-lifetime token; only a per-wait slot and ready bits | Add an accept generation before persistence. `swap_remove`, stale-answer close then upstream open, and same-wake new accepts invalidate pointer/index/fd-only keys. The prior downstream-only group was screened out. |
| TCP upstream, `dns/tcp_upstream.rs` / `tcp_exchange.rs` | `TcpWait` carries raw fd/events/deadline; no connection generation | A server's connection can fail/reopen inside a client transport. Downstream accept generation alone is insufficient. Leave direct unless the connection owner exposes a real lifetime token. |
| UBus, `ParentEvents::disconnect/process_ubus` | No connection epoch; object IDs are bus registration IDs | Disconnect drops the service; reconnect can reuse the numeric fd. Add epoch at these explicit transitions or leave direct. Queued methods may be runnable even with an empty socket. |
| Logger, early logger and TCP log contexts | Rc ownership of File/OwnedFd destinations; no exposed destination generation | Reopen/reconnect/FIFO retries replace destinations; TCP contexts retain earlier shared destinations. Repeated raw fd interests can have multiple logical owners. Rc/object addresses are not permanent tokens. Leave direct without a destination-lifetime key. Debug stderr is borrowed process-lifetime raw fd. |
| DumpHandle, `dump.rs:235` | Shared writer owns a File; no exposed lifetime token | A writer instance has a fixed file, but the handle and descriptor type must be established. Queued file/FIFO interests need direct fallback; no automatic classification as a socket. |
| DNS/DHCP read jobs, HostsRead, EthersRead | Owned File plus data/path/source identifiers, no unique open generation | Jobs replace one another and can reuse fd/path. Regular hosts/DNS read jobs already use runnable work instead of polling when metadata says regular file; FIFO/device jobs still poll. Leave direct without a job-lifetime token. |
| EndpointLookup, `config/dns_lookup.rs:27` | Unreaped child PID plus an owned reader pipe | PID is useful for child ownership but is not an exposed poll registration epoch. Each lookup can replace the preceding one; pipe EOF/cancel/draining must remain ordered. Leave direct initially. |
| Helper, `helper/process.rs:79` | One helper PID and reader/writer File owners | Helper instance is long-lived; pipe roles close independently on EOF/drain. No reopen is observed in that instance. An explicit instance/role key is possible, with normal-only inclusion and exact shutdown behavior. |
| TFTP transfer sockets, `tftp_listener.rs:46` | Internal `TransferId` keys map to transfer sockets | The append API discards IDs; IDs wrap and skip zero, so they are not an unlimited generation guarantee. Server/listener sockets use a vector and endpoint values without lifetime IDs. Both would need explicit identities or remain direct. |
| Probe ICMP socket | Borrowed for one `wait_during_probe` call | Keep direct. It is not a normal-owner registration and must not outlive the borrowed probe. |

## What can actually be counted today

The C TCP-hit trace establishes 14 poll-array **entries** in 4910 of 5052
invocations. The client trace and source identify eight active downstream
connections. Six baseline entries remain. The UDP-miss trace also has an
idle six-entry owner set; its known active IPv4 UDP listener is fd 6, and the
TCP-hit trace identifies the IPv4 TCP listener as fd 7.

Those two listener roles have existing lifetime tokens. The remaining four
baseline entries are **not individually identified by the retained evidence**:
the driver used abbreviated `ppoll([...], nfds, ...)`, attached after startup,
and recorded process maps/stat rather than an fd/link/interest inventory.
IPv6 listeners plus signal/route sockets are a plausible source/configuration
explanation, not verified members. Thus neither "all six are stable" nor a
particular 14-to-2 reduction is an established performance projection.

Current evidence supports these counts only:

- TCP-hit: 8 known downstream connection entries need a new accept generation;
  2 known listener roles have tokens; 4 baseline entries remain unidentified.
- UDP baseline: 2 listener roles are known across the captures; 4 baseline
  entries remain unidentified. UDP upstream sockets are separately tokenized
  when present and can increase the set during misses.

Before any future wider screen, the missing item is a small exact-artifact
interest inventory: per entry owner class, wanted mask, live fd and existing
lifetime identifier, for normal and probe waits. This audit does not collect
it or authorize new instrumentation. Use E's measured residual/variation first
to decide whether that bounded evidence step is worthwhile.

## Normal/probe subset and fallback

Normal waits include file owners, signal, route, listeners, UDP upstream,
TCP work, UBus, DHCP, helper, TFTP and collectors as their current gates allow.
Probe waits instead include its ICMP descriptor, pending dump/log writers,
listeners, upstream/TCP, TFTP, neighbors and the interface collector. They
intentionally exclude outer file watches/jobs, signals/reload/route, UBus,
DHCP input and helper command service while the provider is borrowed.

A persistent group must reconcile to the **current call's** eligible subset
before blocking, or use separate explicitly scoped groups. Leaving a normal-
only ready descriptor registered in a probe group can wake the probe forever
or consume work in the wrong order. Masking that event only after waking is
insufficient. Zero-interest registration is not a reliable suppression of
terminal error/hangup wakes. Subset changes have a real control-syscall cost.

Keep every unclassified, reopenable or unsupported-file entry in direct ppoll.
Do not globally replace `owrt_ubus::sys::poll_fds`: it is used by internal
transport waits and unrelated components. A grouped path must restore each
original entry's requested bits plus ERR/HUP semantics and original ready-
entry count; duplicate logical entries are not one event for diagnostics.
Regular files are not assumed epoll-compatible. Runtime optional-group failure
must safely retain the original direct wait path without consuming SO_ERROR
or changing packet/helper processing order.

Raw-fd reuse cannot be detected by comparing successive numeric arrays.
The usable choices are genuine lifetime keys, explicit owner epoch updates,
or direct-poll exclusion. Per-wait fstat, repeated MOD/ADD checks or duplicated
fds add syscall/resource/lifetime costs and are not an evidence-free shortcut.

## How far the low-complexity boundary goes

A selective hybrid containing proven fixed-lifetime sources and tokenized
DNS listeners/upstream is concrete. Its interfaces would remain a private
owner key beside each eligible explicit entry, a merged mask per registration,
and expansion back to the same caller-visible slots. Some narrow identity
getters/append variants and accept-generation state would still be necessary.
This is a possible next experiment, not a proven safe adapter or approved
implementation.

Including **all** current sources crosses distinct ownership boundaries:
logger shared destinations/reopen, UBus reconnect, TCP upstream connection
replacement, file/endpoint jobs and TFTP listener/transfer ownership. These
need explicit close/replacement identities and failure tests in their actual
owners. That would be a multi-component lifecycle change, not a small
`poll_fds` substitution. Do not expand into that framework automatically.

The existing `components/ubus/src/readiness.rs` provides useful ABI knowledge,
but is not a ready adapter: add always requests IN, it has a fixed 32-event
batch, an allocating Vec output, no epoll-fd accessor and no NVAL adapter.
Copying it wholesale would not solve owner identities or probe subsets.

Additional fd/kernel-watch memory is a measurable resource cost. The existing
TCP EMFILE gate computes pressure from each process's own initial fd count;
it does not require identical numeric limits across implementations. It does
require queued recovery, listener preservation and return to the initial fd
set after clients close. A lazy persistent group therefore cannot simply leak
one new fd after the last client. This is a concrete gate, not a demand for
new cross-system headroom machinery.

Conclusion: wider aggregation is an **unproven but bounded follow-up** when
restricted to identified owners. There is not yet an accurate member-count
or total-cost basis for selecting it. The broader all-source adapter would
cross the concrete lifecycle boundaries above. Neither uncertainty nor that
engineering scope proves kernel readiness work irreducible; E's complete
device evidence and a verified interest inventory should decide the next step.
