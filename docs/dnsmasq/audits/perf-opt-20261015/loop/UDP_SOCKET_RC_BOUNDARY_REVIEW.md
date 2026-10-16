# Private UDP socket handles can use Rc

Read-only review of source `99b519dca413754d19afd9baad825924b06bbf13` finds no
thread, signal-handler or private-test boundary requiring atomic reference
counts for the binary's `DnsSocket` handles. Replacing only those handles
with `Rc<DnsSocket>` is a reasonable small prototype. This is source-boundary
review, not a compiled patch, performance result or complete qualification.
No product edit, build, test or remote action was performed here.

All nine production `Arc<DnsSocket>` type sites are private in `main.rs`:
`DnsListenerPair` (2086), `open_late_dns_listener` (2125), `PollListener` (2376),
`PendingInterfaceUdp` (2623), `PendingUdpAdmission` (2631), `SinglePoll::new`
(3130), `add_listener` (4499), `process_admitted_udp` (5025) and `process_udp`
(5179). `open_dns_listener:2101` and the late factory create the handles.
Startup's local listener vectors move them into the one owner. The two
production socket clone sites are `step_udp:5001` and `step_edns_udp:5160`.

`SinglePoll` already contains `Rc<RefCell<ParentDns>>`, parent events and
interface snapshots. This alone would not prove that an individual Arc never
escapes, so its uses were traced separately: no socket handle is sent to a
thread, callback worker, channel, static, FFI ownership slot or library API.
There is no socket `Weak`, raw-Arc conversion, pointer-identity check,
reference-count assertion or unsafe Send/Sync implementation to preserve.
The public `listeners::DnsSocket` type and its APIs need no change.

Interface-admission and interface-answer continuations retain an owned handle
and resume on the same owner. The MAC/EDNS queue actually stores a listener
`SocketToken`, not an Arc: it looks up the live listener and clones only when
resuming. Keep that distinction, including behavior after listener removal.
`Rc` keeps the existing owned continuation and final-owner socket-close rules;
there is no need to replace owning fields with borrowed lifetimes.

All signal handlers (`main.rs:108–195`) touch atomic flags/counters, write the
nonblocking wake pipe, preserve errno, or call `_exit`. None accesses or drops
the owner or socket handles. Interrupted owner work resumes on the same thread.
Do not replace those signal atomics.

One process boundary does exist: `startup.begin` at1327 runs after listener
creation and double-forks in `startup/daemonize.rs:45,64`. It is explicitly
single-threaded without retained RefCell borrows. Heap reference counts are
separate in the resulting processes for both Arc and Rc; the parent closes
its own descriptor copy, while the intermediate child uses `_exit`. This is
not a thread-sharing requirement and does not require changing startup.

The sole `thread::spawn` in `main*.rs`, `main.rs:8572`, is a cfg(test) TCP
upstream fixture. It captures a `TcpListener` and mpsc endpoints, then creates
its own accepted `TcpStream`; the test's owner is created afterward on the
test thread. No DnsSocket or SinglePoll enters that closure. Other thread
calls in these files are sleep/current/park_timeout, not worker creation.

Private socket test fixtures needing the matching type/constructor update:
`main.rs`, `main_route_resend_tests.rs`, `main_udp_acl_tests.rs`,
`main_hostsdir_init_tests.rs` (including `queued_dns`'s pub(super) return type),
`main_newaddress_tests.rs` and `main_stale_refresh_log_tests.rs`. They create
and consume handles within one test thread. Library listener tests use plain
DnsSocket values and do not require this ownership change.

Keep all lease/interface/domain/config/cache Arc uses intact, including the
Arc weak/count/ptr_eq assertions for TCP snapshot lifetimes. A global textual
Arc replacement would exceed this review. The proposed benefit is removing
atomic operations from the remaining socket clone/drop paths; exact emitted
code and real CPU savings still need separate evidence.
