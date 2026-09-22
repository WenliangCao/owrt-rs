# R131 registration path: read-only audit

This audit identifies executed differences; it does not attribute the router
p95 regression to any one of them. No candidate, benchmark, profile or router
operation was run. The pinned C checkout is
`24864e7840b3a02a9ef76284a373f6b2f00b8a9b`, clean when read. Rust references are
R124 `a5b0ff1` and R131 `4e45d2e`; the exact release identities and retained
disassembly hashes are in [the derived result](r131-registration-path-audit.json).

## Timed path and unchanged work

The shared-path workload runs registration before starting any provider or
event client. `register-cycle` creates a single connection and measures only
ADD_OBJECT followed by REMOVE_OBJECT. Its exact lookup/signature preflight
and final empty lookup are outside timing. There are no event patterns or
monitor clients in these timed cycles.

Both C and Rust perform the following sequence:

1. ADD creates the type/object, validates and installs the named path, emits
   the add event, assigns the client owner, then replies DATA and STATUS.
2. REMOVE replies DATA, removes subscriptions and the object's event patterns,
   emits the removal event while the path still exists, frees registry state,
   then replies STATUS.

R124/R131 source bodies for `add_object`, `remove_object`, `free_object`,
`send_obj_event`, `send_object_reply` and `send_status` are identical. The
changed `dispatch_event` is inlined into `send_obj_event`. With no patterns,
neither Rust version evaluates the message-building closure; neither uses
the batch send helper or grows `event_batch`. The four ordinary reply sends,
ID generation and method/path lifetime remain the relevant common work.
These are source observations, not a newly measured syscall/allocation count.

C also defers event construction. `ubusd_send_obj_event` passes the existing
object pointer to `ubusd_send_event`; a NULL sender passes its ACL check,
the event epoch advances, then the pattern tree is traversed. Only an
eligible receiver triggers `fill_cb`, which reads the object's path and
constructs the event. An empty pattern tree does not construct an event.
C still allocates a shared message wrapper for DATA replies; sharing its
blob buffer does not make `ubus_msg_new(..., true)` allocation-free.

Rust performs an additional registry lookup and `Rc<[u8]>` path clone before
entering `dispatch_event`. This is a reference-count increment/decrement,
not a path heap allocation. It was already present in R124.

## Exact ELF observations

The ordinary empty-pattern path assumes a valid named object, no epoch wrap,
and a path Rc whose count does not reach zero on drop. Counting only executed
instructions inside `send_obj_event`, excluding its common registry-lookup
callee, gives:

| Item | R124 | R131 |
| --- | ---: | ---: |
| Function start | `0x412718` | `0x412bec` |
| Function size | 1196 B | 2864 B |
| Stack frame | 176 B | 208 B |
| Executed instructions on this path | 48 | 51 |
| Calls on this path | One registry lookup | One registry lookup |

R131 additionally loads/spills the monitor length and zeroes the batch length
at entry and exit. It avoids one R124 path-length spill: the net change is
three instructions per object-event call, six per ADD/REMOVE cycle. There is
no added allocation or syscall on this path. The larger function and changed
layout are real, but neither byte count nor instruction count establishes
their cycle cost, cache behavior or contribution to endpoint p95.

Other exact-map sizes: `free_object` is 1572 B in both, `send_object_reply`
256 B in both, and `Client::send_borrowed` 500 B in both. `handle` is
11016/11020 B. Equal sizes do not imply identical instruction bytes; Server
field offsets and call displacements change.

## A bounded future hypothesis, not an implementation

An empty-pattern path could avoid the existing registry lookup and Rc clone,
as well as the new batching setup. It must preserve the event epoch rather
than simply return early. The least ambiguous insertion sites are the two
callers already known to hold a valid named object:

- ADD: `reg.create` succeeded and `set_path(id, path)` returned true; the
  event occurs before assigning the owner, exactly as today.
- Removal: `free_object` initially found the object and its immediate
  `reg.get(id).and_then(|o| o.path.as_ref()).is_some()` guard is true;
  event-pattern cleanup has already run, and registry destruction is later.
  Dispatch is synchronous, so no incoming command mutates this state between
  the check and call.

An explicit helper or caller-local empty-pattern branch should advance
`obj_event_seq` once, clear all `event_seen` stamps and use epoch 1 on wrap,
leave outgoing `event_seq` unchanged, and preserve scratch contents. It must
not advance the epoch for nonexistent/pathless private `send_obj_event`
calls which currently return before dispatch. Existing coverage includes
`events_without_eligible_receivers_do_not_encode_but_advance_round`,
`event_send_preserves_group_root_and_missing_client_acl`, and
`event_round_wrap_unseen_listener`, `event_round_wrap_old_epoch_listener`,
`event_round_wrap_recent_listener`. A future change needs focused caller
coverage in addition to those tests; none is being weakened here.

With zero patterns there is no outgoing event frame to mirror. The ordinary
ADD/REMOVE input and DATA/STATUS mirrors still run at their current outer
send boundaries, including when a monitor exists. Do not broaden this into
another full pattern pre-scan: nonempty-but-unmatched patterns retain the
current dispatch path.

## What existing profiles establish

R121/R125 and R131 `profile-01` are user-event profiles, not timed registration
profiles. In particular the R131 perf ACK begins after event handler
registration/warmup and ends before teardown. They cannot quantify
`send_obj_event`'s contribution to the observed registration regression.
The R130 syscall check covers R124/R130, and the recent R131 syscall check
covers user events; neither is a R124/R131 registration causal comparison.

If profiling proceeds, useful exact-symbol targets are `send_obj_event`,
the registration arms in `handle`, `free_object`, allocator functions,
`getrandom`, and the unchanged reply/receive syscalls. Method Vec/Box
allocations, path Vec-to-Rc conversion, registry growth/tombstones, syscall
blocking and scheduling are hypotheses to measure, not demonstrated new
R131 costs. The event-batch memory growth does not explain a fresh daemon's
empty-listener registration workload: that buffer has never grown there.
