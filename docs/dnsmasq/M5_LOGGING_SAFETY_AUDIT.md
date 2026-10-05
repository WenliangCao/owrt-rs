# M5 logging safety audit

The audited production files are `src/logging.rs`, `src/logging/startup.rs`,
`src/logging/query.rs`, `src/config/logging.rs`, and `src/dhcp/logging.rs` under
`components/dnsmasq/`. Source commits are `844553cd` and `f07648f2`; the main
integration must preserve the actual commit/ELF identity of its Linux checks.
This audit does not claim a final uniform-candidate runtime qualification.

| Boundary | Verified invariant and result |
| --- | --- |
| Address formatting | `inet_ntop` receives live 4/16-byte octets and a writable 46-byte output. Interface-name lookup has Linux IF_NAMESIZE capacity, checks NULL, and adds a scope only within the address buffer limit. |
| File ownership | The borrowed File keeps its descriptor live through `fchown`; gid -1 retains the existing group. `getgid` has no pointer preconditions. Ordinary syscall failure remains an ownership warning. |
| Timestamp formatting | Linux64 time_t has the declared i64 layout. The timestamp calls receive separate live values and the required 26-byte output. |
| Primary/echo writes | Borrowed record slices stay live throughout each synchronous `write`. Offsets advance only after a positive result. Short writes, EINTR, EAGAIN, EPIPE and fallback already have real sink qualification; no syscall retains a slice pointer. |
| Descriptor ownership | Successful `dup`/`socket` descriptors become exactly one OwnedFd. F_GETFL has no third argument; F_SETFL gets an integer argument. Checked errors do not transfer an invalid descriptor. Owner-local snapshots now share File/OwnedFd with Rc. |
| Syslog connect | The zero-filled Linux sockaddr_un has the proper layout, bounded terminated path and supplied size; connect retains no pointer. |
| Error rendering | `strerror` text is copied immediately. A NULL result has an explicit fallback before CStr construction. |
| Startup server records | The optional live ServerId is destructured before use. The two runtime unwraps were removed. |
| Query formatter/configuration | No production unsafe blocks, unwraps or expects. Display IDs wrap explicitly; mode parsing and TXT counted-string bounds stay in their existing qualified code. |
| DHCP serialized details | A minimum 240-byte guard precedes fixed header/field reads. Fixed-size array conversions now use explicit bytes. Option length and region boundaries are checked before slicing; truncated option regions stop their finite traversal. |
| Test-only FFI/assertions | The FIFO fixture documents the CString/mkfifo lifetime and checks the syscall before use. Test assertions/unwraps remain assertions, not production error policy. |

Host query-formatter tests and 180 DHCP tests passed. The logger is a Linux
module, so its Rc/type changes and libc calls require the root task's Linux
cross-check and final sink/ownership/reopen/active-TCP qualification. Existing
record ordering, queue limits, reconnect policy and fork PID guards were retained.
