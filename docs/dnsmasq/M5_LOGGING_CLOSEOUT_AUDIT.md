# M5 logging closeout audit

The finite logging closeout has no observed product-code residual. Candidate
`0dba599a`, ELF `ecbf16f5bab4404cada8b3f627386ac95195cbcaa19eab0675a4fe376215992b`
(1,929,256 bytes), passed **62 actual paired configurations**: 55 ordinary
DHCP callers and seven targeted warning/option-exhaustion inputs. All wire,
health, cleanup and notice comparisons passed; 57 comparison controls remain
active. The complete archive has 750 paths/553 files, SHA256
`22e34aa4c3238d95c98b9ab8f52cb5cfd2ecd7feae08db0eba5d710f7361fc8a`;
every file and metadata record was verified before remote pruning.

[Phase 2 review and receipts](../../private/dnsmasq-rewrite/evidence/M5/logging/logging-final-caller-qualified-0db-20261006/phase2-review.json)
retain identities, coverage, controls, failed calibrations and limitations.
Earlier finite PID/path qualification used `2e446f7e`: all 19 PID/FAC inputs
passed after one fixture-only cmdline decoder replay. Two UDP/TCP query
extremes passed: control/high-byte/maximal legal names and large counted TXT,
including actual cache/client clipping. Final uniform-ELF family replay remains
required; these independent receipts do not replace it.

| Boundary | Disposition and precise limit |
| --- | --- |
| Large PXE menus, enterprise limits, duplicate options and packet exhaustion | Actual C/R callers now emit the same service, priority and order. Source decisions supply menu failure, actual duplicate codes, enterprise number and actual serializer omissions. Both normal/proxy menus, normal/proxy/leasequery enterprise warnings and twenty forced options passed on the final candidate. |
| Opaque/overlong PID and log paths; full debug echo | Actual paired default/foreground/debug/error-frame controls passed. PID uses raw EVENT_PIDFILE13 pathname/errno, including the C incomplete-payload fallback. A faulty UTF8-only `/proc` display decoder was fixed; raw packet/log evidence remains intact. |
| Signed display/counter/reservation wrap | Ten SDK source controls at Os/O2 match unsigned C rendering, including INT_MIN→TCP2147483648. Explicit Rust wrapping and formatter assertions were added. More than two billion daemon queries were not issued: this is controlled source/typed-arithmetic evidence, not actual daemon counter exhaustion. Reference: `cache.c:2496–2509`, `forward.c:1827–1828,2488–2497`. |
| Synthetic short/unknown startup frames and child-crash EOF | Retain the exact private protocol semantics. `dnsmasq.c:613–625,1460–1485,1490–1558` makes short/clean EOF and unknown events reach original-parent exit0; EOF alone cannot distinguish successful handoff from a crash before an error frame. Rust's explicit short-header/EOF/unknown-kind branches retain that behavior, and existing full/short typed-frame assertions check reader boundaries. These cases were source-reviewed, not injected into a live daemon. Process/service health is a separate lifecycle authority. |
| C signal self-pipe allocation | Intentional owner architecture difference: `dnsmasq.c:583–589,1341–1434` and `util.c:352–358` allocate a signal pipe and fail class5 if its allocation/flags fail. Rust records delivered service signals in atomics and allocates no equivalent pipe; adding a redundant pipe solely to reproduce that absent failure is unwarranted. The separate real startup error pipe and its failures remain qualified. C-only self-pipe ENOMEM/EMFILE was not claimed as paired runtime coverage. |
| CHAOS NOTIMP EDE | Retain the disclosed C defect classification: `rfc1035.c:1838–1854` leaves `addr.log.ede` uninitialized, consumed at `cache.c:2373–2399`. Only the observed unknown suffix on the exact CHAOS TXT `version.bind` producer is classified. Nine controls still reject other EDE, question, RCODE, client, ID, name and order changes. |

The safety scope is recorded in [M5_LOGGING_SAFETY_AUDIT.md](M5_LOGGING_SAFETY_AUDIT.md).
Firmware/device data remains outside Git. No physical router operation occurred.
