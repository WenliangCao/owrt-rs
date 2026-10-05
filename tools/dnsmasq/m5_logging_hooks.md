# First logging integration: destinations and startup

The frozen required boundary is `m5_logging_requirements.json`. No option is
qualified by this module submission: paired runtime evidence must cover every
required row before the ledger changes. `log-queries`, DHCP/TFTP producers,
`log-async`, `log-debug`, `log-malloc` and capture remain separate
next integrations. The image was compiled with `no-ID`, so `no-ident` accepts
the Boolean and does not create built-in CHAOS records in either state.

## CLI hook in main.rs (root-owned)

`startup::cli::help_output(false)` contains all193 general-help rows from exact
`option.c` usage/opts/defaults. `help_output(true)` contains all64 DHCP rows from
`dhcp-common.c` opttab, excluding OT_INTERNAL. Both source-derived tables have
been checked byte-for-byte against the actual image's CLI output. Use `print!`
with these complete strings for Action::Help and Action::HelpDhcp. The loader
already preserves C's exact argc3/argv2=dhcp dispatch and terminal-action order.

For Action::Version, print `startup::cli::version_output()`. Its only deliberate
identity difference is the first-line suffix `; dnsmasq-rs 0.1.0 (Rust
implementation)`. The copyright, compile-options/init contract and every GPL
and warranty line remain exact. The image init's lines31 and946 consume the
Compile time options line; they do not require C's first line to impersonate
the Rust binary. The driver separately discloses this fixed identity suffix and
rejects altered or omitted license text. `COMPILE_TIME_OPTIONS` also avoids
duplicating the same image feature string in the startup log producer.

## Configuration and startup hooks in main.rs (root-owned)

Add `logging: dnsmasq_rs::config::logging::LoggingConfig` to `Runtime`, initialize
it with `Default::default()`, and insert `runtime.logging.apply(directive)?` into
the loader's consumer chain. `ProcessConfig` now stores `keep_in_foreground` and
does not consume `log-facility` without applying it.

After `identity.write_pid`, before `identity.drop_privileges`, construct the
owner. The C entry point sets umask022; root must preserve that earlier process
startup policy rather than inherit a caller's restrictive mask.

```rust
let (mut logger, ownership_warning) = dnsmasq_rs::logging::Logger::start(
    &runtime.logging, &runtime.process, identity.log_owner_uid(),
)?;
dnsmasq_rs::startup::redirect_standard_streams(&runtime.process);
```

`Logger::start` opens append/create0640 files, duplicates the inherited stderr
for `-`, or creates a nonblocking AF_UNIX datagram socket. It changes only the
selected log file's owner (and adds group write for an existing root-group
file, as C does). `ownership_warning` is nonfatal and must become C's startup
warning after the normal started/compile-options messages.

The compatible wire tag is `dnsmasq`, with `-dhcp`, `-tftp`, `-script` and
`-debug` service suffixes. Rust implementation identity belongs in version
output, not an accidental change to the logging wire contract.

```rust
use dnsmasq_rs::logging::{LogEvent, Priority, Service};
logger.emit(LogEvent::new(Service::Dns, Priority::Info, message.into_bytes()));
```

Startup events must follow `dnsmasq.c:859-1080`: started version/cache mode,
compile options, then runtime warnings and subsystem startup events. Do not
invent substitute text for currently unimplemented producers. `no-daemon`
cannot close until its default daemonize/parent-error-pipe boundary is also
implemented. Its debug echo and `-k` timestamp distinction can be compared in
this first destination integration.

## SinglePoll hooks (root-owned)

Store the one explicit Logger in `SinglePoll` (or its existing `ParentEvents`
gate). Each producer supplies finite events to that owner; use an explicit
queue/callback, never TLS, a new singleton, or a logging thread.

Before the existing poll, append each `logger.poll_fds()` descriptor with
`POLLOUT`. Call `logger.flush_ready()` once per owner step; it is nonblocking and
bounded to128 write/retry attempts, including EINTR and reconnect. Failed
syslog connections stop registering a permanently-ready descriptor and retry
on the next event. Debug echo has its own bounded queue/FD readiness. File and
stderr destinations use one queued record. `set_queue_limit`/`set_debug_enabled`
are owner primitives only: do not accept their options until their separate
frozen cases pass.

Record SIGUSR2 in the existing signal/event gate and call `logger.reopen()` from
the owner. It affects configured file destinations, preserves the inherited
stderr duplicate, and does not chown files again. A failed reopen falls back to
syslog for subsequent events; reopening again can restore the file.

Emit C's `exiting on receipt of SIGTERM` on the normal termination event. Then
call `logger.finish()`: false retains pending records so the same owner can
poll and retry; true means the queue drained or the syslog connection failed,
matching C's termination condition. Apply an explicit shutdown deadline in the
owner without sleep or blocking write_all.

## Intentional scheduler differences still needing evidence

C uses blocking writes when async0, optional nanosleep queue pacing and a
sleeping flush. This product may never block the poll owner. All logging FDs
therefore use nonblocking writes, retries are bounded, and debug echo retains
at most100 messages of bounded length. FIFO log opening and blocked stderr
must remain explicit policy differences when reproducing the C boundary;
their cases cannot silently disappear from the qualification manifest.
