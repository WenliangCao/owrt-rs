//! ubusd-rs: the OpenWrt system message bus.
//!
//! Behaviour is specified by docs/contracts/ubusd.md, which is derived from
//! the pinned ubus 24864e78 source. Single-threaded readiness loop (epoll on
//! Linux, as uloop gives the C daemon), with no async runtime.
//!
//! Unsafe is denied except for installing the audited signal handlers;
//! libc ABI operations live in owrt-platform.

#![deny(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

mod acl;
mod client;
mod obj;
mod server;
mod sys;

use server::Server;
use owrt_ubus::sys as bus_sys;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// Identifies this binary in a running process, which matters when it is
/// installed at the same path as the daemon it replaces.
pub const BUILD_ID: &str = "ubusd-rs (owrt-control-plane-rs)";

const DEFAULT_SOCKET: &str = "/var/run/ubus/ubus.sock";
const DEFAULT_ACL_DIR: &str = "/usr/share/acl.d";

static RELOAD: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_sighup(_: i32) {
    RELOAD.store(true, Ordering::SeqCst);
    wake();
}

extern "C" fn on_term(_: i32) {
    STOP.store(true, Ordering::SeqCst);
    wake();
}

/// Async-signal-safe wake-up: one byte down the self-pipe.
fn wake() {
    let fd = WAKE_FD.load(Ordering::SeqCst);
    if fd >= 0 { owrt_platform::ubusd::wake(fd); }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn saturated_signal_pipe_preserves_errno() {
    let (_read, write) = bus_sys::nonblocking_pipe().unwrap();
    let fd = write.as_raw_fd();
    while owrt_platform::unix::write_fd(fd, &[0u8; 4096]) > 0 {}
    assert_eq!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock);
    let previous = WAKE_FD.swap(fd, Ordering::SeqCst);
    let (_, after) = owrt_platform::ubusd::with_errno(22, wake);
    WAKE_FD.store(previous, Ordering::SeqCst);
    assert_eq!(after, 22);
}

fn usage(program: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "{BUILD_ID}");
    let _ = writeln!(std::io::stderr(),
        "Usage: {program} [<options>]\n\
         Options: \n\
         \x20 -A <path>:\t\tSet the path to ACL files\n\
         \x20 -s <socket>:\t\tSet the unix domain socket to listen on\n"
    );
    std::process::exit(1);
}

fn main() {
    let mut socket = DEFAULT_SOCKET.to_owned();
    let mut acl_dir = DEFAULT_ACL_DIR.to_owned();
    let args: Vec<String> = std::env::args().collect();
    let program = args.first().cloned().unwrap_or_else(|| "ubusd-rs".to_owned());
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-s" if i + 1 < args.len() => {
                socket = args[i + 1].clone();
                i += 2;
            }
            "-A" if i + 1 < args.len() => {
                acl_dir = args[i + 1].clone();
                i += 2;
            }
            _ => usage(&program),
        }
    }

    // keep BUILD_ID in the binary even when usage() is never reached
    if std::env::var_os("UBUSD_RS_VERSION").is_some() {
        let _ = writeln!(std::io::stdout(), "{BUILD_ID}");
        return;
    }
    if let Err(e) = run(&socket, &acl_dir) {
        eprintln!("ubusd-rs: {e}");
        std::process::exit(1);
    }
}

fn run(socket: &str, acl_dir: &str) -> std::io::Result<()> {
    // A dead peer must not kill the daemon; every write reports EPIPE instead.
    bus_sys::ignore_signal(bus_sys::SIGPIPE);

    let (wake_r, wake_w) = bus_sys::nonblocking_pipe()?;
    WAKE_FD.store(wake_w.as_raw_fd(), Ordering::SeqCst);
    // SAFETY: both fixed handlers only store atomics and write to the live,
    // nonblocking wake pipe while preserving errno; neither allocates or locks.
    #[expect(unsafe_code, reason = "install the audited atomic/self-pipe signal handlers")]
    unsafe {
        let _ = bus_sys::set_signal_handler(sys::SIGHUP, on_sighup);
        let _ = bus_sys::set_signal_handler(bus_sys::SIGTERM, on_term);
        let _ = bus_sys::set_signal_handler(bus_sys::SIGINT, on_term);
    }

    let listener = sys::listen_unix(socket)?;
    let mut server = Server::new(acl_dir.to_owned())?;
    server.load_acl();

    let result = event_loop(&mut server, &listener, &wake_r);
    sys::remove_file(socket);
    result
}

/// Tokens for the two descriptors that are not clients; client tokens are
/// their ids, which the registry keeps below `u32::MAX`.
const TOKEN_LISTENER: u64 = u64::MAX;
const TOKEN_WAKE: u64 = u64::MAX - 1;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const ACCEPT_TRANSIENT_BUDGET: usize = 16;

fn event_loop(server: &mut Server, listener: &OwnedFd, wake_r: &OwnedFd) -> std::io::Result<()> {
    let mut poller = owrt_ubus::readiness::Poller::new()?;
    poller.add(listener.as_raw_fd(), TOKEN_LISTENER, false)?;
    poller.add(wake_r.as_raw_fd(), TOKEN_WAKE, false)?;
    let mut ready: Vec<owrt_ubus::readiness::Ready> = Vec::new();
    // Initialized once, outside both the readiness and per-message loops.
    let mut rx = [0u8; client::RX_SIZE];
    // A resource failure removes the level-triggered listener temporarily.
    // Resources may recover without a client disconnect (SCM_RIGHTS fds,
    // system-wide ENFILE, socket memory), so always arm a timed retry.
    let mut listener_retry_at: Option<Instant> = None;

    while !STOP.load(Ordering::SeqCst) {
        let timeout_ms = if let Some(at) = listener_retry_at {
            let now = Instant::now();
            if now >= at {
                match poller.add(listener.as_raw_fd(), TOKEN_LISTENER, false) {
                    Ok(()) => listener_retry_at = None,
                    Err(e) => {
                        eprintln!("ubusd-rs: listener retry failed: {e}");
                        listener_retry_at = Some(now + ACCEPT_RETRY_DELAY);
                    }
                }
            }
            listener_retry_at.map_or(-1, |next| {
                next.saturating_duration_since(now).as_millis().max(1) as i32
            })
        } else {
            -1
        };
        poller.wait(timeout_ms, &mut ready)?;

        // Signals first, as before: a reload or stop decided in this round
        // takes effect before any client is served.
        if ready.iter().any(|r| r.token == TOKEN_WAKE) {
            let mut buf = [0u8; 64];
            while owrt_platform::unix::read_fd(wake_r.as_raw_fd(), &mut buf).unwrap_or(0) > 0 {}
        }
        if RELOAD.swap(false, Ordering::SeqCst) {
            server.load_acl();
        }
        if STOP.load(Ordering::SeqCst) {
            break;
        }

        for r in &ready {
            match r.token {
                TOKEN_WAKE => {}
                TOKEN_LISTENER => {
                    if r.revents & bus_sys::POLLIN != 0 && !accept_all(server, listener, &mut poller) {
                        poller.remove(listener.as_raw_fd())?;
                        listener_retry_at = Some(Instant::now() + ACCEPT_RETRY_DELAY);
                    }
                }
                token => {
                    let id = token as u32;
                    // A client removed earlier in this round can still have
                    // an entry here; its id is gone from the table.
                    if !server.clients.contains_key(&id) {
                        continue;
                    }
                    if service_client(server, id, r.revents, &mut rx) {
                        sync_write_interest(server, &mut poller, id);
                    } else {
                        disconnect(server, &mut poller, id);
                        // A descriptor is free again: resume accepting.
                        if listener_retry_at.is_some() {
                            listener_retry_at = Some(Instant::now());
                        }
                    }
                }
            }
        }
        // Relays and events write to clients other than the one being served;
        // bring their output interest in line with what is queued for them.
        let mut touched = std::mem::take(&mut server.touched);
        for id in touched.drain(..) {
            sync_write_interest(server, &mut poller, id);
        }
        server.touched = touched;
    }
    Ok(())
}

/// Ask for output readiness exactly while the client has queued output, the
/// way the C daemon adds and drops ULOOP_WRITE around a blocked write.
fn sync_write_interest(server: &mut Server, poller: &mut owrt_ubus::readiness::Poller, id: u32) {
    let Some(c) = server.clients.get_mut(&id) else { return };
    let want = !c.tx_empty();
    let read = !c.eof;
    if (want != c.out_registered || read != c.in_registered)
        && poller.set_interest(c.fd(), u64::from(id), read, want).is_ok() {
        c.out_registered = want;
        c.in_registered = read;
    }
}

fn disconnect(server: &mut Server, poller: &mut owrt_ubus::readiness::Poller, id: u32) {
    if let Some(c) = server.clients.get(&id) {
        let _ = poller.remove(c.fd());
    }
    server.remove_client(id);
}

/// Accept everything queued. EINTR/ECONNABORTED retry as in the C daemon,
/// with a budget so repeated transient errors cannot monopolize the loop.
/// Other errors (including EMFILE/ENFILE) or exhausted retries return false:
/// the caller parks the level-triggered listener and retries after a delay.
fn accept_all(server: &mut Server, listener: &OwnedFd, poller: &mut owrt_ubus::readiness::Poller) -> bool {
    let mut transient_errors = 0;
    loop {
        match sys::accept(listener) {
            Ok(Some(sock)) => match server.add_client(sock) {
                Ok(id) => {
                    let Some(c) = server.clients.get_mut(&id) else { continue };
                    // HELLO was just queued or written; register with the
                    // interest that matches.
                    let write = !c.tx_empty();
                    if poller.add(c.fd(), u64::from(id), write).is_ok() {
                        c.out_registered = write;
                    } else {
                        server.remove_client(id);
                    }
                }
                Err(e) => eprintln!("ubusd-rs: rejecting connection: {e}"),
            },
            Ok(None) => return true,
            Err(e) => {
                if matches!(e.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted) {
                    transient_errors += 1;
                    if transient_errors < ACCEPT_TRANSIENT_BUDGET {
                        continue;
                    }
                }
                eprintln!("ubusd-rs: accept failed: {e}");
                return false;
            }
        }
    }
}

/// Drive one connection for this poll round. Returns false to disconnect it.
fn service_client(server: &mut Server, id: u32, revents: i16, rx: &mut [u8; client::RX_SIZE]) -> bool {
    if revents & (bus_sys::POLLERR) != 0 {
        return false;
    }

    if revents & bus_sys::POLLOUT != 0 {
        let Some(c) = server.clients.get_mut(&id) else { return false };
        if !c.flush() {
            return false;
        }
        if c.tx_empty() && !server.process_cmd_queue(id) {
            return false;
        }
        if server.clients.get(&id).is_some_and(|c| c.eof && c.tx_empty()) {
            return false;
        }
    }

    if revents & (bus_sys::POLLIN | bus_sys::POLLHUP) != 0 {
        let Some(mut c) = server.clients.get_mut(&id) else { return false };
        c.begin_read(rx);
        loop {
            match c.read_message(rx) {
                Ok(Some(msg)) => {
                    if !server.receive(id, msg) {
                        return false;
                    }
                    // Dispatch can change the client table. Reacquire only
                    // here; the first read and end_read already have a borrow.
                    c = match server.clients.get_mut(&id) {
                        Some(c) => c,
                        None => return false,
                    };
                }
                Ok(None) => {
                    c.end_read(rx);
                    // Hold a half-closed connection open only while there is
                    // still queued output for it.
                    if c.eof && c.tx_empty() {
                        return false;
                    }
                    return true;
                }
                Err(_) => return false,
            }
        }
    }
    true
}
