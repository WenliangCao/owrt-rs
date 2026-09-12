//! ubusd-rs: the OpenWrt system message bus.
//!
//! Behaviour is specified by docs/contracts/ubusd.md, which is derived from
//! the pinned ubus 24864e78 source. Single-threaded poll loop, no async
//! runtime, no third-party crates.
//!
//! Every `unsafe` block here is a syscall the standard library does not
//! expose, and each one has to say why it is sound: the lint below makes that
//! a build error rather than a convention.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

mod acl;
mod client;
mod obj;
mod server;
mod sys;

use server::Server;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

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
    #[cfg(target_os = "linux")]
    // SAFETY: preserve this thread's interrupted errno across the pipe write.
    let (errno, saved_errno) = unsafe {
        extern "C" { fn __errno_location() -> *mut i32; }
        let errno = __errno_location();
        (errno, *errno)
    };
    let fd = WAKE_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        sys::write_fd(fd, &[0u8]);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: this thread-local errno cell remains live.
    unsafe { *errno = saved_errno; }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn saturated_signal_pipe_preserves_errno() {
    let (_read, write) = sys::nonblocking_pipe().unwrap();
    let fd = write.as_raw_fd();
    while sys::write_fd(fd, &[0u8; 4096]) > 0 {}
    assert_eq!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock);
    let previous = WAKE_FD.swap(fd, Ordering::SeqCst);
    // SAFETY: __errno_location returns this thread's live error cell.
    let errno = unsafe {
        extern "C" { fn __errno_location() -> *mut i32; }
        __errno_location()
    };
    // SAFETY: simulate the error from an interrupted syscall.
    unsafe { *errno = 22; }
    wake();
    // SAFETY: the thread-local cell remains live.
    let after = unsafe { *errno };
    WAKE_FD.store(previous, Ordering::SeqCst);
    assert_eq!(after, 22);
}

fn usage(program: &str) -> ! {
    eprintln!("{BUILD_ID}");
    eprintln!(
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
        println!("{BUILD_ID}");
        return;
    }
    if let Err(e) = run(&socket, &acl_dir) {
        eprintln!("ubusd-rs: {e}");
        std::process::exit(1);
    }
}

fn run(socket: &str, acl_dir: &str) -> std::io::Result<()> {
    // A dead peer must not kill the daemon; every write reports EPIPE instead.
    sys::ignore_signal(sys::SIGPIPE);

    let (wake_r, wake_w) = sys::nonblocking_pipe()?;
    WAKE_FD.store(wake_w.as_raw_fd(), Ordering::SeqCst);
    sys::set_signal_handler(sys::SIGHUP, on_sighup);
    sys::set_signal_handler(sys::SIGTERM, on_term);
    sys::set_signal_handler(sys::SIGINT, on_term);

    let listener = sys::listen_unix(socket)?;
    let mut server = Server::new(acl_dir.to_owned())?;
    server.load_acl();

    let result = event_loop(&mut server, &listener, &wake_r);
    sys::remove_file(socket);
    result
}

fn event_loop(server: &mut Server, listener: &OwnedFd, wake_r: &OwnedFd) -> std::io::Result<()> {
    let mut fds: Vec<sys::PollFd> = Vec::new();
    let mut ids: Vec<u32> = Vec::new();

    while !STOP.load(Ordering::SeqCst) {
        fds.clear();
        ids.clear();
        fds.push(sys::PollFd { fd: listener.as_raw_fd(), events: sys::POLLIN, revents: 0 });
        fds.push(sys::PollFd { fd: wake_r.as_raw_fd(), events: sys::POLLIN, revents: 0 });
        for (id, c) in &server.clients {
            // Only ask for writability while something is queued, so an idle
            // connection never spins the loop.
            let mut events = sys::POLLIN;
            if !c.tx_empty() {
                events |= sys::POLLOUT;
            }
            fds.push(sys::PollFd { fd: c.fd(), events, revents: 0 });
            ids.push(*id);
        }

        sys::poll_fds(&mut fds, -1)?;

        if fds[1].revents & sys::POLLIN != 0 {
            let mut buf = [0u8; 64];
            while sys::read_fd(wake_r.as_raw_fd(), &mut buf).unwrap_or(0) > 0 {}
        }
        if RELOAD.swap(false, Ordering::SeqCst) {
            server.load_acl();
        }
        if STOP.load(Ordering::SeqCst) {
            break;
        }

        if fds[0].revents & sys::POLLIN != 0 {
            accept_all(server, listener);
        }

        // ids/fds already snapshot the owners for this poll. Handlers can
        // mutate the client table without another allocation of ready ids.
        for (&id, fd) in ids.iter().zip(&fds[2..]) {
            if fd.revents != 0 && !service_client(server, id, fd.revents) {
                server.remove_client(id);
            }
        }
    }
    Ok(())
}

fn accept_all(server: &mut Server, listener: &OwnedFd) {
    loop {
        match sys::accept(listener.as_raw_fd()) {
            Ok(Some(sock)) => {
                if let Err(e) = server.add_client(sock) {
                    eprintln!("ubusd-rs: rejecting connection: {e}");
                }
            }
            Ok(None) => return,
            Err(_) => return,
        }
    }
}

/// Drive one connection for this poll round. Returns false to disconnect it.
fn service_client(server: &mut Server, id: u32, revents: i16) -> bool {
    if revents & (sys::POLLERR) != 0 {
        return false;
    }

    if revents & sys::POLLOUT != 0 {
        let Some(c) = server.clients.get_mut(&id) else { return false };
        if !c.flush() {
            return false;
        }
        if c.tx_empty() {
            server.process_cmd_queue(id);
        }
    }

    if revents & (sys::POLLIN | sys::POLLHUP) != 0 {
        loop {
            let Some(c) = server.clients.get_mut(&id) else { return false };
            match c.read_message() {
                Ok(Some(msg)) => {
                    if !server.receive(id, msg) {
                        return false;
                    }
                }
                Ok(None) => {
                    let Some(c) = server.clients.get(&id) else { return false };
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
