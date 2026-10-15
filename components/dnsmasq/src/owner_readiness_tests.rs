use super::*;
use std::io::Write;
use std::os::unix::net::UnixStream;

fn pair() -> (UnixStream, UnixStream) {
    let pair = UnixStream::pair().unwrap();
    pair.0.set_nonblocking(true).unwrap();
    pair.1.set_nonblocking(true).unwrap();
    pair
}
fn interest(fd: RawFd, events: i16) -> PollFd { PollFd { fd, events, revents: 0 } }
fn owner() -> OwnerReadiness {
    let result = OwnerReadiness::new();
    assert!(result.epoll.is_some());
    result
}

#[test]
fn event_layout_matches_supported_sdk_abi() {
    #[cfg(target_arch = "aarch64")]
    assert_eq!((std::mem::size_of::<Event>(), std::mem::offset_of!(Event, token)), (16, 8));
    #[cfg(target_arch = "x86_64")]
    assert_eq!((std::mem::size_of::<Event>(), std::mem::offset_of!(Event, token)), (12, 4));
}

#[test]
fn duplicate_masks_expand_and_subset_excludes_other_ready_owner() {
    let (socket, mut peer) = pair();
    let (quiet, _quiet_peer) = pair();
    let mut owner = owner();
    let mut fds = [interest(socket.as_raw_fd(), POLLIN), interest(socket.as_raw_fd(), POLLOUT)];
    owner.watch(0, Key::Tcp(1));
    owner.watch(1, Key::Tcp(1));
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 1);
    assert_eq!((fds[0].revents, fds[1].revents), (0, POLLOUT));
    peer.write_all(b"x").unwrap();
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 2);
    assert_eq!((fds[0].revents, fds[1].revents), (POLLIN, POLLOUT));
    assert_eq!(owner.registered.len(), 1);
    owner.begin();
    owner.watch(0, Key::Tcp(2));
    let mut probe = [interest(quiet.as_raw_fd(), POLLIN)];
    assert_eq!(owner.wait(&mut probe, 0).unwrap(), 0);
    assert_eq!(owner.registered.len(), 1);
    assert_eq!(owner.registered[0].key, Key::Tcp(2));
}

#[test]
fn direct_regular_file_and_grouped_socket_keep_original_ready_count() {
    let file = std::fs::File::open("/etc/hosts").unwrap();
    let (socket, mut peer) = pair();
    let mut owner = owner();
    let mut fds = [interest(file.as_raw_fd(), POLLIN), interest(socket.as_raw_fd(), POLLIN)];
    owner.watch(1, Key::Tcp(1));
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 1);
    assert_eq!(fds[0].revents, POLLIN);
    assert_eq!(fds[1].revents, 0);
    peer.write_all(b"x").unwrap();
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 2);
    assert!(owner.epoll.is_some());
    // An accidentally classified unsupported file safely disables optimization.
    owner.begin();
    owner.watch(0, Key::Route);
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 2);
    assert!(owner.epoll.is_none());
}

#[test]
fn a_replaced_numeric_fd_requires_a_new_generation() {
    unsafe extern "C" { fn dup2(old: i32, new: i32) -> i32; }
    let (socket, mut peer) = pair();
    let (replacement, mut replacement_peer) = pair();
    let mut owner = owner();
    let mut fds = [interest(socket.as_raw_fd(), POLLIN)];
    owner.watch(0, Key::Tcp(1));
    peer.write_all(b"old").unwrap();
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 1);
    let first_token = owner.registered[0].token;
    // SAFETY: replace our still-owned target, never a possibly reused unowned
    // number. Both original owners remain valid; the key explicitly advances.
    assert_eq!(unsafe { dup2(replacement.as_raw_fd(), socket.as_raw_fd()) }, socket.as_raw_fd());
    drop(replacement);
    owner.begin();
    owner.watch(0, Key::Tcp(2));
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 0);
    assert_ne!(owner.registered[0].token, first_token);
    replacement_peer.write_all(b"new").unwrap();
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 1);
    drop(replacement_peer);
    let mut reference = [interest(socket.as_raw_fd(), POLLIN)];
    sys::poll_fds(&mut reference, 0).unwrap();
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 1);
    assert_eq!(fds[0].revents, reference[0].revents);
}

#[test]
fn initial_invalid_fd_falls_back_to_per_slot_nval() {
    let mut owner = owner();
    // A permanently out-of-range positive fd avoids closing a descriptor
    // number which a parallel test might immediately reuse.
    let fd = i32::MAX;
    let mut fds = [interest(fd, POLLIN)];
    owner.watch(0, Key::Tcp(1));
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), 1);
    assert_eq!(fds[0].revents, 0x20);
    assert!(owner.epoll.is_none());
}

#[test]
fn all_ready_members_fit_one_extraction_and_large_sets_remain_direct() {
    let pairs: Vec<_> = (0..MAX_TAGS + 1).map(|_| pair()).collect();
    let mut owner = owner();
    let mut fds: Vec<_> = pairs.iter().map(|(socket, _)| interest(socket.as_raw_fd(), POLLOUT)).collect();
    for slot in 0..MAX_TAGS { owner.watch(slot, Key::Tcp(slot as u64)); }
    assert_eq!(owner.wait(&mut fds[..MAX_TAGS], 0).unwrap(), MAX_TAGS);
    assert_eq!(owner.events.len(), MAX_TAGS);
    owner.begin();
    for slot in 0..fds.len() { owner.watch(slot, Key::Tcp(slot as u64)); }
    assert!(owner.oversized);
    assert_eq!(owner.wait(&mut fds, 0).unwrap(), MAX_TAGS + 1);
    assert!(owner.epoll.is_some());
}

#[test]
fn stale_only_group_wake_cannot_shorten_the_caller_idle_interval() {
    let (socket, _peer) = pair();
    let (stale, mut stale_peer) = pair();
    let mut owner = owner();
    owner.ctl(1, Registration { key: Key::Signal, fd: stale.as_raw_fd(), mask: POLLIN, token: 999 }).unwrap();
    stale_peer.write_all(b"stale").unwrap();
    owner.watch(0, Key::Tcp(1));
    let mut fds = [interest(socket.as_raw_fd(), POLLIN)];
    let start = Instant::now();
    assert_eq!(owner.wait(&mut fds, 20).unwrap(), 0);
    assert!(start.elapsed() >= Duration::from_millis(20));
    assert!(owner.epoll.is_none());
}

#[test]
fn internal_extraction_failure_keeps_the_remaining_idle_budget() {
    unsafe extern "C" { fn dup2(old: i32, new: i32) -> i32; }
    let (socket, _peer) = pair();
    let (direct, _direct_peer) = pair();
    let file = std::fs::File::open("/dev/null").unwrap();
    let mut owner = owner();
    owner.watch(0, Key::Tcp(1));
    let mut fds = [interest(socket.as_raw_fd(), POLLIN), interest(direct.as_raw_fd(), POLLIN)];
    owner.prepare(&fds).unwrap();
    let group_fd = owner.epoll.as_ref().unwrap().as_raw_fd();
    // SAFETY: controlled internal backend failure replaces only our owned
    // epoll fd. Source ownership and numeric descriptors are untouched.
    assert_eq!(unsafe { dup2(file.as_raw_fd(), group_fd) }, group_fd);
    let start = Instant::now();
    assert_eq!(owner.wait(&mut fds, 20).unwrap(), 0);
    assert!(start.elapsed() >= Duration::from_millis(20));
    assert!(owner.epoll.is_none());
}
