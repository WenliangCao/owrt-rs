//! Compare repeated two-fd poll scans with a persistent interest set.
//! Readiness is fixed during each stage; these are syscall costs, not latency.
#[path = "../src/readiness.rs"]
mod readiness;
use owrt_ubus::sys::{self, PollFd, POLLIN};
use std::hint::black_box;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}
extern "C" {
    fn clock_gettime(clock: i32, time: *mut Timespec) -> i32;
}
fn thread_cpu_ns() -> u64 {
    let mut time = Timespec { sec: 0, nsec: 0 };
    // SAFETY: Linux CLOCK_THREAD_CPUTIME_ID and a writable 64-bit timespec.
    assert_eq!(unsafe { clock_gettime(3, &mut time) }, 0);
    time.sec as u64 * 1_000_000_000 + time.nsec as u64
}

fn blocking(n: u32, epoll: bool) -> f64 {
    let (mut server, mut client) = UnixStream::pair().unwrap();
    let (wake, _hold) = UnixStream::pair().unwrap();
    let worker = std::thread::spawn(move || {
        let fds = [server.as_raw_fd(), wake.as_raw_fd()];
        let mut persistent = readiness::Readiness::new(fds);
        assert!(persistent.uses_epoll());
        let started = thread_cpu_ns();
        for _ in 0..n {
            if epoll {
                assert_eq!(persistent.wait(-1).unwrap(), [true, false]);
            } else {
                let mut poll = fds.map(|fd| PollFd {
                    fd,
                    events: POLLIN,
                    revents: 0,
                });
                sys::poll_fds(&mut poll, -1).unwrap();
                assert!(poll[0].revents != 0 && poll[1].revents == 0);
            }
            let mut byte = [0];
            server.read_exact(&mut byte).unwrap();
            server.write_all(&byte).unwrap();
        }
        (thread_cpu_ns() - started) as f64 / n as f64
    });
    for _ in 0..n {
        client.write_all(b"x").unwrap();
        client.read_exact(&mut [0]).unwrap();
    }
    worker.join().unwrap()
}

fn main() {
    let n: u32 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1000000".into())
        .parse()
        .unwrap();
    println!("round,state,implementation,iterations,ns_per_op");
    for round in 1..=5 {
        for ready in [false, true] {
            let (a, mut send) = UnixStream::pair().unwrap();
            let (b, _hold) = UnixStream::pair().unwrap();
            if ready {
                send.write_all(b"x").unwrap();
            }
            let fds = [a.as_raw_fd(), b.as_raw_fd()];
            let mut persistent = readiness::Readiness::new(fds);
            assert!(persistent.uses_epoll(), "this diagnostic needs epoll");
            for epoll in if round % 2 == 1 {
                [false, true]
            } else {
                [true, false]
            } {
                let t = Instant::now();
                for _ in 0..n {
                    let events = if epoll {
                        persistent.wait(0).unwrap()
                    } else {
                        let mut poll = fds.map(|fd| PollFd {
                            fd,
                            events: POLLIN,
                            revents: 0,
                        });
                        sys::poll_fds(&mut poll, 0).unwrap();
                        poll.map(|fd| fd.revents != 0)
                    };
                    assert_eq!(black_box(events), [ready, false]);
                }
                println!(
                    "{round},{ready},{},{n},{:.2}",
                    if epoll { "epoll" } else { "poll" },
                    t.elapsed().as_nanos() as f64 / n as f64
                );
            }
        }
        for epoll in if round % 2 == 1 {
            [false, true]
        } else {
            [true, false]
        } {
            let count = n.min(100000);
            println!(
                "{round},blocking_thread_cpu,{},{count},{:.2}",
                if epoll { "epoll" } else { "poll" },
                blocking(count, epoll)
            );
        }
    }
}
