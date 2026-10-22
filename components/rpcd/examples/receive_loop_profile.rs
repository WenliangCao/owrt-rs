//! Actual Connection transport with queued bursts, not a daemon benchmark.
//! Each request keeps its own DATA/STATUS reply and its normal frame boundary.
#[path = "../src/readiness.rs"]
mod readiness;

use owrt_ubus::{
    blob::BlobBuf,
    msg::{attr, ty, Header},
    Connection, Incoming,
};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
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

fn run(n: u32, burst: u32, drain: bool) -> (f64, f64, u32, u32) {
    let path = std::env::temp_dir().join(format!("receive-loop-profile-{}", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .write_all(
                &Header {
                    ty: ty::HELLO,
                    seq: 0,
                    peer: 1,
                }
                .encode(),
            )
            .unwrap();
        socket.write_all(&4u32.to_be_bytes()).unwrap();
        let mut data = BlobBuf::new();
        data.msg_string("ubus_rpc_session", "00000000000000000000000000000000");
        data.msg_string("scope", "ubus");
        data.msg_string("object", "uci");
        data.msg_string("function", "get");
        let mut frame = BlobBuf::new();
        frame
            .put_u32(attr::OBJID, 42)
            .put_string(attr::METHOD, "access")
            .put_string(attr::USER, "root")
            .put_string(attr::GROUP, "root")
            .put(attr::DATA, data.payload());
        let mut batch = Vec::new();
        for _ in 0..burst {
            batch.extend_from_slice(
                &Header {
                    ty: ty::INVOKE,
                    seq: 2,
                    peer: 3,
                }
                .encode(),
            );
            batch.extend_from_slice(frame.as_bytes());
        }
        let mut body = vec![0; 256];
        for _ in 0..n / burst {
            socket.write_all(&batch).unwrap();
            for _ in 0..burst {
                for kind in [ty::DATA, ty::STATUS] {
                    let mut head = [0; 12];
                    socket.read_exact(&mut head).unwrap();
                    assert_eq!(head[1], kind);
                    let len =
                        (u32::from_be_bytes(head[8..].try_into().unwrap()) & 0x00ff_ffff) as usize;
                    socket.read_exact(&mut body[..len - 4]).unwrap();
                }
            }
        }
    });
    let mut conn = Connection::connect(path.to_str()).unwrap();
    let (wake, _hold) = UnixStream::pair().unwrap();
    let mut ready = readiness::Readiness::new([conn.as_raw_fd(), wake.as_raw_fd()]);
    let mut reply = BlobBuf::new();
    reply.msg_bool("access", true);
    let mut waits = 0;
    let mut misses = 0;
    let mut budget = 0;
    let time = Instant::now();
    let cpu = thread_cpu_ns();
    for _ in 0..n {
        let immediate = if drain && budget > 0 {
            let value = conn.incoming_if_started().unwrap();
            if value.is_none() {
                misses += 1;
            }
            value
        } else {
            None
        };
        let msg = if let Some(msg) = immediate {
            budget -= 1;
            msg
        } else {
            assert_eq!(ready.wait(-1).unwrap(), [true, false]);
            waits += 1;
            budget = 31;
            conn.read_incoming().unwrap()
        };
        let Incoming::Invoke(req) = msg else {
            panic!("INVOKE")
        };
        assert_eq!(req.method, "access");
        assert_eq!(req.user.as_deref(), Some("root"));
        assert_eq!(req.group.as_deref(), Some("root"));
        conn.reply_data_status(&req, reply.payload(), 0).unwrap();
        conn.recycle_request(req);
    }
    let cpu_per_op = (thread_cpu_ns() - cpu) as f64 / n as f64;
    let wall_per_op = time.elapsed().as_nanos() as f64 / n as f64;
    peer.join().unwrap();
    std::fs::remove_file(path).unwrap();
    (cpu_per_op, wall_per_op, waits, misses)
}

fn main() {
    let n: u32 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "100000".into())
        .parse()
        .unwrap();
    assert!(n > 0 && n.is_multiple_of(32));
    println!("round,burst,strategy,iterations,thread_cpu_ns,wall_ns,waits,empty_probes");
    for round in 1..=5 {
        for burst in [1, 4, 32] {
            for drain in if round % 2 == 1 {
                [false, true]
            } else {
                [true, false]
            } {
                let (cpu, wall, waits, misses) = run(n, burst, drain);
                println!(
                    "{round},{burst},{},{n},{cpu:.2},{wall:.2},{waits},{misses}",
                    if drain { "drain" } else { "wait" }
                );
            }
        }
    }
}
