//! Load generator for the ubusd differential benchmark (tools/r39).
//!
//! The same client drives the C daemon and ubusd-rs, so the numbers compare
//! servers rather than clients. Not built into the package: the packaging
//! recipe copies only src/*.rs.
//!
//! Usage: bench <socket> <mode> <iterations>
//!   mode = lookup | lookup_all | invoke | notify | serve | serve_many:<n>
//!        | serve_wide:<n>            one object with n methods (large signature)
//!        | serve_wide_many:<o>:<m>   o objects of m methods each, to put more
//!                                    than the 1 MiB transmit cap on the bus
//! `serve` registers an object and answers invokes until killed, so the other
//! modes have something real to call.

use owrt_ubus::{BlobBuf, Connection, Incoming, MsgType};
use std::time::Instant;

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

fn report(label: &str, mut us: Vec<u128>, wall: f64) {
    us.sort_unstable();
    let n = us.len();
    let total: u128 = us.iter().sum();
    println!(
        "{label} n={n} mean_us={:.1} p50_us={} p90_us={} p99_us={} max_us={} ops_per_s={:.0}",
        total as f64 / n.max(1) as f64,
        percentile(&us, 0.50),
        percentile(&us, 0.90),
        percentile(&us, 0.99),
        us.last().copied().unwrap_or(0),
        n as f64 / wall.max(1e-9),
    );
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: bench <socket> <lookup|lookup_all|invoke|notify|serve> [iterations]");
        std::process::exit(2);
    }
    let sock = args[1].clone();
    let mode = args[2].clone();
    let iters: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2000);

    if mode == "serve" {
        return serve(&sock, 1);
    }
    if let Some(n) = mode.strip_prefix("serve_many:") {
        return serve(&sock, n.parse().unwrap_or(1));
    }
    if let Some(n) = mode.strip_prefix("serve_wide:") {
        return serve_wide(&sock, n.parse().unwrap_or(1));
    }
    if let Some(rest) = mode.strip_prefix("serve_wide_many:") {
        let mut it = rest.split(':');
        let objs = it.next().and_then(|v| v.parse().ok()).unwrap_or(1);
        let methods = it.next().and_then(|v| v.parse().ok()).unwrap_or(1);
        return serve_wide_many(&sock, objs, methods);
    }

    let mut c = Connection::connect(Some(&sock))?;
    let mut us = Vec::with_capacity(iters);

    // Warm up so the first-call cost of resolving the object is not measured.
    let target = match mode.as_str() {
        "invoke" | "notify" => Some(c.lookup_id("bench.target", 3000)?),
        _ => None,
    };

    let start = Instant::now();
    for _ in 0..iters {
        let t = Instant::now();
        match mode.as_str() {
            "lookup" => {
                c.lookup_id("bench.target", 3000)?;
            }
            "lookup_all" => {
                c.lookup(None, 3000)?;
            }
            "invoke" => {
                let mut b = BlobBuf::new();
                b.msg_u32("n", 1);
                let payload = b.into_payload();
                c.invoke(target.unwrap(), "ping", &payload, 3000)?;
            }
            "notify" => {
                let mut b = BlobBuf::new();
                b.msg_u32("n", 1);
                let payload = b.into_payload();
                c.notify(target.unwrap(), "tick", &payload)?;
            }
            other => {
                eprintln!("unknown mode {other}");
                std::process::exit(2);
            }
        }
        us.push(t.elapsed().as_micros());
    }
    report(&mode, us, start.elapsed().as_secs_f64());
    Ok(())
}

/// One object with `methods` methods: a large signature, which is what the real
/// rpcd objects have and what `serve_many` deliberately does not.
fn serve_wide(sock: &str, methods: usize) -> std::io::Result<()> {
    let mut c = Connection::connect(Some(sock))?;
    let names: Vec<String> = (0..methods)
        .map(|i| format!("method_number_{i:04}"))
        .collect();
    let policy: &[(&str, MsgType)] = &[
        ("first_argument", MsgType::String),
        ("second_argument", MsgType::Int32),
        ("third_argument", MsgType::Table),
    ];
    let spec: Vec<(&str, &[(&str, MsgType)])> =
        names.iter().map(|n| (n.as_str(), policy)).collect();
    let objid = c.add_object("bench.target", &spec, 3000)?;
    println!("serving bench.target id={objid} methods={methods}");
    answer_forever(&mut c)
}

/// `objs` objects, each with `methods` methods. Enough of these make one
/// lookup reply set exceed the client transmit cap, which is the only way to
/// reach the daemon's silent-drop path.
fn serve_wide_many(sock: &str, objs: usize, methods: usize) -> std::io::Result<()> {
    let mut c = Connection::connect(Some(sock))?;
    let names: Vec<String> = (0..methods)
        .map(|i| format!("method_number_{i:04}"))
        .collect();
    let policy: &[(&str, MsgType)] = &[
        ("first_argument", MsgType::String),
        ("second_argument", MsgType::Int32),
        ("third_argument", MsgType::Table),
    ];
    let spec: Vec<(&str, &[(&str, MsgType)])> =
        names.iter().map(|n| (n.as_str(), policy)).collect();
    c.add_object("bench.target", &spec, 3000)?;
    for i in 1..objs {
        let path = format!("bench.wide{i:04}");
        c.add_object(&path, &spec, 3000)?;
    }
    println!("serving objects={objs} methods={methods}");
    answer_forever(&mut c)
}

/// Register `bench.target` (plus `count-1` extra objects, so lookup_all has a
/// wider tree to walk) and answer every call.
fn serve(sock: &str, count: usize) -> std::io::Result<()> {
    let mut c = Connection::connect(Some(sock))?;
    let objid = c.add_object("bench.target", &[("ping", &[("n", MsgType::Int32)])], 3000)?;
    for i in 1..count {
        let path = format!("bench.filler{i:04}");
        c.add_object(&path, &[("ping", &[("n", MsgType::Int32)])], 3000)?;
    }
    println!("serving bench.target id={objid} objects={count}");
    answer_forever(&mut c)
}

fn answer_forever(c: &mut Connection) -> std::io::Result<()> {
    loop {
        match c.read_incoming() {
            Ok(Incoming::Invoke(req)) => {
                let mut b = BlobBuf::new();
                b.msg_u32("ok", 1);
                let payload = b.into_payload();
                let _ = c.reply_data(&req, &payload);
                let _ = c.reply_status(&req, 0, None);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => break,
        }
    }
    Ok(())
}
