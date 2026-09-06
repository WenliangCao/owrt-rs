//! Load generator for the ubusd differential benchmark (tools/r39).
//!
//! The same client drives the C daemon and ubusd-rs, so the numbers compare
//! servers rather than clients. Not built into the package: the packaging
//! recipe copies only src/*.rs.
//!
//! Usage: bench <socket> <mode> <iterations>
//!   mode = lookup | lookup_all | invoke | notify | serve
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
        return serve(&sock);
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

/// Register `bench.target` with a `ping` method and answer every call.
fn serve(sock: &str) -> std::io::Result<()> {
    let mut c = Connection::connect(Some(sock))?;
    let objid = c.add_object("bench.target", &[("ping", &[("n", MsgType::Int32)])], 3000)?;
    println!("serving bench.target id={objid}");
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
