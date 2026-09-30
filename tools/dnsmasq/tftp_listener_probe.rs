//! Isolated differential fixture. This executable is never installed.
use dnsmasq_rs::tftp_listener::TftpListener;
use dnsmasq_rs::tftp_runtime::{RealFileOpener, RuntimeConfig, RuntimePathPolicy, TransferRuntime};
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() -> io::Result<()> {
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
    let args: Vec<_> = std::env::args().collect();
    let address: SocketAddr = args[1].parse().expect("listen address");
    assert!(address.ip().is_loopback() || address.ip().is_unspecified());
    let runtime = TransferRuntime::new(
        RuntimeConfig {
            path: RuntimePathPolicy {
                prefix: Some(args[2].as_bytes().to_vec()),
                lowercase: false,
            },
            ipv6: address.is_ipv6(),
            max_transfers: args
                .get(3)
                .map(|value| value.parse().expect("capacity"))
                .unwrap_or(50),
            single_port: args.get(4).is_some_and(|value| value == "single"),
            ..RuntimeConfig::default()
        },
        RealFileOpener::new(0, false),
    );
    let mut listener = TftpListener::bind(address, runtime)?;
    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = Arc::clone(&stop);
    let reader = std::thread::spawn(move || {
        let _ = io::stdin().lock().lines().next();
        reader_stop.store(true, Ordering::Relaxed);
    });
    println!("ready");
    io::stdout().flush()?;
    let started = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        listener.poll_once(started.elapsed().as_secs() + 1)?;
        std::thread::sleep(Duration::from_millis(1));
    }
    reader.join().expect("stdin reader");
    Ok(())
}
