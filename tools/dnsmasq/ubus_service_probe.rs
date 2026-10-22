//! Standalone library fixture, not a DNS/DHCP daemon or product executable.
//! The synthetic counter inputs test serialization, not engine increments.
#[allow(dead_code)]
#[path = "../../components/dnsmasq/src/metrics.rs"]
mod metrics;
#[allow(dead_code)]
#[path = "../../components/dnsmasq/src/ubus_service.rs"]
mod ubus_service;

use metrics::{Metric, Metrics};
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use ubus_service::{DhcpEventFields, DhcpEventKind, DhcpLogging, DnsResult, UbusService};

static CANCEL: AtomicBool = AtomicBool::new(false);
fn cancelled() -> bool {
    CANCEL.load(Ordering::Relaxed)
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args[1] == "dns" {
        let mut buffer = owrt_ubus::BlobBuf::new();
        assert!(args[2].len().is_multiple_of(2), "hex fixture has an unmatched nibble");
        let name: Vec<u8> = args[2]
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        DnsResult {
            name: &name,
            ttl: args[3].parse().unwrap(),
            address: args[4].parse().unwrap(),
        }
        .write(&mut buffer);
        for byte in buffer.payload() {
            print!("{byte:02x}");
        }
        println!();
        return;
    }
    assert!(args[1] == "serve" || args[1] == "serve-hex");
    let object_name = if args[1] == "serve-hex" {
        assert!(args[3].len().is_multiple_of(2), "hex fixture has an unmatched nibble");
        args[3].as_bytes().chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    } else {
        args[3].as_bytes().to_vec()
    };
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
    assert!(args[2].starts_with("/run/"));
    let mut service = None;
    let mut metrics = Metrics::default();
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        if service.is_none() {
            if let Ok(connected) = UbusService::connect_bytes(Some(&args[2]), &object_name) {
                service = Some(connected);
                println!("connected");
                io::stdout().flush().unwrap();
            }
        }
        if let Some(connected) = service.as_mut() {
            match connected.process_one(&metrics) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(_) => {
                    service = None;
                    println!("disconnected");
                    io::stdout().flush().unwrap();
                }
            }
        }
        if owrt_ubus::sys::wait_readable(0, 1).unwrap() {
            let mut line = String::new();
            if input.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let command = line.trim();
            if command == "quit" {
                break;
            }
            let connected = service
                .as_mut()
                .expect("command requires a connected service");
            if command == "subscribers" {
                println!("dns-subscribers={}", connected.dns_has_subscribers());
            } else if command.starts_with("doctor ") || command.starts_with("doctor-cancel ") || command.starts_with("doctor-stage ") {
                let parts: Vec<_> = command.split_whitespace().collect();
                assert!(parts[1].len().is_multiple_of(2), "hex fixture has an unmatched nibble");
                let name: Vec<_> = parts[1]
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect();
                let value = DnsResult {
                    name: &name,
                    ttl: parts[2].parse().unwrap(),
                    address: parts[3].parse().unwrap(),
                };
                CANCEL.store(false, Ordering::Relaxed);
                let timer = (parts[0] == "doctor-cancel").then(|| {
                    std::thread::spawn(|| {
                        std::thread::sleep(Duration::from_millis(10));
                        CANCEL.store(true, Ordering::Relaxed);
                    })
                });
                let start = Instant::now();
                let result = connected.doctor_dns(&value, Some(cancelled), &metrics);
                // Explicit fixture value: a caller commits its cache only
                // after the hook returns. Never linked into the daemon.
                if parts[0] == "doctor-stage" {
                    metrics.add(Metric::CacheInserted, 1);
                }
                let elapsed = start.elapsed().as_micros();
                if let Some(timer) = timer {
                    timer.join().unwrap();
                }
                CANCEL.store(false, Ordering::Relaxed);
                match result {
                    Ok(value) => println!(
                        "doctor-result {} {elapsed}",
                        value.map_or("-".to_owned(), |address| address.to_string())
                    ),
                    Err(error) => {
                        println!("doctor-error {:?} {elapsed}", error.kind());
                        service = None;
                    }
                }
            } else {
                let logging = DhcpLogging {
                    quiet_dhcp: command != "events",
                    log_options: command == "quiet-options",
                    has_error: false,
                };
                if command == "events" {
                    for metric in [
                        Metric::DhcpDiscover,
                        Metric::DhcpOffer,
                        Metric::DhcpRequest,
                        Metric::DhcpAck,
                        Metric::DhcpRelease,
                        Metric::LeasesAllocated4,
                        Metric::LeasesPruned4,
                    ] {
                        metrics.add(metric, 1);
                    }
                }
                let ack = connected
                    .notify_dhcp(
                        DhcpEventKind::Ack,
                        DhcpEventFields {
                            mac: Some(b"02:00:00:00:00:01"),
                            ip: Some(b"127.0.0.10"),
                            name: Some(b"client1"),
                            interface: Some(b"lo"),
                        },
                        logging,
                    )
                    .unwrap();
                let release = connected
                    .notify_dhcp(
                        DhcpEventKind::Release,
                        DhcpEventFields {
                            mac: Some(b"02:00:00:00:00:01"),
                            ip: Some(b"127.0.0.10"),
                            name: None,
                            interface: Some(b"lo"),
                        },
                        logging,
                    )
                    .unwrap();
                println!("sent={ack},{release}");
            }
            io::stdout().flush().unwrap();
        } else if service.is_none() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
