//! Verify fatal startup diagnostics through the Linux executable.
#![cfg(target_os = "linux")]

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::net::{TcpListener, UdpSocket};
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod support;
use support::TestDir;

fn free_dns_port() -> u16 {
    for _ in 0..16 {
        let tcp = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = tcp.local_addr().unwrap();
        match UdpSocket::bind(addr) {
            Ok(_) => return addr.port(),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("cannot bind UDP on loopback: {error}"),
        }
    }
    panic!("could not find a free TCP and UDP port on loopback");
}

#[test]
fn foreground_resolver_watch_failure_reaches_log() {
    assert_resolver_watch_failure(OsStr::new("missing-parent/resolv.conf"));
}

#[test]
fn foreground_resolver_watch_failure_preserves_path_bytes() {
    assert_resolver_watch_failure(OsStr::from_bytes(b"missing-\xff/resolv.conf"));
}

fn assert_resolver_watch_failure(missing: &OsStr) {
    let dir = TestDir::new();
    let resolv = dir.0.join(missing);
    let log = dir.0.join("dnsmasq.log");
    let stderr = dir.0.join("stderr");
    let mut log_arg = OsString::from("--log-facility=");
    log_arg.push(&log);
    let mut resolv_arg = OsString::from("--resolv-file=");
    resolv_arg.push(&resolv);
    let mut child = Command::new(env!("CARGO_BIN_EXE_dnsmasq-rs"))
        .args([
            "-k",
            "--conf-file=/dev/null",
            // Empty values skip both credential transitions, including setgroups.
            "--user=",
            "--group=",
            "--listen-address=127.0.0.1",
            "--bind-interfaces",
            "--no-hosts",
            "--pid-file=",
        ])
        .arg(log_arg)
        .arg(resolv_arg)
        .arg(format!("--port={}", free_dns_port()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("dnsmasq did not exit after a resolver watch startup failure");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stderr = fs::read_to_string(stderr).unwrap();
    let log = fs::read(log).unwrap_or_default();
    let diagnostic = String::from_utf8_lossy(&log);
    assert_eq!(
        status.code(),
        Some(5),
        "stderr: {stderr}\nlog: {diagnostic}"
    );
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    let expected = [
        b"directory ",
        resolv.as_os_str().as_bytes(),
        b" for resolv-file is missing, cannot poll",
    ]
    .concat();
    let lines: Vec<_> = log
        .strip_suffix(b"\n")
        .unwrap_or(&log)
        .split(|&byte| byte == b'\n')
        .collect();
    assert!(
        matches!(lines.as_slice(), [first, second] if first.ends_with(&expected)
            && second.ends_with(b": FAILED to start up")),
        "expected the resolver watch error followed by the startup failure marker, got {diagnostic:?}"
    );
}
