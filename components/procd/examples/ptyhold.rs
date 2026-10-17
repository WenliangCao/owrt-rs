//! r72's tty fixture: open the pty master inside the namespace, unlock it so
//! /dev/pts/0 exists for an inittab askfirst entry, wait for boot to reach
//! the marker, then press Enter on the console and record what the console
//! printed. Runs as a child the ns init inherits; exits on its own.
//!
//! Usage: ptyhold <wait-for-file> <banner-out>

#![forbid(unsafe_code)]
use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!("usage: ptyhold <wait-for-file> <banner-out>");
        std::process::exit(2);
    }
    let (wait_for, banner_out) = (&args[0], &args[1]);

    let master = match rustix::fs::open(
        "/dev/pts/ptmx",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => {
            eprintln!("ptyhold: cannot open /dev/pts/ptmx");
            std::process::exit(1);
        }
    };
    if rustix::pty::unlockpt(&master).is_err() {
        eprintln!("ptyhold: unlockpt failed");
        std::process::exit(1);
    }
    // /dev/pts/0 now exists; wait for the boot to produce the marker file.
    for _ in 0..120 {
        if std::fs::metadata(wait_for).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    // Give askfirst a moment to attach and prompt, capture the banner,
    // press Enter, then capture what the activated command prints.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let mut banner = Vec::new();
    let mut buf = [0u8; 4096];
    let mut slurp = |banner: &mut Vec<u8>| loop {
        let Ok(n) = rustix::io::read(&master, &mut buf) else {
            break;
        };
        if n == 0 {
            break;
        }
        banner.extend_from_slice(&buf[..n]);
    };
    slurp(&mut banner);
    let _ = rustix::io::write(&master, b"\n");
    std::thread::sleep(std::time::Duration::from_secs(3));
    slurp(&mut banner);
    if let Ok(mut f) = std::fs::File::create(banner_out) {
        let _ = f.write_all(&banner);
    }
    // Keep the master open a little longer so the console child is not
    // hung up mid-test, then exit; the ns is torn down by the probe.
    std::thread::sleep(std::time::Duration::from_secs(10));
    let _ = std::io::stdout().flush();
    let mut _sink = String::new();
    let _ = std::io::stdin().read_to_string(&mut _sink);
}
