//! r72's tty fixture: open the pty master inside the namespace, unlock it so
//! /dev/pts/0 exists for an inittab askfirst entry, wait for boot to reach
//! the marker, then press Enter on the console and record what the console
//! printed. Runs as a child the ns init inherits; exits on its own.
//!
//! Usage: ptyhold <wait-for-file> <banner-out>

use std::ffi::CString;
use std::io::{Read, Write};

extern "C" {
    fn open(path: *const u8, flags: i32, mode: u32) -> i32;
    fn ioctl(fd: i32, req: u64, arg: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, n: usize) -> isize;
    fn write(fd: i32, buf: *const u8, n: usize) -> isize;
}

const O_RDWR: i32 = 2;
const O_NOCTTY: i32 = 0o400;
const O_NONBLOCK: i32 = 0o4000;
/// TIOCSPTLCK: unlockpt().
const TIOCSPTLCK: u64 = 0x4004_5431;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!("usage: ptyhold <wait-for-file> <banner-out>");
        std::process::exit(2);
    }
    let (wait_for, banner_out) = (&args[0], &args[1]);

    let c = CString::new("/dev/pts/ptmx").unwrap();
    // SAFETY: NUL-terminated path; the fd is used only below.
    let master = unsafe { open(c.as_ptr().cast(), O_RDWR | O_NOCTTY | O_NONBLOCK, 0) };
    if master < 0 {
        eprintln!("ptyhold: cannot open /dev/pts/ptmx");
        std::process::exit(1);
    }
    let mut zero: i32 = 0;
    // SAFETY: unlockpt on a live master fd.
    if unsafe { ioctl(master, TIOCSPTLCK, &mut zero) } != 0 {
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
        // SAFETY: non-blocking read into a live buffer.
        let n = unsafe { read(master, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        banner.extend_from_slice(&buf[..n as usize]);
    };
    slurp(&mut banner);
    // SAFETY: one byte to the live master.
    unsafe { write(master, b"\n".as_ptr(), 1) };
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
