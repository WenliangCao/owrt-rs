//! Exercise the production watchdog init/status path with ioctl injection.
//! WDTFD always owns a socketpair; this program never opens /dev/watchdog.
#![deny(unsafe_op_in_unsafe_fn)]

use std::io::Read;
use std::os::fd::IntoRawFd;
use std::sync::{atomic::{AtomicUsize, Ordering}, Mutex};

static SCENARIO: AtomicUsize = AtomicUsize::new(0);
static LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static IOCTLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

macro_rules! log {
    ($level:expr, $($arg:tt)*) => {{
        let _ = $level;
        crate::LOGS.lock().unwrap().push(format!($($arg)*));
    }};
}
macro_rules! debug {
    ($level:expr, $($arg:tt)*) => { log!($level, $($arg)*); };
}

#[allow(dead_code)]
mod sys {
    pub const LOG_INFO: i32 = 6;
    pub const LOG_ERR: i32 = 3;
    pub fn atoi_u32(s: &str) -> u32 { s.parse().unwrap() }
    unsafe extern "C" { fn close(fd: i32) -> i32; }
    pub unsafe fn close_fd(fd: i32) -> i32 {
        // SAFETY: watchdog relinquishes its owned fd exactly once.
        unsafe { close(fd) }
    }
    pub unsafe fn ioctl<T>(_fd: i32, request: u64, value: *mut T) -> i32 {
        crate::IOCTLS.lock().unwrap().push(request);
        let scenario = crate::SCENARIO.load(crate::Ordering::Relaxed);
        match request {
            0xc004_5706 => assert_eq!(std::mem::size_of::<T>(), 4),
            0x8028_5700 => {
                assert_eq!(std::mem::size_of::<T>(), 40, "watchdog_info ABI");
                if scenario == 0 { return -1; }
                // SAFETY: the production call supplies watchdog_info, whose
                // checked repr(C) first field is its 32-bit options mask.
                unsafe { value.cast::<u32>().write(if scenario == 1 { 0 } else { 0x20 }) };
            }
            0x8004_5702 => {
                assert_eq!(std::mem::size_of::<T>(), 4, "GETBOOTSTATUS ABI");
                if scenario == 2 { return -1; }
                // SAFETY: the checked call supplies a live 32-bit status.
                unsafe { value.cast::<u32>().write(if scenario == 4 { 0x20 } else { 0 }) };
            }
            _ => panic!("unexpected watchdog ioctl {request:x}"),
        }
        0
    }
}

#[allow(dead_code)]
#[path = "../src/watchdog.rs"]
mod watchdog;

fn main() {
    let expected = [
        "Watchdog GETSUPPORT failed",
        "Watchdog does not have CARDRESET support",
        "Watchdog GETBOOTSTATUS failed",
        "Watchdog did not previously reset the system",
        "Watchdog has previously reset the system",
    ];
    for (scenario, message) in expected.iter().enumerate() {
        let (writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd = writer.into_raw_fd();
        // Single-threaded test executable; init consumes this environment fd.
        std::env::set_var("WDTFD", fd.to_string());
        SCENARIO.store(scenario, Ordering::Relaxed);
        LOGS.lock().unwrap().clear();
        IOCTLS.lock().unwrap().clear();
        let mut watchdog = watchdog::Wdt::default();
        watchdog.init(0, false);
        assert!(std::env::var_os("WDTFD").is_none());
        let mut ping = [0u8];
        reader.read_exact(&mut ping).unwrap();
        assert_eq!(ping, *b"X");
        assert_eq!(*LOGS.lock().unwrap(), vec!["- watchdog -".to_string(), (*message).to_string()]);
        assert_eq!(IOCTLS.lock().unwrap().len(), if scenario < 2 { 2 } else { 3 });
        println!("scenario {scenario}: init, ABI, ioctl ordering and status log passed");
    }
}
