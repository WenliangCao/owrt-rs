//! Exercise the production watchdog init/status path with ioctl injection.
//! Each injected descriptor owns a socketpair; this never opens /dev/watchdog.
#![deny(unsafe_code)]

use std::io::Read;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

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
    pub fn atoi_u32(s: &str) -> u32 {
        s.parse().unwrap()
    }
    pub use owrt_platform::procd::watchdog::WatchdogInfo;
    pub fn watchdog_set_timeout(
        _fd: impl std::os::fd::AsFd,
        value: &mut i32,
    ) -> std::io::Result<()> {
        crate::IOCTLS.lock().unwrap().push(0xc004_5706);
        if crate::SCENARIO.load(crate::Ordering::Relaxed) == 5 {
            *value = 20;
        }
        Ok(())
    }
    pub fn watchdog_support(_fd: impl std::os::fd::AsFd) -> std::io::Result<WatchdogInfo> {
        crate::IOCTLS.lock().unwrap().push(0x8028_5700);
        assert_eq!(std::mem::size_of::<WatchdogInfo>(), 40);
        let scenario = crate::SCENARIO.load(crate::Ordering::Relaxed);
        if scenario == 0 {
            return Err(std::io::Error::other("injected GETSUPPORT"));
        }
        Ok(WatchdogInfo {
            options: if scenario == 1 { 0 } else { 0x20 },
            ..Default::default()
        })
    }
    pub fn watchdog_boot_status(_fd: impl std::os::fd::AsFd) -> std::io::Result<i32> {
        crate::IOCTLS.lock().unwrap().push(0x8004_5702);
        let scenario = crate::SCENARIO.load(crate::Ordering::Relaxed);
        if scenario == 2 {
            return Err(std::io::Error::other("injected GETBOOTSTATUS"));
        }
        Ok(if scenario == 4 { 0x20 } else { 0 })
    }
}

#[allow(dead_code)]
#[path = "../src/watchdog.rs"]
mod watchdog;

fn main() {
    if std::env::args().any(|arg| arg == "--adjust-timeout") {
        let (writer, _reader) = std::os::unix::net::UnixStream::pair().unwrap();
        SCENARIO.store(5, Ordering::Relaxed);
        let mut watchdog = watchdog::Wdt::default();
        watchdog.init(0, false, Some(Ok(writer.into())));
        println!("init={} set={}", watchdog.timeout(0), watchdog.timeout(17));
        return;
    }
    let expected = [
        "Watchdog GETSUPPORT failed",
        "Watchdog does not have CARDRESET support",
        "Watchdog GETBOOTSTATUS failed",
        "Watchdog did not previously reset the system",
        "Watchdog has previously reset the system",
    ];
    for (scenario, message) in expected.iter().enumerate() {
        let (writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
        SCENARIO.store(scenario, Ordering::Relaxed);
        LOGS.lock().unwrap().clear();
        IOCTLS.lock().unwrap().clear();
        let mut watchdog = watchdog::Wdt::default();
        watchdog.init(0, false, Some(Ok(writer.into())));
        let mut ping = [0u8];
        reader.read_exact(&mut ping).unwrap();
        assert_eq!(ping, *b"X");
        assert_eq!(
            *LOGS.lock().unwrap(),
            vec!["- watchdog -".to_string(), (*message).to_string()]
        );
        assert_eq!(
            IOCTLS.lock().unwrap().len(),
            if scenario < 2 { 2 } else { 3 }
        );
        println!("scenario {scenario}: init, ABI, ioctl ordering and status log passed");
    }
}
