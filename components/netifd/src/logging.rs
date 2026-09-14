//! The pinned netifd main.c's log level and output channel.
//!
//! The stock network init script does not capture stderr. Normal daemon
//! messages therefore go through libc's syslog, with -S selecting stderr.
//! libc supplies framing, bounded messages and recovery when logd restarts.

use std::ffi::{c_char, CString};
use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Level {
    Warning = 1,
    Notice = 2,
    Info = 3,
    Debug = 4,
}

pub const DEFAULT_LEVEL: i32 = Level::Notice as i32;
static LOG_LEVEL: AtomicI32 = AtomicI32::new(DEFAULT_LEVEL);
// Diagnostics that include this module without starting a daemon use stderr.
static STDERR: AtomicBool = AtomicBool::new(true);

extern "C" {
    fn atoi(text: *const c_char) -> i32;
    fn openlog(ident: *const c_char, option: i32, facility: i32);
    fn syslog(priority: i32, format: *const c_char, ...);
}

/// main.c uses atoi (including decimal prefixes and invalid input -> 0),
/// clamps only the upper end and allows negative levels to disable logging.
pub fn parse_level(text: &str) -> i32 {
    let Ok(text) = CString::new(text) else { return 0 };
    // SAFETY: the argument is a live NUL-terminated string.
    unsafe { atoi(text.as_ptr()) }.min(Level::Debug as i32)
}

/// Called once, before config loading or child creation.
pub fn init(stderr: bool, level: i32) {
    if !stderr {
        // SAFETY: openlog retains a pointer to this static ident. LOG_DAEMON
        // is 3 << 3 on the image's musl; no LOG_PID flag, matching main.c.
        unsafe { openlog(c"netifd".as_ptr(), 0, 3 << 3) };
    }
    LOG_LEVEL.store(level.min(Level::Debug as i32), Ordering::Relaxed);
    STDERR.store(stderr, Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    level as i32 <= LOG_LEVEL.load(Ordering::Relaxed)
}

pub fn write(level: Level, args: fmt::Arguments<'_>) {
    if STDERR.load(Ordering::Relaxed) {
        // A non-blocking or closed stderr must not abort the daemon.
        let _ = writeln!(io::stderr().lock(), "{args}");
    } else {
        let priority = match level {
            Level::Warning => 4,
            Level::Notice => 5,
            Level::Info => 6,
            Level::Debug => 7,
        };
        let mut line = args.to_string();
        line.push('\0');
        // SAFETY: both strings are NUL-terminated and live for this call.
        // A fixed %s format keeps child output from becoming a format string;
        // an embedded NUL terminates it just as in the original's %s path.
        unsafe { syslog(priority, c"%s".as_ptr(), line.as_ptr().cast::<c_char>()) };
    }
}

macro_rules! log {
    ($level:ident, $($args:tt)*) => {{
        let level = $crate::logging::Level::$level;
        if $crate::logging::enabled(level) {
            $crate::logging::write(level, format_args!($($args)*));
        }
    }};
}

pub(crate) use log;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_matches_the_images_atoi_and_upper_clamp() {
        for (text, expected) in [
            ("2", 2),
            ("  +3suffix", 3),
            ("nonnumeric", 0),
            ("", 0),
            ("-1", -1),
            ("99tail", 4),
        ] {
            assert_eq!(parse_level(text), expected, "{text:?}");
        }
    }
}
