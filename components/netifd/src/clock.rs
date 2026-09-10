//! `system_get_rtime`: CLOCK_MONOTONIC, the clock every netifd deadline and
//! uptime is measured on. Wall time is not usable here -- the box has no RTC,
//! NTP moves the clock by decades a few seconds after the interfaces come up,
//! and every lifetime and uptime computed against `SystemTime` moved with it
//! (R81 F07).

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

const CLOCK_MONOTONIC: i32 = 1;

extern "C" {
    fn clock_gettime(clk: i32, ts: *mut Timespec) -> i32;
}

fn read() -> Timespec {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes a timespec into the struct we own; the
    // layout matches the 64-bit kernel ABI on every target this crate builds
    // for (aarch64 and x86_64 musl/gnu).
    unsafe {
        clock_gettime(CLOCK_MONOTONIC, &mut ts);
    }
    ts
}

/// Seconds since boot, truncated -- what `system_get_rtime` returns.
pub fn now() -> u64 {
    read().tv_sec.max(0) as u64
}

/// Milliseconds since boot, for the sub-second deadlines (`uloop_timeout`).
pub fn now_ms() -> u64 {
    let ts = read();
    ts.tv_sec.max(0) as u64 * 1000 + (ts.tv_nsec.max(0) as u64) / 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_is_monotonic_and_not_wall_time() {
        let a = now_ms();
        std::thread::sleep(std::time::Duration::from_millis(15));
        let b = now_ms();
        assert!(b >= a + 10, "{a} -> {b}");
        // seconds since boot, not since 1970
        assert!(now() < 60 * 60 * 24 * 365 * 10, "{}", now());
    }
}
