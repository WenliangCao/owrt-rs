//! `system_get_rtime`: CLOCK_MONOTONIC, the clock every netifd deadline and
//! uptime is measured on. Wall time is not usable here -- the box has no RTC,
//! NTP moves the clock by decades a few seconds after the interfaces come up,
//! and every lifetime and uptime computed against `SystemTime` moved with it
//! (R81 F07).

fn read() -> rustix::time::Timespec {
    rustix::time::clock_gettime(rustix::time::ClockId::Monotonic)
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
