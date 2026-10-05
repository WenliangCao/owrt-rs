//! C delay_dhcp's whole-second clock and quarter-second idle fallback.
//!
//! The owner supplies a poll callback which advances DNS/TFTP/logging only.
//! This module owns no socket, thread, sleep or independent periodic timer.

use std::io;
use std::time::Duration;

pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

pub fn pending(received_at: i64, now: i64, seconds: u32, idle_polls: u64) -> bool {
    now.saturating_sub(received_at) <= i64::from(seconds) && idle_polls < u64::from(seconds) * 4
}

/// `poll` returns true for any admitted activity, including an earlier DNS
/// deadline. Such activity does not consume C's quarter-second idle fallback.
/// Pending signals and additional DHCP input remain with the outer owner.
pub fn wait(
    received_at: i64,
    seconds: u32,
    mut now: impl FnMut() -> i64,
    mut poll: impl FnMut(Duration) -> io::Result<bool>,
) -> io::Result<()> {
    let mut idle_polls = 0;
    while pending(received_at, now(), seconds, idle_polls) {
        match poll(POLL_INTERVAL) {
            Ok(false) => idle_polls += 1,
            Ok(true) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_delay_and_spent_receive_time_never_poll() {
        wait(10, 0, || 10, |_| panic!("zero delay polled")).unwrap();
        wait(10, 1, || 12, |_| panic!("spent delay polled")).unwrap();
        assert!(pending(10, 11, 1, 3));
        assert!(!pending(10, 12, 1, 3));
    }

    #[test]
    fn readiness_and_interrupts_do_not_consume_idle_timeout_budget() {
        let mut polls = 0;
        wait(
            10,
            1,
            || 9,
            |timeout| {
                assert_eq!(timeout, POLL_INTERVAL);
                polls += 1;
                match polls {
                    1 => Err(io::ErrorKind::Interrupted.into()),
                    2 => Ok(true),
                    _ => Ok(false),
                }
            },
        )
        .unwrap();
        assert_eq!(polls, 6);
    }
}
