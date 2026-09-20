//! Read an entire process's POSIX CPU clock, including its threads but not
//! children. Unlike /proc/PID/stat, this is not quantized to clock ticks.
//! Failure stays an error; no silent switch to a different counter.
use std::io;

#[derive(Clone, Copy)]
pub struct Sample {
    pub ns: u64,
    pub resolution_ns: u64,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn sample(pid: u32) -> io::Result<Sample> {
    use std::ffi::{c_int, c_long};
    #[repr(C)]
    #[derive(Default)]
    struct Timespec {
        sec: c_long,
        nsec: c_long,
    }
    unsafe extern "C" {
        fn clock_getcpuclockid(pid: c_int, clock: *mut c_int) -> c_int;
        fn clock_gettime(clock: c_int, time: *mut Timespec) -> c_int;
        fn clock_getres(clock: c_int, time: *mut Timespec) -> c_int;
    }
    fn ns(time: Timespec) -> io::Result<u64> {
        if time.sec < 0 || !(0..1_000_000_000).contains(&time.nsec) {
            return Err(io::Error::other("invalid process CPU timespec"));
        }
        (time.sec as u64).checked_mul(1_000_000_000)
            .and_then(|s| s.checked_add(time.nsec as u64))
            .ok_or_else(|| io::Error::other("process CPU clock overflow"))
    }
    let pid = c_int::try_from(pid).map_err(|_| io::Error::other("PID outside pid_t"))?;
    let mut clock = 0;
    // SAFETY: clock is a valid output pointer; positive pid or 0 is accepted
    // by the POSIX API. Its return value is an error number, not errno.
    let error = unsafe { clock_getcpuclockid(pid, &mut clock) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    let mut resolution = Timespec::default();
    let mut time = Timespec::default();
    // SAFETY: clock came from libc and both outputs match the Linux 64-bit
    // ABI's time_t/long timespec. Neither call changes the target process.
    let failed = unsafe {
        clock_getres(clock, &mut resolution) != 0 || clock_gettime(clock, &mut time) != 0
    };
    if failed {
        return Err(io::Error::last_os_error());
    }
    let resolution_ns = ns(resolution)?;
    if resolution_ns == 0 {
        return Err(io::Error::other("zero CPU clock resolution"));
    }
    Ok(Sample { ns: ns(time)?, resolution_ns })
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
pub fn sample(_: u32) -> io::Result<Sample> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "CPU clock ABI requires 64-bit Linux"))
}

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    #[test]
    fn process_clock_counts_worker_threads_and_rejects_invalid_pid() {
        assert!(sample(u32::MAX).is_err());
        let before = sample(std::process::id()).unwrap();
        std::thread::spawn(|| {
            let end = std::time::Instant::now() + std::time::Duration::from_millis(30);
            while std::time::Instant::now() < end {
                std::hint::black_box(123u64.wrapping_mul(456));
            }
        }).join().unwrap();
        let after = sample(std::process::id()).unwrap();
        assert_eq!(before.resolution_ns, after.resolution_ns);
        assert!(after.ns > before.ns + 1_000_000, "worker CPU was omitted");
    }

    #[test]
    fn external_process_clock_excludes_sleep_and_does_not_follow_exit() {
        // A pipe handshake keeps the child alive at both measurements. The
        // shell builtin loop supplies CPU without spawning measured children.
        let mut child = Command::new("/bin/sh").arg("-c")
            .arg("echo ready; read go; i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; echo done; read stop")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "ready");
        let before = sample(child.id()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let sleeping = sample(child.id()).unwrap();
        child.stdin.as_mut().unwrap().write_all(b"go\n").unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "done");
        let after = sample(child.id()).unwrap();
        child.stdin.take().unwrap().write_all(b"stop\n").unwrap();
        assert!(child.wait().unwrap().success());
        assert!(sample(child.id()).is_err());
        assert!(after.ns > sleeping.ns + 1_000_000);
        assert!(sleeping.ns - before.ns < after.ns - sleeping.ns);
    }
}
