//! ACK-bracketed registration diagnostics, compiled only into a separate ELF.
//! Requests still use register-cycle's original Connection and fixture code.
//! The frozen router benchmark is never rebuilt or replaced by this module.
use super::{emit, integer, obj, require, Json, Result};
use std::ffi::{c_int, c_long};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
compile_error!("registration-perf is a 64-bit Linux-only diagnostic");

#[repr(C)]
#[derive(Default)]
struct Timespec {
    sec: c_long,
    nsec: c_long,
}
#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}
type CpuMask = [u64; 16];
unsafe extern "C" {
    fn clock_getcpuclockid(pid: c_int, clock: *mut c_int) -> c_int;
    fn clock_gettime(clock: c_int, time: *mut Timespec) -> c_int;
    fn clock_getres(clock: c_int, time: *mut Timespec) -> c_int;
    fn sched_getaffinity(pid: c_int, size: usize, mask: *mut CpuMask) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
}

/// Duplicate an inherited descriptor without claiming ownership of its number.
fn inherited_file(fd: c_int) -> io::Result<File> {
    // Linux fcntl F_DUPFD_CLOEXEC; the kernel validates fd and allocates a new
    // descriptor atomically. Environment variables cannot prove ownership of
    // an existing descriptor, even when F_GETFD says it is open.
    const F_DUPFD_CLOEXEC: c_int = 1030;
    // SAFETY: this fcntl command takes an integer lower bound, not a pointer.
    let duplicated = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 3 as c_int) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful fcntl returned a fresh descriptor owned only here.
    Ok(unsafe { File::from_raw_fd(duplicated) })
}

fn clock_read(clock: c_int, resolution: bool) -> Result<u64> {
    let mut value = Timespec::default();
    // SAFETY: this diagnostic is Linux 64-bit; Timespec matches time_t/long.
    let rc = unsafe {
        if resolution {
            clock_getres(clock, &mut value)
        } else {
            clock_gettime(clock, &mut value)
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error().into());
    }
    require(
        value.sec >= 0 && (0..1_000_000_000).contains(&value.nsec),
        "invalid clock value",
    )?;
    Ok((value.sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|x| x.checked_add(value.nsec as u64))
        .ok_or("clock overflow")?)
}

fn process_clock(pid: u32) -> Result<c_int> {
    let mut clock = 0;
    // SAFETY: clock is a valid writable output; pid is range-checked.
    let rc = unsafe { clock_getcpuclockid(c_int::try_from(pid)?, &mut clock) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc).into());
    }
    Ok(clock)
}

fn affinity(pid: u32, cpu: usize) -> Result<()> {
    let mut actual = [0; 16];
    let mut expected = [0; 16];
    expected[cpu / 64] = 1 << (cpu % 64);
    // SAFETY: CpuMask is the aligned 128-byte Linux mask and pid fits pid_t.
    if unsafe {
        sched_getaffinity(
            c_int::try_from(pid)?,
            std::mem::size_of::<CpuMask>(),
            &mut actual,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    require(actual == expected, "unexpected CPU affinity")
}

pub struct Session {
    ctl: File,
    ack: File,
    subject: u32,
    subject_clock: c_int,
    client_clock: c_int,
    subject_resolution: u64,
    client_resolution: u64,
}

pub struct Measurement {
    latency: Vec<u64>,
    wall_before: u64,
    wall_after: u64,
    subject_before: u64,
    subject_after: u64,
    client_before: u64,
    client_after: u64,
}

impl Session {
    pub fn new(subject: u32) -> Result<Self> {
        require(
            subject > 0 && subject != std::process::id(),
            "invalid subject PID",
        )?;
        let ctl: c_int = std::env::var("OWRT_PERF_CTL_FD")?.parse()?;
        let ack: c_int = std::env::var("OWRT_PERF_ACK_FD")?.parse()?;
        require(ctl > 2 && ack > 2 && ctl != ack, "invalid perf descriptors")?;
        // Keep the inherited handles with their owner; own only our copies.
        let ctl = inherited_file(ctl)?;
        let ack = inherited_file(ack)?;
        super::affinity::pin(0)?;
        affinity(0, 0)?;
        affinity(subject, 1)?;
        let subject_clock = process_clock(subject)?;
        let client_clock = process_clock(std::process::id())?;
        Ok(Self {
            ctl,
            ack,
            subject,
            subject_clock,
            client_clock,
            subject_resolution: clock_read(subject_clock, true)?,
            client_resolution: clock_read(client_clock, true)?,
        })
    }

    fn control(&mut self, command: &[u8]) -> Result<()> {
        self.ctl.write_all(command)?;
        // The pinned perf implementation writes sizeof("ack\n"), including
        // its NUL. Consume all five bytes at each boundary.
        let mut reply = [0; 5];
        let mut got = 0;
        while got < reply.len() {
            let mut fd = PollFd {
                fd: self.ack.as_raw_fd(),
                events: 1,
                revents: 0,
            };
            // SAFETY: fd names one live pollfd with a valid inherited fd.
            let rc = unsafe { poll(&mut fd, 1, 10_000) };
            if rc < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            require(
                rc > 0 && fd.revents & 1 != 0,
                "perf acknowledgement timeout or pipe failure",
            )?;
            match self.ack.read(&mut reply[got..]) {
                Ok(0) => return Err("perf acknowledgement pipe closed".into()),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        require(reply == *b"ack\n\0", "invalid perf acknowledgement")
    }

    pub fn measure(
        &mut self,
        n: usize,
        mut operation: impl FnMut() -> Result<u64>,
    ) -> Result<Measurement> {
        let mut latency = vec![0; n];
        for value in &mut latency {
            // SAFETY: each element is uniquely borrowed; touch all sample
            // pages before enabling counters instead of faulting in-loop.
            unsafe {
                std::ptr::write_volatile(value, 0);
            }
        }
        self.control(b"enable\n")?;
        let measured = (|| -> Result<Measurement> {
            let wall_before = clock_read(1, false)?; // CLOCK_MONOTONIC
            let client_before = clock_read(self.client_clock, false)?;
            let subject_before = clock_read(self.subject_clock, false)?;
            for value in &mut latency {
                *value = operation()?;
            }
            let subject_after = clock_read(self.subject_clock, false)?;
            let client_after = clock_read(self.client_clock, false)?;
            let wall_after = clock_read(1, false)?;
            Ok(Measurement {
                latency,
                wall_before,
                wall_after,
                subject_before,
                subject_after,
                client_before,
                client_after,
            })
        })();
        // Attempt the stop handshake even when an operation/clock failed;
        // retain that primary error and never emit a successful measurement.
        let disabled = self.control(b"disable\n");
        let measured = measured?;
        disabled?;
        affinity(0, 0)?;
        affinity(self.subject, 1)?;
        require(
            measured.latency.iter().all(|&x| x > 0)
                && measured.wall_after > measured.wall_before
                && measured.subject_after > measured.subject_before
                && measured.client_after > measured.client_before,
            "non-increasing measurement clock",
        )?;
        Ok(measured)
    }

    pub fn emit(&self, m: Measurement, warmup: usize, methods: usize, name_bytes: usize) {
        emit(obj([
            ("schema", integer(1)),
            ("fixture", Json::Str("rust_register_cycle".into())),
            ("n", integer(m.latency.len() as u64)),
            ("successful", integer(m.latency.len() as u64)),
            ("errors", integer(0)),
            ("warmup", integer(warmup as u64)),
            ("methods", integer(methods as u64)),
            ("name_bytes", integer(name_bytes as u64)),
            ("subject_pid", integer(self.subject as u64)),
            ("client_pid", integer(std::process::id() as u64)),
            ("subject_cpu", integer(1)),
            ("client_cpu", integer(0)),
            ("perf_controlled", Json::Bool(true)),
            ("subject_resolution_ns", integer(self.subject_resolution)),
            ("client_resolution_ns", integer(self.client_resolution)),
            ("subject_before_ns", integer(m.subject_before)),
            ("subject_after_ns", integer(m.subject_after)),
            ("client_before_ns", integer(m.client_before)),
            ("client_after_ns", integer(m.client_after)),
            ("wall_before_ns", integer(m.wall_before)),
            ("wall_after_ns", integer(m.wall_after)),
            ("latency_clock", Json::Str("CLOCK_MONOTONIC".into())),
            ("latency_sample_count", integer(m.latency.len() as u64)),
            (
                "latency_ns",
                Json::Array(m.latency.into_iter().map(integer).collect()),
            ),
            ("full_signature_checked", Json::Bool(true)),
            ("warmup_empty", Json::Bool(true)),
            ("final_empty", Json::Bool(true)),
            ("wire_reply_bytes_checked", Json::Bool(false)),
        ]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn inherited_handles_have_independent_descriptor_ownership() {
        let (mut original, mut peer) = UnixStream::pair().unwrap();
        let duplicate = inherited_file(original.as_raw_fd()).unwrap();
        assert_ne!(duplicate.as_raw_fd(), original.as_raw_fd());
        drop(duplicate);
        original.write_all(b"a").unwrap();
        let mut byte = [0];
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");

        let mut duplicate = inherited_file(original.as_raw_fd()).unwrap();
        drop(original);
        duplicate.write_all(b"b").unwrap();
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"b");
        assert!(inherited_file(-1).is_err());
    }
}
