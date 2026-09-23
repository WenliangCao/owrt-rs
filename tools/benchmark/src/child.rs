//! Run one command like `Command::output()` (stdin null, stdout and stderr
//! piped and drained together) but reap it with wait4(2). The kernel then
//! reports that child's own resource usage, merged with its reaped
//! descendants, per run instead of folding it into RUSAGE_CHILDREN, whose
//! ru_maxrss is a running maximum that cannot give a per-run median.
use std::io;
use std::process::{Command, ExitStatus};

pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub usage: Usage,
}

/// ru_maxrss is the largest resident set (KiB) of the child or any reaped
/// descendant, not a sum over the tree. ru_minflt counts minor page faults
/// of the child and its reaped descendants.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Usage {
    pub maxrss_kib: u64,
    pub minflt: u64,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn output(command: &mut Command) -> io::Result<Output> {
    use std::ffi::{c_int, c_long, c_short, c_ulong};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }
    // glibc's 64-bit struct rusage; musl appends 16 reserved longs.
    #[repr(C)]
    struct Rusage {
        _times: [c_long; 4],
        fields: [c_long; 14],
        _reserved: [c_long; 16],
    }
    unsafe extern "C" {
        fn poll(fds: *mut PollFd, count: c_ulong, timeout: c_int) -> c_int;
        fn wait4(pid: c_int, status: *mut c_int, options: c_int, usage: *mut Rusage) -> c_int;
    }
    const POLLIN: c_short = 1;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pid = c_int::try_from(child.id()).map_err(|_| io::Error::other("PID outside pid_t"))?;
    let out = child.stdout.take().map(|p| File::from(OwnedFd::from(p)));
    let err = child.stderr.take().map(|p| File::from(OwnedFd::from(p)));
    let mut pipes = [out, err];
    let mut stdout = Vec::new();
    let mut buffer = [0u8; 16384];
    while pipes.iter().any(Option::is_some) {
        let mut fds = [0, 1].map(|i| PollFd {
            fd: pipes[i].as_ref().map_or(-1, |f| f.as_raw_fd()),
            events: POLLIN,
            revents: 0,
        });
        // SAFETY: two initialised pollfd entries owned by this frame; the
        // kernel ignores the negative descriptor of an already closed pipe.
        if unsafe { poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        for (i, fd) in fds.iter().enumerate() {
            let Some(pipe) = pipes[i].as_mut().filter(|_| fd.revents != 0) else {
                continue;
            };
            match pipe.read(&mut buffer) {
                Ok(0) => pipes[i] = None,
                // stderr is drained but, as with output(), never validated.
                Ok(n) if i == 0 => stdout.extend_from_slice(&buffer[..n]),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
    let mut status = 0;
    let mut usage = Rusage {
        _times: [0; 4],
        fields: [0; 14],
        _reserved: [0; 16],
    };
    loop {
        // SAFETY: pid is this process's unreaped child. status and usage are
        // writable and at least as large as either libc's definitions.
        let reaped = unsafe { wait4(pid, &mut status, 0, &mut usage) };
        if reaped == pid {
            break;
        }
        let error = io::Error::last_os_error();
        if reaped < 0 && error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(if reaped < 0 {
            error
        } else {
            io::Error::other("wait4 reaped another child")
        });
    }
    let field = |i: usize| {
        u64::try_from(usage.fields[i]).map_err(|_| io::Error::other("negative rusage field"))
    };
    Ok(Output {
        status: ExitStatus::from_raw(status),
        stdout,
        usage: Usage {
            maxrss_kib: field(0)?,
            minflt: field(4)?,
        },
    })
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
pub fn output(_: &mut Command) -> io::Result<Output> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "wait4 rusage ABI requires 64-bit Linux",
    ))
}

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod tests {
    use super::*;

    #[test]
    fn captures_stdout_status_and_the_childs_own_usage() {
        let run = output(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("printf ok; printf err >&2; exit 3"),
        )
        .unwrap();
        assert_eq!(run.stdout, b"ok");
        assert_eq!(run.status.code(), Some(3));
        assert!(
            run.usage.maxrss_kib > 0 && run.usage.minflt > 0,
            "{:?}",
            run.usage
        );
    }

    #[test]
    fn drains_stderr_beyond_a_pipe_buffer_while_reading_stdout() {
        // 256 KiB of stderr before any stdout would block a sequential reader.
        let script = "i=0; while [ $i -lt 4 ]; do head -c 65536 /dev/zero >&2; i=$((i+1)); done; printf done";
        let run = output(Command::new("/bin/sh").arg("-c").arg(script)).unwrap();
        assert!(run.status.success());
        assert_eq!(run.stdout, b"done");
    }

    #[test]
    fn peak_is_per_child_not_a_running_maximum() {
        // A 32 MiB child first, then a small one: RUSAGE_CHILDREN would keep
        // reporting the large child, wait4 reports each child's own peak.
        let big = output(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("x=$(head -c 33554432 /dev/zero | tr '\\0' a); echo ${#x}"),
        )
        .unwrap();
        let small = output(&mut Command::new("/bin/true")).unwrap();
        assert!(big.status.success() && small.status.success());
        assert!(big.usage.maxrss_kib > 32 * 1024, "{:?}", big.usage);
        assert!(
            small.usage.maxrss_kib < big.usage.maxrss_kib / 4,
            "{:?} {:?}",
            small.usage,
            big.usage
        );
    }
}
