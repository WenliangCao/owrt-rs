//! dnsmasq.c:593–640,1090: detach after opening listeners, then report startup
//! through a private pipe. Only the original invoking process waits on it.
use super::{ProcessConfig, StartupError};
use std::fs::File;
use std::io::{self, IoSlice, Read, Write};
use std::os::fd::AsFd;

#[derive(Default)]
pub struct StartupChannel {
    writer: Option<File>,
    failure_bytes: Option<Vec<u8>>,
}

impl StartupChannel {
    pub fn active(&self) -> bool {
        self.writer.is_some()
    }

    /// Returns true in the original parent after successful child startup.
    /// The detached service and foreground modes return false.
    ///
    /// # Safety
    ///
    /// Background mode requires a single-threaded process with private writable
    /// mappings, no application atfork callbacks, and no held locks used by
    /// startup reporting or standard I/O. Foreground modes do not fork.
    /// Inherited signal handlers and panic hooks must not access copied parent
    /// resource owners or held locks; see
    /// [`dnsmasq_platform::process::background_startup`].
    #[expect(
        unsafe_code,
        reason = "daemonization explicitly requires process ownership"
    )]
    pub unsafe fn begin(&mut self, config: &ProcessConfig) -> Result<bool, StartupError> {
        if config.debug {
            return Ok(false);
        }
        std::env::set_current_dir("/")
            .map_err(|error| failure("cannot chdir to filesystem root", error))?;
        if config.keep_in_foreground {
            return Ok(false);
        }
        let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
            .map_err(|error| failure("cannot create pipe", error.into()))?;
        rustix::fs::fcntl_setfl(&writer, rustix::fs::OFlags::NONBLOCK)
            .map_err(|error| failure("cannot create pipe", error.into()))?;
        // SAFETY: the caller supplies the process guarantees above. These
        // fixed callbacks only consume their pipe and emit startup diagnostics;
        // neither can return through or access the copied service owners.
        let writer = unsafe {
            dnsmasq_platform::process::background_startup(
                File::from(reader),
                File::from(writer),
                parent_report,
                fork_failed,
            )
        }
        .map_err(|error| failure("cannot fork into background", error))?;
        self.writer = Some(writer);
        Ok(false)
    }

    pub fn complete(&mut self) {
        self.writer.take();
    }

    /// Typed parent errors retain their raw Unix argument for logging and
    /// stderr. StartupError's public String remains a diagnostic view.
    pub fn take_failure_bytes(&mut self) -> Option<Vec<u8>> {
        self.failure_bytes.take()
    }

    pub fn fail(&mut self, code: i32, message: &str) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        let message = &message.as_bytes()[..message.len().min(4084)];
        write_event(&writer, -1, code, message);
    }

    /// EVENT_PIDFILE13 uses the same optional raw-argument handoff as C.
    pub fn fail_pid(&mut self, errno: i32, path: &[u8]) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        write_event(&writer, 13, errno, path);
    }

    /// Exact EVENT_LOG_ERR has the original path as argument, not a formatted
    /// message. A short payload keeps errno and makes the parent use strerror.
    pub fn fail_log(&mut self, errno: i32, path: &[u8]) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        write_event(&writer, 17, errno, path);
    }

    /// EVENT_TFTP_ERR uses the same errno/optional-path fallback as LOG_ERR.
    pub fn fail_tftp(&mut self, errno: i32, path: &[u8]) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        write_event(&writer, 20, errno, path);
    }
}

fn write_event(fd: impl AsFd, kind: i32, data: i32, argument: &[u8]) {
    let mut header = [0; 12];
    header[..4].copy_from_slice(&kind.to_ne_bytes());
    header[4..8].copy_from_slice(&data.to_ne_bytes());
    header[8..].copy_from_slice(&(argument.len() as i32).to_ne_bytes());
    let vectors = [IoSlice::new(&header), IoSlice::new(argument)];
    // SIGPIPE is already ignored by the startup loader. An absent parent
    // cannot terminate the service before its own orderly failure cleanup.
    for _ in 0..128 {
        if !matches!(
            rustix::io::writev(&fd, &vectors),
            Err(rustix::io::Errno::INTR)
        ) {
            break;
        }
    }
}

fn read_startup_event(
    reader: &mut impl Read,
    failure_bytes: &mut Option<Vec<u8>>,
) -> Result<bool, StartupError> {
    let mut header = [0; 12];
    if reader.read_exact(&mut header).is_err() {
        return Ok(true);
    }
    let kind = i32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
    let data = i32::from_ne_bytes([header[4], header[5], header[6], header[7]]);
    let length = i32::from_ne_bytes([header[8], header[9], header[10], header[11]]);
    if length < 0 {
        return Ok(true);
    }
    let mut argument = Vec::new();
    let complete = if argument.try_reserve_exact(length as usize).is_ok() {
        argument.resize(length as usize, 0);
        reader.read_exact(&mut argument).is_ok()
    } else {
        let mut early = None;
        crate::logging::emit_early(
            &mut early,
            crate::logging::Priority::Error,
            b"failed to allocate memory",
        );
        let mut remaining = length as usize;
        let mut scratch = [0; 1024];
        while remaining > 0 {
            let count = remaining.min(scratch.len());
            if reader.read_exact(&mut scratch[..count]).is_err() {
                break;
            }
            remaining -= count;
        }
        false
    };
    if matches!(kind, 13 | 17 | 20) {
        let error = crate::logging::error_text(&io::Error::from_raw_os_error(data));
        let path = if complete && length != 0 {
            &argument
        } else {
            error.as_bytes()
        };
        let mut message = match kind {
            13 => b"failed to open pidfile ".to_vec(),
            17 => b"cannot open log ".to_vec(),
            _ => b"TFTP directory ".to_vec(),
        };
        message.extend_from_slice(path);
        message.extend_from_slice(if kind != 20 {
            b": ".as_slice()
        } else {
            b" inaccessible: ".as_slice()
        });
        message.extend_from_slice(error.as_bytes());
        let diagnostic = String::from_utf8_lossy(&message).into_owned();
        *failure_bytes = Some(message);
        return Err(StartupError {
            code: 3,
            message: diagnostic,
        });
    }
    if kind != -1 || !complete {
        return Ok(true);
    }
    Err(StartupError {
        code: data,
        message: String::from_utf8_lossy(&argument).into_owned(),
    })
}

/// The original parent reports startup and exits inside the platform boundary;
/// it never returns through the service's inherited Rust ownership graph.
fn parent_report(mut reader: File) -> i32 {
    let mut bytes = None;
    let Err(error) = read_startup_event(&mut reader, &mut bytes) else {
        return 0;
    };
    if let Some(message) = bytes {
        crate::logging::report_startup_failure_bytes(
            &Default::default(),
            &Default::default(),
            &message,
        );
        let mut stderr = io::stderr();
        let _ = stderr.write_all(b"\ndnsmasq: ");
        let _ = stderr.write_all(&message);
        let _ = stderr.write_all(b"\n");
    } else {
        crate::logging::report_startup_failure(
            &Default::default(),
            &Default::default(),
            &error.message,
        );
        eprintln!("\ndnsmasq-rs: {}", error.message);
    }
    error.code
}

fn fork_failed(writer: File, error: io::Error) {
    let mut channel = StartupChannel {
        writer: Some(writer),
        failure_bytes: None,
    };
    let error = failure("cannot fork into background", error);
    channel.fail(error.code, &error.message);
}

fn failure(context: &str, error: io::Error) -> StartupError {
    StartupError {
        code: 5,
        message: format!("{context}: {}", crate::logging::error_text(&error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn log_frame(errno: i32, wanted: i32, argument: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&17i32.to_ne_bytes());
        frame.extend_from_slice(&errno.to_ne_bytes());
        frame.extend_from_slice(&wanted.to_ne_bytes());
        frame.extend_from_slice(argument);
        frame
    }
    #[test]
    fn log_event_preserves_errno_with_a_full_or_incomplete_argument() {
        let complete = log_frame(2, 8, b"/missing");
        let error = read_startup_event(&mut complete.as_slice(), &mut None).unwrap_err();
        assert_eq!(error.code, 3);
        assert_eq!(
            error.message,
            "cannot open log /missing: No such file or directory"
        );
        for frame in [log_frame(2, 8, b"/miss"), log_frame(2, 0, b"")] {
            let error = read_startup_event(&mut frame.as_slice(), &mut None).unwrap_err();
            assert_eq!(error.code, 3);
            assert_eq!(
                error.message,
                "cannot open log No such file or directory: No such file or directory"
            );
        }
        for length in 0..12 {
            assert!(read_startup_event(&mut &complete[..length], &mut None).unwrap());
        }
        for (kind, prefix) in [
            (13i32, b"failed to open pidfile ".as_slice()),
            (20, b"TFTP directory ".as_slice()),
        ] {
            for complete in [true, false] {
                let mut frame = log_frame(2, 8, if complete { b"/missin\xff" } else { b"/miss" });
                frame[..4].copy_from_slice(&kind.to_ne_bytes());
                let mut bytes = None;
                let error = read_startup_event(&mut frame.as_slice(), &mut bytes).unwrap_err();
                assert_eq!(error.code, 3);
                let mut expected = prefix.to_vec();
                expected.extend_from_slice(if complete {
                    b"/missin\xff".as_slice()
                } else {
                    b"No such file or directory"
                });
                expected.extend_from_slice(if kind == 20 {
                    b" inaccessible: ".as_slice()
                } else {
                    b": "
                });
                expected.extend_from_slice(b"No such file or directory");
                assert_eq!(bytes.unwrap(), expected);
            }
        }
        let frame = log_frame(2, 8, b"/missin\xff");
        let mut bytes = None;
        read_startup_event(&mut frame.as_slice(), &mut bytes).unwrap_err();
        assert_eq!(
            bytes.unwrap(),
            b"cannot open log /missin\xff: No such file or directory"
        );
    }
}
