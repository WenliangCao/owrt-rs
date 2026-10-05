//! dnsmasq.c:593–640,1090: detach after opening listeners, then report startup
//! through a private pipe. Only the original invoking process waits on it.
use super::{ProcessConfig, StartupError};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};

#[derive(Default)]
pub struct StartupChannel {
    writer: Option<File>,
}

impl StartupChannel {
    pub fn active(&self) -> bool {
        self.writer.is_some()
    }

    /// Returns true in the original parent after successful child startup.
    /// The detached service and foreground modes return false.
    pub fn begin(&mut self, config: &ProcessConfig) -> Result<bool, StartupError> {
        if config.debug {
            return Ok(false);
        }
        std::env::set_current_dir("/")
            .map_err(|error| failure("cannot chdir to filesystem root", error))?;
        if config.keep_in_foreground {
            return Ok(false);
        }
        let mut fds = [-1; 2];
        // SAFETY: the array has space for the pipe's two uniquely owned FDs.
        if unsafe { pipe2(fds.as_mut_ptr(), 0o2000000) } != 0 {
            return Err(failure("cannot create pipe", io::Error::last_os_error()));
        }
        let mut reader = unsafe { File::from_raw_fd(fds[0]) };
        let writer = unsafe { File::from_raw_fd(fds[1]) };
        // No service threads exist. Mutexes are unlocked before this boundary.
        let pid = unsafe { fork() };
        if pid < 0 {
            return Err(failure(
                "cannot fork into background",
                io::Error::last_os_error(),
            ));
        }
        if pid > 0 {
            drop(writer);
            let mut header = [0u8; 8];
            if reader.read_exact(&mut header).is_err() {
                // C treats EOF (including an incomplete event) as success.
                return Ok(true);
            }
            let code = i32::from_ne_bytes(header[..4].try_into().unwrap());
            let length = u32::from_ne_bytes(header[4..].try_into().unwrap()) as usize;
            if length > 4088 {
                return Ok(true);
            }
            let mut message = vec![0; length];
            if reader.read_exact(&mut message).is_err() {
                return Ok(true);
            }
            return Err(StartupError {
                code,
                message: String::from_utf8_lossy(&message).into_owned(),
            });
        }
        drop(reader);
        self.writer = Some(writer);
        // C ignores setsid failure and still makes its second fork.
        unsafe {
            setsid();
        }
        let pid = unsafe { fork() };
        if pid < 0 {
            let error = failure("cannot fork into background", io::Error::last_os_error());
            self.fail(error.code, &error.message);
            unsafe {
                _exit(0);
            }
        }
        if pid > 0 {
            unsafe {
                _exit(0);
            }
        }
        // One bounded event fits PIPE_BUF. The service never waits for its
        // invoker, even if that invoker disappears while startup is failing.
        if let Some(writer) = &self.writer {
            unsafe {
                fcntl(writer.as_raw_fd(), 4, 0o4000);
            }
        }
        Ok(false)
    }

    pub fn complete(&mut self) {
        self.writer.take();
    }

    pub fn fail(&mut self, code: i32, message: &str) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        let message = &message.as_bytes()[..message.len().min(4088)];
        let mut event = Vec::with_capacity(8 + message.len());
        event.extend_from_slice(&code.to_ne_bytes());
        event.extend_from_slice(&(message.len() as u32).to_ne_bytes());
        event.extend_from_slice(message);
        // SIGPIPE is already ignored by the startup loader. An absent parent
        // cannot terminate the service before its own orderly failure cleanup.
        let _ = unsafe { write(writer.as_raw_fd(), event.as_ptr(), event.len()) };
    }
}

fn failure(context: &str, error: io::Error) -> StartupError {
    StartupError {
        code: 5,
        message: format!("{context}: {}", crate::logging::error_text(&error)),
    }
}
unsafe extern "C" {
    fn pipe2(fds: *mut i32, flags: i32) -> i32;
    fn fork() -> i32;
    fn setsid() -> i32;
    fn fcntl(fd: i32, operation: i32, ...) -> i32;
    fn write(fd: i32, bytes: *const u8, length: usize) -> isize;
    fn _exit(code: i32) -> !;
}
