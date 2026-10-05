//! One bounded result pipe for blocking libc hostname lookup in a child.
//! The daemon remains single-threaded and polls this pipe. No live owner call
//! invokes getaddrinfo or a blocking waitpid.
use super::{endpoints, RuleTarget, ServerHost, ServerRule};
use owrt_ubus::sys::PollFd;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd};

unsafe extern "C" {
    fn pipe2(fds: *mut i32, flags: i32) -> i32;
    fn fork() -> i32;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn signal(number: i32, handler: usize) -> usize;
    fn kill(pid: i32, signal: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
}

pub struct LookupResult {
    pub rules: Vec<ServerRule>,
    pub error: Option<String>,
}

pub struct EndpointLookup {
    pid: Option<i32>,
    reader: File,
    bytes: Vec<u8>,
    eof: bool,
    cancelled: bool,
    status: Option<i32>,
    failure: Option<String>,
    rules: Vec<ServerRule>,
}

impl EndpointLookup {
    /// Call only from the single-threaded service owner. The child closes its
    /// inherited listener/helper descriptors before entering the libc resolver.
    pub fn start(rules: Vec<ServerRule>, reverse: bool) -> io::Result<Self> {
        let mut fds = [-1; 2];
        // SAFETY: pipe2 initializes the two-fd buffer and creates new owners.
        if unsafe { pipe2(fds.as_mut_ptr(), 0o2000000 | 0o4000) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful pipe2 created both fresh fds; give each one File owner.
        let reader = unsafe { File::from_raw_fd(fds[0]) };
        let mut writer = unsafe { File::from_raw_fd(fds[1]) };
        let inherited: Vec<i32> = std::fs::read_dir("/proc/self/fd")?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        // SAFETY: the caller is the documented single-thread owner. The child
        // uses only its forked memory/FD table and terminates via _exit.
        let pid = unsafe { fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            for fd in inherited {
                if fd != writer.as_raw_fd() {
                    // SAFETY: this fork child owns its copied fd table; it
                    // retains only writer and terminates via _exit, without
                    // dropping parent File objects after closing their copies.
                    unsafe {
                        close(fd);
                    }
                }
            }
            // SAFETY: scalar POSIX dispositions and fcntl flags apply only to
            // this single-threaded fork child and its live retained writer.
            unsafe {
                signal(2, 0);
                signal(15, 0);
                signal(13, 0);
                let flags = fcntl(writer.as_raw_fd(), 3);
                if flags >= 0 {
                    fcntl(writer.as_raw_fd(), 4, flags & !0o4000);
                }
            }
            let expanded = endpoints::resolve_rules(&rules, reverse);
            let bytes = encode(&rules, expanded);
            let exit = if writer.write_all(&bytes).is_ok() {
                0
            } else {
                1
            };
            // SAFETY: child-only exit never runs parent-object destructors.
            unsafe { _exit(exit) };
        }
        drop(writer);
        Ok(Self {
            pid: Some(pid),
            reader,
            bytes: Vec::new(),
            eof: false,
            cancelled: false,
            status: None,
            failure: None,
            rules,
        })
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<PollFd>) {
        if !self.eof && !self.cancelled {
            fds.push(PollFd {
                fd: self.reader.as_raw_fd(),
                events: 1,
                revents: 0,
            });
        }
    }

    pub fn cancel(&mut self) {
        if !self.cancelled {
            self.cancelled = true;
            if let Some(pid) = self.pid {
                // SAFETY: pid is the positive, unreaped child owned by this
                // job; cancellation never targets a process group or foreign pid.
                unsafe {
                    kill(pid, 9);
                }
            }
        }
    }

    /// At most one 4096-byte read and one WNOHANG reap in each owner turn.
    pub fn step(&mut self) -> Option<LookupResult> {
        if !self.eof && !self.cancelled {
            let mut buffer = [0; 4096];
            match self.reader.read(&mut buffer) {
                Ok(0) => self.eof = true,
                Ok(length) => self.bytes.extend_from_slice(&buffer[..length]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => {
                    self.failure = Some(format!("endpoint resolver pipe: {error}"));
                    self.cancel();
                }
            }
        }
        if let Some(pid) = self.pid {
            let mut status = 0;
            // SAFETY: waitpid is restricted to this owned child; WNOHANG
            // never waits for the resolver or steals another helper's status.
            let reaped = unsafe { waitpid(pid, &mut status, 1) };
            if reaped == pid {
                self.pid = None;
                self.status = Some(status);
            } else if reaped < 0 && io::Error::last_os_error().raw_os_error() == Some(10) {
                self.pid = None;
                self.failure = Some("endpoint resolver child was already reaped".into());
            } else {
                return None;
            }
        }
        if self.cancelled {
            return Some(LookupResult {
                rules: Vec::new(),
                error: self.failure.take(),
            });
        }
        if self.failure.is_some() || self.status.is_some_and(|status| status != 0) {
            return Some(LookupResult {
                rules: Vec::new(),
                error: self
                    .failure
                    .take()
                    .or_else(|| Some("endpoint resolver child failed".into())),
            });
        }
        if !self.eof {
            return None;
        }
        Some(
            decode(&self.rules, &self.bytes).unwrap_or_else(|_| LookupResult {
                rules: Vec::new(),
                error: Some("invalid endpoint resolver result".into()),
            }),
        )
    }

    /// A completed pipe may precede child exit by one owner turn.
    pub fn reap_pending(&self) -> bool {
        self.eof || self.cancelled
    }
}

impl Drop for EndpointLookup {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            // Shutdown callers retain the job until step reaps it. This is a
            // last-resort cancellation for an abruptly abandoned owner only.
            // SAFETY: positive owned child remains unreaped; cancellation and
            // WNOHANG wait are specific to it, with an optional null status pointer.
            unsafe {
                kill(pid, 9);
                waitpid(pid, std::ptr::null_mut(), 1);
            }
        }
    }
}

fn encode(original: &[ServerRule], expanded: endpoints::Expansion) -> Vec<u8> {
    let mut bytes = (expanded.rules.len() as u32).to_be_bytes().to_vec();
    for (rule, index) in expanded.rules.iter().zip(&expanded.origins) {
        debug_assert!(original.get(*index).is_some());
        let RuleTarget::Upstream(endpoint) = &rule.target else {
            unreachable!()
        };
        let ServerHost::Address(address) = endpoint.host else {
            unreachable!()
        };
        bytes.extend_from_slice(&(*index as u32).to_be_bytes());
        match address {
            IpAddr::V4(address) => {
                bytes.push(4);
                bytes.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                bytes.push(6);
                bytes.extend_from_slice(&address.octets());
            }
        }
        bytes.extend_from_slice(&endpoint.scope_id.unwrap_or(u32::MAX).to_be_bytes());
    }
    if let Some(error) = expanded.error {
        bytes.extend_from_slice(error.0.as_bytes());
    }
    bytes
}

fn decode(original: &[ServerRule], bytes: &[u8]) -> Result<LookupResult, ()> {
    fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], ()> {
        if bytes.len() < length {
            return Err(());
        }
        let (value, tail) = bytes.split_at(length);
        *bytes = tail;
        Ok(value)
    }
    fn integer(bytes: &mut &[u8]) -> Result<u32, ()> {
        Ok(u32::from_be_bytes(
            take(bytes, 4)?.try_into().map_err(|_| ())?,
        ))
    }
    let mut bytes = bytes;
    let count = integer(&mut bytes)?;
    let mut rules = Vec::new();
    for _ in 0..count {
        let index = integer(&mut bytes)? as usize;
        let family = take(&mut bytes, 1)?[0];
        let address = match family {
            4 => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(take(&mut bytes, 4)?).map_err(|_| ())?,
            )),
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(take(&mut bytes, 16)?).map_err(|_| ())?,
            )),
            _ => return Err(()),
        };
        let scope = integer(&mut bytes)?;
        let mut rule = original.get(index).ok_or(())?.clone();
        let RuleTarget::Upstream(endpoint) = &mut rule.target else {
            return Err(());
        };
        endpoint.host = ServerHost::Address(address);
        endpoint.scope_id = (scope != u32::MAX).then_some(scope);
        rules.push(rule);
    }
    let error = (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned());
    Ok(LookupResult { rules, error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{dns::parse_rules, EncodedArg};
    #[test]
    fn result_roundtrip_preserves_partial_error_and_rejects_truncation() {
        let original =
            parse_rules(b"server", &EncodedArg::command_line(b"/one/two/127.0.0.2")).unwrap();
        let mut expanded = endpoints::resolve_rules(&original, false);
        expanded.error = Some(crate::config::Error("bad interface name"));
        let bytes = encode(&original, expanded);
        let result = decode(&original, &bytes).unwrap();
        assert_eq!(result.rules, original);
        assert_eq!(result.error.as_deref(), Some("bad interface name"));
        assert!(decode(&original, &bytes[..5]).is_err());
    }
}
