//! One nonblocking result pipe for the restricted libc hostname worker.
//! The daemon remains single-threaded and polls this pipe. No live owner call
//! invokes getaddrinfo or a blocking waitpid.
use super::{endpoints, RuleTarget, ServerHost, ServerRule};
use dnsmasq_platform::poll::PollFd;
use rustix::process::{Pid, Signal, WaitOptions};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

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
    /// The fixed worker receives only owned rules and its result writer.
    /// No live service owner calls the blocking resolver or a blocking wait.
    pub fn start(rules: Vec<ServerRule>, reverse: bool) -> io::Result<Self> {
        // All fields are owned names/IPs/scalars, not references or FD owners.
        // The poll turn holds no lock/stdio guard and worker_entry never
        // reaches the service's discarded owner graph or reinstalls handlers.
        let ((rules, _), pid, reader) =
            dnsmasq_platform::process::spawn_lookup((rules, reverse), worker_entry)?;
        Ok(Self {
            pid: Some(pid.as_raw_nonzero().get()),
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
                let _ = rustix::process::kill_process(Pid::from_raw(pid).unwrap(), Signal::KILL);
            }
        }
    }

    /// At most one 4096-byte read and one WNOHANG reap per owner turn.
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
            match rustix::process::waitpid(Pid::from_raw(pid), WaitOptions::NOHANG) {
                Ok(Some((_, status))) => {
                    self.pid = None;
                    self.status = Some(status.as_raw());
                }
                Err(rustix::io::Errno::CHILD) => {
                    self.pid = None;
                    self.failure = Some("endpoint resolver child was already reaped".into());
                }
                _ => return None,
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
            let _ = rustix::process::kill_process(Pid::from_raw(pid).unwrap(), Signal::KILL);
            let _ = rustix::process::waitpid(Pid::from_raw(pid), WaitOptions::NOHANG);
        }
    }
}

fn worker_entry((rules, reverse): (Vec<ServerRule>, bool), mut writer: File) -> i32 {
    let expanded = endpoints::resolve_rules(&rules, reverse);
    i32::from(writer.write_all(&encode(&rules, expanded)).is_err())
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
    fn finish(lookup: &mut EndpointLookup) -> LookupResult {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let before = lookup.bytes.len();
            let result = lookup.step();
            assert!(lookup.bytes.len() - before <= 4096);
            if let Some(result) = result {
                return result;
            }
            assert!(std::time::Instant::now() < deadline, "lookup timeout");
            let mut fds = Vec::new();
            lookup.append_poll_fds(&mut fds);
            dnsmasq_platform::poll::poll_fds(&mut fds, 10).unwrap();
        }
    }

    #[test]
    fn fork_lookup_preserves_rules_and_cancel_reaps_before_result() {
        let mut rules = parse_rules(
            b"server",
            &EncodedArg::command_line(b"/one/two/127.0.0.2#5353@192.0.2.1#5300"),
        )
        .unwrap();
        for rule in &mut rules {
            let RuleTarget::Upstream(endpoint) = &mut rule.target else {
                unreachable!()
            };
            endpoint.host = ServerHost::Name(b"127.0.0.2".to_vec());
        }
        let expected = endpoints::resolve_rules(&rules, false);
        let mut lookup = EndpointLookup::start(rules.clone(), false).unwrap();
        let result = finish(&mut lookup);
        assert_eq!(result.rules, expected.rules);
        assert!(result.error.is_none());
        assert!(lookup.pid.is_none());

        let mut cancelled = EndpointLookup::start(rules, false).unwrap();
        cancelled.cancel();
        let result = finish(&mut cancelled);
        assert!(result.rules.is_empty() && result.error.is_none());
        assert!(cancelled.pid.is_none());
    }

    #[test]
    fn large_result_uses_one_read_interest_and_bounded_owner_turns() {
        let one = parse_rules(b"server", &EncodedArg::command_line(b"/one/127.0.0.2"))
            .unwrap()
            .remove(0);
        let rules = vec![one; 512];
        let mut lookup = EndpointLookup::start(rules.clone(), false).unwrap();
        let mut fds = Vec::new();
        lookup.append_poll_fds(&mut fds);
        assert_eq!(fds.len(), 1);
        assert_eq!(fds[0].events, 1);
        let result = finish(&mut lookup);
        assert_eq!(result.rules, rules);
        assert!(lookup.bytes.len() > 4096);
        assert!(result.error.is_none());
    }

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
