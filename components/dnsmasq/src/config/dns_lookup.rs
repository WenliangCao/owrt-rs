//! Bounded request/result pipes for a self-exec libc hostname lookup child.
//! The daemon remains single-threaded and polls this pipe. No live owner call
//! invokes getaddrinfo or a blocking waitpid.
use super::{
    endpoints, DomainPattern, RuleTarget, ServerEndpoint, ServerHost, ServerRule, SourceBinding,
};
use dnsmasq_platform::poll::PollFd;
use rustix::process::{Pid, Signal, WaitOptions};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd};
use std::process::Command;

const INTERNAL_LOOKUP: &str = "--dnsmasq-internal-lookup-v1";
const MAX_REQUEST: usize = 4 * 1024 * 1024;
#[cfg(test)]
const TEST_CHANNELS: &str = "DNSMASQ_TEST_LOOKUP_CHANNELS";

/// Called before normal CLI parsing or service resource creation.
pub fn dispatch_internal_lookup() -> Option<i32> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new(INTERNAL_LOOKUP)) {
        return None;
    }
    let descriptors = args
        .next()
        .and_then(|value| value.to_str().map(str::to_owned));
    if args.next().is_some() {
        return Some(1);
    }
    Some(descriptors.as_deref().map_or(1, dispatch_channels))
}

fn dispatch_channels(descriptors: &str) -> i32 {
    let Some((input, output)) = descriptors.split_once(':') else {
        return 1;
    };
    let Ok(input) = input.parse() else {
        return 1;
    };
    let Ok(output) = output.parse() else {
        return 1;
    };
    let Ok(mut input) = dnsmasq_platform::process::inherited_pipe(input, true) else {
        return 1;
    };
    let Ok(mut output) = dnsmasq_platform::process::inherited_pipe(output, false) else {
        return 1;
    };
    let Ok((rules, reverse)) = read_request(&mut input) else {
        return 1;
    };
    if rules
        .first()
        .is_some_and(|rule| !matches!(rule.target, RuleTarget::Upstream(_)))
    {
        return 1;
    }
    let expanded = endpoints::resolve_rules(&rules, reverse);
    i32::from(output.write_all(&encode(&rules, expanded)).is_err())
}

fn nonblocking(fd: impl AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    Ok(rustix::fs::fcntl_setfl(
        fd,
        flags | rustix::fs::OFlags::NONBLOCK,
    )?)
}

pub struct LookupResult {
    pub rules: Vec<ServerRule>,
    pub error: Option<String>,
}

pub struct EndpointLookup {
    pid: Option<i32>,
    reader: File,
    writer: Option<File>,
    request: Vec<u8>,
    written: usize,
    bytes: Vec<u8>,
    eof: bool,
    cancelled: bool,
    status: Option<i32>,
    failure: Option<String>,
    rules: Vec<ServerRule>,
}

impl EndpointLookup {
    /// The isolated exec image inherits only its private pipes. Neither the
    /// child resolver nor its response writer can block the service owner.
    pub fn start(rules: Vec<ServerRule>, reverse: bool) -> io::Result<Self> {
        let request = encode_request(&rules, reverse)?;
        let (request_read, request_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        let (result_read, result_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        nonblocking(&request_write)?;
        nonblocking(&result_read)?;
        let descriptors = format!("{}:{}", request_read.as_raw_fd(), result_write.as_raw_fd());
        let mut command = Command::new("/proc/self/exe");
        #[cfg(not(test))]
        command.arg(INTERNAL_LOOKUP).arg(&descriptors);
        #[cfg(test)]
        command
            .args([
                "--exact",
                "config::dns::lookup::tests::internal_lookup_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(TEST_CHANNELS, &descriptors);
        dnsmasq_platform::process::isolated_lookup_command(
            &mut command,
            request_read,
            result_write,
        )?;
        let process = command.spawn()?;
        let pid = i32::try_from(process.id()).map_err(|_| invalid_request())?;
        drop(command);
        Ok(Self {
            pid: Some(pid),
            reader: File::from(result_read),
            writer: Some(File::from(request_write)),
            request,
            written: 0,
            bytes: Vec::new(),
            eof: false,
            cancelled: false,
            status: None,
            failure: None,
            rules,
        })
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<PollFd>) {
        if !self.cancelled {
            if !self.eof {
                fds.push(PollFd {
                    fd: self.reader.as_raw_fd(),
                    events: 1,
                    revents: 0,
                });
            }
            if let Some(writer) = &self.writer {
                fds.push(PollFd {
                    fd: writer.as_raw_fd(),
                    events: 4,
                    revents: 0,
                });
            }
        }
    }

    pub fn cancel(&mut self) {
        if !self.cancelled {
            self.cancelled = true;
            self.writer.take();
            self.request.clear();
            if let Some(pid) = self.pid {
                let _ = rustix::process::kill_process(Pid::from_raw(pid).unwrap(), Signal::KILL);
            }
        }
    }

    /// At most one 4096-byte write/read and one WNOHANG reap per owner turn.
    pub fn step(&mut self) -> Option<LookupResult> {
        if let Some(writer) = &mut self.writer {
            let end = self.request.len().min(self.written + 4096);
            match writer.write(&self.request[self.written..end]) {
                Ok(0) => {
                    self.failure = Some("endpoint resolver request pipe: zero write".into());
                    self.cancel();
                }
                Ok(length) => {
                    self.written += length;
                    if self.written == self.request.len() {
                        self.writer.take();
                        self.request.clear();
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => {
                    self.failure = Some(format!("endpoint resolver request pipe: {error}"));
                    self.cancel();
                }
            }
        }
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

fn invalid_request() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid endpoint resolver request",
    )
}

fn request_bytes(output: &mut Vec<u8>, bytes: Option<&[u8]>) -> io::Result<()> {
    match bytes {
        Some(bytes) => {
            if output.len().saturating_add(4).saturating_add(bytes.len()) > MAX_REQUEST {
                return Err(invalid_request());
            }
            output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            output.extend_from_slice(bytes);
        }
        None => output.extend_from_slice(&u32::MAX.to_be_bytes()),
    }
    Ok(())
}

fn request_ip(output: &mut Vec<u8>, address: Option<IpAddr>) {
    match address {
        None => output.push(0),
        Some(IpAddr::V4(address)) => {
            output.push(4);
            output.extend(address.octets());
        }
        Some(IpAddr::V6(address)) => {
            output.push(6);
            output.extend(address.octets());
        }
    }
}

/// This transport preserves the original typed rules. The child executes the
/// single existing expansion implementation; it never parses a second syntax.
fn encode_request(rules: &[ServerRule], reverse: bool) -> io::Result<Vec<u8>> {
    let count = u32::try_from(rules.len()).map_err(|_| invalid_request())?;
    let mut output = b"DNSLKP01".to_vec();
    output.push(u8::from(reverse));
    output.extend(count.to_be_bytes());
    for rule in rules {
        output.push(
            u8::from(rule.domain.wildcard)
                | (u8::from(rule.domain.wildcard_dot) << 1)
                | (u8::from(rule.domain.dotless) << 2),
        );
        request_bytes(&mut output, Some(&rule.domain.suffix))?;
        match &rule.target {
            RuleTarget::Upstream(endpoint) => {
                output.push(0);
                match &endpoint.host {
                    ServerHost::Address(address) => request_ip(&mut output, Some(*address)),
                    ServerHost::Name(name) => {
                        output.push(0);
                        request_bytes(&mut output, Some(name))?;
                    }
                }
                output.extend(endpoint.port.to_be_bytes());
                request_bytes(&mut output, endpoint.scope.as_deref())?;
                output.push(u8::from(endpoint.scope_id.is_some()));
                if let Some(index) = endpoint.scope_id {
                    output.extend(index.to_be_bytes());
                }
                output.push(u8::from(endpoint.source.is_some()));
                if let Some(source) = &endpoint.source {
                    request_ip(&mut output, source.address);
                    request_bytes(&mut output, source.interface.as_deref())?;
                    output.extend(source.port.to_be_bytes());
                }
            }
            RuleTarget::DefaultResolvers => output.push(1),
            RuleTarget::LocalOnly => output.push(2),
            RuleTarget::Literal(address) => {
                output.push(3);
                request_ip(&mut output, Some(*address));
            }
            RuleTarget::ZeroAddresses => output.push(4),
        }
        if output.len() > MAX_REQUEST {
            return Err(invalid_request());
        }
    }
    let mut framed = (output.len() as u32).to_be_bytes().to_vec();
    framed.extend(output);
    Ok(framed)
}

struct RequestReader<'a>(&'a [u8]);
impl<'a> RequestReader<'a> {
    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let (head, tail) = self
            .0
            .split_at_checked(length)
            .ok_or_else(invalid_request)?;
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn boolean(&mut self) -> io::Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid_request()),
        }
    }
    fn short(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn integer(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<Option<Vec<u8>>> {
        let length = self.integer()?;
        if length == u32::MAX {
            Ok(None)
        } else {
            Ok(Some(self.take(length as usize)?.to_vec()))
        }
    }
    fn ip(&mut self, family: u8) -> io::Result<Option<IpAddr>> {
        match family {
            0 => Ok(None),
            4 => Ok(Some(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(self.take(4)?).unwrap(),
            )))),
            6 => Ok(Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(self.take(16)?).unwrap(),
            )))),
            _ => Err(invalid_request()),
        }
    }
}

fn decode_request(bytes: &[u8]) -> io::Result<(Vec<ServerRule>, bool)> {
    if bytes.len() > MAX_REQUEST {
        return Err(invalid_request());
    }
    let mut input = RequestReader(bytes);
    if input.take(8)? != b"DNSLKP01" {
        return Err(invalid_request());
    }
    let reverse = input.boolean()?;
    let count = input.integer()? as usize;
    // Every rule contains at least flags, a four-byte name size and a target.
    // Reject forged counts before allocating typed rules.
    if count > input.0.len() / 6 {
        return Err(invalid_request());
    }
    let mut rules = Vec::new();
    for _ in 0..count {
        let flags = input.byte()?;
        if flags > 7 {
            return Err(invalid_request());
        }
        let domain = DomainPattern {
            suffix: input.bytes()?.ok_or_else(invalid_request)?,
            wildcard: flags & 1 != 0,
            wildcard_dot: flags & 2 != 0,
            dotless: flags & 4 != 0,
        };
        let target = match input.byte()? {
            0 => {
                let family = input.byte()?;
                let host = match input.ip(family)? {
                    Some(address) => ServerHost::Address(address),
                    None => ServerHost::Name(input.bytes()?.ok_or_else(invalid_request)?),
                };
                let port = input.short()?;
                let scope = input.bytes()?;
                let scope_id = if input.boolean()? {
                    Some(input.integer()?)
                } else {
                    None
                };
                let source = if input.boolean()? {
                    let family = input.byte()?;
                    Some(SourceBinding {
                        address: input.ip(family)?,
                        interface: input.bytes()?,
                        port: input.short()?,
                    })
                } else {
                    None
                };
                RuleTarget::Upstream(ServerEndpoint {
                    host,
                    port,
                    scope,
                    scope_id,
                    source,
                })
            }
            1 => RuleTarget::DefaultResolvers,
            2 => RuleTarget::LocalOnly,
            3 => {
                let family = input.byte()?;
                RuleTarget::Literal(input.ip(family)?.ok_or_else(invalid_request)?)
            }
            4 => RuleTarget::ZeroAddresses,
            _ => return Err(invalid_request()),
        };
        rules.push(ServerRule { domain, target });
    }
    if !input.0.is_empty() {
        return Err(invalid_request());
    }
    Ok((rules, reverse))
}

fn read_request(input: &mut File) -> io::Result<(Vec<ServerRule>, bool)> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if !(13..=MAX_REQUEST).contains(&length) {
        return Err(invalid_request());
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    decode_request(&bytes)
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
    fn internal_lookup_entry() {
        if let Ok(descriptors) = std::env::var(TEST_CHANNELS) {
            std::process::exit(dispatch_channels(&descriptors));
        }
    }

    fn finish(lookup: &mut EndpointLookup) -> LookupResult {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(result) = lookup.step() {
                return result;
            }
            assert!(std::time::Instant::now() < deadline, "lookup timeout");
            let mut fds = Vec::new();
            lookup.append_poll_fds(&mut fds);
            dnsmasq_platform::poll::poll_fds(&mut fds, 10).unwrap();
        }
    }

    #[test]
    fn private_request_preserves_every_field_and_partial_result_origin() {
        let endpoint = ServerEndpoint {
            host: ServerHost::Name(b"upstream.example".to_vec()),
            port: 5353,
            scope: Some(b"scope-\xff".to_vec()),
            scope_id: Some(77),
            source: Some(SourceBinding {
                address: Some("2001:db8::5".parse().unwrap()),
                interface: Some(b"source-\xff".to_vec()),
                port: 5300,
            }),
        };
        let first = ServerRule {
            domain: DomainPattern {
                suffix: b".one.example".to_vec(),
                wildcard: true,
                wildcard_dot: true,
                dotless: false,
            },
            target: RuleTarget::Upstream(endpoint),
        };
        let mut second = first.clone();
        second.domain = DomainPattern {
            suffix: Vec::new(),
            wildcard: false,
            wildcard_dot: false,
            dotless: true,
        };
        let original = vec![first, second];
        for reverse in [false, true] {
            let framed = encode_request(&original, reverse).unwrap();
            let (transferred, actual_reverse) = decode_request(&framed[4..]).unwrap();
            assert_eq!((&transferred, actual_reverse), (&original, reverse));
            // A successful later-origin row followed by a scope error must
            // keep that original row's domain and complete source binding.
            let mut partial = transferred[1].clone();
            let RuleTarget::Upstream(endpoint) = &mut partial.target else {
                unreachable!()
            };
            endpoint.host = ServerHost::Address("192.0.2.53".parse().unwrap());
            endpoint.scope_id = None;
            let expanded = endpoints::Expansion {
                rules: vec![partial.clone()],
                origins: vec![1],
                error: Some(crate::config::Error("bad interface name")),
            };
            let result = decode(&original, &encode(&transferred, expanded)).unwrap();
            assert_eq!(result.rules, vec![partial]);
            assert_eq!(result.error.as_deref(), Some("bad interface name"));
        }
    }

    #[test]
    fn private_request_rejects_bad_header_flags_counts_and_truncation() {
        let rules = parse_rules(b"server", &EncodedArg::command_line(b"/one/127.0.0.2")).unwrap();
        let framed = encode_request(&rules, false).unwrap();
        let bytes = &framed[4..];
        for length in 0..bytes.len() {
            assert!(decode_request(&bytes[..length]).is_err());
        }
        for (index, value) in [(0, 0), (8, 2), (9, 255), (13, 8)] {
            let mut malformed = bytes.to_vec();
            malformed[index] = value;
            assert!(decode_request(&malformed).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
    }

    #[test]
    fn self_exec_lookup_preserves_rules_and_cancel_reaps_before_result() {
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
    fn large_request_uses_poll_write_interest_and_bounded_owner_turns() {
        let one = parse_rules(b"server", &EncodedArg::command_line(b"/one/127.0.0.2"))
            .unwrap()
            .remove(0);
        let rules = vec![one; 512];
        let mut lookup = EndpointLookup::start(rules.clone(), false).unwrap();
        assert!(lookup.request.len() > 4096);
        let mut fds = Vec::new();
        lookup.append_poll_fds(&mut fds);
        assert!(fds.iter().any(|fd| fd.events == 4));
        assert!(lookup.step().is_none());
        assert!(lookup.written <= 4096 && lookup.writer.is_some());
        let result = finish(&mut lookup);
        assert_eq!(result.rules, rules);
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
