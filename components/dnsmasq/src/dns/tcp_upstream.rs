//! Per-downstream-session upstream TCP transport, from forward.c::tcp_talk.
//!
//! The caller selects a RoutingTable group, decorates the query, and applies
//! process/reply/cache policy to the returned packet. RCODEs are returned as
//! received: TCP does not inherit UDP's SERVFAIL/REFUSED retry state machine.

use super::forward::{GroupId, Question, ServerGroup, ServerId};
use super::service::encode_tcp_frame;
use super::upstream::source_sockets::SourceSpec;
use super::wire::{Header, WireError};
use dnsmasq_platform::poll::{poll_fds, PollFd};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const CANCEL_INTERVAL: Duration = Duration::from_millis(50);

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "tcp_connect.rs"]
mod tcp_connect;
#[path = "tcp_exchange.rs"]
mod tcp_exchange;
use tcp_exchange::Exchange;

#[derive(Clone, Copy, Debug)]
pub struct TcpOptions {
    pub connect_timeout: Duration,
    pub write_timeout: Duration,
    pub read_timeout: Duration,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
pub enum TcpError {
    InvalidOptions,
    BoundSocketUnsupported,
    InvalidQuery,
    Wire(WireError),
    UnknownGroup,
    NoReply,
    Deadline,
    Cancelled,
    Busy,
    NotStarted,
}

impl From<WireError> for TcpError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

struct Connection {
    stream: TcpStream,
    had_reply: bool,
}

struct Server {
    id: ServerId,
    address: SocketAddr,
    source: Option<SourceSpec>,
    connection: Option<Connection>,
}

struct Group {
    servers: Vec<Server>,
    strict_order: bool,
    last_connected: usize,
}

/// Readiness required to advance an in-flight exchange. The fd is borrowed
/// until the next start/step/clear call; the caller must not close it. A negative
/// fd means yield to the owner loop and step again at `deadline`.
#[derive(Clone, Copy, Debug)]
pub struct TcpWait {
    pub fd: std::os::fd::RawFd,
    pub events: i16,
    pub deadline: Instant,
}

#[derive(Debug)]
pub enum TcpProgress {
    Pending(TcpWait),
    Complete(Vec<u8>),
}

/// One instance belongs to one accepted downstream TCP connection. Dropping
/// it or calling `clear` closes every persistent upstream connection. There
/// are no background threads or tasks and no sharing between client sessions.
pub struct TcpUpstream {
    groups: HashMap<GroupId, Group>,
    options: TcpOptions,
    pending: Option<Exchange>,
    connection_failures: Vec<SocketAddr>,
    reply_server: Option<SocketAddr>,
}

impl TcpUpstream {
    pub fn new(
        groups: impl IntoIterator<Item = ServerGroup>,
        options: TcpOptions,
    ) -> Result<Self, TcpError> {
        if options.connect_timeout.is_zero()
            || options.write_timeout.is_zero()
            || options.read_timeout.is_zero()
        {
            return Err(TcpError::InvalidOptions);
        }
        let mut configured = HashMap::new();
        for group in groups {
            if group
                .servers
                .iter()
                .any(|server| server.bound_socket.is_some())
            {
                return Err(TcpError::BoundSocketUnsupported);
            }
            configured.insert(
                group.id,
                Group {
                    strict_order: group.strict_order,
                    last_connected: 0,
                    servers: group
                        .servers
                        .into_iter()
                        .map(|server| Server {
                            id: server.id,
                            source: None,
                            address: server.address,
                            connection: None,
                        })
                        .collect(),
                },
            );
        }
        Ok(Self {
            groups: configured,
            options,
            pending: None,
            connection_failures: Vec::new(),
            reply_server: None,
        })
    }

    /// Call on the newly accepted downstream snapshot. Existing connections
    /// continue to own their original source and destination until close.
    pub fn set_source_bindings(&mut self, bindings: &HashMap<ServerId, SourceSpec>) {
        for server in self
            .groups
            .values_mut()
            .flat_map(|group| &mut group.servers)
        {
            server.source = bindings.get(&server.id).cloned();
        }
    }

    /// Seed a newly accepted child's first choice from the parent's successful
    /// UDP forwarding state, as C inherits serverarray[first]->last_server.
    pub fn set_preferred_servers(
        &mut self,
        preferred: impl IntoIterator<Item = (GroupId, ServerId)>,
    ) {
        for (id, server) in preferred {
            if let Some(group) = self.groups.get_mut(&id) {
                if let Some(index) = group.servers.iter().position(|entry| entry.id == server) {
                    group.last_connected = index;
                }
            }
        }
    }

    pub fn socket_count(&self) -> usize {
        self.groups
            .values()
            .flat_map(|group| &group.servers)
            .filter(|server| server.connection.is_some())
            .count()
    }

    pub fn clear(&mut self) {
        self.pending = None;
        self.reply_server = None;
        for server in self
            .groups
            .values_mut()
            .flat_map(|group| &mut group.servers)
        {
            server.connection = None;
        }
    }

    /// Start one exchange without waiting for connect, read or write readiness.
    /// A downstream session may have one exchange in flight. Completed replies
    /// retain their upstream connection for the next request, as tcp_talk does.
    pub fn start(
        &mut self,
        group: GroupId,
        query: &[u8],
        deadline: Instant,
    ) -> Result<TcpProgress, TcpError> {
        if self.pending.is_some() {
            return Err(TcpError::Busy);
        }
        check_bound(deadline, &|| false)?;
        let header = Header::parse(query)?;
        if query.len() > u16::MAX as usize || header.flags & 0x8000 != 0 || header.opcode() != 0 {
            return Err(TcpError::InvalidQuery);
        }
        let question = Question::parse(query)?;
        let frame = encode_tcp_frame(query).map_err(|_| TcpError::InvalidQuery)?;
        let configured = self.groups.get(&group).ok_or(TcpError::UnknownGroup)?;
        let start = if configured.strict_order {
            0
        } else {
            configured.last_connected
        };
        self.pending = Some(Exchange::new(group, question, frame, start, deadline));
        self.step()
    }

    /// Advance only currently possible I/O, then return its fd interest and
    /// next absolute timer. Call after readiness or a timer, and on each owner
    /// loop turn if convenient. No poll, sleep, timeout connect or thread runs
    /// here. A fixed I/O budget keeps a writable peer from owning the loop.
    pub fn step(&mut self) -> Result<TcpProgress, TcpError> {
        let mut pending = self.pending.take().ok_or(TcpError::NotStarted)?;
        let result = pending.step(
            &mut self.groups,
            self.options,
            &mut self.connection_failures,
        );
        if matches!(result, Ok(TcpProgress::Complete(_))) {
            self.reply_server = pending.reply_server(&self.groups);
        }
        if matches!(result, Ok(TcpProgress::Pending(_))) {
            self.pending = Some(pending);
        } else if matches!(result, Err(TcpError::Deadline | TcpError::Cancelled)) {
            self.clear();
        }
        result
    }

    pub fn take_connection_failures(&mut self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.connection_failures)
    }

    /// tcp_request logs the server only after tcp_talk returns a valid reply.
    pub fn take_reply_server(&mut self) -> Option<SocketAddr> {
        self.reply_server.take()
    }

    /// Compatibility wrapper for synchronous callers. The production single
    /// poll owner uses start/step instead; both paths execute the same state
    /// machine and preserve C's question, reuse and failover rules.
    pub fn exchange(
        &mut self,
        group: GroupId,
        query: &[u8],
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TcpError> {
        if let Err(error) = check_bound(deadline, stopped) {
            self.clear();
            return Err(error);
        }
        let mut progress = self.start(group, query, deadline)?;
        loop {
            match progress {
                TcpProgress::Complete(reply) => return Ok(reply),
                TcpProgress::Pending(wait) => {
                    if let Err(error) = check_bound(deadline, stopped) {
                        self.clear();
                        return Err(error);
                    }
                    let timeout = wait
                        .deadline
                        .saturating_duration_since(Instant::now())
                        .min(CANCEL_INTERVAL);
                    let mut poll = [PollFd {
                        fd: wait.fd,
                        events: wait.events,
                        revents: 0,
                    }];
                    if poll_fds(&mut poll, timeout.as_millis() as i32).is_err() {
                        self.clear();
                        return Err(TcpError::NoReply);
                    }
                    if let Err(error) = check_bound(deadline, stopped) {
                        self.clear();
                        return Err(error);
                    }
                    progress = self.step()?;
                }
            }
        }
    }
}

fn matches_question(reply: &[u8], question: &Question) -> bool {
    Header::parse(reply).is_ok_and(|header| header.flags & 0x8000 != 0 && header.questions == 1)
        && Question::parse(reply).is_ok_and(|candidate| {
            candidate.name.eq_ignore_ascii_case(&question.name)
                && candidate.rrtype == question.rrtype
                && candidate.class == question.class
        })
}

fn check_bound(deadline: Instant, stopped: &dyn Fn() -> bool) -> Result<(), TcpError> {
    if stopped() {
        Err(TcpError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(TcpError::Deadline)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "tcp_upstream_tests.rs"]
mod tests;
