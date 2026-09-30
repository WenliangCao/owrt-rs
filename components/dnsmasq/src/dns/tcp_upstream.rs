//! Per-downstream-session upstream TCP transport, from forward.c::tcp_talk.
//!
//! The caller selects a RoutingTable group, decorates the query, and applies
//! process/reply/cache policy to the returned packet. RCODEs are returned as
//! received: TCP does not inherit UDP's SERVFAIL/REFUSED retry state machine.

use super::forward::{GroupId, Question, ServerGroup};
use super::service::encode_tcp_frame;
use super::wire::{Header, WireError};
use owrt_ubus::sys::{poll_fds, PollFd, POLLIN, POLLOUT};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

const CANCEL_INTERVAL: Duration = Duration::from_millis(50);

#[cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "tcp_connect.rs"]
mod tcp_connect;

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
    address: SocketAddr,
    connection: Option<Connection>,
}

struct Group {
    servers: Vec<Server>,
    strict_order: bool,
    last_connected: usize,
}

/// One instance belongs to one accepted downstream TCP connection. Dropping
/// it or calling `clear` closes every persistent upstream connection. There
/// are no background threads or tasks and no sharing between client sessions.
pub struct TcpUpstream {
    groups: HashMap<GroupId, Group>,
    options: TcpOptions,
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
        })
    }

    pub fn socket_count(&self) -> usize {
        self.groups
            .values()
            .flat_map(|group| &group.servers)
            .filter(|server| server.connection.is_some())
            .count()
    }

    pub fn clear(&mut self) {
        for server in self
            .groups
            .values_mut()
            .flat_map(|group| &mut group.servers)
        {
            server.connection = None;
        }
    }

    /// Exchange one query using C's persistent-connection and failover rules.
    /// `deadline` is the containing downstream connection's absolute bound.
    /// Read/write waits observe cancellation at least every 50 ms. Linux
    /// aarch64/x86_64 connects use the same cancellation interval; other hosts
    /// use std's bounded connect, which cannot observe cancellation mid-call.
    ///
    /// As in tcp_talk, reply acceptance checks QR and the complete question;
    /// it does not introduce a transaction-ID check absent from the C path.
    pub fn exchange(
        &mut self,
        group: GroupId,
        query: &[u8],
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TcpError> {
        let result = self.exchange_inner(group, query, deadline, stopped);
        if matches!(result, Err(TcpError::Cancelled | TcpError::Deadline)) {
            self.clear();
        }
        result
    }

    fn exchange_inner(
        &mut self,
        group: GroupId,
        query: &[u8],
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TcpError> {
        check_bound(deadline, stopped)?;
        let header = Header::parse(query)?;
        if query.len() > u16::MAX as usize || header.flags & 0x8000 != 0 || header.opcode() != 0 {
            return Err(TcpError::InvalidQuery);
        }
        let question = Question::parse(query)?;
        let frame = encode_tcp_frame(query).map_err(|_| TcpError::InvalidQuery)?;
        let group = self.groups.get_mut(&group).ok_or(TcpError::UnknownGroup)?;
        let start = if group.strict_order {
            0
        } else {
            group.last_connected
        };
        for offset in 0..group.servers.len() {
            let index = (start + offset) % group.servers.len();
            let server = &mut group.servers[index];
            loop {
                check_bound(deadline, stopped)?;
                if server.connection.is_none() {
                    let timeout = self
                        .options
                        .connect_timeout
                        .min(deadline.saturating_duration_since(Instant::now()));
                    if timeout.is_zero() {
                        return Err(TcpError::Deadline);
                    }
                    let stream = match connect_until(server.address, timeout, deadline, stopped) {
                        Ok(stream) => stream,
                        Err(TcpError::NoReply) => {
                            check_bound(deadline, stopped)?;
                            break;
                        }
                        Err(error) => return Err(error),
                    };
                    check_bound(deadline, stopped)?;
                    if stream.set_nonblocking(true).is_err() {
                        break;
                    }
                    server.connection = Some(Connection {
                        stream,
                        had_reply: false,
                    });
                    group.last_connected = index;
                }
                let connection = server.connection.as_mut().expect("connection established");
                match exchange_frame(
                    &mut connection.stream,
                    &frame,
                    self.options,
                    deadline,
                    stopped,
                ) {
                    Ok(reply) => {
                        // Question mismatches try another server while retaining
                        // this connected fd, exactly as tcp_talk does.
                        if !matches_question(&reply, &question) {
                            break;
                        }
                        connection.had_reply = true;
                        return Ok(reply);
                    }
                    Err(TcpError::Cancelled) => return Err(TcpError::Cancelled),
                    Err(TcpError::Deadline) => return Err(TcpError::Deadline),
                    Err(_) => {
                        let retry = connection.had_reply;
                        server.connection = None;
                        // A connection that previously returned data is allowed
                        // one fresh reconnect. A fresh failure advances server.
                        if !retry {
                            break;
                        }
                    }
                }
            }
        }
        Err(TcpError::NoReply)
    }
}

fn connect_until(
    address: SocketAddr,
    timeout: Duration,
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
) -> Result<TcpStream, TcpError> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        tcp_connect::connect_until(address, Instant::now() + timeout, deadline, stopped)
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let result = TcpStream::connect_timeout(&address, timeout).map_err(|_| TcpError::NoReply);
        check_bound(deadline, stopped)?;
        result
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

fn exchange_frame(
    stream: &mut TcpStream,
    frame: &[u8],
    options: TcpOptions,
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
) -> Result<Vec<u8>, TcpError> {
    let mut remaining = frame;
    let mut idle = Instant::now() + options.write_timeout;
    while !remaining.is_empty() {
        check_bound(deadline, stopped)?;
        match stream.write(remaining) {
            Ok(0) => return Err(TcpError::NoReply),
            Ok(count) => {
                remaining = &remaining[count..];
                idle = Instant::now() + options.write_timeout;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(stream, POLLOUT, idle, deadline, stopped)?;
            }
            Err(_) => return Err(TcpError::NoReply),
        }
    }
    let mut prefix = [0; 2];
    read_exact(stream, &mut prefix, options.read_timeout, deadline, stopped)?;
    // The wire u16 bounds allocation before any body is read. Zero-length
    // frames proceed to question validation, as C's read_write(0) does.
    let mut reply = vec![0; usize::from(u16::from_be_bytes(prefix))];
    read_exact(stream, &mut reply, options.read_timeout, deadline, stopped)?;
    Ok(reply)
}

fn read_exact(
    stream: &mut TcpStream,
    mut output: &mut [u8],
    timeout: Duration,
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
) -> Result<(), TcpError> {
    let mut idle = Instant::now() + timeout;
    while !output.is_empty() {
        check_bound(deadline, stopped)?;
        match stream.read(output) {
            Ok(0) => return Err(TcpError::NoReply),
            Ok(count) => {
                output = &mut output[count..];
                idle = Instant::now() + timeout;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(stream, POLLIN, idle, deadline, stopped)?;
            }
            Err(_) => return Err(TcpError::NoReply),
        }
    }
    Ok(())
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

fn wait_ready(
    stream: &TcpStream,
    events: i16,
    idle: Instant,
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
) -> Result<(), TcpError> {
    check_bound(deadline, stopped)?;
    let remaining = idle.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(TcpError::NoReply);
    }
    let wait = remaining
        .min(deadline.saturating_duration_since(Instant::now()))
        .min(CANCEL_INTERVAL);
    let mut fd = [PollFd {
        fd: stream.as_raw_fd(),
        events,
        revents: 0,
    }];
    poll_fds(&mut fd, wait.as_millis().max(1) as i32).map_err(|_| TcpError::NoReply)?;
    Ok(())
}

#[cfg(test)]
#[path = "tcp_upstream_tests.rs"]
mod tests;
