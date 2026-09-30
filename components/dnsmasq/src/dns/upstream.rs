//! Nonblocking UDP transport for the forwarding dispatcher.
//!
//! `start_udp`, `poll` and `tick` keep a fixed monotonic deadline per query.
//! Every socket belongs to one transaction and is dropped on completion,
//! cancellation, expiry or I/O failure. Received packets are still **unchecked
//! by process_reply policy**: callers must apply address/rebind/cache/EDNS and
//! OpenWrt policies before replying to clients. TCP has no adapter here.

use super::forward::{
    Client, Flags, GroupId, QueryId, Random, Recipient, ReleaseReason, ReplyAction, Scope,
    SendPlan, ServerId, SocketToken, Submission, ABSOLUTE_TIMEOUT,
};
use super::forward_service::{DispatchError, ForwardDispatcher};
use super::wire::{Header, WireError};
use owrt_ubus::sys::{PollFd, POLLERR, POLLHUP, POLLIN};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RECEIVE_BUDGET: usize = 16;
const POLLNVAL: i16 = 0x20;

#[derive(Debug)]
pub enum ResolveError {
    Dispatch(DispatchError),
    Wire(WireError),
    Io(io::Error),
    Timeout,
    NoServer,
    /// A synchronous call must not consume another caller's asynchronous work.
    Busy,
    /// This transport owns random-port sockets; server-bound sockets need the
    /// daemon's socket allocator and are explicitly outside this adapter.
    BoundSocketUnsupported,
    Released(ReleaseReason),
}

impl From<DispatchError> for ResolveError {
    fn from(value: DispatchError) -> Self {
        Self::Dispatch(value)
    }
}
impl From<WireError> for ResolveError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}
impl From<io::Error> for ResolveError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// The ID, question, socket and upstream endpoint matched a pending query.
/// No claim is made about answer RDATA, rebind policy, subnet options, cache
/// insertion or the client-visible packet. In particular, this packet retains
/// the upstream ID/case/OPT until the caller performs reply processing.
#[derive(Debug)]
pub struct UncheckedReply {
    pub packet: Vec<u8>,
    /// Whether the authenticated UDP response carried DNS header TC.
    ///
    /// The exact OpenWrt `nodhcpv6` build has no `HAVE_DNSSEC`, so C returns
    /// this response downstream with TC set.  Keeping the classification at
    /// the transport boundary lets a future DNSSEC-enabled caller request
    /// TCP without treating a valid truncated response as an upstream error.
    pub truncated: bool,
    pub server: ServerId,
    pub flags: Flags,
    pub recipients: Vec<Recipient>,
}

/// Classify the DNS header's truncation bit after source/ID/question
/// authentication.  This helper deliberately does not alter forwarding
/// state: ordinary `nodhcpv6` callers deliver a truncated UDP response, while
/// a DNSSEC-enabled caller may use the result to start a separate TCP query.
pub fn udp_reply_is_truncated(packet: &[u8]) -> Result<bool, WireError> {
    Ok(Header::parse(packet)?.flags & 0x0200 != 0)
}

#[derive(Debug)]
pub struct UpstreamEvent {
    pub id: QueryId,
    pub result: Result<UncheckedReply, ResolveError>,
}

/// OS randomness is opened once per transport; failures propagate before a
/// query can be sent with a predictable ID.
pub struct OsRandom(File);
impl OsRandom {
    pub fn new() -> io::Result<Self> {
        File::open("/dev/urandom").map(Self)
    }
}
impl Random for OsRandom {
    fn next_u32(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.0.read_exact(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }
}

struct Transaction {
    deadline: Instant,
    sockets: HashMap<ServerId, SocketToken>,
}
struct OwnedSocket {
    query: QueryId,
    server: ServerId,
    socket: UdpSocket,
}

/// An event-driven UDP transport with a single-query convenience wrapper.
/// It neither delivers client responses nor performs automatic TCP fallback.
/// Query/socket counts are observable for resource tests; the dispatcher is
/// read-only to callers so transactions cannot bypass socket ownership.
pub struct UpstreamResolver<R = OsRandom> {
    dispatcher: ForwardDispatcher,
    random: R,
    transactions: HashMap<QueryId, Transaction>,
    sockets: HashMap<SocketToken, OwnedSocket>,
    events: VecDeque<UpstreamEvent>,
    timeout: Duration,
    clock_origin: Instant,
    next_socket: u64,
    receive_buffer: Vec<u8>,
}

impl UpstreamResolver<OsRandom> {
    pub fn new(dispatcher: ForwardDispatcher, timeout: Duration) -> io::Result<Self> {
        Self::with_random(dispatcher, OsRandom::new()?, timeout)
    }
}

impl<R: Random> UpstreamResolver<R> {
    pub fn with_random(
        mut dispatcher: ForwardDispatcher,
        random: R,
        timeout: Duration,
    ) -> io::Result<Self> {
        if timeout.is_zero() || !dispatcher.table().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport requires a nonzero timeout and an empty dispatcher",
            ));
        }
        if dispatcher
            .take_released()
            .iter()
            .any(|released| !released.sockets.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport cannot adopt caller-owned sockets",
            ));
        }
        Ok(Self {
            dispatcher,
            random,
            transactions: HashMap::new(),
            sockets: HashMap::new(),
            events: VecDeque::new(),
            timeout: timeout.min(Duration::from_secs(ABSOLUTE_TIMEOUT as u64)),
            clock_origin: Instant::now(),
            next_socket: 0,
            receive_buffer: vec![0; u16::MAX as usize],
        })
    }

    pub fn dispatcher(&self) -> &ForwardDispatcher {
        &self.dispatcher
    }
    pub fn pending_count(&self) -> usize {
        self.transactions.len()
    }
    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    /// Start/merge a UDP query. A duplicate keeps the first query's deadline.
    /// An immediate send failure leaves no transaction or socket behind.
    pub fn start_udp(
        &mut self,
        packet: &[u8],
        client: Client,
        group: GroupId,
        scope: Scope,
    ) -> Result<Submission, ResolveError> {
        self.run_timers();
        let selected = self
            .dispatcher
            .group(group)
            .ok_or(DispatchError::UnknownGroup(group))?;
        if selected
            .servers
            .iter()
            .any(|server| server.bound_socket.is_some())
        {
            return Err(ResolveError::BoundSocketUnsupported);
        }
        let submitted = self.dispatcher.submit(
            packet,
            client,
            group,
            scope,
            unix_seconds(),
            &mut self.random,
        );
        // submit may reclaim a different query when its C forwarding slot is
        // reused. Consume its release even if admission of this one failed.
        self.consume_releases();
        let submitted = submitted?;
        let id = submitted.id;
        self.transactions.entry(id).or_insert_with(|| Transaction {
            deadline: Instant::now() + self.timeout,
            sockets: HashMap::new(),
        });
        if let (Some(packet), Some(plan)) = (submitted.packet, submitted.send_plan) {
            if let Err(error) = self.send_plan(id, &packet, &plan) {
                self.cancel(id);
                return Err(error);
            }
        }
        Ok(Submission {
            id,
            kind: submitted.kind,
        })
    }

    /// Wait up to max_wait, process a bounded batch from every ready socket,
    /// then return all terminal events. EINTR, invalid packets and REFUSED
    /// wait states never restart a query's deadline.
    pub fn poll(&mut self, max_wait: Duration) -> io::Result<Vec<UpstreamEvent>> {
        self.poll_with_filter(max_wait, |_| false)
    }

    /// Poll upstream sockets while allowing the caller to reject a matched
    /// reply before it changes forwarding state.  dnsmasq's `ignore-address`
    /// path deliberately leaves the query pending so a later upstream or
    /// retry can still produce the client-visible result.
    pub fn poll_with_filter<F>(
        &mut self,
        max_wait: Duration,
        ignore: F,
    ) -> io::Result<Vec<UpstreamEvent>>
    where
        F: Fn(&[u8]) -> bool,
    {
        let call_deadline = Instant::now()
            .checked_add(max_wait)
            .unwrap_or_else(Instant::now);
        loop {
            self.run_timers();
            if !self.events.is_empty() || self.transactions.is_empty() {
                return Ok(self.events.drain(..).collect());
            }
            let mut tokens = Vec::with_capacity(self.sockets.len());
            let mut fds = Vec::with_capacity(self.sockets.len());
            for (&token, owned) in &self.sockets {
                tokens.push(token);
                fds.push(PollFd {
                    fd: owned.socket.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
            }
            let deadline = self.next_wakeup(call_deadline);
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(
                    !remaining.subsec_nanos().is_multiple_of(1_000_000),
                ))
                .min(i32::MAX as u128) as i32;
            match poll_once(&mut fds, millis) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    // poll-wide failures cannot leave hidden pending work.
                    self.clear();
                    return Err(error);
                }
                Ok(_) => {}
            }
            for (token, fd) in tokens.into_iter().zip(fds) {
                if fd.revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL) != 0 {
                    self.receive_ready(token, fd.revents, &ignore);
                }
            }
            self.run_timers();
            // One ready batch per call makes work bounded under continuous
            // input and gives a containing daemon its other work back.
            return Ok(self.events.drain(..).collect());
        }
    }

    /// Expire fixed deadlines and perform only configured fast-retry sends.
    /// A receive timeout by itself never becomes an UpstreamError retry.
    pub fn tick(&mut self) -> Vec<UpstreamEvent> {
        self.run_timers();
        self.events.drain(..).collect()
    }

    /// Cancel one transaction immediately, releasing every owned socket.
    /// Explicit cancellation does not enqueue a terminal event.
    pub fn cancel(&mut self, id: QueryId) -> bool {
        let existed = self.transactions.remove(&id).is_some();
        self.dispatcher.cancel(id);
        self.consume_releases();
        // Also remove a socket allocated before its first failed send, which
        // has not yet acquired a ForwardTable socket reference.
        self.sockets.retain(|_, owned| owned.query != id);
        existed
    }

    pub fn clear(&mut self) {
        let ids: Vec<_> = self.transactions.keys().copied().collect();
        for id in ids {
            self.cancel(id);
        }
        self.events.clear();
    }

    /// Convenience wrapper for one UDP query. Busy is returned before any
    /// mutation if asynchronous work or unconsumed events already exist.
    /// The result is still an UncheckedReply, never a client response.
    pub fn resolve_udp(
        &mut self,
        packet: &[u8],
        client: Client,
        group: GroupId,
        scope: Scope,
    ) -> Result<UncheckedReply, ResolveError> {
        if !self.transactions.is_empty() || !self.events.is_empty() {
            return Err(ResolveError::Busy);
        }
        let submission = self.start_udp(packet, client, group, scope)?;
        loop {
            if let Some(event) = self.poll(self.timeout)?.into_iter().next() {
                debug_assert_eq!(event.id, submission.id);
                return event.result;
            }
        }
    }

    fn milliseconds(&self) -> u32 {
        self.clock_origin.elapsed().as_millis() as u32
    }

    fn next_wakeup(&self, mut deadline: Instant) -> Instant {
        for transaction in self.transactions.values() {
            deadline = deadline.min(transaction.deadline);
        }
        let retry = self
            .dispatcher
            .table()
            .fast_retries(unix_seconds(), self.milliseconds());
        if !retry.due.is_empty() {
            return Instant::now();
        }
        if let Some(millis) = retry.next_ms {
            deadline = deadline.min(Instant::now() + Duration::from_millis(millis.into()));
        }
        deadline
    }

    fn run_timers(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .transactions
            .iter()
            .filter(|(_, transaction)| now >= transaction.deadline)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            self.fail(id, ResolveError::Timeout);
        }
        let now_ms = self.milliseconds();
        // Plan the due set once. One bad packet cannot prevent another pending
        // query's retry; each send either advances its delay or fails its own
        // transaction and releases its own sockets.
        let plans = match self.dispatcher.plan_retries(unix_seconds(), now_ms) {
            Ok(plans) => plans,
            Err(error) => {
                let ids: Vec<_> = self.transactions.keys().copied().collect();
                for id in ids {
                    self.fail(id, error.into());
                }
                Vec::new()
            }
        };
        for plan in plans {
            match self.send_plan(plan.id, &plan.packet, &plan.send_plan) {
                Ok(()) => self.dispatcher.retry_finished(plan.id),
                Err(error) => self.fail(plan.id, error),
            }
        }
        self.consume_releases();
    }

    fn socket_for(
        &mut self,
        id: QueryId,
        server: ServerId,
        address: SocketAddr,
    ) -> io::Result<SocketToken> {
        if let Some(&token) = self.transactions[&id].sockets.get(&server) {
            return Ok(token);
        }
        let socket = UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.set_nonblocking(true)?;
        self.next_socket = self
            .next_socket
            .checked_add(1)
            .ok_or_else(|| io::Error::other("upstream socket token exhausted"))?;
        let token = SocketToken(self.next_socket);
        self.sockets.insert(
            token,
            OwnedSocket {
                query: id,
                server,
                socket,
            },
        );
        self.transactions
            .get_mut(&id)
            .unwrap()
            .sockets
            .insert(server, token);
        Ok(token)
    }

    fn send_plan(
        &mut self,
        id: QueryId,
        packet: &[u8],
        plan: &SendPlan,
    ) -> Result<(), ResolveError> {
        if plan.exhausted || plan.candidates.is_empty() {
            return Err(ResolveError::NoServer);
        }
        let group_id = self
            .dispatcher
            .table()
            .get(id)
            .ok_or(ResolveError::Timeout)?
            .group;
        let mut last_error = ResolveError::NoServer;
        let mut sent = false;
        for &server in &plan.candidates {
            let Some(address) = self
                .dispatcher
                .group(group_id)
                .and_then(|group| {
                    group
                        .servers
                        .iter()
                        .find(|candidate| candidate.id == server)
                })
                .map(|server| server.address)
            else {
                continue;
            };
            let token = match self.socket_for(id, server, address) {
                Ok(token) => token,
                Err(error) => {
                    last_error = error.into();
                    continue;
                }
            };
            let result = self.sockets[&token].socket.send_to(packet, address);
            match result {
                Ok(length) if length == packet.len() => {
                    self.dispatcher
                        .note_sent(id, server, token, self.milliseconds());
                    sent = true;
                    if !plan.send_all {
                        break;
                    }
                }
                result => {
                    last_error = match result {
                        Err(error) => error.into(),
                        Ok(_) => {
                            io::Error::new(io::ErrorKind::WriteZero, "partial UDP send").into()
                        }
                    };
                    // Leave a previously referenced socket alive: an older
                    // successful send may still have a reply in flight. An
                    // unsent socket is reclaimed on completion/cancel below.
                }
            }
        }
        if sent {
            Ok(())
        } else {
            Err(last_error)
        }
    }

    fn receive_ready<F>(&mut self, token: SocketToken, revents: i16, ignore: &F)
    where
        F: Fn(&[u8]) -> bool,
    {
        let Some(owned) = self.sockets.get(&token) else {
            return;
        };
        let id = owned.query;
        if revents & POLLNVAL != 0 {
            self.fail(id, io::Error::other("invalid upstream socket").into());
            return;
        }
        if revents & (POLLERR | POLLHUP) != 0 && revents & POLLIN == 0 {
            self.fail(id, io::Error::other("upstream socket poll error").into());
            return;
        }
        for _ in 0..RECEIVE_BUDGET {
            let Some(transaction) = self.transactions.get(&id) else {
                break;
            };
            if Instant::now() >= transaction.deadline {
                self.fail(id, ResolveError::Timeout);
                break;
            }
            let Some(owned) = self.sockets.get(&token) else {
                break;
            };
            let result = owned.socket.recv_from(&mut self.receive_buffer);
            let (length, source) = match result {
                Ok(result) => result,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.fail(id, error.into());
                    break;
                }
            };
            let Some(pending) = self.dispatcher.table().get(id) else {
                break;
            };
            let Some(matched) = self.dispatcher.accept_reply(
                &self.receive_buffer[..length],
                source,
                token,
                pending.group,
                unix_seconds(),
            ) else {
                continue;
            };
            if matched.id != id {
                continue;
            }
            // Keep the transaction and its server/retry counters untouched.
            // This must happen after source/ID admission but before
            // `complete_reply`, matching forward.c::reply_query.
            if ignore(&self.receive_buffer[..length]) {
                continue;
            }
            let truncated = match udp_reply_is_truncated(&self.receive_buffer[..length]) {
                Ok(truncated) => truncated,
                Err(error) => {
                    self.fail(id, error.into());
                    break;
                }
            };
            match self.dispatcher.complete_reply(matched) {
                Some(ReplyAction::Wait) => {}
                Some(ReplyAction::Retry) => {
                    let Some(plan) = self.dispatcher.plan_after_error(id, unix_seconds()) else {
                        break;
                    };
                    // C strict-order exhaustion leaves the query pending until
                    // normal collection; it does not re-send the last error.
                    if !plan.exhausted {
                        match self.dispatcher.upstream_packet(id) {
                            Ok(Some(packet)) => {
                                if let Err(error) = self.send_plan(id, &packet, &plan) {
                                    self.fail(id, error);
                                }
                            }
                            Err(error) => self.fail(id, error.into()),
                            Ok(None) => {}
                        }
                    }
                }
                Some(ReplyAction::Deliver) => {
                    let packet = self.receive_buffer[..length].to_vec();
                    let pending = self.dispatcher.finish(id).expect("matched query exists");
                    self.transactions.remove(&id);
                    self.consume_releases();
                    self.sockets.retain(|_, owned| owned.query != id);
                    self.events.push_back(UpstreamEvent {
                        id,
                        result: Ok(UncheckedReply {
                            packet,
                            truncated,
                            server: matched.server,
                            flags: pending.flags,
                            recipients: pending.recipients,
                        }),
                    });
                    break;
                }
                None => break,
            }
        }
    }

    fn fail(&mut self, id: QueryId, error: ResolveError) {
        if self.cancel(id) {
            self.events.push_back(UpstreamEvent {
                id,
                result: Err(error),
            });
        }
    }

    fn consume_releases(&mut self) {
        for released in self.dispatcher.take_released() {
            for token in released.sockets {
                if let Some(owned) = self.sockets.remove(&token) {
                    if let Some(transaction) = self.transactions.get_mut(&owned.query) {
                        transaction.sockets.remove(&owned.server);
                    }
                }
            }
            if self.dispatcher.table().get(released.id).is_none()
                && self.transactions.remove(&released.id).is_some()
            {
                self.sockets.retain(|_, owned| owned.query != released.id);
                self.events.push_back(UpstreamEvent {
                    id: released.id,
                    result: Err(ResolveError::Released(released.reason)),
                });
            }
        }
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

// owrt_ubus::sys::poll_fds retries EINTR with the original timeout. This small
// boundary deliberately returns EINTR so the caller recomputes its deadline.
#[cfg(target_os = "macos")]
type Nfds = u32;
#[cfg(not(target_os = "macos"))]
type Nfds = usize;
extern "C" {
    #[link_name = "poll"]
    fn system_poll(fds: *mut PollFd, count: Nfds, timeout: i32) -> i32;
}
fn poll_once(fds: &mut [PollFd], timeout: i32) -> io::Result<usize> {
    // SAFETY: PollFd is the repository's repr(C) pollfd with native Unix
    // fields. This slice stays alive and exclusively borrowed for the call;
    // count uses Darwin's u32 or Linux's unsigned-long nfds_t ABI.
    let result = unsafe { system_poll(fds.as_mut_ptr(), fds.len() as Nfds, timeout) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::forward::{Options, Server, ServerGroup};
    use crate::dns::wire::{Header, Message, Name, PacketWriter, Section};
    use std::sync::mpsc;
    use std::thread;

    struct Counter(u32);
    impl Random for Counter {
        fn next_u32(&mut self) -> io::Result<u32> {
            self.0 += 1;
            Ok(self.0)
        }
    }

    fn query() -> Vec<u8> {
        let name = Name::from_ascii("upstream.test").unwrap();
        let mut writer = PacketWriter::new(0x1234, 0x100, 1232).unwrap();
        writer.question(&name, 1, 1).unwrap();
        writer.finish()
    }

    fn client() -> Client {
        Client {
            source: "127.0.0.1:53000".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
            listener: None,
            udp_limit: 512,
            log_id: 1,
        }
    }

    fn response(request: &[u8], flags: u16, answer: bool) -> Vec<u8> {
        let header = Header::parse(request).unwrap();
        let name = Name::from_ascii("upstream.test").unwrap();
        let mut writer = PacketWriter::new(header.id, flags, 1232).unwrap();
        writer.question(&name, 1, 1).unwrap();
        if answer {
            writer
                .record(Section::Answer, &name, 1, 1, 20, &[192, 0, 2, 9])
                .unwrap();
        }
        writer.finish()
    }

    fn group(addresses: &[SocketAddr], all_servers: bool) -> ServerGroup {
        ServerGroup::new(
            GroupId(1),
            addresses
                .iter()
                .enumerate()
                .map(|(index, &address)| Server {
                    id: ServerId(index as u64 + 1),
                    address,
                    bound_socket: None,
                })
                .collect(),
            true,
            all_servers,
        )
    }

    fn transport(
        group: ServerGroup,
        options: Options,
        timeout: Duration,
    ) -> UpstreamResolver<Counter> {
        let dispatcher = ForwardDispatcher::new(options, [group], 1232);
        UpstreamResolver::with_random(dispatcher, Counter(0), timeout).unwrap()
    }

    fn wait_for_event(
        transport: &mut UpstreamResolver<Counter>,
        timeout: Duration,
    ) -> UpstreamEvent {
        for _ in 0..20 {
            let events = transport.poll(timeout).unwrap();
            if let Some(event) = events.into_iter().next() {
                return event;
            }
        }
        panic!("no upstream event");
    }

    #[test]
    fn poll_authenticates_peer_and_releases_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let spoof = UdpSocket::bind("127.0.0.1:0").unwrap();
            spoof
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
            server
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
        });
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        let submission = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let event = wait_for_event(&mut transport, Duration::from_millis(100));
        assert_eq!(event.id, submission.id);
        let reply = event.result.unwrap();
        assert_eq!(Header::parse(&reply.packet).unwrap().answers, 1);
        assert_eq!(reply.server, ServerId(1));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn ignored_reply_stays_pending_until_a_later_upstream_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            server
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
            thread::sleep(Duration::from_millis(60));
            server
                .send_to(&response(&input[..length], 0x8180, false), peer)
                .unwrap();
        });
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        let submission = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let ignored = transport
            .poll_with_filter(Duration::from_millis(20), |packet| {
                Message::parse(packet)
                    .ok()
                    .is_some_and(|message| message.records(Section::Answer).next().is_some())
            })
            .unwrap();
        assert!(ignored.is_empty());
        assert_eq!(transport.pending_count(), 1);
        let events = transport
            .poll_with_filter(Duration::from_millis(200), |_| false)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, submission.id);
        assert!(events[0].result.is_ok());
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn truncated_udp_reply_is_delivered_without_retry_or_state_leak() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            server
                .send_to(&response(&input[..length], 0x8380, false), peer)
                .unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            assert!(
                server.recv_from(&mut input).is_err(),
                "TC response was retried"
            );
        });
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        let submission = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let event = wait_for_event(&mut transport, Duration::from_millis(100));
        let reply = event.result.unwrap();
        assert_eq!(event.id, submission.id);
        assert!(reply.truncated);
        assert!(udp_reply_is_truncated(&reply.packet).unwrap());
        assert_eq!(Header::parse(&reply.packet).unwrap().flags & 0x0200, 0x0200);
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn truncated_classifier_rejects_short_header() {
        assert_eq!(udp_reply_is_truncated(&[0; 11]), Err(WireError::Truncated));
        assert!(!udp_reply_is_truncated(&[0; 12]).unwrap());
    }

    #[test]
    fn failed_first_send_falls_back_without_leaking_failed_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            server
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
        });
        // The unspecified destination has no route on supported Unix hosts;
        // unlike a closed loopback port, send_to fails synchronously.
        let bad = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut transport = transport(
            group(&[bad, address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let event = wait_for_event(&mut transport, Duration::from_millis(100));
        assert_eq!(event.result.unwrap().server, ServerId(2));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn all_servers_refused_waits_without_resending() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        let first_address = first.local_addr().unwrap();
        let second_address = second.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let first_thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = first.recv_from(&mut input).unwrap();
            tx.send(()).unwrap();
            first
                .send_to(&response(&input[..length], 0x8185, false), peer)
                .unwrap();
            first
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            assert!(
                first.recv_from(&mut input).is_err(),
                "REFUSED caused a resend"
            );
        });
        let second_thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = second.recv_from(&mut input).unwrap();
            thread::sleep(Duration::from_millis(20));
            second
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
            second
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            assert!(
                second.recv_from(&mut input).is_err(),
                "REFUSED caused a resend"
            );
        });
        let mut transport = transport(
            group(&[first_address, second_address], true),
            Options::default(),
            Duration::from_secs(1),
        );
        transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        rx.recv_timeout(Duration::from_millis(250)).unwrap();
        let event = wait_for_event(&mut transport, Duration::from_millis(100));
        assert_eq!(event.result.unwrap().server, ServerId(2));
        first_thread.join().unwrap();
        second_thread.join().unwrap();
    }

    #[test]
    fn timeout_is_bounded_and_is_not_an_upstream_error_retry() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        drop(server);
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_millis(25),
        );
        let started = Instant::now();
        transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let event = wait_for_event(&mut transport, Duration::from_secs(1));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(matches!(event.result, Err(ResolveError::Timeout)));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
    }

    #[test]
    fn duplicate_coalesces_without_second_send_and_cancel_reclaims_refs() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, _) = server.recv_from(&mut input).unwrap();
            tx.send(length).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            assert!(
                server.recv_from(&mut input).is_err(),
                "coalesced query was resent"
            );
        });
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        let first = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let mut second_client = client();
        second_client.source = "127.0.0.1:53001".parse().unwrap();
        let second = transport
            .start_udp(&query(), second_client, GroupId(1), Scope::Shared)
            .unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(
            second.kind,
            super::super::forward::SubmissionKind::Coalesced
        );
        rx.recv_timeout(Duration::from_millis(250)).unwrap();
        assert!(transport.cancel(first.id));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn fast_retry_is_explicit_and_cancel_reclaims_refs() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            for _ in 0..2 {
                let (length, _) = server.recv_from(&mut input).unwrap();
                tx.send(length).unwrap();
            }
        });
        let options = Options {
            fast_retry_ms: 5,
            fast_retry_timeout_s: 10,
            ..Options::default()
        };
        let mut transport = transport(group(&[address], false), options, Duration::from_secs(1));
        let submission = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        rx.recv_timeout(Duration::from_millis(250)).unwrap();
        thread::sleep(Duration::from_millis(10));
        assert!(transport.tick().is_empty());
        rx.recv_timeout(Duration::from_millis(250)).unwrap();
        assert!(transport.cancel(submission.id));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }
}
