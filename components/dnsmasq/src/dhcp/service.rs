//! Bounded DHCPv4 datagram admission and dispatch.
//!
//! This is the socket-independent boundary between `recvmsg(2)`/pktinfo and
//! the state machine.  The C implementation performs the same split in
//! `dhcp.c:130-373`: it bounds the receive buffer, rejects non-requests, then
//! chooses local, relay, BOOTP, PXE, or leasequery handling before calling
//! `dhcp_reply()`.  Interface discovery, relay forwarding, reply serialising,
//! and actual UDP sockets remain caller responsibilities.

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use super::packet::MAX_PACKET_LEN;
use super::packet::{Packet, ParseError, FIXED_LEN};

/// IPv4 UDP input limit; reply capacity remains MAX_PACKET_LEN.
pub const MAX_DATAGRAM_LEN: usize = 65_507;
#[cfg(any(test, all(target_os = "linux", target_pointer_width = "64")))]
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::os::fd::AsRawFd;

/// C's DHCP and PXE listeners use separate UDP sockets (dhcp.c:130-133).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    Dhcp,
    Pxe,
}

/// Metadata that a recvmsg/pktinfo adapter must supply before dispatch.
/// `unicast_destination` is the C `IP_PKTINFO`/MSG_BCAST result used when
/// selecting the renewal destination and NAK broadcast policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ingress {
    pub listener: Listener,
    pub interface_index: u32,
    pub unicast_destination: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchKind {
    /// DHCP message type 1..9, handed to the RFC 2131 state machine.
    Dhcp,
    /// BOOTP has no option 53 and uses the 64-byte vendor area on reply.
    Bootp,
    /// RFC 4388 DHCPLEASEQUERY (message type 10).
    LeaseQuery,
    /// A PXE vendor match or the dedicated UDP 4011 listener.
    Pxe,
    /// An option-53 value for which rfc2131.c has no request branch.  The C
    /// default returns no reply, so callers must not pass this to a mutating
    /// state transition.
    Unsupported,
}

/// Route selected from `giaddr`, including dnsmasq's all-ones local-test
/// extension (dhcp.c:251-264).  The original address is retained for audit;
/// the C path clears it before context matching and restores it for sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Local,
    Relay { giaddr: Ipv4Addr },
    RelaySource { original_giaddr: Ipv4Addr },
}

#[derive(Clone, Copy, Debug)]
pub struct Dispatch<'a> {
    pub packet: Packet<'a>,
    pub ingress: Ingress,
    pub kind: DispatchKind,
    pub route: Route,
}

/// A datagram after Linux `recvmsg`/pktinfo admission. The containing runtime
/// owns the socket and may pass `dispatch` to the state machine without
/// losing the source/destination metadata needed by the send path.
#[derive(Clone, Copy, Debug)]
pub struct Received<'a> {
    pub dispatch: Dispatch<'a>,
    pub peer: SocketAddr,
    pub destination: IpAddr,
    /// Local interface address (`ipi_spec_dst`), distinct from a broadcast
    /// or multicast IP-header destination.
    pub local_address: IpAddr,
    pub interface: u32,
}

/// Input states understood by the socket-independent poll adapter.  A socket
/// wrapper maps `recvmsg`'s `EAGAIN` to `WouldBlock` and ancillary/policy
/// drops to `Ignored` without handing either to the DHCP state machine.
#[derive(Clone, Copy, Debug)]
pub enum PollInput<'a> {
    Datagram(&'a [u8]),
    Ignored,
    WouldBlock,
}

/// One non-blocking poll step. `Admitted` is the only variant that may be
/// handed to a state-machine caller; all other variants have no lease or DNS
/// side effects. The generic payload lets the pure adapter return `Dispatch`
/// while the Linux socket wrapper retains peer/pktinfo in `Received`.
#[derive(Clone, Copy, Debug)]
pub enum PollOutcome<T> {
    Admitted(T),
    Malformed(DispatchError),
    Ignored,
    WouldBlock,
    Stopped,
}

/// Result of one owned listener step.  `Processed` is returned only after a
/// datagram passed pktinfo admission and the runtime had a chance to build and
/// send its reply.  A malformed or ancillary-data drop is kept distinct from
/// `WouldBlock`, so callers can account for wire errors without mutating lease
/// state.  The listener itself remains non-blocking; event-loop ownership and
/// retry policy stay with the caller.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[derive(Debug)]
pub enum ListenerStep {
    Stopped,
    Ignored,
    WouldBlock,
    Malformed(DispatchError),
    Processed(Result<super::runtime::RuntimeReport, Box<super::runtime::RuntimeFailure>>),
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
struct PendingReply {
    bytes: Vec<u8>,
    destination: super::runtime::Destination,
    listener: Listener,
    would_block_count: u16,
}

#[cfg(any(test, all(target_os = "linux", target_pointer_width = "64")))]
struct DeviceBinding {
    name: Vec<u8>,
    bind_main: bool,
    did_bind: bool,
    warned: bool,
}

#[cfg(any(test, all(target_os = "linux", target_pointer_width = "64")))]
impl DeviceBinding {
    /// dhcp-common.c:608-641 combines both socket results. EPERM counts as
    /// success, while any other error fails even if the other socket binds.
    fn bind(
        &self,
        has_pxe: bool,
        mut bind: impl FnMut(Listener, &[u8]) -> io::Result<()>,
    ) -> io::Result<bool> {
        let mut did_bind = false;
        let mut error = None;
        let mut failed = false;
        for (listener, enabled) in [(Listener::Dhcp, self.bind_main), (Listener::Pxe, has_pxe)] {
            if !enabled {
                continue;
            }
            match bind(listener, &self.name) {
                Ok(()) => did_bind = true,
                Err(failure) if failure.raw_os_error() == Some(1) => {
                    did_bind = true;
                    error = Some(failure);
                }
                Err(failure) => {
                    failed = true;
                    error = Some(failure);
                }
            }
        }
        // C combines both result bits but die formats errno from the last
        // failing syscall, including a later ignored EPERM.
        if failed {
            Err(error.unwrap_or_else(|| io::Error::other("device binding failed")))
        } else {
            Ok(did_bind)
        }
    }

    fn retry(
        &mut self,
        has_pxe: bool,
        bind: impl FnMut(Listener, &[u8]) -> io::Result<()>,
    ) -> Option<Vec<u8>> {
        if self.bind(has_pxe, bind).is_ok() || self.warned {
            return None;
        }
        self.warned = true;
        let mut message = b"error binding DHCP socket to device ".to_vec();
        message.extend_from_slice(&self.name);
        Some(message)
    }
}

/// Admit at most one deferred reply. Returning success means the owner has
/// accepted the packet; a full kernel queue is retried on the next poll turn.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
struct OwnerSender<'a, S> {
    dump: crate::dump::DumpHandle,
    dump_source: Option<SocketAddr>,
    socket: &'a mut S,
    pending: &'a mut Option<PendingReply>,
    listener: Listener,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl<S: super::runtime::DatagramSender> super::runtime::DatagramSender for OwnerSender<'_, S> {
    fn interface_name(&mut self, index: u32) -> io::Result<Option<[u8; 16]>> {
        super::runtime::DatagramSender::interface_name(self.socket, index)
    }
    fn prepare_destination(&mut self, destination: &super::runtime::Destination) -> io::Result<()> {
        super::runtime::DatagramSender::prepare_destination(self.socket, destination)
    }
    fn send(&mut self, bytes: &[u8], destination: &super::runtime::Destination) -> io::Result<()> {
        if let Some(source) = self.dump_source {
            self.dump.udp(crate::dump::DHCP, bytes, source, destination.address);
        }
        match super::runtime::DatagramSender::send(self.socket, bytes, destination) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                debug_assert!(self.pending.is_none());
                *self.pending = Some(PendingReply {
                    bytes: bytes.to_vec(),
                    destination: destination.clone(),
                    listener: self.listener,
                    would_block_count: u16::from(error.kind() == io::ErrorKind::WouldBlock),
                });
                Ok(())
            }
            result => result,
        }
    }
}

/// An isolated AF_INET DHCP/PXE socket with the bounded receive buffer and
/// configured vendor prefixes owned by one value.  This is the service
/// boundary used by an event loop: it does not bind privileged ports unless
/// the caller explicitly supplies one, and it never discovers or changes
/// physical interfaces.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub struct SocketListener {
    dump: crate::dump::DumpHandle,
    socket: crate::net::DatagramSocket,
    pxe_socket: Option<crate::net::DatagramSocket>,
    pending_reply: Option<PendingReply>,
    random: std::fs::File,
    listener: Listener,
    pxe_prefixes: Vec<Vec<u8>>,
    buffer: Vec<u8>,
    relay: Option<super::relay::RelayService>,
    ports: crate::config::dhcp_relay::DhcpPorts,
    device_binding: Option<DeviceBinding>,
    network_notices: Vec<crate::logging::LogEvent>,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl SocketListener {
    /// Bind a non-blocking IPv4 socket.  `DatagramSocket::bind` enables
    /// `IP_PKTINFO`, matching dnsmasq's `dhcp_init` receive contract.
    pub fn bind(
        address: SocketAddr,
        listener: Listener,
        pxe_prefixes: &[&[u8]],
    ) -> io::Result<Self> {
        Self::bind_with_reuse(address, listener, pxe_prefixes, false)
    }

    pub fn bind_with_reuse(
        address: SocketAddr,
        listener: Listener,
        pxe_prefixes: &[&[u8]],
        reuse: bool,
    ) -> io::Result<Self> {
        if !address.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DHCPv4 listener requires an IPv4 bind address",
            ));
        }
        let socket = crate::net::DatagramSocket::bind_dhcp(address, reuse)?;
        socket.configure_dhcp()?;
        Ok(Self {
            dump: Default::default(),
            socket,
            pxe_socket: None,
            pending_reply: None,
            random: std::fs::File::open("/dev/urandom")?,
            listener,
            pxe_prefixes: pxe_prefixes.iter().map(|prefix| prefix.to_vec()).collect(),
            buffer: vec![0; MAX_PACKET_LEN],
            relay: None,
            ports: crate::config::dhcp_relay::DhcpPorts::default(),
            device_binding: None,
            network_notices: Vec::new(),
        })
    }

    pub fn configure_relay(
        &mut self,
        rules: &[crate::config::dhcp_relay::RelayRule],
        dns: &crate::config::dns::DnsConfig,
        excluded: &[Option<Vec<u8>>],
        ports: crate::config::dhcp_relay::DhcpPorts,
        network: &crate::config::dhcp_network::NetworkConfig,
    ) -> io::Result<()> {
        self.ports = ports;
        if !rules.is_empty() {
            self.buffer.resize(super::relay::MAX_DATAGRAM, 0);
            self.relay = Some(super::relay::RelayService::new(
                rules,
                dns,
                excluded,
                ports.client,
                network,
            )?);
        }
        Ok(())
    }
    pub fn set_logging(&mut self, enabled: bool) {
        if let Some(relay) = &mut self.relay {
            relay.set_logging(enabled);
        }
    }

    pub fn set_dump(&mut self, dump: crate::dump::DumpHandle) {
        if let Some(relay) = &mut self.relay {
            relay.set_dump(dump.clone());
        }
        self.dump = dump;
    }

    pub fn take_network_notices(&mut self) -> Vec<crate::logging::LogEvent> {
        let mut notices = std::mem::take(&mut self.network_notices);
        if let Some(relay) = &mut self.relay {
            notices.extend(relay.take_notices());
        }
        notices
    }

    /// Store whichdevice's startup selection. Configure PXE first: its
    /// existing socket is bound even when relay4 suppresses the main socket.
    pub fn configure_device_binding(
        &mut self,
        name: Option<Vec<u8>>,
        bind_main: bool,
    ) -> io::Result<bool> {
        let Some(name) = name else {
            self.device_binding = None;
            return Ok(false);
        };
        let mut binding = DeviceBinding {
            name,
            bind_main,
            did_bind: false,
            warned: false,
        };
        binding.did_bind =
            binding.bind(self.pxe_socket.is_some(), |listener, name| match listener {
                Listener::Dhcp => self.socket.bind_device(name),
                Listener::Pxe => self
                    .pxe_socket
                    .as_ref()
                    .ok_or_else(|| io::Error::other("PXE device binding has no socket"))?
                    .bind_device(name),
            })?;
        let did_bind = binding.did_bind;
        self.device_binding = Some(binding);
        Ok(did_bind)
    }

    /// Only a real startup bind attempt (including C's ignored EPERM) earns
    /// dnsmasq.c:1028's DHCP startup notice. Retry success cannot create it.
    pub fn bound_device_notice(&self) -> Option<&[u8]> {
        self.device_binding
            .as_ref()
            .filter(|binding| binding.did_bind)
            .map(|binding| binding.name.as_slice())
    }

    /// One nonblocking retry on every outer owner turn, using the original
    /// name. dnsmasq.c:1136-1143 logs the first non-EPERM error only.
    pub fn retry_device_binding(&mut self) {
        let Some(binding) = &mut self.device_binding else {
            return;
        };
        let notice = binding.retry(self.pxe_socket.is_some(), |listener, name| match listener {
            Listener::Dhcp => self.socket.bind_device(name),
            Listener::Pxe => self
                .pxe_socket
                .as_ref()
                .ok_or_else(|| io::Error::other("PXE device binding has no socket"))?
                .bind_device(name),
        });
        if let Some(notice) = notice {
            self.network_notices.push(crate::logging::LogEvent::new(
                crate::logging::Service::Dns,
                crate::logging::Priority::Error,
                notice,
            ));
        }
    }

    pub fn configure_pxe(
        &mut self,
        enabled: bool,
        prefixes: &[Vec<u8>],
        reuse: bool,
    ) -> io::Result<()> {
        if !enabled {
            return Ok(());
        }
        let socket = crate::net::DatagramSocket::bind_dhcp(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4011)),
            reuse,
        )?;
        socket.configure_dhcp()?;
        self.pxe_socket = Some(socket);
        self.pxe_prefixes = prefixes.to_vec();
        self.buffer.resize(MAX_DATAGRAM_LEN, 0);
        Ok(())
    }

    /// A deferred send is runnable owner state even without readable input.
    pub fn has_pending_reply(&self) -> bool {
        self.pending_reply.is_some()
    }

    /// Observe readiness without consuming the queued packet. The owner can
    /// complete its kernel address dump before borrowing packet/state buffers.
    pub fn has_input(&self) -> io::Result<bool> {
        if self.pending_reply.is_some() {
            return Ok(true);
        }
        let mut fds = vec![dnsmasq_platform::poll::PollFd {
            fd: self.socket.as_raw_fd(),
            events: 1,
            revents: 0,
        }];
        if let Some(socket) = &self.pxe_socket {
            fds.push(dnsmasq_platform::poll::PollFd {
                fd: socket.as_raw_fd(),
                events: 1,
                revents: 0,
            });
        }
        Ok(dnsmasq_platform::poll::poll_fds(&mut fds, 0)? != 0)
    }

    /// Add the DHCP and optional PXE sockets to the main owner's wait set.
    /// The sockets are nonblocking; packet processing remains bounded by the
    /// caller's normal DHCP turn and never runs from the poll itself.
    pub fn append_poll_fds(&self, fds: &mut Vec<dnsmasq_platform::poll::PollFd>) {
        use dnsmasq_platform::poll::{PollFd, POLLIN, POLLOUT};
        // A queued reply has no unread request left to wake the owner. Wait
        // for the socket which owns that reply to become writable instead.
        let pending_listener = self.pending_reply.as_ref().map(|reply| reply.listener);
        fds.push(PollFd {
            fd: self.socket.as_raw_fd(),
            events: POLLIN | if pending_listener == Some(self.listener) { POLLOUT } else { 0 },
            revents: 0,
        });
        if let Some(socket) = &self.pxe_socket {
            fds.push(PollFd {
                fd: socket.as_raw_fd(),
                events: POLLIN | if pending_listener.is_some_and(|kind| kind != self.listener) {
                    POLLOUT
                } else { 0 },
                revents: 0,
            });
        }
    }

    pub fn has_pxe_listener(&self) -> bool {
        self.pxe_socket.is_some()
    }

    pub fn invalidate_relay_interfaces(&mut self) {
        if let Some(relay) = &mut self.relay {
            relay.invalidate_interfaces();
        }
    }

    /// Relay-only service deliberately creates no lease provider or file.
    pub fn process_once_relay_only(
        &mut self,
        stop: impl FnMut() -> bool,
    ) -> io::Result<ListenerStep> {
        Ok(match self.receive_for_local(self.listener, stop)? {
            Ok(_) => ListenerStep::Ignored,
            Err(step) => step,
        })
    }

    pub fn process_once_pxe_relay_only(
        &mut self,
        stop: impl FnMut() -> bool,
    ) -> io::Result<ListenerStep> {
        Ok(match self.receive_for_local(Listener::Pxe, stop)? {
            Ok(_) => ListenerStep::Ignored,
            Err(step) => step,
        })
    }

    fn flush_pending_reply(&mut self) -> io::Result<bool> {
        let Some(mut pending) = self.pending_reply.take() else {
            return Ok(true);
        };
        let socket = if pending.listener == self.listener {
            &mut self.socket
        } else {
            self.pxe_socket
                .as_mut()
                .ok_or_else(|| io::Error::other("queued PXE reply has no socket"))?
        };
        match super::runtime::DatagramSender::send(socket, &pending.bytes, &pending.destination) {
            Ok(()) => Ok(true),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                if error.kind() == io::ErrorKind::Interrupted {
                    pending.would_block_count = 0;
                } else {
                    pending.would_block_count += 1;
                    if pending.would_block_count > 1000 {
                        return Err(error);
                    }
                }
                self.pending_reply = Some(pending);
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn receive_for_local(
        &mut self,
        listener: Listener,
        mut stop: impl FnMut() -> bool,
    ) -> io::Result<Result<crate::net::Datagram, ListenerStep>> {
        if stop() {
            return Ok(Err(ListenerStep::Stopped));
        }
        if !self.flush_pending_reply()? {
            return Ok(Err(ListenerStep::WouldBlock));
        }
        let socket = if listener == self.listener {
            &self.socket
        } else if let Some(socket) = self.pxe_socket.as_ref() {
            socket
        } else {
            return Ok(Err(ListenerStep::WouldBlock));
        };
        let datagram = match socket.receive(&mut self.buffer) {
            Ok(Some(datagram)) => datagram,
            Ok(None) => return Ok(Err(ListenerStep::Ignored)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(Err(ListenerStep::WouldBlock))
            }
            Err(error) => return Err(error),
        };
        if !datagram.destination.is_ipv4()
            || !datagram.local_address.is_ipv4()
            || datagram.interface == 0
        {
            return Ok(Err(ListenerStep::Ignored));
        }
        self.dump.udp(
            crate::dump::DHCP,
            &self.buffer[..datagram.len],
            datagram.peer,
            SocketAddr::new(datagram.destination, self.ports.server),
        );
        if let Some(relay) = &mut self.relay {
            if relay.intercept(
                &self.socket,
                socket,
                listener == Listener::Pxe,
                &mut self.buffer[..datagram.len],
                &datagram,
            )? {
                return Ok(Err(ListenerStep::Ignored));
            }
        }
        Ok(Ok(datagram))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Poll one datagram while retaining ownership of the packet buffer.  The
    /// returned `Received` borrows this listener and must be consumed before
    /// the next call, which prevents an unbounded queue of attacker-controlled
    /// packets.
    pub fn poll<'a>(
        &'a mut self,
        stop: impl FnMut() -> bool,
    ) -> io::Result<PollOutcome<Received<'a>>> {
        let prefixes: Vec<&[u8]> = self.pxe_prefixes.iter().map(Vec::as_slice).collect();
        poll_once(
            &self.socket,
            &mut self.buffer,
            self.listener,
            &prefixes,
            stop,
        )
    }

    /// Poll and run one local DHCP/BOOTP request using the listener socket for
    /// the reply.  Unsupported relay/PXE/LEASEQUERY routes are reported by
    /// `runtime::process` before the provider is called.  State and name/DNS
    /// side effects remain the provider's responsibility and therefore commit
    /// before a later send failure, exactly as the C path does.
    pub fn process_once_local<P>(
        &mut self,
        provider: &mut P,
        options: &[super::reply::ReplyOption<'_>],
        output: &mut [u8],
        stop: impl FnMut() -> bool,
    ) -> io::Result<ListenerStep>
    where
        P: super::runtime::OutcomeProvider,
    {
        self.process_once_on_listener(self.listener, provider, options, output, stop)
    }

    pub fn process_once_on_listener<P>(
        &mut self,
        listener: Listener,
        provider: &mut P,
        options: &[super::reply::ReplyOption<'_>],
        output: &mut [u8],
        stop: impl FnMut() -> bool,
    ) -> io::Result<ListenerStep>
    where
        P: super::runtime::OutcomeProvider,
    {
        let datagram = match self.receive_for_local(listener, stop)? {
            Ok(datagram) => datagram,
            Err(step) => return Ok(step),
        };
        let prefixes: Vec<&[u8]> = self.pxe_prefixes.iter().map(Vec::as_slice).collect();
        let dispatch = match dispatch(
            &self.buffer[..datagram.len],
            Ingress {
                listener,
                interface_index: datagram.interface,
                unicast_destination: datagram.destination != IpAddr::V4(Ipv4Addr::BROADCAST),
            },
            &prefixes,
        ) {
            Ok(dispatch) => dispatch,
            Err(error) => return Ok(ListenerStep::Malformed(error)),
        };
        let socket = if listener == self.listener {
            &mut self.socket
        } else {
            self.pxe_socket
                .as_mut()
                .ok_or_else(|| io::Error::other("PXE receive has no socket"))?
        };
        let mut sender = OwnerSender {
            dump: self.dump.clone(),
            dump_source: self.dump.enabled(crate::dump::DHCP)
                .then(|| socket.local_addr()).transpose()?,
            socket,
            pending: &mut self.pending_reply,
            listener,
        };
        Ok(ListenerStep::Processed(
            super::runtime::process_with_random_and_ports(
                dispatch,
                datagram.peer,
                provider,
                &mut sender,
                options,
                output,
                self.ports,
                || {
                    use std::io::Read;
                    let mut bytes = [0; 2];
                    self.random.read_exact(&mut bytes)?;
                    Ok(u16::from_ne_bytes(bytes))
                },
            ),
        ))
    }
}

/// Classify one bounded datagram without touching a socket or lease provider.
/// This is the deterministic handoff used by platform receive loops and is
/// directly testable on every host target.
pub fn dispatch_poll<'a>(
    input: PollInput<'a>,
    ingress: Ingress,
    pxe_prefixes: &[&[u8]],
    stop: bool,
) -> PollOutcome<Dispatch<'a>> {
    if stop {
        return PollOutcome::Stopped;
    }
    match input {
        PollInput::Datagram(bytes) => match dispatch(bytes, ingress, pxe_prefixes) {
            Ok(dispatch) => PollOutcome::Admitted(dispatch),
            Err(error) => PollOutcome::Malformed(error),
        },
        PollInput::Ignored => PollOutcome::Ignored,
        PollInput::WouldBlock => PollOutcome::WouldBlock,
    }
}

/// Receive one bounded DHCP/PXE datagram through the audited pktinfo socket.
/// `Ok(None)` means the kernel discarded a truncated datagram or reported no
/// usable ancillary destination metadata. A malformed but bounded packet is
/// returned as `Some(Err(...))` so callers can account for the drop.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn receive_once<'a>(
    socket: &crate::net::DatagramSocket,
    buffer: &'a mut [u8],
    listener: Listener,
    pxe_prefixes: &[&[u8]],
) -> io::Result<Option<Result<Received<'a>, DispatchError>>> {
    let Some(datagram) = socket.receive(buffer)? else {
        return Ok(None);
    };
    // dhcp_init() binds the DHCPv4 and PXE descriptors with AF_INET
    // (dhcp.c:40-109).  Do not let a caller accidentally pass an IPv6
    // DatagramSocket here and reinterpret an arbitrary 236-byte payload as
    // BOOTP; DHCPv6 belongs to odhcpd and is not compiled in this variant.
    if !matches!(datagram.destination, IpAddr::V4(_))
        || !matches!(datagram.local_address, IpAddr::V4(_))
    {
        return Ok(None);
    }
    // dhcp.c resolves the pktinfo index with indextoname() before any
    // interface/context matching.  An index of zero is therefore an
    // admission failure, even if the payload itself is a valid BOOTP packet.
    if datagram.interface == 0 {
        return Ok(None);
    }
    let ingress = Ingress {
        listener,
        interface_index: datagram.interface,
        // dhcp.c:196 compares the IP-header destination with INADDR_BROADCAST,
        // not the local interface address supplied alongside it by pktinfo.
        unicast_destination: datagram.destination != IpAddr::V4(Ipv4Addr::BROADCAST),
    };
    let result =
        dispatch(&buffer[..datagram.len], ingress, pxe_prefixes).map(|dispatch| Received {
            dispatch,
            peer: datagram.peer,
            destination: datagram.destination,
            local_address: datagram.local_address,
            interface: datagram.interface,
        });
    Ok(Some(result))
}

/// Stop-aware wrapper for one non-blocking Linux receive step. `DatagramSocket`
/// is created with `SOCK_NONBLOCK`, so checking `stop` before the receive
/// cannot strand a shutdown waiter in a blocking syscall.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn poll_once<'a>(
    socket: &crate::net::DatagramSocket,
    buffer: &'a mut [u8],
    listener: Listener,
    pxe_prefixes: &[&[u8]],
    mut stop: impl FnMut() -> bool,
) -> io::Result<PollOutcome<Received<'a>>> {
    if stop() {
        return Ok(PollOutcome::Stopped);
    }
    match receive_once(socket, buffer, listener, pxe_prefixes) {
        Ok(Some(Ok(received))) => Ok(PollOutcome::Admitted(received)),
        Ok(Some(Err(error))) => Ok(PollOutcome::Malformed(error)),
        Ok(None) => Ok(PollOutcome::Ignored),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(PollOutcome::WouldBlock),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// A UDP datagram larger than the C receive buffer is not admitted.  This
    /// check also prevents a future reply builder from allocating unbounded
    /// memory from attacker-controlled input.
    DatagramTooLarge {
        length: usize,
        maximum: usize,
    },
    Packet(ParseError),
}

/// Decode one received DHCP datagram and hand it to the state-machine caller.
/// No reply is generated and no lease is mutated here.  `pxe_prefixes` are
/// configured `dhcp-vendorclass` prefixes; matching uses the C starts-with
/// rule (`rfc2131.c:is_pxe_client`).
pub fn dispatch<'a>(
    bytes: &'a [u8],
    ingress: Ingress,
    pxe_prefixes: &[&[u8]],
) -> Result<Dispatch<'a>, DispatchError> {
    if bytes.len() > MAX_DATAGRAM_LEN {
        return Err(DispatchError::DatagramTooLarge {
            length: bytes.len(),
            maximum: MAX_DATAGRAM_LEN,
        });
    }
    // Keep the explicit lower bound in this boundary: dhcp.c drops a short
    // recvmsg result before invoking rfc2131.c, even though Packet::parse also
    // reports the same error.
    if bytes.len() < FIXED_LEN {
        return Err(DispatchError::Packet(ParseError::TruncatedHeader));
    }
    let packet = Packet::parse(bytes).map_err(DispatchError::Packet)?;
    let route = match packet.giaddr() {
        address if address == Ipv4Addr::new(255, 255, 255, 255) => Route::RelaySource {
            original_giaddr: address,
        },
        address if !address.is_unspecified() => Route::Relay { giaddr: address },
        _ => Route::Local,
    };
    let kind = if packet.message_type() == 10 {
        DispatchKind::LeaseQuery
    } else if ingress.listener == Listener::Pxe || packet.pxe_vendor(pxe_prefixes).is_some() {
        DispatchKind::Pxe
    } else {
        match packet.message_type() {
            0 => DispatchKind::Bootp,
            1..=9 => DispatchKind::Dhcp,
            10 => DispatchKind::LeaseQuery,
            _ => DispatchKind::Unsupported,
        }
    };
    Ok(Dispatch {
        packet,
        ingress,
        kind,
        route,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::packet::COOKIE;

    fn packet(options: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes.extend_from_slice(options);
        bytes
    }

    fn ingress() -> Ingress {
        Ingress {
            listener: Listener::Dhcp,
            interface_index: 3,
            unicast_destination: false,
        }
    }

    fn device_binding(bind_main: bool) -> DeviceBinding {
        DeviceBinding {
            name: b"test-vlan".to_vec(),
            bind_main,
            did_bind: false,
            warned: false,
        }
    }

    #[test]
    fn device_binding_requires_an_attempt_and_binds_pxe_even_with_relay() {
        let binding = device_binding(false);
        assert!(!binding
            .bind(false, |_, _| panic!("no selected socket"))
            .unwrap());
        let mut attempts = Vec::new();
        assert!(binding
            .bind(true, |listener, name| {
                attempts.push((listener, name.to_vec()));
                Err(io::Error::from_raw_os_error(1))
            })
            .unwrap());
        assert_eq!(attempts, [(Listener::Pxe, b"test-vlan".to_vec())]);
    }

    #[test]
    fn device_binding_attempts_both_sockets_despite_one_error() {
        let binding = device_binding(true);
        let mut attempts = Vec::new();
        let error = binding
            .bind(true, |listener, _| {
                attempts.push(listener);
                if listener == Listener::Dhcp {
                    Err(io::Error::from_raw_os_error(19))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(19));
        assert_eq!(attempts, [Listener::Dhcp, Listener::Pxe]);
        let error = binding
            .bind(true, |listener, _| {
                Err(io::Error::from_raw_os_error(
                    if listener == Listener::Dhcp { 19 } else { 1 },
                ))
            })
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(1));
    }

    #[test]
    fn device_binding_retries_original_name_but_warns_once() {
        let mut binding = device_binding(true);
        let mut attempts = Vec::new();
        for turn in 0..3 {
            let notice = binding.retry(true, |listener, name| {
                attempts.push((listener, name.to_vec()));
                Err(io::Error::from_raw_os_error(19))
            });
            if turn == 0 {
                let notice = notice.unwrap();
                assert_eq!(notice, b"error binding DHCP socket to device test-vlan");
            } else {
                assert!(notice.is_none());
            }
        }
        assert_eq!(attempts.len(), 6);
        assert!(attempts.iter().all(|(_, name)| name == b"test-vlan"));
        assert!(binding.retry(true, |_, _| Ok(())).is_none());
        assert!(
            !binding.did_bind,
            "runtime success cannot create a startup notice"
        );
    }

    #[test]
    fn device_binding_success_does_not_remove_the_per_turn_rebind() {
        let mut binding = device_binding(true);
        binding.did_bind = true;
        let mut attempts = 0;
        assert!(binding.retry(false, |_, _| { attempts += 1; Ok(()) }).is_none());
        assert!(binding.retry(false, |_, _| {
            attempts += 1;
            Err(io::Error::from_raw_os_error(19))
        }).is_some(), "a removed interface must still be detected after startup success");
        assert!(binding.retry(false, |_, _| { attempts += 1; Ok(()) }).is_none());
        assert_eq!(attempts, 3, "D2 must retain binding retry on every owner turn");
        assert!(binding.did_bind, "the startup notice bit is not current binding state");
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires an isolated Linux network namespace with CAP_NET_ADMIN"]
    fn device_binding_linux_sockets_retry_and_relay_gate() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        fn ip(args: &[&str]) {
            assert!(std::process::Command::new("ip")
                .args(args)
                .status()
                .unwrap()
                .success());
        }
        fn bound_device(socket: &crate::net::DatagramSocket) -> Vec<u8> {

            let mut name = [0u8; 16];
            dnsmasq_platform::socket_options::bound_device(socket, &mut name).unwrap();
            name[..name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len())]
                .to_vec()
        }
        let device = b"m5-bind";
        ip(&["link", "add", "m5-bind", "type", "dummy"]);
        let mut listener =
            SocketListener::bind("127.0.0.1:0".parse().unwrap(), Listener::Dhcp, &[]).unwrap();
        listener.configure_pxe(true, &[], false).unwrap();
        assert!(listener
            .configure_device_binding(Some(device.to_vec()), true)
            .unwrap());
        assert_eq!(bound_device(&listener.socket), device);
        assert_eq!(bound_device(listener.pxe_socket.as_ref().unwrap()), device);
        listener.set_logging(false);
        ip(&["link", "del", "m5-bind"]);
        listener.retry_device_binding();
        listener.retry_device_binding();
        let notices = listener.take_network_notices();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].service, crate::logging::Service::Dns);
        assert_eq!(notices[0].priority, crate::logging::Priority::Error);
        assert_eq!(
            notices[0].message,
            b"error binding DHCP socket to device m5-bind"
        );
        assert_eq!(listener.bound_device_notice(), Some(device.as_slice()));
        ip(&["link", "add", "m5-bind", "type", "dummy"]);
        listener.retry_device_binding();
        assert_eq!(bound_device(&listener.socket), device);
        assert_eq!(bound_device(listener.pxe_socket.as_ref().unwrap()), device);
        assert!(listener.take_network_notices().is_empty());
        drop(listener);

        let mut relay =
            SocketListener::bind("127.0.0.1:0".parse().unwrap(), Listener::Dhcp, &[]).unwrap();
        relay.configure_pxe(true, &[], false).unwrap();
        assert!(relay
            .configure_device_binding(Some(device.to_vec()), false)
            .unwrap());
        assert!(bound_device(&relay.socket).is_empty());
        assert_eq!(bound_device(relay.pxe_socket.as_ref().unwrap()), device);
        ip(&["link", "del", "m5-bind"]);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn transient_send_is_deferred_without_an_inner_retry_loop() {
        use super::super::runtime::{DatagramSender, Destination, DestinationKind};
        struct Blocked(usize);
        impl DatagramSender for Blocked {
            fn send(&mut self, _: &[u8], _: &Destination) -> io::Result<()> {
                self.0 += 1;
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
        let mut socket = Blocked(0);
        let mut pending = None;
        let destination = Destination {
            address: "127.0.0.1:4011".parse().unwrap(),
            interface: 0,
            kind: DestinationKind::Peer,
            arp: None,
        };
        let mut sender = OwnerSender {
            dump: crate::dump::DumpHandle::default(),
            dump_source: None,
            socket: &mut socket,
            pending: &mut pending,
            listener: Listener::Pxe,
        };
        sender.send(&[2; 300], &destination).unwrap();
        assert_eq!(socket.0, 1);
        let pending = pending.unwrap();
        assert_eq!(pending.bytes, [2; 300]);
        assert_eq!(pending.destination.address, destination.address);
        assert_eq!(pending.listener, Listener::Pxe);
        assert_eq!(pending.would_block_count, 1);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn deferred_reply_wakes_on_write_without_another_dhcp_request() {
        use super::super::runtime::{Destination, DestinationKind};
        use dnsmasq_platform::poll::{poll_fds, POLLOUT};
        use std::net::UdpSocket;
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
        let mut listener = SocketListener::bind(
            "127.0.0.1:0".parse().unwrap(), Listener::Dhcp, &[],
        ).unwrap();
        let destination = Destination {
            address: peer.local_addr().unwrap(), interface: 0,
            kind: DestinationKind::Peer, arp: None,
        };
        // This is the exact state produced by OwnerSender on EAGAIN, above.
        listener.pending_reply = Some(PendingReply {
            bytes: b"deferred reply".to_vec(), destination,
            listener: Listener::Dhcp, would_block_count: 1,
        });
        assert!(listener.has_pending_reply());
        let mut fds = Vec::new();
        listener.append_poll_fds(&mut fds);
        assert_eq!(poll_fds(&mut fds, 1000).unwrap(), 1);
        assert_ne!(fds[0].revents & POLLOUT, 0,
            "an unread packet cannot be the wakeup for a deferred send");
        assert!(listener.flush_pending_reply().unwrap());
        assert!(!listener.has_pending_reply());
        let mut bytes = [0; 64];
        let (length, _) = peer.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..length], b"deferred reply");
        fds.clear();
        listener.append_poll_fds(&mut fds);
        assert_eq!(poll_fds(&mut fds, 0).unwrap(), 0,
            "drained output must not leave an always-writable interest");
    }

    #[test]
    fn dispatch_poll_separates_stop_idle_drop_and_malformed_states() {
        let valid = packet(&[]);
        assert!(matches!(
            dispatch_poll(PollInput::Datagram(&valid), ingress(), &[], true),
            PollOutcome::Stopped
        ));
        assert!(matches!(
            dispatch_poll(PollInput::Ignored, ingress(), &[], false),
            PollOutcome::Ignored
        ));
        assert!(matches!(
            dispatch_poll(PollInput::WouldBlock, ingress(), &[], false),
            PollOutcome::WouldBlock
        ));
        assert!(matches!(
            dispatch_poll(
                PollInput::Datagram(&[0; FIXED_LEN - 1]),
                ingress(),
                &[],
                false
            ),
            PollOutcome::Malformed(DispatchError::Packet(ParseError::TruncatedHeader))
        ));
        assert!(matches!(
            dispatch_poll(PollInput::Datagram(&valid), ingress(), &[], false),
            PollOutcome::Admitted(_)
        ));
    }

    #[test]
    fn short_and_oversized_datagrams_are_rejected_before_state() {
        assert!(matches!(
            dispatch(&[0; FIXED_LEN - 1], ingress(), &[]),
            Err(DispatchError::Packet(ParseError::TruncatedHeader))
        ));
        let bytes = vec![0; MAX_DATAGRAM_LEN + 1];
        match dispatch(&bytes, ingress(), &[]) {
            Err(DispatchError::DatagramTooLarge { length, maximum }) => {
                assert_eq!(length, MAX_DATAGRAM_LEN + 1);
                assert_eq!(maximum, MAX_DATAGRAM_LEN);
            }
            other => panic!("unexpected dispatch result: {other:?}"),
        }
    }

    #[test]
    fn dispatches_bootp_leasequery_and_regular_dhcp() {
        let bootp = packet(&[]);
        assert_eq!(
            dispatch(&bootp, ingress(), &[]).unwrap().kind,
            DispatchKind::Bootp
        );
        let query = packet(&[53, 1, 10]);
        assert_eq!(
            dispatch(&query, ingress(), &[]).unwrap().kind,
            DispatchKind::LeaseQuery
        );
        let discover = packet(&[53, 1, 1]);
        assert_eq!(
            dispatch(&discover, ingress(), &[]).unwrap().kind,
            DispatchKind::Dhcp
        );
        let unknown = packet(&[53, 1, 99]);
        assert_eq!(
            dispatch(&unknown, ingress(), &[]).unwrap().kind,
            DispatchKind::Unsupported
        );
    }

    #[test]
    fn preserves_relay_source_extension_and_normal_giaddr() {
        let mut source = packet(&[53, 1, 3]);
        source[24..28].copy_from_slice(&[255, 255, 255, 255]);
        assert_eq!(
            dispatch(&source, ingress(), &[]).unwrap().route,
            Route::RelaySource {
                original_giaddr: Ipv4Addr::new(255, 255, 255, 255)
            }
        );
        let mut relay = packet(&[53, 1, 3]);
        relay[24..28].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(
            dispatch(&relay, ingress(), &[]).unwrap().route,
            Route::Relay {
                giaddr: Ipv4Addr::new(192, 0, 2, 1)
            }
        );
    }

    #[test]
    fn pxe_listener_and_vendor_prefix_are_explicit_dispatches() {
        let vendor = packet(&[
            53, 1, 1, 60, 9, b'P', b'X', b'E', b'C', b'l', b'i', b'e', b'n', b't',
        ]);
        assert_eq!(
            dispatch(&vendor, ingress(), &[b"PXEClient"]).unwrap().kind,
            DispatchKind::Pxe
        );
        let pxe = Ingress {
            listener: Listener::Pxe,
            ..ingress()
        };
        let ordinary = packet(&[53, 1, 1]);
        assert_eq!(
            dispatch(&ordinary, pxe, &[]).unwrap().kind,
            DispatchKind::Pxe
        );
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires Linux isolated loopback; run with run_isolated.sh"]
    fn socket_listener_processes_local_ack_and_replies_to_peer() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let mut listener =
            SocketListener::bind("127.0.0.1:0".parse().unwrap(), Listener::Dhcp, &[]).unwrap();
        let target = listener.local_addr().unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut bytes = packet(&[53, 1, 3, 255]);
        bytes[12..16].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
        client.send_to(&bytes, target).unwrap();

        let mut provider = |_dispatch: &Dispatch<'_>| {
            Ok(crate::dhcp::state::Outcome {
                reply: crate::dhcp::state::Reply::Ack {
                    address: Ipv4Addr::LOCALHOST,
                    lease_time: 60,
                    context: 0,
                    server: Ipv4Addr::new(127, 0, 0, 1),
                    rapid_commit: false,
                },
                removed: Vec::new(),
                lost_names: Vec::new(),
                newly_allocated: false,
            })
        };
        let mut output = vec![0; 548];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let report = loop {
            assert!(std::time::Instant::now() < deadline, "DHCP loopback reply did not become ready");
            match listener
                .process_once_local(&mut provider, &[], &mut output, || false)
                .unwrap()
            {
                ListenerStep::Processed(Ok(report)) => break report,
                ListenerStep::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(1)),
                other => panic!("unexpected listener result: {other:?}"),
            }
        };
        assert!(report.events.iter().any(|event| matches!(
            event,
            crate::dhcp::runtime::RuntimeEvent::Sent { length } if *length >= 300
        )));
        let mut response = [0; 548];
        let (length, peer) = client.recv_from(&mut response).unwrap();
        // The socket source is the listener's address. The exact source-port
        // choice is kernel/pktinfo dependent in this loopback fixture; C's
        // destination selection is covered separately by `destination` tests.
        assert_eq!(peer.ip(), target.ip());
        assert!(length >= 300);
        assert_eq!(&response[..4], &[2, 1, 6, 0]);
        assert_eq!(response[16..20], Ipv4Addr::LOCALHOST.octets());
    }

    #[test]
    fn pxe_admission_keeps_large_input_and_leasequery_precedence() {
        let mut bytes = packet(&[53, 1, 1, 255]);
        bytes.resize(MAX_DATAGRAM_LEN, 0);
        let pxe_ingress = Ingress {
            listener: Listener::Pxe,
            ..ingress()
        };
        assert_eq!(
            dispatch(&bytes, pxe_ingress, &[]).unwrap().kind,
            DispatchKind::Pxe
        );
        bytes[242] = 10;
        assert_eq!(
            dispatch(&bytes, pxe_ingress, &[]).unwrap().kind,
            DispatchKind::LeaseQuery
        );
    }

    #[test]
    fn malformed_request_is_rejected_without_panicking() {
        let mut bytes = packet(&[53, 1, 1]);
        bytes[0] = 2; // BOOTREPLY: dhcp.c/rfc2131.c only accepts BOOTREQUEST.
        assert!(matches!(
            dispatch(&bytes, ingress(), &[]),
            Err(DispatchError::Packet(ParseError::NotRequest))
        ));
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires Linux isolated loopback; run with run_isolated.sh"]
    fn receive_once_admits_loopback_pktinfo_and_preserves_addresses() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let listener = crate::net::DatagramSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let target = listener.local_addr().unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bytes = packet(&[]);
        client.send_to(&bytes, target).unwrap();
        let mut buffer = vec![0; MAX_PACKET_LEN];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let received = loop {
            assert!(std::time::Instant::now() < deadline, "DHCP loopback input did not become ready");
            match receive_once(&listener, &mut buffer, Listener::Dhcp, &[]) {
                Ok(Some(Ok(received))) => break received,
                Ok(Some(Err(error))) => panic!("unexpected DHCP parse error: {error:?}"),
                Ok(None) => panic!("pktinfo datagram was not admitted"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("receive_once failed: {error}"),
            }
        };
        assert_eq!(received.destination, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(received.local_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            received.interface,
            received.dispatch.ingress.interface_index
        );
        assert_ne!(received.interface, 0);
        assert!(received.dispatch.ingress.unicast_destination);
        assert_eq!(received.dispatch.kind, DispatchKind::Bootp);
        assert_eq!(received.peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(received.dispatch.packet.bytes(), bytes.as_slice());
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires Linux isolated loopback; run with run_isolated.sh"]
    fn receive_once_rejects_ipv6_for_dhcpv4() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let listener = match crate::net::DatagramSocket::bind("[::1]:0".parse().unwrap()) {
            Ok(listener) => listener,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::AddrNotAvailable) => return,
            Err(error) => panic!("IPv6 loopback bind failed: {error}"),
        };
        let target = listener.local_addr().unwrap();
        let client = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let bytes = packet(&[]);
        client.send_to(&bytes, target).unwrap();
        let mut buffer = vec![0; MAX_PACKET_LEN];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            assert!(std::time::Instant::now() < deadline, "IPv6 loopback input did not become ready");
            match receive_once(&listener, &mut buffer, Listener::Dhcp, &[]) {
                Ok(None) => break,
                Ok(Some(Ok(received))) => {
                    panic!("IPv6 DHCPv4 datagram admitted: {received:?}")
                }
                Ok(Some(Err(error))) => panic!("unexpected DHCP parse error: {error:?}"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("receive_once failed: {error}"),
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires Linux isolated loopback; run with run_isolated.sh"]
    fn poll_once_is_nonblocking_and_stop_aware() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let listener = crate::net::DatagramSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut buffer = vec![0; MAX_PACKET_LEN];
        assert!(matches!(
            poll_once(&listener, &mut buffer, Listener::Dhcp, &[], || true).unwrap(),
            PollOutcome::Stopped
        ));
        assert!(matches!(
            poll_once(&listener, &mut buffer, Listener::Dhcp, &[], || false).unwrap(),
            PollOutcome::WouldBlock
        ));
    }
}
