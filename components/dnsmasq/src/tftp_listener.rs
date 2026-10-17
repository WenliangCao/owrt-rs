//! Single-owner TFTP listeners sharing one transfer table and capacity limit.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

#[path = "tftp_policy.rs"]
mod policy;
use crate::config::{dns::DnsConfig, tftp::TftpConfig};
use crate::neighbors::MacLookup;
use crate::interfaces::DnsInterface;
use crate::net::{Datagram, DatagramSocket};
use crate::tftp_runtime::{
    Completion, FileOpener, RealFileOpener, RequestPolicy, RuntimeConfig, RuntimeEvent,
    RuntimePathPolicy, SocketRole, TransferId, TransferRuntime,
};
use policy::{Admission, Policy};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, UdpSocket};
use std::os::fd::{AsFd, AsRawFd};

struct Server {
    socket: DatagramSocket,
    address: SocketAddr,
    accepting: bool,
    bound_interface: Option<BoundInterface>,
    persistent_unowned: bool,
}
struct BoundInterface {
    name: Vec<u8>,
    mtu: Option<u32>,
}
#[derive(Clone, Copy)]
struct Route {
    server: SocketAddr,
    local: IpAddr,
    interface: u32,
}
struct Pending {
    datagram: Datagram,
    bytes: Vec<u8>,
    route: Route,
    name: Vec<u8>,
    mtu: Option<u32>,
    deadline: u64,
}

pub struct TftpListener<O> {
    dump: crate::dump::DumpHandle,
    servers: Vec<Server>,
    transfers: BTreeMap<TransferId, UdpSocket>,
    routes: BTreeMap<TransferId, Route>,
    runtime: TransferRuntime<O>,
    port_range: Option<(u16, u16)>,
    single_port: bool,
    buffer: Vec<u8>,
    policy: Option<Policy>,
    pending: VecDeque<Pending>,
    pending_admission: Option<(Pending, bool)>,
    completed: VecDeque<Completion>,
    refreshed: u64,
    accepting: bool,
    pending_bind: Vec<SocketAddr>,
    shared_listener_owner: bool,
    retired_explicit: Vec<IpAddr>,
    restricted_transfer_limit: Option<i128>,
}
impl TftpListener<RealFileOpener> {
    /// Bind before dropping privileges. Directory checks belong to
    /// validate_roots AFTER the caller drops its UID/GID/capabilities.
    /// random_sockets is C's DNS-forward-max / 2, or zero with DNS disabled.
    pub fn bind_config(
        config: &TftpConfig,
        dns: &DnsConfig,
        no_dhcp: &[Option<Vec<u8>>],
        no_tftp: &[Option<Vec<u8>>],
        effective_uid: u32,
        random_sockets: usize,
        packet_buffer_size: usize,
    ) -> io::Result<Self> {
        let policy = Policy::new(config, dns, no_dhcp, no_tftp)?;
        let open_max = descriptor_limit()?;
        let random_sockets = random_sockets.min((open_max / 3) as usize);
        let signed_limit = config.signed_transfer_limit(open_max, random_sockets);
        let limit = config.transfer_limit(open_max, random_sockets);
        let runtime = TransferRuntime::new(
            RuntimeConfig {
                packet_buffer_size,
                path: RuntimePathPolicy {
                    prefix: config.root.clone(),
                    lowercase: config.lowercase,
                },
                mtu: config.mtu,
                secure: config.secure,
                effective_uid,
                no_block_size: config.no_block_size,
                max_transfers: limit.unwrap_or(0),
                single_port: config.single_port,
                ..RuntimeConfig::default()
            },
            RealFileOpener::new(effective_uid, config.secure),
        );
        let mut listener = Self::empty(runtime, config.port_range);
        listener.accepting = limit.is_some();
        listener.restricted_transfer_limit =
            (signed_limit < config.max_transfers as i128).then_some(signed_limit);
        listener.policy = Some(policy);
        listener.sync_servers(true)?;
        Ok(listener)
    }
}
impl<O: FileOpener> TftpListener<O> {
    fn empty(runtime: TransferRuntime<O>, port_range: Option<(u16, u16)>) -> Self {
        let single_port = runtime.single_port();
        Self {
            dump: Default::default(),
            servers: Vec::new(),
            transfers: BTreeMap::new(),
            routes: BTreeMap::new(),
            runtime,
            port_range: port_range.map(|(a, b)| (a.min(b), a.max(b))),
            single_port,
            // The shared pktinfo receiver rejects truncated datagrams. Read
            // the full UDP packet, then expose only C's503-byte workspace.
            buffer: vec![0; 65535],
            policy: None,
            pending: VecDeque::new(),
            pending_admission: None,
            completed: VecDeque::new(),
            refreshed: 0,
            accepting: true,
            pending_bind: Vec::new(),
            shared_listener_owner: false,
            retired_explicit: Vec::new(),
            restricted_transfer_limit: None,
        }
    }
    pub fn bind(address: SocketAddr, runtime: TransferRuntime<O>) -> io::Result<Self> {
        Self::bind_with_port_range(address, runtime, None)
    }
    pub fn set_dump(&mut self, dump: crate::dump::DumpHandle) {
        self.dump = dump;
    }
    pub fn bind_with_port_range(
        address: SocketAddr,
        runtime: TransferRuntime<O>,
        port_range: Option<(u16, u16)>,
    ) -> io::Result<Self> {
        let socket = DatagramSocket::bind(address)?;
        let address = socket.local_addr()?;
        let mut listener = Self::empty(runtime, port_range);
        listener.servers.push(Server {
            socket,
            address,
            accepting: true,
            bound_interface: None,
            persistent_unowned: false,
        });
        Ok(listener)
    }
    pub fn validate_roots(&self) -> io::Result<Vec<Vec<u8>>> {
        self.policy
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |policy| policy.config.validate_roots())
    }
    pub fn root_accesses(
        &self,
    ) -> Result<Vec<crate::config::tftp::RootWarning>, crate::config::tftp::RootAccessError> {
        self.policy
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |policy| policy.config.root_accesses())
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.servers
            .first()
            .map(|server| server.address)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no TFTP listener"))
    }
    pub fn active_transfers(&self) -> usize {
        self.runtime.active_len()
    }
    /// Pending MAC lookups need owner wakeups even before a transfer exists.
    pub fn has_pending_work(&self) -> bool {
        self.runtime.active_len() != 0 || !self.pending.is_empty() || self.pending_admission.is_some()
    }
    pub fn needs_interface_admission(&self) -> bool {
        self.pending_admission.is_some()
    }
    /// Resume the saved datagram after the existing shared owner's collection.
    /// It now tests only C's published-list exceptions, never the old name.
    pub fn resume_interface_admission(&mut self, interfaces: &[DnsInterface], now: u64) {
        let Some((mut pending, loopback)) = self.pending_admission.take() else { return };
        self.refresh_listener_interfaces(interfaces);
        if self.policy.as_ref().is_some_and(|policy|
            policy.admitted_exception(&pending.datagram, &pending.name, loopback))
        {
            pending.deadline = now.saturating_add(2);
            self.pending.push_back(pending);
        }
    }
    pub fn needs_mac_lookup(&self) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|policy| policy.config.unique_root_mac)
    }
    pub fn quiet_not_found(&self) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|policy| policy.config.quiet)
    }
    pub fn restricted_transfer_limit(&self) -> Option<i128> {
        self.restricted_transfer_limit
    }
    /// The owner queries this before dropping privileges. Only static DAD
    /// and dynamic listeners can need a later privileged TFTP bind.
    pub fn needs_privileged_rebind(&self) -> bool {
        !self.pending_bind.is_empty()
            || self
                .policy
                .as_ref()
                .is_some_and(|policy| policy.dns.bind_dynamic)
    }
    /// DNS and TFTP share iface->done in C. The main owner enables this after
    /// startup, then attempts all transports once per address generation.
    pub fn use_shared_listener_owner(&mut self) {
        self.shared_listener_owner = true;
    }
    pub fn listener_addresses(&self) -> Vec<SocketAddr> {
        self.policy.as_ref().map_or_else(Vec::new, |policy| {
            let mut addresses = policy.addresses();
            for server in self
                .servers
                .iter()
                .filter(|server| server.persistent_unowned)
            {
                if !addresses.contains(&server.address) {
                    addresses.push(server.address);
                }
            }
            // C's INAME_USED stays set after an explicit address gains an
            // interface. Losing its last owner cannot create a fallback.
            addresses.retain(|address| {
                !self.retired_explicit.contains(&address.ip())
                    || policy
                        .interfaces
                        .iter()
                        .any(|row| row.address == address.ip())
            });
            addresses
        })
    }
    pub fn pending_listener_addresses(&self) -> &[SocketAddr] {
        &self.pending_bind
    }
    /// Any DNS/TFTP transport success sets C's shared iface->done latch.
    pub fn finish_shared_listener_attempt(&mut self, mut address: SocketAddr) {
        address.set_port(69);
        self.pending_bind.retain(|pending| *pending != address);
    }
    /// A common owner key can carry the DNS port (including disabled port 0).
    pub fn has_listener(&self, mut address: SocketAddr) -> bool {
        address.set_port(69);
        self.servers
            .iter()
            .any(|server| server.address == address && server.accepting)
    }
    pub fn refresh_listener_interfaces(&mut self, interfaces: &[crate::interfaces::DnsInterface]) {
        let Some(policy) = self.policy.as_mut() else {
            return;
        };
        policy.interfaces = interfaces.to_vec();
        let dynamic = policy.dns.bind_dynamic;
        if dynamic {
            self.pending_bind = policy.addresses().into_iter()
                .filter(|address| policy.tentative(*address))
                .collect();
            let addresses = self.listener_addresses();
            for server in &mut self.servers {
                server.accepting = server.persistent_unowned || addresses.contains(&server.address);
            }
            self.discard_inactive_servers();
        }
    }
    /// Retire the last interface owner's listener. Only configured explicit
    /// IPs are retained as history, bounding this state by configuration size.
    /// A later real interface can reactivate the address.
    pub fn retire_listener(&mut self, mut address: SocketAddr) {
        address.set_port(69);
        if self
            .servers
            .iter()
            .any(|server| server.address == address && server.persistent_unowned)
        {
            return;
        }
        if self
            .policy
            .as_ref()
            .is_some_and(|policy| policy.dns.listen_addresses.contains(&address.ip()))
            && !self.retired_explicit.contains(&address.ip())
        {
            self.retired_explicit.push(address.ip());
        }
        for server in &mut self.servers {
            if server.address == address {
                server.accepting = false;
            }
        }
        self.discard_inactive_servers();
    }
    /// Return false for a transport which is disabled by interface policy or
    /// still waiting for DAD. The owner records success of any transport; an
    /// error must not cause an independently successful DNS socket to be lost.
    pub fn bind_listener(&mut self, mut address: SocketAddr) -> io::Result<bool> {
        address.set_port(69);
        let Some(policy) = self.policy.as_ref() else {
            return Ok(false);
        };
        if !self.listener_addresses().contains(&address) || policy.tentative(address) {
            return Ok(false);
        }
        if self.has_listener(address) {
            return Ok(true);
        }
        let socket = DatagramSocket::bind(address)?;
        let bound_interface = bound_interface(policy, address, &socket);
        let persistent_unowned = !policy
            .interfaces
            .iter()
            .any(|row| row.address == address.ip());
        self.servers.push(Server {
            socket,
            address,
            accepting: true,
            bound_interface,
            persistent_unowned,
        });
        self.pending_bind.retain(|pending| *pending != address);
        Ok(true)
    }
    /// Retain successful transfers until the poll owner hands each event to
    /// the nonblocking helper. Active plus completed transfers share the
    /// configured capacity, so a slow script cannot grow this queue.
    pub fn front_completion(&self) -> Option<&Completion> {
        self.completed.front()
    }

    pub fn pop_completion(&mut self) -> Option<Completion> {
        self.completed.pop_front()
    }

    fn has_capacity(&self) -> bool {
        self.runtime
            .active_len()
            .saturating_add(self.completed.len())
            < self.runtime.transfer_capacity()
    }

    fn can_start(&self, peer: SocketAddr) -> bool {
        self.has_capacity() || self.single_port && self.runtime.has_peer(peer)
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<dnsmasq_platform::poll::PollFd>) {
        use dnsmasq_platform::poll::{PollFd, POLLIN};
        for server in self.servers.iter().filter(|_| self.pending_admission.is_none()) {
            if self.single_port || self.accepting && server.accepting && self.has_capacity() {
                fds.push(PollFd {
                    fd: server.socket.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
            }
        }
        for socket in self.transfers.values() {
            fds.push(PollFd {
                fd: socket.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            });
        }
    }
    pub fn poll_once(&mut self, now: u64) -> io::Result<Vec<RuntimeEvent>> {
        self.poll_once_with_mac(now, &mut |_, _, _| MacLookup::Ready(None))
    }
    /// The callback checks DHCP leases first, then the shared nonblocking
    /// neighbor cache. At most eight RRQs may await a neighbor snapshot.
    pub fn poll_once_with_mac(
        &mut self,
        now: u64,
        mac: &mut dyn FnMut(IpAddr, u32, u64) -> MacLookup,
    ) -> io::Result<Vec<RuntimeEvent>> {
        let mut events = Vec::new();
        if self.policy.is_some() && !self.shared_listener_owner && now != self.refreshed {
            self.refreshed = now;
            if let Some(policy) = self.policy.as_mut() {
                policy.refresh()?;
            }
            self.sync_servers(false)?;
        }
        let waiting = self.pending.len();
        for _ in 0..waiting {
            // `waiting` is a snapshot, but a future queue implementation may
            // coalesce or drop an entry while dispatching. Treat an empty
            // queue as drained instead of turning a malformed state into a
            // daemon panic.
            let Some(pending) = self.pending.pop_front() else {
                break;
            };
            let need_mac = matches!(pending.bytes.get(..2), Some([0, 1] | [0, 2]))
                && self.policy.as_ref().is_some_and(|policy| policy.needs_mac(&pending.name));
            let found = if need_mac {
                match mac(pending.datagram.peer.ip(), pending.datagram.interface, now) {
                    MacLookup::Ready(found) => found,
                    MacLookup::Pending if now < pending.deadline => {
                        self.pending.push_back(pending);
                        continue;
                    }
                    MacLookup::Pending => None,
                }
            } else {
                None
            };
            self.dispatch(pending, found, now, &mut events)?;
        }
        for index in 0..self.servers.len() {
            self.receive_server(index, now, mac, &mut events)?;
        }
        if !self.single_port {
            let ids: Vec<_> = self.transfers.keys().copied().collect();
            for id in ids {
                self.receive_transfer(id, now, &mut events)?;
            }
        }
        let mut tick = self.runtime.tick(now).map_err(runtime_io)?;
        self.flush_events(&mut tick, None, None);
        events.extend(tick);
        self.routes
            .retain(|id, _| self.runtime.contains_transfer(*id));
        Ok(events)
    }
    fn sync_servers(&mut self, initial: bool) -> io::Result<()> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        if !initial && !policy.dns.bind_dynamic && self.pending_bind.is_empty() {
            return Ok(());
        }
        let addresses = if initial || policy.dns.bind_dynamic {
            policy.addresses()
        } else {
            self.pending_bind.clone()
        };
        if policy.dns.bind_dynamic {
            for server in &mut self.servers {
                server.accepting = addresses.contains(&server.address);
            }
        }
        self.pending_bind.clear();
        for address in addresses {
            if self.servers.iter().any(|server| server.address == address) {
                continue;
            }
            if !initial
                && !policy.dns.bind_dynamic
                && !policy
                    .interfaces
                    .iter()
                    .any(|row| row.address == address.ip())
            {
                self.pending_bind.push(address);
                continue;
            }
            // Like C iface->dad, defer only addresses still undergoing DAD.
            // Static binding retries these at refresh; other bind errors
            // remain startup failures.
            if policy.tentative(address) {
                self.pending_bind.push(address);
                continue;
            }
            match DatagramSocket::bind(address) {
                Ok(socket) => {
                    let bound_interface = bound_interface(policy, address, &socket);
                    let persistent_unowned = !policy
                        .interfaces
                        .iter()
                        .any(|row| row.address == address.ip());
                    self.servers.push(Server {
                        socket,
                        address,
                        accepting: true,
                        bound_interface,
                        persistent_unowned,
                    });
                }
                Err(error)
                    if policy.dns.bind_dynamic
                        && (error.kind() == io::ErrorKind::AddrNotAvailable || !initial) => {}
                // A kernel without IPv6 follows C's optional IPv6 listener.
                Err(error) if crate::net::is_unsupported_socket_error(&error) => {}
                Err(error) => return Err(error),
            }
        }
        self.discard_inactive_servers();
        Ok(())
    }
    fn discard_inactive_servers(&mut self) {
        // Keep a removed single-port listener until its existing transfers
        // finish, preserving ACK and retransmission routing during reload.
        self.servers.retain(|server| {
            server.accepting
                || self
                    .routes
                    .values()
                    .any(|route| route.server == server.address)
        });
    }
    fn receive_server(
        &mut self,
        index: usize,
        now: u64,
        mac: &mut dyn FnMut(IpAddr, u32, u64) -> MacLookup,
        events: &mut Vec<RuntimeEvent>,
    ) -> io::Result<()> {
        if self.pending_admission.is_some() {
            return Ok(());
        }
        if !self.single_port
            && (!self.accepting || !self.servers[index].accepting || !self.has_capacity())
        {
            return Ok(());
        }
        let Some(datagram) = receive_pending(&self.servers[index].socket, &mut self.buffer)? else {
            return Ok(());
        };
        self.dump.udp(
            crate::dump::TFTP,
            &self.buffer[..datagram.len.min(crate::tftp_service::MAX_PATH_BYTES)],
            datagram.peer,
            self.servers[index].socket.local_addr()?,
        );
        let bytes = self.buffer[..datagram.len.min(crate::tftp_service::MAX_PATH_BYTES)].to_vec();
        let new_request = matches!(bytes.get(..2), Some([0, 1] | [0, 2]));
        if new_request
            && (!self.accepting || !self.servers[index].accepting || !self.can_start(datagram.peer))
        {
            return Ok(());
        }
        let route = Route {
            server: self.servers[index].address,
            local: datagram.local_address,
            interface: datagram.interface,
        };
        let mut name = Vec::new();
        let mut mtu = None;
        let mut loopback = false;
        let mut refresh = false;
        if let Some(policy) = &self.policy {
            let bound =
                policy.dns.bind_interfaces && !policy.dns.bind_dynamic && datagram.peer.is_ipv4();
            if bound {
                if let Some(interface) = &self.servers[index].bound_interface {
                    name.clone_from(&interface.name);
                    mtu = interface.mtu;
                }
            } else {
                let Ok(found) =
                    crate::net::interface_name(&self.servers[index].socket, datagram.interface)
                else {
                    return Ok(());
                };
                loopback = crate::net::interface_loopback(&self.servers[index].socket, &found)
                    .is_ok_and(|value| value);
                name.extend(found.into_iter().take_while(|byte| *byte != 0));
            }
            match policy.admission(&datagram, &name, loopback) {
                Admission::Accept => {}
                Admission::Reject => return Ok(()),
                Admission::Refresh => refresh = true,
            }
            if !bound {
                mtu = interface_mtu(&self.servers[index].socket, &name);
            }
        }
        let pending = Pending {
            datagram,
            bytes,
            route,
            name,
            mtu,
            deadline: now.saturating_add(2),
        };
        if refresh {
            if self.shared_listener_owner {
                // One original packet shares the existing eight-waiter cap;
                // the main owner supplies its existing collector continuation.
                if self.pending.len() < 8 {
                    self.pending_admission = Some((pending, loopback));
                }
                return Ok(());
            }
            let Some(policy) = &mut self.policy else { return Ok(()) };
            policy.refresh()?;
            if !policy.admitted_exception(&datagram, &pending.name, loopback) {
                return Ok(());
            }
        }
        let need_mac = new_request
            && self
                .policy
                .as_ref()
                .is_some_and(|policy| policy.needs_mac(&pending.name));
        if need_mac && self.pending.len() >= 8 {
            return Ok(());
        }
        let found = if need_mac {
            match mac(datagram.peer.ip(), datagram.interface, now) {
                MacLookup::Ready(found) => found,
                MacLookup::Pending => {
                    if self.pending.len() < 8 {
                        self.pending.push_back(pending);
                    }
                    return Ok(());
                }
            }
        } else {
            None
        };
        self.dispatch(pending, found, now, events)
    }
    fn dispatch(
        &mut self,
        pending: Pending,
        mac: Option<[u8; 6]>,
        now: u64,
        events: &mut Vec<RuntimeEvent>,
    ) -> io::Result<()> {
        let Pending {
            datagram,
            bytes,
            route,
            name,
            mtu,
            ..
        } = pending;
        if matches!(bytes.get(..2), Some([0, 1] | [0, 2])) && !self.can_start(datagram.peer) {
            return Ok(());
        }
        // C opens the transfer socket before opening the file.
        let socket = if !self.single_port && matches!(bytes.get(..2), Some([0, 1] | [0, 2])) {
            match bind_transfer_address(
                local_address(route.local, route.interface),
                self.port_range,
            ) {
                Ok(socket) => Some(socket),
                Err(error) => {
                    if self.port_range.is_some_and(|(start, _)| start != 0)
                        && error.kind() == io::ErrorKind::AddrInUse
                    {
                        events.push(RuntimeEvent::NoFreePort);
                    }
                    events.push(RuntimeEvent::TransportError {
                        id: None,
                        peer: datagram.peer,
                        kind: error.kind(),
                    });
                    return Ok(());
                }
            }
        } else {
            None
        };
        let request: Option<RequestPolicy> = self
            .policy
            .as_ref()
            .map(|policy| policy.request(&datagram, &name, mtu, mac));
        let mut received = self
            .runtime
            .handle_datagram_with_policy(datagram.peer, &bytes, now, request.as_ref())
            .map_err(runtime_io)?;
        self.flush_events(&mut received, socket, Some(route));
        events.extend(received);
        Ok(())
    }
    fn receive_transfer(
        &mut self,
        id: TransferId,
        now: u64,
        events: &mut Vec<RuntimeEvent>,
    ) -> io::Result<()> {
        let Some(socket) = self.transfers.get(&id) else {
            return Ok(());
        };
        let (len, peer) =
            match socket.recv_from(&mut self.buffer[..crate::tftp_service::MAX_PATH_BYTES]) {
                Ok(value) => value,
                Err(_) => return Ok(()),
            };
        self.dump.udp(
            crate::dump::TFTP,
            &self.buffer[..len],
            peer,
            socket.local_addr()?,
        );
        let mut received = self
            .runtime
            .handle_socket_datagram(SocketRole::Transfer(id), peer, &self.buffer[..len], now)
            .map_err(runtime_io)?;
        self.flush_events(&mut received, None, None);
        events.extend(received);
        Ok(())
    }
    fn flush_events(
        &mut self,
        events: &mut Vec<RuntimeEvent>,
        mut socket: Option<UdpSocket>,
        route: Option<Route>,
    ) {
        let mut errors = Vec::new();
        for event in &*events {
            let sending = match event {
                RuntimeEvent::Send { id, peer, packet } => Some((*id, *peer, packet)),
                RuntimeEvent::TidError { id, peer, packet } => Some((Some(*id), *peer, packet)),
                RuntimeEvent::Completed(done) => {
                    self.transfers.remove(&done.id);
                    self.routes.remove(&done.id);
                    self.completed.push_back(done.clone());
                    None
                }
                RuntimeEvent::Failed { id, .. }
                | RuntimeEvent::TimedOut { id, .. }
                | RuntimeEvent::Discarded { id } => {
                    self.transfers.remove(id);
                    self.routes.remove(id);
                    None
                }
                RuntimeEvent::TransportError { .. }
                | RuntimeEvent::ClientError { .. }
                | RuntimeEvent::NoFreePort => None,
            };
            if let Some((id, peer, packet)) = sending {
                if let (Some(id), Some(route)) = (id, route) {
                    self.routes.entry(id).or_insert(route);
                }
                if let Err(error) = self.transmit(id, peer, packet, &mut socket, route) {
                    errors.push(RuntimeEvent::TransportError {
                        id,
                        peer,
                        kind: error.kind(),
                    });
                }
            }
        }
        events.extend(errors);
    }
    fn transmit(
        &mut self,
        id: Option<TransferId>,
        peer: SocketAddr,
        packet: &[u8],
        new_socket: &mut Option<UdpSocket>,
        incoming: Option<Route>,
    ) -> io::Result<()> {
        if self.single_port {
            let route = id
                .and_then(|id| self.routes.get(&id).copied())
                .or(incoming)
                .ok_or_else(|| io::Error::other("missing TFTP source route"))?;
            let server = self
                .servers
                .iter()
                .find(|server| server.address == route.server)
                .ok_or_else(|| io::Error::other("missing TFTP listener"))?;
            self.dump
                .udp(crate::dump::TFTP, packet, server.socket.local_addr()?, peer);
            return server
                .socket
                .send(packet, peer, Some((route.local, route.interface)));
        }
        let socket = if let Some(id) = id {
            if let std::collections::btree_map::Entry::Vacant(entry) = self.transfers.entry(id) {
                entry.insert(
                    new_socket
                        .take()
                        .ok_or_else(|| io::Error::other("missing TFTP transfer socket"))?,
                );
            }
            self.transfers
                .get(&id)
                .ok_or_else(|| io::Error::other("missing TFTP transfer socket"))?
        } else {
            new_socket
                .as_ref()
                .ok_or_else(|| io::Error::other("missing TFTP error socket"))?
        };
        self.dump
            .udp(crate::dump::TFTP, packet, socket.local_addr()?, peer);
        match socket.send_to(packet, peer) {
            Ok(sent) if sent == packet.len() => Ok(()),
            Ok(_) => Err(io::Error::new(io::ErrorKind::WriteZero, "short TFTP send")),
            Err(error) => Err(error),
        }
    }
}
fn local_address(ip: IpAddr, interface: u32) -> SocketAddr {
    match ip {
        IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
            ip,
            0,
            0,
            if ip.is_unicast_link_local() {
                interface
            } else {
                0
            },
        )),
        ip => SocketAddr::new(ip, 0),
    }
}
#[cfg(test)]
fn bind_transfer(ip: IpAddr, range: Option<(u16, u16)>) -> io::Result<UdpSocket> {
    bind_transfer_address(SocketAddr::new(ip, 0), range)
}
fn bind_transfer_address(
    mut address: SocketAddr,
    range: Option<(u16, u16)>,
) -> io::Result<UdpSocket> {
    let (start, end) = range.unwrap_or((0, 0));
    let end = if start == 0 { 0 } else { end };
    for port in start..=end {
        address.set_port(port);
        match UdpSocket::bind(address) {
            Ok(socket) => {
                // tftp.c:342: permit IPv4 fragmentation for negotiated blocks
                // exceeding the path MTU, including IPv4 on a dual-family fd.

                rustix::net::sockopt::set_ip_mtu_discover(
                    &socket, rustix::net::sockopt::Ipv4PathMtuDiscovery::DONT,
                )?;
                socket.set_nonblocking(true)?;
                return Ok(socket);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && port < end => {}
            Err(error) => return Err(error),
        }
    }
    unreachable!("normalized port range")
}
fn receive_pending(socket: &DatagramSocket, buffer: &mut [u8]) -> io::Result<Option<Datagram>> {
    match socket.receive(buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        result => result,
    }
}
fn runtime_io<E: std::fmt::Debug>(error: E) -> io::Error {
    io::Error::other(format!("TFTP runtime: {error:?}"))
}
fn interface_mtu(fd: &impl AsFd, name: &[u8]) -> Option<u32> {
    dnsmasq_platform::interfaces::interface_mtu(fd, name).ok()
}
fn bound_interface(policy: &Policy, address: SocketAddr, fd: &impl AsFd) -> Option<BoundInterface> {
    if !policy.dns.bind_interfaces || policy.dns.bind_dynamic || address.is_ipv6() {
        return None;
    }
    let row = policy
        .interfaces
        .iter()
        .find(|row| row.address == address.ip())?;
    let name = row.link_name().to_vec();
    Some(BoundInterface {
        mtu: interface_mtu(fd, &name),
        name,
    })
}
fn descriptor_limit() -> io::Result<u64> {
    Ok(rustix::process::getrlimit(rustix::process::Resource::Nofile).current.unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tftp_runtime::{RealFileOpener, RuntimeConfig, RuntimePathPolicy};
    use std::net::UdpSocket;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    #[test]
    #[ignore = "requires tools/dnsmasq/run_isolated.sh network namespace"]
    fn port_range_upper_bound_exhaustion_and_zero_start() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        for ip in ["127.0.0.1", "::1"] {
            let ip: IpAddr = ip.parse().unwrap();
            let blocker = UdpSocket::bind(SocketAddr::new(ip, u16::MAX)).unwrap();
            assert_eq!(
                bind_transfer(ip, Some((u16::MAX, u16::MAX)))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AddrInUse
            );
            drop(blocker);
            let released = bind_transfer(ip, Some((u16::MAX, u16::MAX))).unwrap();
            assert_eq!(released.local_addr().unwrap().port(), u16::MAX);
            let ephemeral = bind_transfer(ip, Some((0, 1))).unwrap();
            assert!(ephemeral.local_addr().unwrap().port() > 1);
        }
    }

    #[test]
    #[ignore = "requires tools/dnsmasq/run_isolated.sh network namespace"]
    fn dedicated_tid_idle_tick_and_cleanup_on_ipv4_and_ipv6() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let root = std::env::temp_dir().join(format!("tftp-listener-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("boot.bin");
        std::fs::write(&path, b"hello").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        for ip in ["127.0.0.1", "::1"] {
            let address = SocketAddr::new(ip.parse().unwrap(), 0);
            let runtime = TransferRuntime::new(
                RuntimeConfig {
                    path: RuntimePathPolicy {
                        prefix: Some(root.as_os_str().as_bytes().to_vec()),
                        lowercase: false,
                    },
                    ipv6: address.is_ipv6(),
                    ..RuntimeConfig::default()
                },
                RealFileOpener::new(0, false),
            );
            let mut listener = TftpListener::bind(address, runtime).unwrap();
            let server = listener.local_addr().unwrap();
            let first = UdpSocket::bind(address).unwrap();
            let second = UdpSocket::bind(address).unwrap();
            for client in [&first, &second] {
                client
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
            }
            assert!(listener.poll_once(1).unwrap().is_empty());
            let mut transfer_addresses = Vec::new();
            let mut buffer = [0; 512];
            for client in [&first, &second] {
                client.send_to(b"\0\x01boot.bin\0octet\0", server).unwrap();
                listener.poll_once(1).unwrap();
                let (len, transfer) = client.recv_from(&mut buffer).unwrap();
                assert_eq!(&buffer[..len], b"\0\x03\0\x01hello");
                assert_ne!(transfer, server);
                // A second SO_REUSEADDR socket must not be able to claim
                // an active transfer's TID (the C transfer bind is exclusive).
                assert!(DatagramSocket::bind(transfer).is_err());
                transfer_addresses.push(transfer);
            }
            assert_ne!(transfer_addresses[0], transfer_addresses[1]);
            for packet in [&[0][..], &[0, 4, 0, 1], &[0, 5, 0, 0]] {
                second.send_to(packet, transfer_addresses[0]).unwrap();
                let events = listener.poll_once(1).unwrap();
                assert!(matches!(events.as_slice(), [RuntimeEvent::TidError { .. }]));
                let (len, source) = second.recv_from(&mut buffer).unwrap();
                assert!(len >= 5);
                assert_eq!(&buffer[..4], &[0, 5, 0, 5]);
                assert_eq!(source, transfer_addresses[0]);
                assert_eq!(listener.active_transfers(), 2);
                assert_eq!(listener.transfers.len(), 2);
            }
            // An idle server must not starve the transfer sockets or timer.
            first.send_to(&[0, 4, 0, 1], transfer_addresses[0]).unwrap();
            let events = listener.poll_once(1).unwrap();
            assert!(matches!(events.as_slice(), [RuntimeEvent::Completed(_)]));
            assert_eq!(listener.transfers.len(), 1);
            let _reclaimed = UdpSocket::bind(transfer_addresses[0]).unwrap();
            let retry = listener.poll_once(3).unwrap();
            assert!(matches!(retry.as_slice(), [RuntimeEvent::Send { .. }]));
            let (len, source) = second.recv_from(&mut buffer).unwrap();
            assert_eq!(source, transfer_addresses[1]);
            assert_eq!(&buffer[..len], b"\0\x03\0\x01hello");
            let timeout = listener.poll_once(122).unwrap();
            assert!(matches!(timeout.as_slice(), [RuntimeEvent::Completed(_)]));
            assert_eq!(listener.active_transfers(), 0);
            assert!(listener.transfers.is_empty());
            // C treats missing only the final ACK as successful.
            assert_eq!(listener.completed.len(), 2);
            let done = listener.pop_completion().unwrap();
            assert_eq!(done.peer, first.local_addr().unwrap());
            assert_eq!(done.size, 5);
            assert_eq!(
                listener.pop_completion().unwrap().peer,
                second.local_addr().unwrap()
            );
            assert!(listener.front_completion().is_none());
            let _reclaimed = UdpSocket::bind(transfer_addresses[1]).unwrap();
            drop(listener);
            let _reclaimed = UdpSocket::bind(server).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    #[ignore = "requires tools/dnsmasq/run_isolated.sh network namespace"]
    fn integrated_dual_stack_shares_capacity_and_pending_mac_does_not_block() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let root = std::env::temp_dir().join(format!("tftp-policy-{}", std::process::id()));
        let unique = root.join("02-00-00-00-00-01");
        std::fs::create_dir_all(&unique).unwrap();
        std::fs::write(unique.join("boot.bin"), b"selected").unwrap();
        std::fs::set_permissions(
            unique.join("boot.bin"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let config = TftpConfig {
            enabled: true,
            root: Some(root.as_os_str().as_bytes().to_vec()),
            unique_root_mac: true,
            max_transfers: 0,
            ..TftpConfig::default()
        };
        let dns = DnsConfig::default();
        let mut listener = TftpListener::bind_config(&config, &dns, &[], &[], 0, 0, 1497).unwrap();
        assert_eq!(listener.servers.len(), 2);
        assert!(listener.validate_roots().unwrap().is_empty());
        let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let v6 = UdpSocket::bind("[::1]:0").unwrap();
        for endpoint in [&v4, &v6] {
            endpoint
                .set_read_timeout(Some(Duration::from_millis(30)))
                .unwrap();
        }
        v4.send_to(b"\0\x01boot.bin\0octet\0", "127.0.0.1:69")
            .unwrap();
        assert!(listener
            .poll_once_with_mac(1, &mut |_, _, _| MacLookup::Pending)
            .unwrap()
            .is_empty());
        assert_eq!(listener.pending.len(), 1);
        assert_eq!(listener.active_transfers(), 0);
        assert!(listener.has_pending_work(), "MAC waiter still needs owner wakeups");
        let mut bytes = [0; 512];
        assert!(v4.recv_from(&mut bytes).is_err());
        listener
            .poll_once_with_mac(1, &mut |_, _, _| MacLookup::Ready(Some([2, 0, 0, 0, 0, 1])))
            .unwrap();
        let (len, source) = v4.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"\0\x03\0\x01selected");
        assert_eq!(listener.active_transfers(), 1);
        v6.send_to(b"\0\x01boot.bin\0octet\0", "[::1]:69").unwrap();
        listener
            .poll_once_with_mac(1, &mut |_, _, _| MacLookup::Ready(Some([2, 0, 0, 0, 0, 1])))
            .unwrap();
        assert!(
            v6.recv_from(&mut bytes).is_err(),
            "capacity is global across address families"
        );
        v4.send_to(&[0, 4, 0, 1], source).unwrap();
        listener.poll_once(1).unwrap();
        assert_eq!(listener.active_transfers(), 0);
        assert_eq!(
            listener.front_completion().unwrap().peer,
            v4.local_addr().unwrap()
        );
        listener
            .poll_once_with_mac(1, &mut |_, _, _| MacLookup::Ready(Some([2, 0, 0, 0, 0, 1])))
            .unwrap();
        assert!(
            v6.recv_from(&mut bytes).is_err(),
            "helper backpressure reserves capacity"
        );
        assert_eq!(listener.completed.len(), 1);
        listener.pop_completion().unwrap();
        listener
            .poll_once_with_mac(1, &mut |_, _, _| MacLookup::Ready(Some([2, 0, 0, 0, 0, 1])))
            .unwrap();
        let (len, source) = v6.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"\0\x03\0\x01selected");
        v6.send_to(&[0, 4, 0, 1], source).unwrap();
        listener.poll_once(1).unwrap();
        assert_eq!(listener.active_transfers(), 0);
        assert!(listener.transfers.is_empty());
        assert!(listener.routes.is_empty());
        assert_eq!(
            listener.pop_completion().unwrap().peer,
            v6.local_addr().unwrap()
        );
        assert!(listener.pop_completion().is_none());
        drop(listener);
        std::fs::remove_dir_all(root).unwrap();
    }
}
