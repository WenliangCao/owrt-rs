//! The protocol loop owns sockets, kernel state and leases. A single bounded
//! worker owns blocking ubus I/O; a missing bus never blocks packet service.
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]
use owrt_odhcpd::config::{self, Config, HostConfig, NetworkInterface, PoolConfig};
use owrt_odhcpd::control::{Bus, Call, Event};
use owrt_odhcpd::dhcpv6::{Dhcpv6, RequestContext};
use owrt_odhcpd::kernel::{Changes, Kernel};
use owrt_odhcpd::leases::{self, StateFiles};
use owrt_odhcpd::model::{Clock, KernelState, Link};
use owrt_odhcpd::netio::{Kind, Socket};
use owrt_odhcpd::router::{self, Advertisement, RaContext, Router};
use owrt_platform::unix::{self, PollFd};
use owrt_ubus::{status, BlobBuf};
use std::ffi::{c_char, c_int, CString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::net::SocketAddrV6;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn signal(number: i32) {
    match number {
        1 => RELOAD.store(true, Ordering::Relaxed),
        2 | 15 => STOP.store(true, Ordering::Relaxed),
        _ => {}
    }
}

unsafe extern "C" {
    fn openlog(ident: *const c_char, option: c_int, facility: c_int);
    fn syslog(priority: c_int, format: *const c_char, ...);
}

struct Logger {
    stderr: bool,
    level: u8,
}

impl Logger {
    fn message(&self, level: u8, message: &str) {
        if level > self.level {
            return;
        }
        if self.stderr {
            eprintln!("odhcpd-rs: {message}");
        } else if let Ok(message) = CString::new(message) {
            // SAFETY: the fixed format and message are terminated strings;
            // user-controlled message text is never interpreted as a format.
            unsafe { syslog(level as c_int, c"%s".as_ptr(), message.as_ptr()) };
        }
    }
}

#[derive(Default)]
struct Options {
    directory: Option<PathBuf>,
    log_level: Option<u8>,
    stderr: bool,
    no_ubus: bool,
}

fn help() {
    println!("odhcpd-rs 0.1.0\nFeatures: ra no-ndp dhcpv6 no-dhcpv4 ubus\nUsage: odhcpd-rs [-c config-directory] [-l loglevel] [-f] [-u] [-h]");
}

fn options() -> Result<Option<Options>, String> {
    let mut options = Options::default();
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let text = argument.to_str().ok_or("non-UTF8 option")?;
        match text {
            "-h" => {
                help();
                return Ok(None);
            }
            "-f" => options.stderr = true,
            "-u" => options.no_ubus = true,
            "-c" => {
                options.directory = Some(arguments.next().ok_or("-c needs a directory")?.into())
            }
            "-l" => {
                let value = arguments.next().ok_or("-l needs a level")?;
                options.log_level =
                    Some((value.to_string_lossy().parse::<i32>().unwrap_or(0) & 7) as u8);
            }
            _ if text.starts_with("-l") && text.len() > 2 => {
                options.log_level = Some((text[2..].parse::<i32>().unwrap_or(0) & 7) as u8);
            }
            _ if text.starts_with("-c") && text.len() > 2 => {
                options.directory = Some(text[2..].into())
            }
            _ => return Err(format!("unknown option: {text}")),
        }
    }
    Ok(Some(options))
}

fn clock() -> Clock {
    let monotonic = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    Clock {
        monotonic_ms: monotonic.tv_sec.max(0) as u64 * 1000
            + monotonic.tv_nsec.max(0) as u64 / 1_000_000,
        unix_seconds: wall.tv_sec,
    }
}

struct RaService {
    socket: Socket,
    router: Router,
    hop_limit: u8,
}

struct Service {
    pool: PoolConfig,
    index: u32,
    ra: Option<RaService>,
    dhcp: Option<Socket>,
}

fn emit_ra(
    ra: &mut RaService,
    packet: Advertisement,
    link: &Link,
    directory: Option<&Path>,
    now: Clock,
) -> io::Result<()> {
    let Some(source) = link.link_local() else {
        return Ok(());
    };
    let destination = SocketAddrV6::new(packet.destination, 0, 0, link.index);
    let written = ra.socket.send(&packet.bytes, destination, Some(source))?;
    if written != packet.bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short RA datagram",
        ));
    }
    ra.router.sent();
    if let Some(directory) = directory {
        ra.router.save_state(directory, now)?;
    }
    Ok(())
}

struct App {
    options: Options,
    logger: Logger,
    config: Config,
    networks: Vec<NetworkInterface>,
    generation: u64,
    kernel: Kernel,
    state: KernelState,
    kernel_dirty: bool,
    services: Vec<Service>,
    dhcp: Dhcpv6,
    files: StateFiles,
    files_dirty: bool,
    bus: Option<Bus>,
    random: File,
}

impl App {
    fn new(options: Options) -> Result<Self, Box<dyn std::error::Error>> {
        // Reject unsupported modes before opening any service socket or
        // exporting files. Later reloads validate a complete replacement too.
        let config = Config::load(options.directory.as_deref())?;
        let logger = Logger {
            stderr: options.stderr,
            level: options.log_level.unwrap_or(config.log_level),
        };
        let mut kernel = Kernel::open()?;
        let state = kernel.snapshot(clock())?;
        let bus = if options.no_ubus {
            None
        } else {
            Some(Bus::start(None)?)
        };
        let mut app = Self {
            options,
            logger,
            config,
            networks: Vec::new(),
            generation: 0,
            kernel,
            state,
            kernel_dirty: false,
            services: Vec::new(),
            dhcp: Dhcpv6::default(),
            files: StateFiles::default(),
            // Like C, a process restart does not import or immediately erase
            // the old export. Publish on an IA/address event instead.
            files_dirty: false,
            bus,
            random: File::open("/dev/urandom")?,
        };
        app.services(true, &Changes::default(), None, clock())?;
        Ok(app)
    }

    fn random(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.random.read_exact(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    fn reload(&mut self, now: Clock) -> Result<(), Box<dyn std::error::Error>> {
        let mut candidate = Config::load(self.options.directory.as_deref())?;
        candidate.apply_network(&self.networks)?;
        self.logger.level = self.options.log_level.unwrap_or(candidate.log_level);
        self.config = candidate;
        self.state = self.kernel.snapshot(now)?;
        self.kernel_dirty = false;
        self.services(true, &Changes::default(), None, now)?;
        self.reconcile(now, false);
        Ok(())
    }

    fn services(
        &mut self,
        reload: bool,
        changes: &Changes,
        previous: Option<&KernelState>,
        now: Clock,
    ) -> io::Result<()> {
        let mut assigned = Vec::new();
        for pool in self.config.pools.iter().filter(|pool| pool.enabled()) {
            if let Some(link) = self
                .state
                .link(pool.ifname.as_deref().unwrap_or(&pool.name))
            {
                if assigned.contains(&link.index) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "multiple IPv6 service pools on one device are unsupported",
                    ));
                }
                assigned.push(link.index);
            }
        }
        let mut old = std::mem::take(&mut self.services);
        for pool in self.config.pools.iter().filter(|pool| pool.enabled()) {
            let device = pool.ifname.as_deref().unwrap_or(&pool.name);
            let Some(link) = self.state.link(device).filter(|link| link.running()) else {
                continue;
            };
            let found = old.iter().position(|service| {
                service.pool.ifname.as_deref().unwrap_or(&service.pool.name) == device
                    && service.index == link.index
            });
            let mut service = if let Some(index) = found {
                old.remove(index)
            } else {
                Service {
                    pool: pool.clone(),
                    index: link.index,
                    ra: None,
                    dhcp: None,
                }
            };
            if pool.ra && service.ra.is_none() {
                let socket = Socket::open(Kind::Router, link)?;
                let mut router = Router::new(device, now);
                if let Some(directory) = &self.config.pio_dir {
                    if let Err(error) = router.load_state(directory, now) {
                        self.logger
                            .message(4, &format!("{device}: PIO state: {error}"));
                    }
                }
                let hop_limit =
                    fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{device}/hop_limit"))
                        .ok()
                        .and_then(|value| value.trim().parse::<u8>().ok())
                        .unwrap_or(0);
                service.ra = Some(RaService {
                    socket,
                    router,
                    hop_limit,
                });
            } else if !pool.ra {
                if let Some(mut ra) = service.ra.take() {
                    let context = RaContext {
                        pool: &service.pool,
                        kernel: &self.state,
                        hop_limit: ra.hop_limit,
                        clock: now,
                        random: 0,
                    };
                    if let Some(packet) = ra.router.shutdown(&context) {
                        if let Err(error) =
                            emit_ra(&mut ra, packet, link, self.config.pio_dir.as_deref(), now)
                        {
                            self.logger
                                .message(4, &format!("{device}: final RA: {error}"));
                        }
                    }
                }
            }
            if pool.dhcpv6 && service.dhcp.is_none() {
                service.dhcp = Some(Socket::open(Kind::Dhcp6, link)?);
            } else if !pool.dhcpv6 {
                service.dhcp = None;
            }
            if reload
                || changes.affects_router(link.index)
                || previous.is_some_and(|state| {
                    owrt_odhcpd::kernel::ra_addresses_changed(
                        state.link(device),
                        link,
                        now.seconds(),
                    )
                })
            {
                if let Some(ra) = &mut service.ra {
                    ra.router.trigger(now);
                }
            }
            service.pool = pool.clone();
            self.services.push(service);
        }
        // A removed pool withdraws what it advertised if its old link still
        // exists. A vanished ifindex cannot transmit; its PIO file is retained.
        for mut service in old {
            if let Some(mut ra) = service.ra.take() {
                let context = RaContext {
                    pool: &service.pool,
                    kernel: &self.state,
                    hop_limit: ra.hop_limit,
                    clock: now,
                    random: 0,
                };
                if let Some(packet) = ra.router.shutdown(&context) {
                    if let Some(link) = self.state.link(ra.router.device()) {
                        if link.index == service.index {
                            if let Err(error) =
                                emit_ra(&mut ra, packet, link, self.config.pio_dir.as_deref(), now)
                            {
                                self.logger
                                    .message(4, &format!("removed interface RA: {error}"));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn refresh_kernel(&mut self, changes: &Changes, now: Clock) -> io::Result<()> {
        let state = self.kernel.snapshot(now)?;
        let previous = std::mem::replace(&mut self.state, state);
        self.kernel_dirty = false;
        let address_change = self.services.iter().any(|service| {
            service.dhcp.is_some()
                && self.state.links.iter().any(|link| {
                    link.index == service.index
                        && owrt_odhcpd::kernel::ra_addresses_changed(
                            previous.link(&link.name),
                            link,
                            now.seconds(),
                        )
                })
        });
        // A snapshot after our PD route ACK may also observe a concurrent
        // address/link change. Always consume its old -> new transition here;
        // the later queued notification must not compare the new state to itself.
        self.services(false, changes, Some(&previous), now)?;
        self.reconcile(now, address_change);
        Ok(())
    }

    fn write_files(&mut self, now: Clock) {
        if self.files_dirty {
            match self.files.write(&self.config, self.dhcp.leases(), now) {
                Ok(_) => self.files_dirty = false,
                Err(error) => self
                    .logger
                    .message(4, &format!("lease state files: {error}")),
            }
        }
        self.files.reap();
    }

    fn reconcile(&mut self, now: Clock, write: bool) {
        let before = self.dhcp.leases().to_vec();
        let kernel = &mut self.kernel;
        let dirty = &mut self.kernel_dirty;
        let result = self
            .dhcp
            .reconcile(&self.config, &self.state, now, &mut |route, add| {
                let result = kernel.route(route, add);
                if result.is_ok() {
                    *dirty = true;
                }
                result
            });
        if let Err(error) = result {
            self.logger.message(4, &format!("PD routes: {error}"));
        }
        self.files_dirty |= write || before != self.dhcp.leases();
        self.write_files(now);
    }

    fn ra_fields(&self, now: Clock) -> Vec<u8> {
        let mut output = BlobBuf::new();
        let interfaces = output.msg_open_table("interfaces");
        for ra in self
            .services
            .iter()
            .filter_map(|service| service.ra.as_ref())
        {
            let array = output.msg_open_array(ra.router.device());
            if let Some(entries) = ra.router.ipv6ra(now).as_array() {
                for entry in entries {
                    let table = output.msg_open_table("");
                    if let Some(owrt_ubus::json::Json::Int(value)) = entry.get("lifetime") {
                        output.msg_u32("lifetime", *value as u32);
                    }
                    if let Some(value) = entry.get("prefix").and_then(|value| value.as_str()) {
                        output.msg_string("prefix", value);
                    }
                    if let Some(owrt_ubus::json::Json::Int(value)) = entry.get("length") {
                        output.msg_u16("length", *value as u16);
                    }
                    output.msg_bool(
                        "stale",
                        matches!(entry.get("stale"), Some(owrt_ubus::json::Json::Bool(true))),
                    );
                    output.msg_close(table);
                }
            }
            output.msg_close(array);
        }
        output.msg_close(interfaces);
        output.into_payload()
    }

    fn add_host(&mut self, host: HostConfig, now: Clock) {
        // lease_cfg_cmp keys the complete ordered DUID-byte and MAC lists;
        // IAID is mutable data, not part of that key.
        if let Some(old) = self.config.hosts.iter_mut().find(|old| {
            old.macs == host.macs
                && old
                    .duids
                    .iter()
                    .map(|entry| &entry.duid)
                    .eq(host.duids.iter().map(|entry| &entry.duid))
        }) {
            // C's lease_cfg_change retains identity/IAID and ignore_v6.
            old.hostname = host.hostname;
            old.lease_time = host.lease_time;
            old.ipv4 = host.ipv4;
            old.host_id = host.host_id;
        } else {
            self.config.hosts.push(host);
        }
        self.reconcile(now, false);
    }

    fn call(&mut self, call: Call, now: Clock) {
        if call.generation < self.generation {
            return;
        }
        self.generation = call.generation;
        let (fields, code) = match call.request.method.as_str() {
            "ipv6leases" => {
                let devices = self
                    .services
                    .iter()
                    .filter(|service| service.dhcp.is_some())
                    .filter_map(|service| {
                        self.state
                            .links
                            .iter()
                            .find(|link| link.index == service.index)
                    })
                    .map(|link| link.name.clone())
                    .collect::<Vec<_>>();
                (
                    leases::ubus_leases(self.dhcp.leases(), &devices, now),
                    status::OK,
                )
            }
            "ipv6ra" => (self.ra_fields(now), status::OK),
            "add_lease" => match config::host_from_blob(&call.request.data) {
                Ok(host) => {
                    self.add_host(host, now);
                    (Vec::new(), status::OK)
                }
                Err(_) => (Vec::new(), status::INVALID_ARGUMENT),
            },
            _ => (Vec::new(), status::METHOD_NOT_FOUND),
        };
        if let Some(bus) = &self.bus {
            if let Err(error) = bus.reply(call, fields, code) {
                self.logger.message(4, &format!("ubus reply: {error}"));
            }
        }
    }

    fn bus_events(&mut self, now: Clock) -> Result<(), Box<dyn std::error::Error>> {
        let mut changed = false;
        for _ in 0..32 {
            let event = match self.bus.as_mut() {
                Some(bus) => bus.try_event()?,
                None => None,
            };
            match event {
                None => break,
                Some(Event::Request(call)) => {
                    // A call after a dump must observe that dump. In
                    // particular, do not erase a successful add_lease with
                    // a deferred UCI reload at the end of this queue drain.
                    if changed {
                        self.reload(now)?;
                        changed = false;
                    }
                    self.call(call, now);
                }
                Some(Event::Network {
                    generation,
                    interfaces,
                }) if generation >= self.generation => {
                    self.generation = generation;
                    self.networks = interfaces;
                    changed = true;
                }
                Some(Event::Connected { generation }) => {
                    self.generation = self.generation.max(generation)
                }
                Some(Event::Disconnected { .. }) => self
                    .logger
                    .message(4, "ubus disconnected; retaining protocol state"),
                Some(_) => {}
            }
        }
        if changed {
            self.reload(now)?;
        }
        Ok(())
    }

    fn packets(&mut self, ready: &[PollFd], now: Clock) -> io::Result<()> {
        for service in &mut self.services {
            let Some(link) = self
                .state
                .links
                .iter()
                .find(|link| link.index == service.index)
            else {
                continue;
            };
            if let Some(ra) = &mut service.ra {
                if ready
                    .iter()
                    .any(|fd| fd.fd == ra.socket.as_raw_fd() && fd.revents & (1 | 8 | 16) != 0)
                {
                    for _ in 0..32 {
                        let packet = match ra.socket.recv() {
                            Ok(Some(packet)) => packet,
                            Ok(None) => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) => {
                                self.logger.message(4, &format!("RA receive: {error}"));
                                break;
                            }
                        };
                        let Some(hop_limit) =
                            packet.hop_limit.and_then(|value| u8::try_from(value).ok())
                        else {
                            continue;
                        };
                        if !router::valid_solicitation(
                            &packet.bytes,
                            *packet.source.ip(),
                            hop_limit,
                        ) {
                            continue;
                        }
                        let mut random = [0; 4];
                        self.random.read_exact(&mut random)?;
                        let context = RaContext {
                            pool: &service.pool,
                            kernel: &self.state,
                            hop_limit: ra.hop_limit,
                            clock: now,
                            random: u32::from_ne_bytes(random),
                        };
                        if let Some(reply) = ra.router.solicit(&context, *packet.source.ip()) {
                            if let Err(error) =
                                emit_ra(ra, reply, link, self.config.pio_dir.as_deref(), now)
                            {
                                self.logger.message(4, &format!("RS reply: {error}"));
                            }
                        }
                    }
                }
            }
            if let Some(socket) = &service.dhcp {
                if ready
                    .iter()
                    .any(|fd| fd.fd == socket.as_raw_fd() && fd.revents & (1 | 8 | 16) != 0)
                {
                    for _ in 0..32 {
                        let packet = match socket.recv() {
                            Ok(Some(packet)) => packet,
                            Ok(None) => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) => {
                                self.logger.message(4, &format!("DHCPv6 receive: {error}"));
                                break;
                            }
                        };
                        let context = RequestContext {
                            source: packet.source,
                            destination: packet.destination,
                            link,
                            pool: &service.pool,
                            config: &self.config,
                            clock: now,
                        };
                        let kernel = &mut self.kernel;
                        let dirty = &mut self.kernel_dirty;
                        let outcome =
                            self.dhcp.handle(&packet.bytes, context, &mut |route, add| {
                                let result = kernel.route(route, add);
                                if result.is_ok() {
                                    *dirty = true;
                                }
                                result
                            });
                        if let Some(reply) = outcome.reply {
                            let mut destination = packet.source;
                            destination.set_port(546);
                            if destination.ip().is_unicast_link_local() {
                                destination.set_scope_id(link.index);
                            }
                            if let Err(error) = socket.send(&reply, destination, None) {
                                self.logger.message(4, &format!("DHCPv6 reply: {error}"));
                            }
                        }
                        self.files_dirty |= outcome.write_state;
                    }
                }
            }
        }
        self.write_files(now);
        Ok(())
    }

    fn timers(&mut self, now: Clock) -> io::Result<()> {
        for index in 0..self.services.len() {
            if !self.services[index].ra.as_ref().is_some_and(|ra| {
                ra.router
                    .deadline()
                    .is_some_and(|deadline| deadline <= now.monotonic_ms)
            }) {
                continue;
            }
            let random = self.random()?;
            let service = &mut self.services[index];
            let Some(ra) = &mut service.ra else {
                continue;
            };
            let context = RaContext {
                pool: &service.pool,
                kernel: &self.state,
                hop_limit: ra.hop_limit,
                clock: now,
                random,
            };
            if let Some(reply) = ra.router.timer(&context) {
                if let Some(link) = self
                    .state
                    .links
                    .iter()
                    .find(|link| link.index == service.index)
                {
                    if let Err(error) =
                        emit_ra(ra, reply, link, self.config.pio_dir.as_deref(), now)
                    {
                        self.logger.message(4, &format!("periodic RA: {error}"));
                    }
                }
            }
        }
        Ok(())
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut next_expiry = clock().monotonic_ms + 1000;
        self.reconcile(clock(), false);
        loop {
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let now = clock();
            if RELOAD.swap(false, Ordering::Relaxed) {
                self.reload(now)?;
                if let Some(bus) = &self.bus {
                    let _ = bus.refresh();
                }
            }
            if self.kernel_dirty {
                self.refresh_kernel(&Changes::default(), now)?;
            }
            if now.monotonic_ms >= next_expiry {
                self.reconcile(now, false);
                next_expiry = now.monotonic_ms.saturating_add(1000);
            }
            self.timers(now)?;
            let mut descriptors = vec![PollFd {
                fd: self.kernel.as_raw_fd(),
                events: 1,
                revents: 0,
            }];
            if let Some(bus) = &self.bus {
                descriptors.push(PollFd {
                    fd: bus.as_raw_fd(),
                    events: 1,
                    revents: 0,
                });
            }
            for service in &self.services {
                if let Some(ra) = &service.ra {
                    descriptors.push(PollFd {
                        fd: ra.socket.as_raw_fd(),
                        events: 1,
                        revents: 0,
                    });
                }
                if let Some(socket) = &service.dhcp {
                    descriptors.push(PollFd {
                        fd: socket.as_raw_fd(),
                        events: 1,
                        revents: 0,
                    });
                }
            }
            let deadline = self
                .services
                .iter()
                .filter_map(|service| service.ra.as_ref().and_then(|ra| ra.router.deadline()))
                .fold(next_expiry, u64::min);
            let wait = deadline.saturating_sub(clock().monotonic_ms).min(1000) as i32;
            match unix::poll_once(&mut descriptors, wait) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            if descriptors.iter().any(|fd| fd.revents & 32 != 0) {
                return Err(io::Error::other("invalid descriptor in protocol loop").into());
            }
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let now = clock();
            if descriptors[0].revents != 0 {
                let changes = self.kernel.changed()?;
                if changes.any {
                    self.refresh_kernel(&changes, now)?;
                }
            }
            if self.bus.as_ref().is_some_and(|bus| {
                descriptors
                    .iter()
                    .any(|fd| fd.fd == bus.as_raw_fd() && fd.revents != 0)
            }) {
                self.bus_events(now)?;
            }
            self.packets(&descriptors, now)?;
        }
        // Match C's ordinary process stop: no unsolicited withdrawal or UCI
        // mutation. Configuration/link removal has its separate RA path.
        if let Some(bus) = &mut self.bus {
            bus.stop()?;
        }
        self.files.reap();
        Ok(())
    }
}

fn main() {
    let options = match options() {
        Ok(Some(options)) => options,
        Ok(None) => return,
        Err(error) => {
            eprintln!("odhcpd-rs: {error}");
            std::process::exit(2);
        }
    };
    if !rustix::process::getuid().is_root() {
        eprintln!("odhcpd-rs: root privileges are required");
        std::process::exit(2);
    }
    // SAFETY: the logger retains a static C string; LOG_PID and LOG_DAEMON
    // are fixed libc options and do not change process credentials.
    unsafe { openlog(c"odhcpd-rs".as_ptr(), 1, 24) };
    for number in [1, 2, 15] {
        if let Err(error) = unix::set_signal_handler(number, signal) {
            eprintln!("odhcpd-rs: signal setup: {error}");
            std::process::exit(4);
        }
    }
    match App::new(options).and_then(|mut app| app.run()) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("odhcpd-rs: {error}");
            std::process::exit(4);
        }
    }
}
