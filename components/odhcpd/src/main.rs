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
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);
static SIGNAL_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn signal(number: i32) {
    match number {
        1 => RELOAD.store(true, Ordering::Relaxed),
        2 | 15 => STOP.store(true, Ordering::Relaxed),
        _ => {}
    }
    let fd = SIGNAL_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = number as u8;
        // SAFETY: the main thread keeps this nonblocking pipe alive while
        // handlers are installed. write is async-signal-safe; a full pipe
        // already guarantees a wake. Preserve the interrupted thread's errno.
        unsafe {
            let saved = *__errno_location();
            while write(fd, &byte, 1) < 0 && *__errno_location() == 4 {} // EINTR only.
            *__errno_location() = saved;
        }
    }
}

unsafe extern "C" {
    fn openlog(ident: *const c_char, option: c_int, facility: c_int);
    fn syslog(priority: c_int, format: *const c_char, ...);
    fn write(fd: c_int, bytes: *const u8, count: usize) -> isize;
    fn __errno_location() -> *mut c_int;
}

struct Signals {
    read: OwnedFd,
    write: OwnedFd,
}

impl Signals {
    fn new() -> io::Result<Self> {
        let (read, write) = owrt_ubus::sys::nonblocking_pipe()?;
        Ok(Self { read, write })
    }

    fn install(&self) -> io::Result<()> {
        SIGNAL_FD.store(self.write.as_raw_fd(), Ordering::Relaxed);
        for number in [1, 2, 15, 17] {
            unix::set_signal_handler(number, signal)?;
        }
        Ok(())
    }

    fn drain(&self) -> io::Result<()> {
        let mut bytes = [0; 64];
        loop {
            match rustix::io::read(&self.read, &mut bytes) {
                Ok(0) => return Err(io::Error::other("signal pipe closed")),
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(rustix::io::Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        let _ = SIGNAL_FD.compare_exchange(
            self.write.as_raw_fd(),
            -1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
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

    fn configuration_diagnostics(&self, config: &mut Config) {
        for diagnostic in config.diagnostics.drain(..) {
            self.message(4, &diagnostic);
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
}

fn ra_hop_limit(pool: &PoolConfig, device: &str) -> u8 {
    if pool.ra_hop_limit != 0 {
        return pool.ra_hop_limit;
    }
    // Like C's send_router_advert(), sample the default at packet construction.
    // Keeping the socket alive must not freeze a later sysctl change.
    fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{device}/hop_limit"))
        .ok()
        .and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(0)
}

const KERNEL_RETRY_MS: u64 = 1000;
const STATE_FLUSH_MS: u64 = 1;

fn poll_timeout(deadline: Option<u64>, now: u64) -> i32 {
    deadline.map_or(-1, |at| at.saturating_sub(now).min(i32::MAX as u64) as i32)
}

fn prefix_expiry(link: &Link, after: u64) -> Option<u64> {
    link.addresses
        .iter()
        .filter(|address| address.scope == 0)
        .flat_map(|address| [address.preferred_until, address.valid_until])
        .filter(|until| *until != owrt_odhcpd::model::INFINITE && *until > after)
        .min()
}

fn transient_snapshot_error(error: &io::Error) -> bool {
    // EINTR/EAGAIN, ENOBUFS, and a prior interrupted dump still in progress.
    // Invalid descriptors, permissions and malformed input remain fatal.
    matches!(error.raw_os_error(), Some(4 | 11 | 16 | 105))
}

fn update_host_config(config: &mut Config, host: HostConfig) {
    // lease_cfg_cmp keys the complete ordered DUID-byte and MAC lists;
    // lease_cfg_change retains identity/IAID and ignore_v6 on an existing key.
    if let Some(old) = config.hosts.iter_mut().find(|old| {
        old.macs == host.macs
            && old
                .duids
                .iter()
                .map(|entry| &entry.duid)
                .eq(host.duids.iter().map(|entry| &entry.duid))
    }) {
        old.hostname = host.hostname;
        old.lease_time = host.lease_time;
        old.ipv4 = host.ipv4;
        old.host_id = host.host_id;
    } else {
        config.hosts.push(host);
    }
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
    kernel_retry_at: Option<u64>,
    route_retry_at: Option<u64>,
    service_retry_at: Option<u64>,
    last_expiry_seconds: u64,
    pending_config: Option<Config>,
    services: Vec<Service>,
    dhcp: Dhcpv6,
    files: StateFiles,
    files_dirty: bool,
    file_flush_at: Option<u64>,
    bus: Option<Bus>,
    random: File,
    #[cfg(test)]
    next_snapshot_error: Option<i32>,
}

impl App {
    fn new(options: Options) -> Result<Self, Box<dyn std::error::Error>> {
        // Reject unsupported modes before opening any service socket or
        // exporting files. Later reloads validate a complete replacement too.
        let mut config = Config::load(options.directory.as_deref())?;
        let logger = Logger {
            stderr: options.stderr,
            level: options.log_level.unwrap_or(config.log_level),
        };
        logger.configuration_diagnostics(&mut config);
        config.validate_devices()?;
        let mut kernel = Kernel::open()?;
        let state = kernel.snapshot(clock())?;
        let bus = if options.no_ubus {
            None
        } else {
            Some(Bus::start(None)?)
        };
        if let Some(bus) = &bus {
            bus.set_ignored_interfaces(config.ignored_interfaces());
        }
        let mut app = Self {
            options,
            logger,
            config,
            networks: Vec::new(),
            generation: 0,
            kernel,
            state,
            kernel_dirty: false,
            kernel_retry_at: None,
            route_retry_at: None,
            service_retry_at: None,
            last_expiry_seconds: clock().seconds(),
            pending_config: None,
            services: Vec::new(),
            dhcp: Dhcpv6::default(),
            files: StateFiles::default(),
            // Like C, a process restart does not import or immediately erase
            // the old export. Publish on an IA/address event instead.
            files_dirty: false,
            file_flush_at: None,
            bus,
            random: File::open("/dev/urandom")?,
            #[cfg(test)]
            next_snapshot_error: None,
        };
        app.services(true, &Changes::default(), None, clock());
        Ok(app)
    }

    fn random(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.random.read_exact(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    fn reload(&mut self, now: Clock) -> Result<(), Box<dyn std::error::Error>> {
        let candidate =
            match Config::load(self.options.directory.as_deref()).and_then(|mut config| {
                self.logger.configuration_diagnostics(&mut config);
                let result = config.apply_network(&self.networks);
                self.logger.configuration_diagnostics(&mut config);
                result?;
                config.validate_devices()?;
                Ok(config)
            }) {
                Ok(candidate) => candidate,
                Err(error) => {
                    // A rejected reload must neither stop working interfaces nor
                    // apply an older pending config after the latest request failed.
                    // App::new still rejects unsupported startup configurations.
                    self.pending_config = None;
                    self.logger.message(
                        4,
                        &format!(
                            "configuration reload rejected; retaining active services: {error}"
                        ),
                    );
                    return Ok(());
                }
            };
        let Some(state) = self.read_kernel_state(now)? else {
            // Do not lose the only SIGHUP/dump that requested this config, or
            // expose a new config while its corresponding services stay old.
            self.pending_config = Some(candidate);
            return Ok(());
        };
        self.pending_config = None;
        self.logger.level = self.options.log_level.unwrap_or(candidate.log_level);
        self.config = candidate;
        if let Some(bus) = &self.bus {
            bus.set_ignored_interfaces(self.config.ignored_interfaces());
        }
        self.state = state;
        self.services(true, &Changes::default(), None, now);
        self.reconcile(now, false);
        Ok(())
    }

    fn services(
        &mut self,
        reload: bool,
        changes: &Changes,
        previous: Option<&KernelState>,
        now: Clock,
    ) {
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
            let report_socket_error = reload || found.is_none();
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
                match Socket::open(Kind::Router, link) {
                    Ok(socket) => {
                        let mut router = Router::new(device, now);
                        if let Some(directory) = &self.config.pio_dir {
                            if let Err(error) = router.load_state(directory, now) {
                                self.logger
                                    .message(4, &format!("{device}: PIO state: {error}"));
                            }
                        }
                        service.ra = Some(RaService { socket, router });
                    }
                    Err(error) if report_socket_error => self.logger.message(
                        4,
                        &format!("{device}: RA socket: {error}; retrying in one second"),
                    ),
                    Err(_) => {}
                }
            } else if !pool.ra {
                if let Some(mut ra) = service.ra.take() {
                    let context = RaContext {
                        pool: &service.pool,
                        kernel: &self.state,
                        hop_limit: ra_hop_limit(&service.pool, device),
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
                match Socket::open(Kind::Dhcp6, link) {
                    Ok(socket) => service.dhcp = Some(socket),
                    Err(error) if report_socket_error => self.logger.message(
                        4,
                        &format!("{device}: DHCPv6 socket: {error}; retrying in one second"),
                    ),
                    Err(_) => {}
                }
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
        self.service_retry_at = self
            .services
            .iter()
            .any(|service| {
                service.pool.ra && service.ra.is_none()
                    || service.pool.dhcpv6 && service.dhcp.is_none()
            })
            .then_some(now.monotonic_ms.saturating_add(KERNEL_RETRY_MS));
        // A removed pool withdraws what it advertised if its old link still
        // exists. A vanished ifindex cannot transmit; its PIO file is retained.
        for mut service in old {
            if let Some(mut ra) = service.ra.take() {
                let context = RaContext {
                    pool: &service.pool,
                    kernel: &self.state,
                    hop_limit: ra_hop_limit(&service.pool, ra.router.device()),
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
    }

    fn refresh_kernel(&mut self, changes: &Changes, now: Clock) -> io::Result<()> {
        let retrying = self.kernel_retry_at.is_some();
        let Some(state) = self.read_kernel_state(now)? else {
            return Ok(());
        };
        let previous = std::mem::replace(&mut self.state, state);
        let reloaded = if let Some(candidate) = self.pending_config.take() {
            self.logger.level = self.options.log_level.unwrap_or(candidate.log_level);
            self.config = candidate;
            if let Some(bus) = &self.bus {
                bus.set_ignored_interfaces(self.config.ignored_interfaces());
            }
            true
        } else {
            false
        };
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
        // The failed observation may have consumed a default-route event.
        // Resynchronise every router after a retry, even with no new event.
        let recovered = Changes {
            all_routers: true,
            ..Changes::default()
        };
        self.services(
            reloaded,
            if retrying { &recovered } else { changes },
            Some(&previous),
            now,
        );
        self.reconcile(now, address_change);
        Ok(())
    }

    fn read_kernel_state(&mut self, now: Clock) -> io::Result<Option<KernelState>> {
        if self
            .kernel_retry_at
            .is_some_and(|deadline| now.monotonic_ms < deadline)
        {
            return Ok(None);
        }
        #[cfg(test)]
        let injected = self.next_snapshot_error.take();
        #[cfg(not(test))]
        let injected: Option<i32> = None;
        let result = match injected {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => self.kernel.snapshot(now),
        };
        match result {
            Ok(state) => {
                self.kernel_dirty = false;
                self.kernel_retry_at = None;
                Ok(Some(state))
            }
            Err(error) if transient_snapshot_error(&error) => {
                self.logger.message(
                    4,
                    &format!(
                        "kernel snapshot: {error}; retaining state and retrying in one second"
                    ),
                );
                self.kernel_dirty = true;
                self.kernel_retry_at = Some(now.monotonic_ms.saturating_add(KERNEL_RETRY_MS));
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn mark_files_dirty(&mut self, now: Clock) {
        self.files_dirty = true;
        // A burst coalesces only its export snapshot. Never postpone an
        // already scheduled flush when another successful reply changes it.
        self.file_flush_at
            .get_or_insert(now.monotonic_ms.saturating_add(STATE_FLUSH_MS));
    }

    fn write_files(&mut self, now: Clock, force: bool) {
        if self.files_dirty
            && (force || self.file_flush_at.is_some_and(|at| at <= now.monotonic_ms))
        {
            match self.files.write(&self.config, self.dhcp.leases(), now) {
                Ok(_) => {
                    self.files_dirty = false;
                    self.file_flush_at = None;
                }
                Err(error) => {
                    self.logger
                        .message(4, &format!("lease state files: {error}"));
                    self.file_flush_at = Some(now.monotonic_ms.saturating_add(KERNEL_RETRY_MS));
                }
            }
        }
        self.files.reap();
    }

    fn reconcile(&mut self, now: Clock, write: bool) {
        if self.kernel_retry_at.is_some() {
            // In particular, old kernel.routes cannot disprove a just-ACKed
            // PD installation or erase a deletion still awaiting retry.
            if write {
                self.mark_files_dirty(now);
            }
            return;
        }
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
            self.route_retry_at = Some(now.monotonic_ms.saturating_add(KERNEL_RETRY_MS));
        } else {
            self.route_retry_at = None;
        }
        self.last_expiry_seconds = now.seconds();
        if write || before != self.dhcp.leases() {
            self.mark_files_dirty(now);
        }
    }

    fn expiry_deadline(&self) -> Option<u64> {
        if self.kernel_retry_at.is_some() {
            // The retry's fresh snapshot must precede lease/route reconciliation.
            return None;
        }
        let prefixes = self
            .services
            .iter()
            .filter(|service| service.dhcp.is_some())
            .filter_map(|service| {
                self.state
                    .links
                    .iter()
                    .find(|link| link.index == service.index)
            })
            .filter_map(|link| prefix_expiry(link, self.last_expiry_seconds));
        self.dhcp
            .next_expiry()
            .into_iter()
            .chain(prefixes)
            .min()
            .map(|seconds| seconds.saturating_mul(1000))
    }

    fn next_deadline(&self) -> Option<u64> {
        self.services
            .iter()
            .filter_map(|service| service.ra.as_ref().and_then(|ra| ra.router.deadline()))
            .chain(
                [
                    self.expiry_deadline(),
                    self.kernel_retry_at,
                    self.service_retry_at,
                    self.file_flush_at,
                    self.route_retry_at
                        .filter(|_| self.kernel_retry_at.is_none()),
                    (self.kernel_dirty && self.kernel_retry_at.is_none()).then_some(0),
                ]
                .into_iter()
                .flatten(),
            )
            .min()
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
        if let Some(pending) = &mut self.pending_config {
            // A successful call after the reload request must survive its
            // delayed kernel resynchronisation, in the same request order.
            update_host_config(pending, host.clone());
        }
        update_host_config(&mut self.config, host);
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
                            hop_limit: ra_hop_limit(&service.pool, ra.router.device()),
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
                        let retry_at = &mut self.route_retry_at;
                        let outcome =
                            self.dhcp.handle(&packet.bytes, context, &mut |route, add| {
                                let result = kernel.route(route, add);
                                if result.is_ok() {
                                    *dirty = true;
                                } else {
                                    *retry_at =
                                        Some(now.monotonic_ms.saturating_add(KERNEL_RETRY_MS));
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
                        if outcome.write_state {
                            self.files_dirty = true;
                            self.file_flush_at
                                .get_or_insert(now.monotonic_ms.saturating_add(STATE_FLUSH_MS));
                        }
                    }
                }
            }
        }
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
                hop_limit: ra_hop_limit(&service.pool, ra.router.device()),
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

    fn run(&mut self, signals: &Signals) -> Result<(), Box<dyn std::error::Error>> {
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
            if self.kernel_dirty
                && self
                    .kernel_retry_at
                    .is_none_or(|deadline| now.monotonic_ms >= deadline)
            {
                self.refresh_kernel(&Changes::default(), now)?;
            }
            if self
                .service_retry_at
                .is_some_and(|deadline| now.monotonic_ms >= deadline)
            {
                // Retry only absent sockets; services retains healthy sockets
                // and their RA timers. A transient bind/open failure must not
                // leave a running daemon permanently unable to serve clients.
                self.services(false, &Changes::default(), None, now);
            }
            if self
                .expiry_deadline()
                .is_some_and(|at| now.monotonic_ms >= at)
                || (self.kernel_retry_at.is_none()
                    && self.route_retry_at.is_some_and(|at| now.monotonic_ms >= at))
            {
                self.reconcile(now, false);
            }
            self.timers(now)?;
            // File deadlines use a fresh clock after other work. One millisecond
            // makes the snapshot eligible; blocking I/O is not a hard-time promise.
            self.write_files(clock(), false);
            let mut descriptors = vec![PollFd {
                fd: self.kernel.as_raw_fd(),
                events: 1,
                revents: 0,
            }];
            descriptors.push(PollFd {
                fd: signals.read.as_raw_fd(),
                events: 1,
                revents: 0,
            });
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
            let wait = poll_timeout(self.next_deadline(), clock().monotonic_ms);
            match unix::poll_once(&mut descriptors, wait) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            if descriptors.iter().any(|fd| fd.revents & 32 != 0) {
                return Err(io::Error::other("invalid descriptor in protocol loop").into());
            }
            if descriptors[1].revents != 0 {
                signals.drain()?;
                self.files.reap();
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
        // A successful DHCP reply must not leave its queued export behind when
        // orderly shutdown wins the one-shot timer race. Try once, retaining
        // the normal error diagnostic if storage is unavailable.
        self.write_files(clock(), true);
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
    let signals = match Signals::new().and_then(|signals| {
        signals.install()?;
        Ok(signals)
    }) {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("odhcpd-rs: signal setup: {error}");
            std::process::exit(4);
        }
    };
    match App::new(options).and_then(|mut app| app.run(&signals)) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("odhcpd-rs: {error}");
            std::process::exit(4);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    static SIGNAL_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Fixture {
        directory: PathBuf,
        app: App,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "odhcpd-runtime-test-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&directory).unwrap();
            fs::write(
                directory.join("dhcp"),
                "config dhcp 'test'\n option ra 'disabled'\n option dhcpv6 'disabled'\n",
            )
            .unwrap();
            fs::write(directory.join("network"), "").unwrap();
            fs::write(directory.join("system"), "").unwrap();
            let app = App::new(Options {
                directory: Some(directory.clone()),
                no_ubus: true,
                stderr: true,
                log_level: Some(0),
            })
            .unwrap();
            Self { directory, app }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn at(monotonic_ms: u64) -> Clock {
        Clock {
            monotonic_ms,
            unix_seconds: 0,
        }
    }

    #[test]
    fn only_pending_work_has_a_deadline_and_snapshot_retry_wins_routes() {
        let mut fixture = Fixture::new();
        let app = &mut fixture.app;
        assert_eq!(app.next_deadline(), None);
        assert_eq!(poll_timeout(app.next_deadline(), 10_000), -1);
        app.route_retry_at = Some(11_000);
        assert_eq!(app.next_deadline(), Some(11_000));
        app.kernel_retry_at = Some(12_000);
        assert_eq!(app.next_deadline(), Some(12_000));
        app.file_flush_at = Some(10_001);
        assert_eq!(app.next_deadline(), Some(10_001));
        assert_eq!(poll_timeout(app.next_deadline(), 10_000), 1);
        app.file_flush_at = None;
        app.kernel_retry_at = None;
        app.kernel_dirty = true;
        assert_eq!(poll_timeout(app.next_deadline(), 10_000), 0);
        assert_eq!(poll_timeout(Some(u64::MAX), 10_000), i32::MAX);
    }

    #[test]
    fn finite_prefix_deadlines_are_consumed_without_an_expired_timer_spin() {
        use owrt_odhcpd::model::{Address, INFINITE};
        let link = Link {
            name: "lan".into(),
            index: 1,
            flags: 0x40,
            mtu: 1500,
            mac: [0; 6],
            addresses: vec![
                Address {
                    address: "2001:db8::1".parse().unwrap(),
                    length: 64,
                    preferred_until: 101,
                    valid_until: 103,
                    scope: 0,
                    flags: 0,
                },
                Address {
                    address: "fd00::1".parse().unwrap(),
                    length: 60,
                    preferred_until: INFINITE,
                    valid_until: INFINITE,
                    scope: 0,
                    flags: 0,
                },
                Address {
                    address: "fe80::1".parse().unwrap(),
                    length: 64,
                    preferred_until: 100,
                    valid_until: 102,
                    scope: 253,
                    flags: 0,
                },
            ],
        };
        assert_eq!(prefix_expiry(&link, 100), Some(101));
        assert_eq!(prefix_expiry(&link, 101), Some(103));
        assert_eq!(prefix_expiry(&link, 103), None);
    }

    #[test]
    fn state_export_coalesces_without_postponing_first_dirty_deadline() {
        let mut fixture = Fixture::new();
        let path = fixture.directory.join("leases");
        let app = &mut fixture.app;
        app.config.lease_file = Some(path.clone());
        app.mark_files_dirty(at(10_000));
        app.mark_files_dirty(at(10_001));
        assert_eq!(app.file_flush_at, Some(10_001));
        app.write_files(at(10_000), false);
        assert!(!path.exists());
        assert!(app.files_dirty);
        app.write_files(at(10_001), false);
        assert!(path.exists());
        assert!(!app.files_dirty);
        assert_eq!(app.file_flush_at, None);
    }

    #[test]
    fn failed_export_retries_once_due_and_orderly_stop_flushes_pending_export() {
        let _serial = SIGNAL_TEST.lock().unwrap();
        let mut fixture = Fixture::new();
        let parent = fixture.directory.join("blocked");
        fs::write(&parent, b"not a directory").unwrap();
        let path = parent.join("leases");
        let app = &mut fixture.app;
        app.config.lease_file = Some(path.clone());
        app.mark_files_dirty(at(10_000));
        app.write_files(at(10_001), false);
        assert!(app.files_dirty);
        assert_eq!(app.file_flush_at, Some(11_001));
        fs::remove_file(&parent).unwrap();
        app.write_files(at(11_000), false);
        assert!(!path.exists());
        app.write_files(at(11_001), false);
        assert!(path.exists());
        assert!(!app.files_dirty);
        fs::remove_file(&path).unwrap();
        app.mark_files_dirty(Clock {
            monotonic_ms: u64::MAX - 1,
            unix_seconds: 0,
        });
        let signals = Signals::new().unwrap();
        STOP.store(true, Ordering::Relaxed);
        let result = app.run(&signals);
        STOP.store(false, Ordering::Relaxed);
        result.unwrap();
        assert!(path.exists());
        assert!(!app.files_dirty);
    }

    #[test]
    fn signal_on_another_thread_remains_readable_before_poll_starts() {
        let _serial = SIGNAL_TEST.lock().unwrap();
        let signals = Signals::new().unwrap();
        SIGNAL_FD.store(signals.write.as_raw_fd(), Ordering::Relaxed);
        // Models delivery to the bus worker between the protocol thread's flag
        // check and poll. SIGCHLD must wake even though it sets no state flag.
        std::thread::spawn(|| signal(17)).join().unwrap();
        let mut fds = [PollFd {
            fd: signals.read.as_raw_fd(),
            events: 1,
            revents: 0,
        }];
        assert_eq!(unix::poll_once(&mut fds, 0).unwrap(), 1);
        signals.drain().unwrap();
        assert_eq!(unix::poll_once(&mut fds, 0).unwrap(), 0);
        std::thread::spawn(|| signal(1)).join().unwrap();
        assert!(RELOAD.swap(false, Ordering::Relaxed));
        assert_eq!(unix::poll_once(&mut fds, 0).unwrap(), 1);
        signals.drain().unwrap();
        let fill = [0; 4096];
        loop {
            match rustix::io::write(&signals.write, &fill) {
                Ok(_) => {}
                Err(rustix::io::Errno::AGAIN) => break,
                Err(error) => panic!("fill signal pipe: {error}"),
            }
        }
        // A full pipe cannot swallow the state flag or block the handler; its
        // existing readability still wakes the protocol owner.
        std::thread::spawn(|| signal(15)).join().unwrap();
        assert!(STOP.swap(false, Ordering::Relaxed));
        assert_eq!(unix::poll_once(&mut fds, 0).unwrap(), 1);
        signals.drain().unwrap();
    }

    #[test]
    fn snapshot_retry_preserves_state_and_respects_its_deadline() {
        let mut fixture = Fixture::new();
        let app = &mut fixture.app;
        app.state.links = vec![Link {
            name: "old-observation".into(),
            index: u32::MAX,
            flags: 0,
            mtu: 1500,
            mac: [0; 6],
            addresses: Vec::new(),
        }];
        app.next_snapshot_error = Some(105);
        app.refresh_kernel(&Changes::default(), at(10_000)).unwrap();
        assert!(app.kernel_dirty);
        assert_eq!(app.kernel_retry_at, Some(11_000));
        assert_eq!(app.state.links[0].name, "old-observation");

        // Repeated route/link notifications may not turn one-second retries
        // into a busy loop. The unconsumed injected EBADF proves no read ran.
        app.next_snapshot_error = Some(9);
        app.refresh_kernel(&Changes::default(), at(10_999)).unwrap();
        assert_eq!(app.next_snapshot_error, Some(9));
        assert_eq!(
            app.refresh_kernel(&Changes::default(), at(11_000))
                .unwrap_err()
                .raw_os_error(),
            Some(9)
        );
        assert_eq!(app.state.links[0].name, "old-observation");

        app.refresh_kernel(&Changes::default(), at(11_001)).unwrap();
        assert!(app
            .state
            .links
            .iter()
            .all(|link| link.name != "old-observation"));
        assert!(!app.kernel_dirty);
        assert_eq!(app.kernel_retry_at, None);
    }

    #[test]
    fn failed_reload_applies_latest_config_and_later_add_lease_after_resync() {
        let mut fixture = Fixture::new();
        fixture.app.next_snapshot_error = Some(105);
        fs::write(
            fixture.directory.join("dhcp"),
            "config dhcp 'test'\n option leasetime '10m'\n",
        )
        .unwrap();
        fixture.app.reload(at(10_000)).unwrap();
        assert_eq!(fixture.app.config.pools[0].lease_time, 43_200);
        assert_eq!(
            fixture.app.pending_config.as_ref().unwrap().pools[0].lease_time,
            600
        );

        fs::write(
            fixture.directory.join("dhcp"),
            "config dhcp 'test'\n option leasetime '20m'\n",
        )
        .unwrap();
        fixture.app.reload(at(10_001)).unwrap();
        let host = HostConfig {
            hostname: Some("after-reload".into()),
            host_id: 0x123,
            ..HostConfig::default()
        };
        fixture.app.add_host(host, at(10_002));
        assert_eq!(
            fixture.app.config.hosts[0].hostname.as_deref(),
            Some("after-reload")
        );
        fixture
            .app
            .refresh_kernel(&Changes::default(), at(11_000))
            .unwrap();
        assert_eq!(fixture.app.config.pools[0].lease_time, 1200);
        assert_eq!(fixture.app.config.hosts.len(), 1);
        assert_eq!(
            fixture.app.config.hosts[0].hostname.as_deref(),
            Some("after-reload")
        );
        assert!(fixture.app.pending_config.is_none());
    }

    #[test]
    fn only_transient_observation_errors_are_retried() {
        for errno in [4, 11, 16, 105] {
            assert!(transient_snapshot_error(&io::Error::from_raw_os_error(
                errno
            )));
        }
        for errno in [1, 9, 13, 22] {
            assert!(!transient_snapshot_error(&io::Error::from_raw_os_error(
                errno
            )));
        }
        assert!(!transient_snapshot_error(&io::Error::new(
            io::ErrorKind::InvalidData,
            "bad dump"
        )));
    }

    #[test]
    fn invalid_runtime_config_keeps_active_state_and_cancels_older_pending_reload() {
        let mut fixture = Fixture::new();
        fixture.app.next_snapshot_error = Some(105);
        fs::write(
            fixture.directory.join("dhcp"),
            "config dhcp 'test'\n option leasetime '10m'\n",
        )
        .unwrap();
        fixture.app.reload(at(10_000)).unwrap();
        assert!(fixture.app.pending_config.is_some());
        fs::write(
            fixture.directory.join("dhcp"),
            "config dhcp 'test'\n option ra 'relay'\n",
        )
        .unwrap();
        fixture.app.reload(at(10_001)).unwrap();
        assert!(fixture.app.pending_config.is_none());
        assert_eq!(fixture.app.config.pools[0].lease_time, 43_200);
        fixture
            .app
            .refresh_kernel(&Changes::default(), at(11_000))
            .unwrap();
        assert_eq!(fixture.app.config.pools[0].lease_time, 43_200);
        assert!(!fixture.app.config.pools[0].ra);
        assert!(Config::load(Some(&fixture.directory)).is_err());
    }

    #[test]
    fn explicit_ra_hop_limit_does_not_require_a_sysctl() {
        let mut pool = PoolConfig::new("test");
        pool.ra_hop_limit = 123;
        assert_eq!(ra_hop_limit(&pool, "missing-device"), 123);
    }

    #[test]
    fn alias_reload_is_rejected_before_snapshot_and_preserves_active_services() {
        let mut fixture = Fixture::new();
        let mut active = PoolConfig::new("active");
        active.ifname = Some("existing-device".into());
        active.ra = true;
        active.ignore_updates = false;
        fixture.app.config.pools = vec![active.clone()];
        fixture.app.services.push(Service {
            pool: active,
            index: 123,
            ra: None,
            dhcp: None,
        });
        let previous = fixture.app.config.clone();
        fixture.app.pending_config = Some(previous.clone());
        fs::write(
            fixture.directory.join("dhcp"),
            "config dhcp lan\n option ra server\nconfig dhcp lan6\n option dhcpv6 server\n",
        )
        .unwrap();
        fixture.app.networks = ["lan", "lan6"]
            .into_iter()
            .map(|name| NetworkInterface {
                name: name.into(),
                device: Some("br-lan".into()),
                up: true,
                data: owrt_ubus::json::Json::Object(Vec::new()),
            })
            .collect();
        fixture.app.next_snapshot_error = Some(9);
        fixture.app.reload(at(10_000)).unwrap();
        assert_eq!(fixture.app.config, previous);
        assert!(fixture.app.pending_config.is_none());
        assert_eq!(fixture.app.next_snapshot_error, Some(9));
        assert_eq!(fixture.app.services.len(), 1);
        assert_eq!(fixture.app.services[0].pool.name, "active");
        assert_eq!(fixture.app.services[0].index, 123);

        // The same unsupported topology is a startup configuration error when
        // the two device names are already known from explicit UCI bindings.
        fs::write(fixture.directory.join("dhcp"), "config dhcp lan\n option ra server\n option ifname br-lan\nconfig dhcp lan6\n option dhcpv6 server\n option ifname br-lan\n").unwrap();
        assert!(App::new(Options {
            directory: Some(fixture.directory.clone()),
            no_ubus: true,
            stderr: true,
            log_level: Some(0)
        })
        .is_err());
    }

    #[test]
    fn unrelated_client_data_and_bad_host_do_not_block_a_runtime_lan_binding() {
        let mut fixture = Fixture::new();
        fs::write(fixture.directory.join("dhcp"), "config dhcp lan\n option ra server\n option dhcpv6 server\nconfig host broken\n option duid 0001000123456\nconfig host valid\n option name valid\n option hostid 123\n").unwrap();
        fixture.app.networks = vec![
            NetworkInterface {
                name: "wwan".into(),
                device: Some("fixture-client".into()),
                up: true,
                data: owrt_ubus::json::parse(r#"{"dhcpserver":"192.0.2.1","leasetime":60}"#)
                    .unwrap(),
            },
            NetworkInterface {
                name: "lan".into(),
                device: Some("fixture-lan".into()),
                up: true,
                data: owrt_ubus::json::Json::Object(Vec::new()),
            },
        ];
        fixture.app.reload(at(10_000)).unwrap();
        let lan = fixture
            .app
            .config
            .pools
            .iter()
            .find(|pool| pool.name == "lan")
            .unwrap();
        assert_eq!(lan.ifname.as_deref(), Some("fixture-lan"));
        assert!(lan.ra && lan.dhcpv6);
        assert_eq!(fixture.app.config.hosts.len(), 1);
        assert_eq!(
            fixture.app.config.hosts[0].hostname.as_deref(),
            Some("valid")
        );
        assert!(fixture.app.config.diagnostics.is_empty()); // Consumed by Logger.
        assert_eq!(fixture.app.config.ignored_interfaces(), vec!["wwan"]);
    }
}
