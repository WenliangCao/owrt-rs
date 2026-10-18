//! A single bounded ubus worker. The protocol owner never waits for bus I/O.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use owrt_ubus::json::Json;
use owrt_ubus::readiness::Poller;
use owrt_ubus::{blob, status, Connection, Incoming, MsgType, Request};

use crate::config::NetworkInterface;

const IO_MS: i32 = 100;
const RETRY: Duration = Duration::from_secs(1);
const CAPACITY: usize = 8;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const WAKE: u64 = 1;
const CONNECTION: u64 = 2;

pub const METHODS: &[(&str, &[(&str, MsgType)])] = &[
    ("ipv6leases", &[]),
    ("ipv6ra", &[]),
    (
        "add_lease",
        &[
            ("ip", MsgType::String),
            ("mac", MsgType::Array),
            ("duid", MsgType::Array),
            ("hostid", MsgType::String),
            ("leasetime", MsgType::String),
            ("name", MsgType::String),
        ],
    ),
];

#[derive(Debug)]
pub struct Call {
    /// Requests belong to one connection; never reply using a newer session.
    pub generation: u64,
    pub request: Request,
}

#[derive(Debug)]
pub enum Event {
    Request(Call),
    Network {
        generation: u64,
        interfaces: Vec<NetworkInterface>,
    },
    Connected {
        generation: u64,
    },
    Disconnected {
        generation: u64,
    },
}

enum Command {
    Reply {
        call: Call,
        fields: Vec<u8>,
        code: i32,
    },
    Refresh,
}

pub struct Bus {
    commands: SyncSender<Command>,
    events: Receiver<Event>,
    wake: UnixStream,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    #[cfg(test)]
    before_wake_read: Option<Box<dyn FnOnce() + Send>>,
}

impl Bus {
    pub fn start(socket: Option<String>) -> io::Result<Self> {
        let (wake, worker_wake) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        worker_wake.set_nonblocking(true)?;
        let (commands, command_rx) = mpsc::sync_channel(CAPACITY);
        let (event_tx, events) = mpsc::sync_channel(CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = thread::Builder::new()
            .name("odhcpd-ubus".into())
            .stack_size(128 * 1024)
            .spawn(move || run(socket, worker_wake, command_rx, event_tx, worker_stop))?;
        Ok(Self {
            commands,
            events,
            wake,
            stop,
            worker: Some(worker),
            #[cfg(test)]
            before_wake_read: None,
        })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    /// Drain until None after every wakeup, including wakeups without events.
    pub fn try_event(&mut self) -> io::Result<Option<Event>> {
        #[cfg(test)]
        if let Some(hook) = self.before_wake_read.take() {
            hook();
        }
        // Consume at most one notification before checking the queue. A
        // publication after this read either enters the queue before try_recv,
        // or retains its notification for the owner's next readiness wait.
        // Reading after try_recv(Empty) could swallow that sole notification.
        // One byte also preserves readiness when the owner reaches its drain
        // budget with additional events still queued.
        let mut byte = [0u8; 1];
        loop {
            match self.wake.read(&mut byte) {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(match self.events.try_recv() {
            Ok(event) => Some(event),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ubus worker stopped",
                ))
            }
        })
    }

    pub fn reply(&self, call: Call, fields: Vec<u8>, code: i32) -> io::Result<()> {
        self.command(Command::Reply { call, fields, code })
    }

    pub fn refresh(&self) -> io::Result<()> {
        self.command(Command::Refresh)
    }

    fn command(&self, command: Command) -> io::Result<()> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "ubus command queue full")
                }
                TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "ubus worker stopped")
                }
            })?;
        notify(&self.wake);
        Ok(())
    }

    /// All worker operations have a 100 ms I/O bound and check this stop flag
    /// between steps. This joins only the owned worker, never another service.
    pub fn stop(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        notify(&self.wake);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("ubus worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn notify(mut wake: &UnixStream) {
    // The channel is the state; a full wake socket already makes poll readable.
    let _ = wake.write(&[1]);
}

fn drain_wake(mut wake: &UnixStream) {
    let mut bytes = [0u8; 64];
    loop {
        match wake.read(&mut bytes) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fn emit(events: &SyncSender<Event>, wake: &UnixStream, event: Event) -> Option<Event> {
    match events.try_send(event) {
        Ok(()) => {
            notify(wake);
            None
        }
        Err(TrySendError::Full(event)) => Some(event),
        Err(TrySendError::Disconnected(_)) => None,
    }
}

fn check_stop(stop: &AtomicBool) -> io::Result<()> {
    if stop.load(Ordering::Acquire) {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Ok(())
    }
}

struct Session {
    connection: Connection,
    dhcp: u32,
    subscriber: u32,
    events: u32,
    netifd: Option<u32>,
    dump_needed: bool,
}

impl Session {
    fn connect(socket: Option<&str>, stop: &AtomicBool) -> io::Result<Self> {
        check_stop(stop)?;
        let mut connection =
            Connection::connect_timeout(socket, Duration::from_millis(IO_MS as u64))?;
        connection.set_server_io_timeout(Duration::from_millis(IO_MS as u64));
        check_stop(stop)?;
        let dhcp = connection.add_object("dhcp", METHODS, IO_MS)?;
        check_stop(stop)?;
        let subscriber = connection.add_anonymous_object(IO_MS)?;
        check_stop(stop)?;
        let events = connection.add_anonymous_object(IO_MS)?;
        check_stop(stop)?;
        connection.register_event_handler(events, Some("ubus.object.*"), IO_MS)?;
        check_stop(stop)?;
        let netifd = match connection.lookup_id("network.interface", IO_MS) {
            Ok(id) => Some(id),
            Err(error) if owrt_ubus::conn::error_status(&error) == Some(status::NOT_FOUND) => None,
            Err(error) => return Err(error),
        };
        if let Some(id) = netifd {
            check_stop(stop)?;
            connection.subscribe(subscriber, id, IO_MS)?;
        }
        Ok(Self {
            connection,
            dhcp,
            subscriber,
            events,
            netifd,
            dump_needed: netifd.is_some(),
        })
    }

    fn dump(&mut self) -> io::Result<Option<Vec<NetworkInterface>>> {
        self.dump_needed = false;
        let Some(id) = self.netifd else {
            return Ok(None);
        };
        let reply = self.connection.invoke(id, "dump", &[], IO_MS)?;
        let data = owrt_ubus::convert::fields_to_json(&reply.fields());
        parse_network_dump(&data).map(Some)
    }

    fn incoming(
        &mut self,
        incoming: Incoming,
        generation: u64,
        stop: &AtomicBool,
    ) -> io::Result<Option<Call>> {
        let Incoming::Invoke(request) = incoming else {
            return Ok(None);
        };
        if request.objid == self.dhcp {
            if !METHODS.iter().any(|(method, _)| *method == request.method) {
                self.connection
                    .reply_status(&request, status::METHOD_NOT_FOUND, None)?;
                self.connection.recycle_request(request);
                return Ok(None);
            }
            if request.data.len() > MAX_REQUEST_BYTES {
                self.connection
                    .reply_status(&request, status::NO_MEMORY, None)?;
                self.connection.recycle_request(request);
                return Ok(None);
            }
            return Ok(Some(Call {
                generation,
                request,
            }));
        }
        if request.objid == self.subscriber {
            self.dump_needed = true;
        } else if request.objid == self.events {
            let data = owrt_ubus::convert::fields_to_json(&request.data);
            if data.get("path").and_then(Json::as_str) == Some("network.interface") {
                if request.method == "ubus.object.add" {
                    let id = blob::fields(&request.data)
                        .find(|field| field.name == "id")
                        .and_then(|field| field.as_u32());
                    if let Some(id) = id {
                        self.connection.subscribe(self.subscriber, id, IO_MS)?;
                        check_stop(stop)?;
                        self.netifd = Some(id);
                        self.dump_needed = true;
                    }
                } else if request.method == "ubus.object.remove" {
                    self.netifd = None;
                    self.dump_needed = false;
                }
            }
        }
        self.connection.reply_status(&request, status::OK, None)?;
        self.connection.recycle_request(request);
        Ok(None)
    }
}

pub fn parse_network_dump(data: &Json) -> io::Result<Vec<NetworkInterface>> {
    let interfaces = data
        .get("interface")
        .and_then(Json::as_array)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "netifd dump has no interface array",
            )
        })?;
    let mut result = Vec::with_capacity(interfaces.len());
    for interface in interfaces {
        let Some(name) = interface.get("interface").and_then(Json::as_str) else {
            continue;
        };
        let Some(data @ Json::Object(_)) = interface.get("data") else {
            continue;
        };
        result.push(NetworkInterface {
            name: name.into(),
            device: interface
                .get("l3_device")
                .and_then(Json::as_str)
                .map(str::to_owned),
            up: matches!(interface.get("up"), Some(Json::Bool(true))),
            data: data.clone(),
        });
    }
    Ok(result)
}

fn run(
    socket: Option<String>,
    wake: UnixStream,
    commands: Receiver<Command>,
    events: SyncSender<Event>,
    stop: Arc<AtomicBool>,
) {
    let Ok(mut poller) = Poller::new() else {
        return;
    };
    if poller.add(wake.as_raw_fd(), WAKE, false).is_err() {
        return;
    }
    let mut session: Option<Session> = None;
    let mut generation = 0u64;
    let mut retry_at = Instant::now();
    let mut ready = Vec::new();
    let mut pending_network: Option<Event> = None;
    while !stop.load(Ordering::Acquire) {
        if session.is_none() && Instant::now() >= retry_at {
            retry_at = Instant::now() + RETRY;
            if let Ok(opened) = Session::connect(socket.as_deref(), &stop) {
                if poller
                    .add(opened.connection.as_raw_fd(), CONNECTION, false)
                    .is_err()
                {
                    return;
                }
                generation = generation.wrapping_add(1);
                session = Some(opened);
                let _ = emit(&events, &wake, Event::Connected { generation });
            }
        }
        let mut failed = false;
        for _ in 0..CAPACITY {
            match commands.try_recv() {
                Ok(Command::Refresh) => {
                    if let Some(session) = session.as_mut() {
                        session.dump_needed = true;
                    }
                }
                Ok(Command::Reply { call, fields, code }) => {
                    if let Some(session) =
                        session.as_mut().filter(|_| call.generation == generation)
                    {
                        let result = if fields.is_empty() {
                            session.connection.reply_status(&call.request, code, None)
                        } else {
                            session
                                .connection
                                .reply_data_status(&call.request, &fields, code)
                        };
                        if result.is_err() {
                            failed = true;
                        }
                        session.connection.recycle_request(call.request);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
            if stop.load(Ordering::Acquire) {
                return;
            }
        }
        if !failed {
            if let Some(session) = session.as_mut() {
                // Drain queued notifications before issuing a replacement dump.
                for _ in 0..32 {
                    let incoming = match session.connection.incoming_if_complete() {
                        Ok(Some(incoming)) => incoming,
                        Ok(None) => break,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    };
                    match session.incoming(incoming, generation, &stop) {
                        Ok(Some(call)) => {
                            if let Some(Event::Request(call)) =
                                emit(&events, &wake, Event::Request(call))
                            {
                                if session
                                    .connection
                                    .reply_status(&call.request, status::NO_MEMORY, None)
                                    .is_err()
                                {
                                    failed = true;
                                }
                                session.connection.recycle_request(call.request);
                            }
                        }
                        Ok(None) => {}
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                }
                if !failed && session.dump_needed && !stop.load(Ordering::Acquire) {
                    match session.dump() {
                        Ok(Some(interfaces)) => {
                            pending_network = Some(Event::Network {
                                generation,
                                interfaces,
                            })
                        }
                        Ok(None) => {}
                        Err(_) => failed = true,
                    }
                }
            }
        }
        if failed {
            if let Some(session) = session.take() {
                let _ = poller.remove(session.connection.as_raw_fd());
                // Connection/type IDs and undelivered old snapshots die here.
                pending_network = None;
                let _ = emit(&events, &wake, Event::Disconnected { generation });
            }
            retry_at = Instant::now() + RETRY;
        }
        if let Some(event) = pending_network.take() {
            pending_network = emit(&events, &wake, event);
        }
        if stop.load(Ordering::Acquire) {
            break;
        }
        let timeout = if session.as_ref().is_some_and(|s| s.connection.has_pending()) {
            0
        } else if pending_network.is_some() {
            10
        } else if session.is_none() {
            retry_at
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(1000) as i32
        } else {
            1000
        };
        if poller.wait(timeout, &mut ready).is_err() {
            return;
        }
        if ready.iter().any(|event| event.token == WAKE) {
            drain_wake(&wake);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bus() -> (Bus, SyncSender<Event>, UnixStream) {
        let (wake, worker_wake) = UnixStream::pair().unwrap();
        wake.set_nonblocking(true).unwrap();
        worker_wake.set_nonblocking(true).unwrap();
        let (commands, _command_rx) = mpsc::sync_channel(CAPACITY);
        let (event_tx, events) = mpsc::sync_channel(CAPACITY);
        (
            Bus {
                commands,
                events,
                wake,
                stop: Arc::new(AtomicBool::new(false)),
                worker: None,
                before_wake_read: None,
            },
            event_tx,
            worker_wake,
        )
    }

    #[test]
    fn concurrent_publication_during_empty_drain_is_delivered_without_another_event() {
        let (mut bus, events, wake) = test_bus();
        let mut poller = Poller::new().unwrap();
        poller.add(bus.as_raw_fd(), WAKE, false).unwrap();
        // A late notification from an already consumed event can wake the
        // production owner while its queue is empty.
        notify(&wake);
        let (publish, publish_rx) = mpsc::sync_channel(0);
        let (published, published_rx) = mpsc::sync_channel(0);
        let (finish, finish_rx) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            publish_rx.recv().unwrap();
            assert!(emit(&events, &wake, Event::Connected { generation: 17 }).is_none());
            published.send(()).unwrap();
            finish_rx.recv().unwrap();
        });
        // Force publication immediately before the notification read. With
        // the old dequeue-then-read order this was after try_recv(Empty): both
        // notification bytes disappeared and the owner returned None forever.
        bus.before_wake_read = Some(Box::new(move || {
            publish.send(()).unwrap();
            published_rx.recv().unwrap();
        }));
        let mut ready = Vec::new();
        poller.wait(1000, &mut ready).unwrap();
        assert!(ready.iter().any(|event| event.token == WAKE));
        assert!(matches!(
            bus.try_event().unwrap(),
            Some(Event::Connected { generation: 17 })
        ));
        assert!(bus.try_event().unwrap().is_none());
        poller.wait(0, &mut ready).unwrap();
        assert!(ready.is_empty());
        finish.send(()).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn partial_owner_drain_leaves_remaining_events_readable() {
        let (mut bus, events, wake) = test_bus();
        for generation in 0..CAPACITY as u64 {
            assert!(emit(&events, &wake, Event::Connected { generation }).is_none());
        }
        let mut poller = Poller::new().unwrap();
        poller.add(bus.as_raw_fd(), WAKE, false).unwrap();
        let mut ready = Vec::new();
        for generation in 0..CAPACITY as u64 {
            poller.wait(1000, &mut ready).unwrap();
            assert!(ready.iter().any(|event| event.token == WAKE));
            assert!(
                matches!(bus.try_event().unwrap(), Some(Event::Connected { generation: got }) if got == generation)
            );
        }
        assert!(bus.try_event().unwrap().is_none());
        poller.wait(0, &mut ready).unwrap();
        assert!(ready.is_empty());
    }

    #[test]
    fn dump_retains_only_typed_complete_interface_entries() {
        let data = owrt_ubus::json::parse(r#"{"interface":[{"interface":"lan","l3_device":"br-lan","up":true,"data":{}},{"interface":"wan","data":{}},{"interface":"bad"}]}"#).unwrap();
        let interfaces = parse_network_dump(&data).unwrap();
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].device.as_deref(), Some("br-lan"));
        assert!(interfaces[0].up);
        assert!(parse_network_dump(&Json::Null).is_err());
    }
    #[test]
    fn absent_bus_does_not_block_owner_or_shutdown() {
        let started = Instant::now();
        let mut bus =
            Bus::start(Some(format!("/tmp/odhcpd-no-bus-{}", std::process::id()))).unwrap();
        assert!(bus.try_event().unwrap().is_none());
        bus.stop().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[ignore = "requires OWRT_TEST_UBUSD pointing to a private stock ubusd launcher"]
    fn private_bus_recovers_objects_requests_and_latest_full_queue_snapshot() {
        use std::process::{Child, Command as ProcessCommand, Stdio};
        struct Fixture {
            child: Child,
            directory: std::path::PathBuf,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let _ = std::fs::remove_dir_all(&self.directory);
            }
        }
        let launcher = std::env::var("OWRT_TEST_UBUSD").expect("stock ubusd launcher");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("odhcpd-bus-test-{}-{unique}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("ubus.sock");
        let socket_text = socket.to_str().unwrap();
        let spawn = || {
            ProcessCommand::new(&launcher)
                .args(["-s", socket_text])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut fixture = Fixture {
            child: spawn(),
            directory,
        };
        let connect = || {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Ok(connection) =
                    Connection::connect_timeout(Some(socket_text), Duration::from_millis(100))
                {
                    break connection;
                }
                assert!(Instant::now() < deadline, "private ubusd did not start");
                thread::sleep(Duration::from_millis(5));
            }
        };
        fn serve(connection: &mut Connection, device: &str) -> bool {
            let mut served = false;
            while let Some(incoming) = connection.incoming_if_complete().unwrap() {
                if let Incoming::Invoke(request) = incoming {
                    assert_eq!(request.method, "dump");
                    let value = Json::Object(vec![(
                        "interface".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("interface".into(), Json::Str("lan".into())),
                            ("l3_device".into(), Json::Str(device.into())),
                            ("up".into(), Json::Bool(true)),
                            ("data".into(), Json::Object(vec![])),
                        ])]),
                    )]);
                    let fields = owrt_ubus::convert::object_to_payload(&value);
                    connection
                        .reply_data_status(&request, &fields, status::OK)
                        .unwrap();
                    served = true;
                }
            }
            served
        }
        fn wait_network(bus: &mut Bus, netifd: &mut Connection, device: &str) -> u64 {
            let deadline = Instant::now() + Duration::from_secs(4);
            loop {
                serve(netifd, device);
                while let Some(event) = bus.try_event().unwrap() {
                    if let Event::Network {
                        generation,
                        interfaces,
                    } = event
                    {
                        if interfaces.first().and_then(|i| i.device.as_deref()) == Some(device) {
                            return generation;
                        }
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "latest network snapshot did not arrive"
                );
                thread::sleep(Duration::from_millis(2));
            }
        }
        let mut netifd = connect();
        let mut netifd_id = netifd
            .add_object("network.interface", &[("dump", &[])], 1000)
            .unwrap();
        let mut bus = Bus::start(Some(socket_text.into())).unwrap();
        let generation = wait_network(&mut bus, &mut netifd, "br-lan");
        assert!(generation > 0);
        let mut observer = connect();
        let entries = observer.lookup(Some("dhcp"), 1000).unwrap();
        let names: Vec<_> = blob::fields(&entries[0].signature)
            .map(|field| field.name.to_owned())
            .collect();
        assert_eq!(names, vec!["ipv6leases", "ipv6ra", "add_lease"]);

        // An owner request is delivered unchanged, and its reply returns over
        // the worker connection rather than the owner's protocol poll loop.
        let mut caller = connect();
        let dhcp = caller.lookup_id("dhcp", 1000).unwrap();
        let request_thread = thread::spawn(move || caller.invoke(dhcp, "ipv6leases", &[], 3000));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(Event::Request(call)) = bus.try_event().unwrap() {
                assert_eq!(call.generation, generation);
                assert_eq!(call.request.method, "ipv6leases");
                let fields = owrt_ubus::convert::object_to_payload(&Json::Object(vec![(
                    "device".into(),
                    Json::Object(vec![]),
                )]));
                bus.reply(call, fields, status::OK).unwrap();
                break;
            }
            assert!(Instant::now() < deadline, "owner did not receive request");
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(request_thread.join().unwrap().unwrap().status, status::OK);

        netifd.remove_object(netifd_id, 1000).unwrap();
        netifd_id = netifd
            .add_object("network.interface", &[("dump", &[])], 1000)
            .unwrap();
        assert_eq!(wait_network(&mut bus, &mut netifd, "br-new"), generation);

        // Leave the owner's bounded event queue undrained while enough dumps
        // complete to fill it; the final snapshot must be retried, not lost.
        for index in 0..(CAPACITY + 3) {
            netifd.notify(netifd_id, "interface.update", &[]).unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                if serve(&mut netifd, &format!("br-{index}")) {
                    break;
                }
                assert!(Instant::now() < deadline, "no subscribed dump");
                thread::sleep(Duration::from_millis(2));
            }
        }
        netifd.notify(netifd_id, "interface.update", &[]).unwrap();
        assert_eq!(wait_network(&mut bus, &mut netifd, "br-final"), generation);

        // Restart only this fixture's daemon. New connection-local IDs and
        // subscriptions must be established without restarting the Bus owner.
        fixture.child.kill().unwrap();
        fixture.child.wait().unwrap();
        fixture.child = spawn();
        drop(netifd);
        let mut netifd = connect();
        netifd
            .add_object("network.interface", &[("dump", &[])], 1000)
            .unwrap();
        assert!(wait_network(&mut bus, &mut netifd, "br-reconnected") > generation);
        let started = Instant::now();
        bus.stop().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
