//! Linux UDP listener around the socket-independent TFTP transfer runtime.
//!
//! The runtime owns protocol state and file descriptors; this module owns the
//! port-69 socket, per-RRQ transfer sockets, pktinfo admission and event
//! cleanup. Interface admission and helper integration remain caller-owned.

#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use crate::net::{Datagram, DatagramSocket};
use crate::tftp_runtime::{FileOpener, RuntimeEvent, SocketRole, TransferId, TransferRuntime};
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

pub struct TftpListener<O> {
    server: DatagramSocket,
    transfers: BTreeMap<TransferId, UdpSocket>,
    runtime: TransferRuntime<O>,
    bind_ip: IpAddr,
    single_port: bool,
    buffer: Vec<u8>,
}

impl<O: FileOpener> TftpListener<O> {
    pub fn bind(address: SocketAddr, runtime: TransferRuntime<O>) -> io::Result<Self> {
        let server = DatagramSocket::bind(address)?;
        let single_port = runtime_single_port(&runtime);
        Ok(Self {
            server,
            transfers: BTreeMap::new(),
            runtime,
            bind_ip: address.ip(),
            single_port,
            buffer: vec![0; 65_535],
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.server.local_addr()
    }

    pub fn active_transfers(&self) -> usize {
        self.runtime.active_len()
    }

    /// Poll one bounded datagram from the server/transfer sockets and run one
    /// retransmission tick. `Send` events are attempted before return;
    /// nonfatal socket/send failures are reported as `TransportError`.
    pub fn poll_once(&mut self, now: u64) -> io::Result<Vec<RuntimeEvent>> {
        let mut events = Vec::new();
        self.receive_server(now, &mut events)?;
        if !self.single_port {
            let ids: Vec<_> = self.transfers.keys().copied().collect();
            for id in ids {
                self.receive_transfer(id, now, &mut events)?;
            }
        }
        let mut tick_events = self.runtime.tick(now).map_err(runtime_io)?;
        self.flush_events(&mut tick_events, None);
        events.extend(tick_events);
        Ok(events)
    }

    fn receive_server(&mut self, now: u64, events: &mut Vec<RuntimeEvent>) -> io::Result<()> {
        if !self.runtime.can_receive_server() {
            return Ok(());
        }
        let Some(datagram) = receive_pending(&self.server, &mut self.buffer)? else {
            return Ok(());
        };
        let bytes = self.buffer[..datagram.len].to_vec();
        // C allocates/binds the dedicated socket before opening the file.
        // This order also decides the wire result with only one FD left.
        let socket = if !self.single_port && matches!(bytes.get(..2), Some([0, 1] | [0, 2])) {
            match bind_transfer(self.bind_ip) {
                Ok(socket) => Some(socket),
                Err(error) => {
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
        let mut received = self
            .runtime
            .handle_socket_datagram(SocketRole::Server, datagram.peer, &bytes, now)
            .map_err(runtime_io)?;
        self.flush_events(&mut received, socket);
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
        // C's dedicated path uses recvfrom, without ancillary admission.
        // A receive error leaves the transfer for its timer/retry path.
        let (len, peer) = match socket.recv_from(&mut self.buffer) {
            Ok(datagram) => datagram,
            Err(_) => return Ok(()),
        };
        let bytes = self.buffer[..len].to_vec();
        let mut received = self
            .runtime
            .handle_socket_datagram(SocketRole::Transfer(id), peer, &bytes, now)
            .map_err(runtime_io)?;
        self.flush_events(&mut received, None);
        events.extend(received);
        Ok(())
    }

    fn flush_events(&mut self, events: &mut Vec<RuntimeEvent>, mut new_socket: Option<UdpSocket>) {
        let mut errors = Vec::new();
        for event in &*events {
            let sending = match event {
                RuntimeEvent::Send { id, peer, packet } => Some((*id, *peer, packet)),
                RuntimeEvent::TidError { id, peer, packet } => Some((Some(*id), *peer, packet)),
                RuntimeEvent::Completed(completion) => {
                    self.transfers.remove(&completion.id);
                    None
                }
                RuntimeEvent::Failed { id, .. } | RuntimeEvent::TimedOut { id, .. } => {
                    self.transfers.remove(id);
                    None
                }
                RuntimeEvent::TransportError { .. } => None,
            };
            if let Some((id, peer, packet)) = sending {
                // C ignores send_from's failure result and keeps the transfer
                // for its normal retransmission/timeout path.
                if let Err(error) = self.transmit(id, peer, packet, &mut new_socket) {
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
    ) -> io::Result<()> {
        if self.single_port {
            return self.server.send(packet, peer, None);
        }
        let socket = if let Some(id) = id {
            if let std::collections::btree_map::Entry::Vacant(entry) = self.transfers.entry(id) {
                entry.insert(
                    new_socket
                        .take()
                        .ok_or_else(|| io::Error::other("missing TFTP transfer socket"))?,
                );
            }
            self.transfers.get(&id).expect("inserted transfer socket")
        } else {
            new_socket
                .as_ref()
                .ok_or_else(|| io::Error::other("missing TFTP error socket"))?
        };
        loop {
            match socket.send_to(packet, peer) {
                Ok(sent) if sent == packet.len() => return Ok(()),
                Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short TFTP send")),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

fn bind_transfer(ip: IpAddr) -> io::Result<UdpSocket> {
    // Unlike DNS listeners these sockets must not use SO_REUSEADDR: each
    // live RRQ requires its own source TID, including identical peers.
    let socket = UdpSocket::bind(SocketAddr::new(ip, 0))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
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

fn runtime_single_port<O: FileOpener>(runtime: &TransferRuntime<O>) -> bool {
    runtime.single_port()
}

fn runtime_io<E: std::fmt::Debug>(error: E) -> io::Error {
    io::Error::other(format!("TFTP runtime: {error:?}"))
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
            assert!(matches!(
                timeout.as_slice(),
                [RuntimeEvent::TimedOut { .. }]
            ));
            assert_eq!(listener.active_transfers(), 0);
            assert!(listener.transfers.is_empty());
            let _reclaimed = UdpSocket::bind(transfer_addresses[1]).unwrap();
            drop(listener);
            let _reclaimed = UdpSocket::bind(server).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
