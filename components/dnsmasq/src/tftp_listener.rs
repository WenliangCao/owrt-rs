//! Linux UDP listener around the socket-independent TFTP transfer runtime.
//!
//! The runtime owns protocol state and file descriptors; this module owns the
//! port-69 socket, per-peer transfer sockets, pktinfo admission and event
//! cleanup. It is intentionally independent from the dnsmasq CLI until the
//! corresponding TFTP options are wired into the loader.

#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use crate::net::DatagramSocket;
use crate::tftp_runtime::{FileOpener, RuntimeEvent, SocketRole, TransferRuntime};
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

pub struct TftpListener<O> {
    server: DatagramSocket,
    transfers: BTreeMap<SocketAddr, DatagramSocket>,
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
    /// retransmission tick. All `Send` events are transmitted before return;
    /// the event list remains available for metrics and completion consumers.
    pub fn poll_once(&mut self, now: u64) -> io::Result<Vec<RuntimeEvent>> {
        let mut events = Vec::new();
        self.receive_server(now, &mut events)?;
        if !self.single_port {
            let peers: Vec<_> = self.transfers.keys().copied().collect();
            for peer in peers {
                self.receive_transfer(peer, now, &mut events)?;
            }
        }
        events.extend(self.runtime.tick(now).map_err(runtime_io)?);
        self.flush_events(&events)?;
        Ok(events)
    }

    fn receive_server(&mut self, now: u64, events: &mut Vec<RuntimeEvent>) -> io::Result<()> {
        let Some(datagram) = self.server.receive(&mut self.buffer)? else {
            return Ok(());
        };
        let bytes = self.buffer[..datagram.len].to_vec();
        events.extend(
            self.runtime
                .handle_socket_datagram(SocketRole::Server, datagram.peer, &bytes, now)
                .map_err(runtime_io)?,
        );
        Ok(())
    }

    fn receive_transfer(
        &mut self,
        peer: SocketAddr,
        now: u64,
        events: &mut Vec<RuntimeEvent>,
    ) -> io::Result<()> {
        let Some(socket) = self.transfers.get(&peer) else {
            return Ok(());
        };
        let Some(datagram) = socket.receive(&mut self.buffer)? else {
            return Ok(());
        };
        let bytes = self.buffer[..datagram.len].to_vec();
        events.extend(
            self.runtime
                .handle_socket_datagram(SocketRole::Transfer, peer, &bytes, now)
                .map_err(runtime_io)?,
        );
        Ok(())
    }

    fn flush_events(&mut self, events: &[RuntimeEvent]) -> io::Result<()> {
        for event in events {
            match event {
                RuntimeEvent::Send { peer, packet } | RuntimeEvent::TidError { peer, packet } => {
                    if self.single_port {
                        self.server.send(packet, *peer, None)?;
                    } else {
                        let socket = self.transfer_socket(*peer)?;
                        socket.send(packet, *peer, None)?;
                    }
                }
                RuntimeEvent::Completed(completion) => {
                    self.transfers.remove(&completion.peer);
                }
                RuntimeEvent::Failed { peer } | RuntimeEvent::TimedOut { peer } => {
                    self.transfers.remove(peer);
                }
            }
        }
        Ok(())
    }

    fn transfer_socket(&mut self, peer: SocketAddr) -> io::Result<&mut DatagramSocket> {
        if !self.transfers.contains_key(&peer) {
            let socket = DatagramSocket::bind(SocketAddr::new(self.bind_ip, 0))?;
            self.transfers.insert(peer, socket);
        }
        Ok(self
            .transfers
            .get_mut(&peer)
            .expect("inserted transfer socket"))
    }
}

fn runtime_single_port<O: FileOpener>(runtime: &TransferRuntime<O>) -> bool {
    runtime.single_port()
}

fn runtime_io<E: std::fmt::Debug>(error: E) -> io::Error {
    io::Error::other(format!("TFTP runtime: {error:?}"))
}
