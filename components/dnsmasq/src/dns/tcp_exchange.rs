//! Incremental tcp_talk transport. Only this state machine owns progress for
//! one query; all persistent connections remain owned by its TcpUpstream.

use super::{
    matches_question, Connection, Group, GroupId, Question, TcpError, TcpOptions, TcpProgress,
    TcpWait,
};
use dnsmasq_platform::poll::{POLLIN, POLLOUT};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pick,
    Connect,
    Write,
    Prefix,
    Body,
}

pub(super) struct Exchange {
    group: GroupId,
    question: Question,
    frame: Vec<u8>,
    start: usize,
    offset: usize,
    phase: Phase,
    position: usize,
    prefix: [u8; 2],
    reply: Vec<u8>,
    deadline: Instant,
    idle: Instant,
}

impl Exchange {
    pub(super) fn reply_server(
        &self,
        groups: &HashMap<GroupId, Group>,
    ) -> Option<std::net::SocketAddr> {
        let group = groups.get(&self.group)?;
        let index = (self.start + self.offset) % group.servers.len();
        Some(group.servers.get(index)?.address)
    }

    pub(super) fn new(
        group: GroupId,
        question: Question,
        frame: Vec<u8>,
        start: usize,
        deadline: Instant,
    ) -> Self {
        Self {
            group,
            question,
            frame,
            start,
            offset: 0,
            phase: Phase::Pick,
            position: 0,
            prefix: [0; 2],
            reply: Vec::new(),
            deadline,
            idle: deadline,
        }
    }

    pub(super) fn step(
        &mut self,
        groups: &mut HashMap<GroupId, Group>,
        options: TcpOptions,
        connection_failures: &mut Vec<std::net::SocketAddr>,
    ) -> Result<TcpProgress, TcpError> {
        let group = groups.get_mut(&self.group).ok_or(TcpError::UnknownGroup)?;
        // Fairness bound covers interrupted syscalls, partial reads/writes,
        // mismatched replies and configurations with many failed upstreams.
        for _ in 0..64 {
            let now = Instant::now();
            if now >= self.deadline {
                return Err(TcpError::Deadline);
            }
            if self.offset >= group.servers.len() {
                return Err(TcpError::NoReply);
            }
            let index = (self.start + self.offset) % group.servers.len();
            let server = &mut group.servers[index];
            if self.phase != Phase::Pick && now >= self.idle {
                if self.phase == Phase::Connect
                    || server
                        .connection
                        .as_ref()
                        .is_some_and(|connection| !connection.had_reply)
                {
                    connection_failures.push(server.address);
                }
                self.failed(&mut server.connection);
                continue;
            }
            if self.phase == Phase::Pick {
                self.position = 0;
                self.reply.clear();
                if server.connection.is_some() {
                    self.phase = Phase::Write;
                    self.idle = now + options.write_timeout;
                    continue;
                }
                #[cfg(all(
                    any(target_os = "linux", target_os = "macos"),
                    any(target_arch = "aarch64", target_arch = "x86_64")
                ))]
                let opened = super::tcp_connect::start(server.address, server.source.as_ref());
                #[cfg(not(all(
                    any(target_os = "linux", target_os = "macos"),
                    any(target_arch = "aarch64", target_arch = "x86_64")
                )))]
                let opened: Result<(std::net::TcpStream, bool), TcpError> = Err(TcpError::NoReply);
                match opened {
                    Ok((stream, connected)) => {
                        server.connection = Some(Connection {
                            stream,
                            had_reply: false,
                        });
                        self.phase = if connected {
                            Phase::Write
                        } else {
                            Phase::Connect
                        };
                        self.idle = now
                            + if connected {
                                options.write_timeout
                            } else {
                                options.connect_timeout
                            };
                        if connected {
                            group.last_connected = index;
                        }
                    }
                    Err(_) => {
                        connection_failures.push(server.address);
                        self.offset += 1;
                    }
                }
                continue;
            }
            let connection = server
                .connection
                .as_mut()
                .expect("active phase owns a connection");
            if self.phase == Phase::Connect {
                #[cfg(all(
                    any(target_os = "linux", target_os = "macos"),
                    any(target_arch = "aarch64", target_arch = "x86_64")
                ))]
                let connected = super::tcp_connect::connected(&connection.stream);
                #[cfg(not(all(
                    any(target_os = "linux", target_os = "macos"),
                    any(target_arch = "aarch64", target_arch = "x86_64")
                )))]
                let connected = Err(TcpError::NoReply);
                match connected {
                    Ok(true) => {
                        group.last_connected = index;
                        self.phase = Phase::Write;
                        self.idle = now + options.write_timeout;
                    }
                    Ok(false) => return Ok(self.wait(group)),
                    Err(_) => {
                        connection_failures.push(server.address);
                        self.failed(&mut server.connection);
                    }
                }
                continue;
            }
            if self.phase == Phase::Body && self.position == self.reply.len() {
                // C retains the connection but advances server on a question
                // mismatch. It checks QR/question, not transaction ID/RCODE.
                if matches_question(&self.reply, &self.question) {
                    connection.had_reply = true;
                    return Ok(TcpProgress::Complete(std::mem::take(&mut self.reply)));
                }
                self.offset += 1;
                self.phase = Phase::Pick;
                continue;
            }
            let result = match self.phase {
                Phase::Write => connection.stream.write(&self.frame[self.position..]),
                Phase::Prefix => connection.stream.read(&mut self.prefix[self.position..]),
                Phase::Body => connection.stream.read(&mut self.reply[self.position..]),
                Phase::Pick | Phase::Connect => unreachable!(),
            };
            match result {
                Ok(0) => {
                    if !connection.had_reply {
                        connection_failures.push(server.address);
                    }
                    self.failed(&mut server.connection);
                }
                Ok(count) => {
                    self.position += count;
                    self.idle = Instant::now()
                        + if self.phase == Phase::Write {
                            options.write_timeout
                        } else {
                            options.read_timeout
                        };
                    match self.phase {
                        Phase::Write if self.position == self.frame.len() => {
                            self.phase = Phase::Prefix;
                            self.position = 0;
                            self.idle = Instant::now() + options.read_timeout;
                        }
                        Phase::Prefix if self.position == 2 => {
                            // Allocation is bounded by the u16 frame length;
                            // zero length proceeds to question rejection.
                            self.reply = vec![0; usize::from(u16::from_be_bytes(self.prefix))];
                            self.phase = Phase::Body;
                            self.position = 0;
                        }
                        _ => {}
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(self.wait(group))
                }
                Err(_) => {
                    if !connection.had_reply {
                        connection_failures.push(server.address);
                    }
                    self.failed(&mut server.connection);
                }
            }
        }
        // Schedule an immediate owner-loop turn when the I/O budget, rather
        // than readiness, stops progress. poll ignores a negative fd.
        Ok(TcpProgress::Pending(TcpWait {
            fd: -1,
            events: 0,
            deadline: Instant::now().min(self.deadline),
        }))
    }

    fn failed(&mut self, connection: &mut Option<Connection>) {
        // One reconnect for a socket that previously returned a valid reply.
        // A fresh socket never has this bit, so its failure advances server.
        let retry = connection
            .take()
            .is_some_and(|connection| connection.had_reply);
        if !retry {
            self.offset += 1;
        }
        self.phase = Phase::Pick;
    }

    fn wait(&self, group: &Group) -> TcpProgress {
        let index = (self.start + self.offset) % group.servers.len();
        let connection = group.servers[index]
            .connection
            .as_ref()
            .expect("waiting owns a connection");
        TcpProgress::Pending(TcpWait {
            fd: connection.stream.as_raw_fd(),
            events: if matches!(self.phase, Phase::Connect | Phase::Write) {
                POLLOUT
            } else {
                POLLIN
            },
            deadline: self.idle.min(self.deadline),
        })
    }
}
