//! Transport boundaries for the local DNS engine.
//!
//! The service owns socket I/O and TCP framing, while `local::LocalAnswerer`
//! owns answer selection.  An unowned query is returned as `None` so a future
//! upstream dispatcher can take over without changing the wire boundary.

use super::local::{AnswerError, LocalAnswerer};
use crate::config::dns::DnsConfig;
use crate::hosts::Hosts;
use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    Empty,
    TooLarge,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated DNS TCP frame",
            Self::Empty => "empty DNS TCP frame",
            Self::TooLarge => "DNS TCP frame exceeds 65535 bytes",
        })
    }
}

impl std::error::Error for FrameError {}

pub fn encode_tcp_frame(packet: &[u8]) -> Result<Vec<u8>, FrameError> {
    if packet.is_empty() {
        return Err(FrameError::Empty);
    }
    if packet.len() > u16::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    let mut frame = Vec::with_capacity(packet.len() + 2);
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}

/// Incremental DNS-over-TCP decoder.  It never allocates according to an
/// incomplete frame and rejects zero-length frames before returning payload.
#[derive(Debug, Default)]
pub struct TcpFramer {
    bytes: Vec<u8>,
}

impl TcpFramer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            // Append only the bytes needed for the current frame. This keeps
            // the decoder bounded while accepting one read with many frames.
            if self.bytes.len() < 2 {
                let needed = 2 - self.bytes.len();
                let count = needed.min(input.len() - offset);
                self.bytes.extend_from_slice(&input[offset..offset + count]);
                offset += count;
                if self.bytes.len() < 2 {
                    break;
                }
            }
            let length = u16::from_be_bytes([self.bytes[0], self.bytes[1]]) as usize;
            if length == 0 {
                self.bytes.clear();
                return Err(FrameError::Empty);
            }
            let needed = length + 2 - self.bytes.len();
            let count = needed.min(input.len() - offset);
            self.bytes.extend_from_slice(&input[offset..offset + count]);
            offset += count;
            if self.bytes.len() < length + 2 {
                break;
            }
            let frame = self.bytes[2..length + 2].to_vec();
            self.bytes.clear();
            frames.push(frame);
        }
        Ok(frames)
    }

    pub fn finish(&self) -> Result<(), FrameError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(FrameError::Truncated)
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Debug)]
pub enum ServiceError {
    Answer(AnswerError),
    Frame(FrameError),
    Io(io::Error),
}

impl From<AnswerError> for ServiceError {
    fn from(value: AnswerError) -> Self {
        Self::Answer(value)
    }
}
impl From<FrameError> for ServiceError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}
impl From<io::Error> for ServiceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// A socket-independent service that can be embedded by a daemon or exercised
/// in an isolated namespace.  It currently answers only locally owned names.
pub struct LocalDnsService {
    pub config: DnsConfig,
    pub hosts: Hosts,
    pub local_ttl: u32,
    pub max_udp: usize,
}

impl LocalDnsService {
    pub fn new(config: DnsConfig, hosts: Hosts, local_ttl: u32, max_udp: usize) -> Self {
        Self {
            config,
            hosts,
            local_ttl,
            max_udp: max_udp.max(512),
        }
    }

    pub fn handle_udp(&mut self, query: &[u8]) -> Result<Option<Vec<u8>>, ServiceError> {
        let mut answerer = LocalAnswerer {
            config: &self.config,
            hosts: &mut self.hosts,
            local_ttl: self.local_ttl,
            max_packet: self.max_udp,
        };
        answerer.answer(query).map_err(ServiceError::from)
    }

    pub fn handle_tcp_payload(&mut self, query: &[u8]) -> Result<Option<Vec<u8>>, ServiceError> {
        let mut answerer = LocalAnswerer {
            config: &self.config,
            hosts: &mut self.hosts,
            local_ttl: self.local_ttl,
            max_packet: u16::MAX as usize,
        };
        answerer.answer(query).map_err(ServiceError::from)
    }

    pub fn handle_tcp_frame(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, ServiceError> {
        let mut framer = TcpFramer::new();
        let frames = framer.push(frame)?;
        if frames.len() != 1 || framer.buffered_len() != 0 {
            return Err(FrameError::Truncated.into());
        }
        self.handle_tcp_payload(&frames[0])?
            .map(|packet| encode_tcp_frame(&packet).map_err(ServiceError::from))
            .transpose()
    }

    /// Receive and answer one UDP datagram.  `None` means the query belongs to
    /// the upstream path and is intentionally left untouched here.
    pub fn serve_udp_once(&mut self, socket: &UdpSocket) -> Result<bool, ServiceError> {
        let mut query = vec![0; 65_535];
        let (length, peer) = socket.recv_from(&mut query)?;
        // std::net::UdpSocket does not expose MSG_TRUNC.  Reading the maximum
        // IPv4/IPv6 datagram and applying the configured receive limit before
        // parsing has the same observable result: an oversized request is
        // discarded without creating a forward or local answer.
        if length > self.max_udp {
            return Ok(false);
        }
        if let Some(answer) = self.handle_udp(&query[..length])? {
            socket.send_to(&answer, peer)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Serve a blocking TCP connection until EOF.  The framing decoder keeps
    /// partial reads and permits multiple queries on one connection.
    pub fn serve_tcp_connection(&mut self, mut stream: TcpStream) -> Result<(), ServiceError> {
        let mut framer = TcpFramer::new();
        let mut input = [0u8; 4096];
        loop {
            let count = stream.read(&mut input)?;
            if count == 0 {
                return framer.finish().map_err(ServiceError::from);
            }
            for query in framer.push(&input[..count])? {
                if let Some(answer) = self.handle_tcp_payload(&query)? {
                    stream.write_all(&encode_tcp_frame(&answer)?)?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dns::DnsConfig;
    use crate::config::{lex_line, validate_directive};
    use crate::dns::wire::{Header, Name};

    fn query() -> Vec<u8> {
        let name = Name::from_ascii("router.test").unwrap();
        let mut packet = vec![0; 12];
        Header {
            id: 1,
            flags: 0x0100,
            questions: 1,
            ..Header::default()
        }
        .write(&mut packet)
        .unwrap();
        packet.extend(name.as_wire());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn tcp_framer_handles_split_and_multiple_frames() {
        let first = encode_tcp_frame(b"one").unwrap();
        let second = encode_tcp_frame(b"two").unwrap();
        let mut input = first.clone();
        input.extend_from_slice(&second);
        let mut framer = TcpFramer::new();
        assert!(framer.push(&input[..2]).unwrap().is_empty());
        let mut rest = input[2..4].to_vec();
        assert!(framer.push(&rest).unwrap().is_empty());
        rest = input[4..].to_vec();
        assert_eq!(
            framer.push(&rest).unwrap(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert!(framer.finish().is_ok());
    }

    #[test]
    fn local_service_uses_tcp_frame_boundary() {
        let mut config = DnsConfig::default();
        let directive = lex_line(b"host-record=router.test,192.0.2.1")
            .unwrap()
            .unwrap();
        validate_directive(&directive).unwrap();
        config.apply(&directive).unwrap();
        let service = LocalDnsService::new(config, Hosts::new(), 60, 512);
        let mut service = service;
        let response = service
            .handle_tcp_frame(&encode_tcp_frame(&query()).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]) as usize,
            response.len() - 2
        );
    }

    #[test]
    fn tcp_framer_accepts_maximum_frame_followed_by_another_frame() {
        let first = vec![0xa5; u16::MAX as usize];
        let second = encode_tcp_frame(b"second").unwrap();
        let mut input = encode_tcp_frame(&first).unwrap();
        input.extend_from_slice(&second);
        let mut framer = TcpFramer::new();
        let frames = framer.push(&input).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], first);
        assert_eq!(frames[1], b"second");
        assert!(framer.finish().is_ok());
    }

    #[test]
    fn tcp_framer_rejects_zero_length_and_reports_partial_tail() {
        let mut framer = TcpFramer::new();
        assert_eq!(framer.push(&[0, 0]), Err(FrameError::Empty));
        assert_eq!(framer.push(&[0, 3, b'a']), Ok(Vec::new()));
        assert_eq!(framer.finish(), Err(FrameError::Truncated));
    }
}
