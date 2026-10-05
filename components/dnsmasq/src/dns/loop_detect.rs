//! loop.c identifies returned TXT probes by a stable per-server random uid.
use super::files::{ServerSources, Source};
use super::forward::{Random, ServerId};
use super::wire::Header;
use crate::config::dns::RuleTarget;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;

#[derive(Default)]
pub struct LoopState {
    uids: HashMap<ServerId, u32>,
    pub disabled: HashSet<ServerId>,
}

pub struct LoopProbe {
    pub server: ServerId,
    pub address: SocketAddr,
    pub endpoint: crate::config::dns::ServerEndpoint,
    pub packet: [u8; 31],
}

impl LoopState {
    /// add_update_server assigns a new uid even when a file row reuses a
    /// server record. Unchanged rows in other sources keep their identity.
    pub fn reset_source(&mut self, source: Source, sources: &ServerSources) {
        for row in sources.rules().iter().filter(|row| row.source == source) {
            if let Some(id) = row.server {
                self.uids.remove(&id);
                self.disabled.remove(&id);
            }
        }
    }

    pub fn probes<R: Random>(
        &mut self,
        sources: &ServerSources,
        random: &mut R,
    ) -> io::Result<Vec<LoopProbe>> {
        self.uids
            .retain(|id, _| sources.rules().iter().any(|row| row.server == Some(*id)));
        self.disabled.retain(|id| self.uids.contains_key(id));
        let mut probes = Vec::new();
        for row in sources.rules() {
            let Some(id) = row.server else { continue };
            let uid = if let Some(uid) = self.uids.get(&id) {
                *uid
            } else {
                let uid = random.next_u32()?;
                self.uids.insert(id, uid);
                uid
            };
            let domain = &row.value.rule.domain;
            if !domain.suffix.is_empty() || domain.dotless {
                continue;
            }
            self.disabled.remove(&id);
            let RuleTarget::Upstream(endpoint) = &row.value.rule.target else {
                continue;
            };
            let address = row
                .value
                .address
                .or_else(|| super::routing::validate_endpoint(endpoint).ok());
            if let Some(address) = address {
                probes.push(LoopProbe {
                    server: id,
                    address,
                    endpoint: endpoint.clone(),
                    packet: probe(uid, random.next_u32()? as u16),
                });
            }
        }
        Ok(probes)
    }

    pub fn detect(&mut self, packet: &[u8], sources: &ServerSources) -> Option<ServerId> {
        let header = Header::parse(packet).ok()?;
        // receive_query calls detect_loop only after extract_request accepts
        // one standard QUERY question; malformed counts never disable a bank.
        if header.questions != 1
            || header.flags & 0xf800 != 0
            || header.answers != 0
            || header.authorities != 0
        {
            return None;
        }
        let question = super::forward::Question::parse(packet).ok()?;
        if question.rrtype != 16 {
            return None;
        }
        let name = question.name.dnsmasq_bytes();
        if name.len() != 13 || &name[9..] != b"test" || !name[..8].iter().all(u8::is_ascii_hexdigit)
        {
            return None;
        }
        let uid = u32::from_str_radix(std::str::from_utf8(&name[..8]).ok()?, 16).ok()?;
        let id = sources.rules().iter().find_map(|row| {
            row.server.filter(|id| {
                row.value.rule.domain.suffix.is_empty()
                    && !self.disabled.contains(id)
                    && self.uids.get(id) == Some(&uid)
            })
        })?;
        self.disabled.insert(id);
        Some(id)
    }
}

pub fn probe(uid: u32, id: u16) -> [u8; 31] {
    let mut packet = [0; 31];
    packet[..2].copy_from_slice(&id.to_be_bytes());
    packet[2] = 1; // RD
    packet[5] = 1; // one question
    packet[12] = 8;
    for (index, byte) in packet[13..21].iter_mut().enumerate() {
        *byte = b"0123456789abcdef"[((uid >> (28 - index * 4)) & 15) as usize];
    }
    packet[21..].copy_from_slice(b"\x04test\0\x00\x10\x00\x01");
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::files::SourceRule;

    struct Sequence(u32);
    impl Random for Sequence {
        fn next_u32(&mut self) -> io::Result<u32> {
            self.0 += 1;
            Ok(self.0)
        }
    }

    #[test]
    fn nonstandard_request_headers_do_not_disable_a_server() {
        let row = SourceRule::resolver("127.0.0.2:15970".parse().unwrap(), 1);
        let sources = ServerSources::new(&[row.rule]);
        for (index, value) in [(2, 9), (2, 0x81), (5, 2), (7, 1), (9, 1)] {
            let mut state = LoopState::default();
            let mut packet = state.probes(&sources, &mut Sequence(0)).unwrap()[0].packet;
            packet[index] = value;
            assert_eq!(state.detect(&packet, &sources), None);
            assert!(state.disabled.is_empty());
        }
    }

    #[test]
    fn reloaded_file_rows_renew_uid_while_inline_rows_keep_uid() {
        let inline = SourceRule::resolver("127.0.0.2:15970".parse().unwrap(), 1);
        let file = SourceRule::resolver("127.0.0.3:15971".parse().unwrap(), 1);
        let mut sources = ServerSources::new(&[inline.rule]);
        sources.replace(Source::ServersFile, vec![file.clone()]);
        let mut state = LoopState::default();
        let mut random = Sequence(0);
        let first = state.probes(&sources, &mut random).unwrap();
        sources.replace(Source::ServersFile, vec![file]);
        state.reset_source(Source::ServersFile, &sources);
        let next = state.probes(&sources, &mut random).unwrap();
        assert_eq!(first[0].server, next[0].server);
        assert_eq!(&first[0].packet[13..21], &next[0].packet[13..21]);
        assert_eq!(first[1].server, next[1].server);
        assert_ne!(&first[1].packet[13..21], &next[1].packet[13..21]);
        assert_eq!(state.detect(&first[1].packet, &sources), None);
        assert_eq!(
            state.detect(&next[1].packet, &sources),
            Some(next[1].server)
        );
        assert_eq!(state.detect(&next[1].packet, &sources), None);
    }
}
