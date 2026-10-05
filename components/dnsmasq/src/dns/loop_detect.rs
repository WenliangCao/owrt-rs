//! loop.c identifies returned TXT probes by a stable per-server random uid.
use super::files::ServerSources;
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
    pub packet: Vec<u8>,
}

impl LoopState {
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
        if header.questions != 1 {
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

pub fn probe(uid: u32, id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(30);
    for value in [id, 0x0100, 1, 0, 0, 0] {
        packet.extend_from_slice(&value.to_be_bytes());
    }
    packet.push(8);
    packet.extend_from_slice(format!("{uid:08x}").as_bytes());
    packet.extend_from_slice(b"\x04test\0\x00\x10\x00\x01");
    packet
}
