//! PRIVATE ordinary-TCP correctness owner. Deep cloning is a cost reference,
//! not an accepted product representation. No transport or resolver is owned.

use super::cache::{Cache, CacheCounters, CacheTransaction};
use super::cache_engine::{CacheContext, OrdinaryCacheMode};
use super::daemon::DaemonError;
use super::process::AddressPolicy;
use super::service::{append_empty_opt, LocalDnsService};
use super::wire::{find_pseudoheader, Header};

/// A deliverable cached answer with the cache engine's observed stale flag.
/// The flag cannot be inferred from TTL (expiry equality and CNAME pre-scan).
#[derive(Debug)]
pub struct TcpCachedAnswer {
    pub packet: Vec<u8>,
    pub stale: bool,
}

pub struct TcpCache {
    pub(super) cache: Option<Cache>,
    pub(super) counters: CacheCounters,
    pub(super) negative_cache: bool,
    pub(super) negative_ttl: u32,
    pub(super) accepted_at: i64,
}

impl TcpCache {
    pub fn accepted_at(&self) -> i64 {
        self.accepted_at
    }

    pub fn answer(
        &mut self,
        query: &[u8],
        local: &mut LocalDnsService,
    ) -> Result<Option<TcpCachedAnswer>, DaemonError> {
        let Some(cache) = &mut self.cache else {
            return Ok(None);
        };
        let scan = find_pseudoheader(query, true)?;
        // TCP applies its own envelope/output limit. Never route this through
        // answer_udp's 512-byte envelope or silently treat DO as plain DNS.
        if scan.signed
            || scan.opt.as_ref().is_some_and(|opt| opt.dnssec_ok())
            || !super::forward_service::ordinary_cache_query(query)
        {
            return Ok(None);
        }
        let header = Header::parse(query)?;
        if header.questions != 1
            || header.answers != 0
            || header.authorities != 0
            || header.additionals != u16::from(scan.opt.is_some())
            || header.opcode() != 0
            || header.flags & 0x8000 != 0
        {
            return Ok(None);
        }
        let question = super::forward::Question::parse(query)?;
        let answer = CacheContext {
            cache,
            counters: &mut self.counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
        }
        .answer_records(
            &question,
            header,
            self.accepted_at,
            local,
            usize::from(u16::MAX),
        )?;
        // A stale observation without a packet is an ordinary forward miss.
        let Some(mut packet) = answer.packet else {
            return Ok(None);
        };
        if scan.opt.is_some() {
            if answer.stale {
                super::tcp_service::add_ede(
                    &mut packet,
                    local.edns_packet_max,
                    false,
                    3,
                    usize::from(u16::MAX),
                )?;
            } else {
                append_empty_opt(
                    &mut packet,
                    local.edns_packet_max,
                    false,
                    usize::from(u16::MAX),
                )
                .map_err(super::cache_engine::CacheError::from)?;
            }
        }
        Ok(Some(TcpCachedAnswer {
            packet,
            stale: answer.stale,
        }))
    }

    pub(super) fn capture_reply(
        &mut self,
        packet: &[u8],
        local: &LocalDnsService,
        policy: &AddressPolicy,
        rcode: u16,
        ordinary: OrdinaryCacheMode,
    ) -> Option<CacheTransaction> {
        let cache = self.cache.as_mut()?;
        CacheContext {
            cache,
            counters: &mut self.counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
        }
        .capture_reply_with_policy(
            packet,
            self.accepted_at,
            local,
            policy,
            rcode,
            ordinary,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dns::DnsConfig;
    use crate::dns::cache::{Kind, Policy, Record, StalePolicy};
    use crate::dns::wire::{Message, Name, PacketWriter, Section};
    use crate::hosts::Hosts;

    fn name() -> Name {
        Name::from_ascii("stale.test").unwrap()
    }

    fn query(kind: u16, opt: bool) -> Vec<u8> {
        let mut writer = PacketWriter::new(1, 0x100, 1232).unwrap();
        writer.question(&name(), kind, 1).unwrap();
        if opt {
            writer
                .record(Section::Additional, &Name::root(), 41, 1232, 0, &[])
                .unwrap();
        }
        writer.finish()
    }

    fn local() -> LocalDnsService {
        LocalDnsService::new(DnsConfig::default(), Hosts::new(), 0, 1232)
    }

    fn owner(accepted_at: i64, stale: StalePolicy) -> TcpCache {
        let mut cache = Cache::new(
            8,
            Policy {
                stale,
                ..Policy::default()
            },
        );
        cache.start_insert();
        cache
            .insert(
                Record {
                    name: name(),
                    kind: Kind::Ipv4,
                    negative: false,
                    data: vec![192, 0, 2, 7],
                },
                100,
                1,
            )
            .unwrap();
        assert!(cache.commit());
        TcpCache {
            cache: Some(cache),
            counters: CacheCounters::default(),
            negative_cache: true,
            negative_ttl: 30,
            accepted_at,
        }
    }

    #[test]
    fn expiry_equality_is_zero_ttl_without_stale_but_later_accept_is_stale() {
        for (now, policy, expected) in [
            (100, StalePolicy::Seconds(3), Some((1, false))),
            (101, StalePolicy::Seconds(3), Some((0, false))),
            (102, StalePolicy::Seconds(3), Some((0, true))),
            (104, StalePolicy::Seconds(3), None),
            (104, StalePolicy::Forever, Some((0, true))),
        ] {
            let answer = owner(now, policy)
                .answer(&query(1, true), &mut local())
                .unwrap();
            assert_eq!(answer.is_some(), expected.is_some());
            if let (Some(answer), Some((ttl, stale))) = (answer, expected) {
                let packet = Message::parse(&answer.packet).unwrap();
                assert_eq!(packet.records(Section::Answer).next().unwrap().ttl, ttl);
                assert_eq!(answer.stale, stale);
                let opt = find_pseudoheader(&answer.packet, true)
                    .unwrap()
                    .opt
                    .unwrap();
                assert_eq!(
                    opt.record.rdata,
                    if stale { &[0, 15, 0, 2, 0, 3][..] } else { &[] }
                );
            }
        }
    }

    #[test]
    fn observed_stale_without_any_answer_is_an_ordinary_forward_miss() {
        assert!(owner(102, StalePolicy::Forever)
            .answer(&query(255, false), &mut local())
            .unwrap()
            .is_none());
    }

    #[test]
    fn stale_marker_does_not_come_from_the_selected_answers_ttl() {
        let mut owner = owner(103, StalePolicy::Forever);
        let cache = owner.cache.as_mut().unwrap();
        cache.clear();
        cache.start_insert();
        cache
            .insert(
                Record {
                    name: name(),
                    kind: Kind::NxDomain,
                    negative: true,
                    data: Vec::new(),
                },
                100,
                1,
            )
            .unwrap();
        assert!(cache.commit());
        cache.start_insert();
        cache
            .insert(
                Record {
                    name: name(),
                    kind: Kind::Ipv4,
                    negative: false,
                    data: vec![192, 0, 2, 8],
                },
                102,
                120,
            )
            .unwrap();
        assert!(cache.commit());
        let answer = owner
            .answer(&query(1, false), &mut local())
            .unwrap()
            .unwrap();
        let packet = Message::parse(&answer.packet).unwrap();
        assert_eq!(packet.records(Section::Answer).next().unwrap().ttl, 119);
        assert!(answer.stale);
    }
}
