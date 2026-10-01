//! PRIVATE ordinary-TCP correctness owner. Deep cloning is a cost reference,
//! not an accepted product representation. No transport or resolver is owned.

use super::cache::{Cache, CacheCounters, CacheTransaction};
use super::cache_engine::{CacheContext, OrdinaryCacheMode};
use super::daemon::DaemonError;
use super::process::AddressPolicy;
use super::service::{append_empty_opt, LocalDnsService};
use super::wire::{find_pseudoheader, Header};

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
    ) -> Result<Option<Vec<u8>>, DaemonError> {
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
        let mut answer = CacheContext {
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
        debug_assert!(
            !answer.stale,
            "private TCP prototype excludes stale cache policy"
        );
        if scan.opt.is_some() {
            if let Some(packet) = &mut answer.packet {
                append_empty_opt(packet, local.edns_packet_max, false, usize::from(u16::MAX))
                    .map_err(super::cache_engine::CacheError::from)?;
            }
        }
        Ok(answer.packet)
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
