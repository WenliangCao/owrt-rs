//! Write a selected positive forward-cache record into a caller-owned packet.
//!
//! References: `rfc1035.c::crec_ttl` (1654–1686), address record output
//! (2100–2170) and generic record output (2283–2347). This helper does not
//! decide whether a query can be answered from cache. The caller owns RRset
//! selection, CNAME traversal, negative answers/SOA, query flags, and EDNS.

use super::cache::{Cache, CnameTarget, EntryId, Kind};
use super::wire::{PacketWriter, Section, WireError};

/// Append one selected, live, positive A/AAAA or generic cache record.
///
/// `Ok(false)` leaves the writer untouched for an invalid/expired handle,
/// negative record, or CNAME. Those cases require the caller's cache-answer
/// state machine. `Ok(true)` means that one complete RR was appended.
/// `WireError::Full` leaves existing records intact and sets the writer's TC
/// bit; the caller decides whether the resulting response should be sent.
///
/// The cached owner and canonical RDATA are used verbatim. The caller must
/// select every RR in the requested RRset and validate generic RDATA before
/// insertion; this helper never treats a single record as a complete answer.
/// `owner_offset` may reference the same owner already written by the caller
/// as the question or a preceding CNAME target.
pub fn append_positive_record(
    writer: &mut PacketWriter,
    cache: &Cache,
    id: EntryId,
    section: Section,
    now: i64,
    owner_offset: Option<u16>,
) -> Result<bool, WireError> {
    if !cache.is_valid(id, now) {
        return Ok(false);
    }
    let entry = cache.get(id).expect("valid handle refers to an entry");
    if entry.record.negative {
        return Ok(false);
    }
    let rrtype = match entry.record.kind {
        Kind::Ipv4 if entry.record.data.len() == 4 => 1,
        Kind::Ipv6 if entry.record.data.len() == 16 => 28,
        Kind::Ipv4 | Kind::Ipv6 => return Err(WireError::InvalidName),
        Kind::Generic(rrtype) => rrtype,
        Kind::Cname | Kind::NxDomain | Kind::ReverseIpv4 | Kind::ReverseIpv6 => return Ok(false),
    };
    let ttl = entry.reply_ttl(now, cache.policy());
    if let Some(offset) = owner_offset {
        writer.record_at(section, offset, rrtype, 1, ttl, &entry.record.data)?;
    } else {
        writer.record(
            section,
            &entry.record.name,
            rrtype,
            1,
            ttl,
            &entry.record.data,
        )?;
    }
    Ok(true)
}

/// Append one cached CNAME and return its target descriptor. A local target
/// owns its name after release; the caller must check current local membership
/// separately before emitting a terminal address or configured CNAME chain.
/// `owner_offset` has the same caller-owned contract as for positive records.
pub fn append_cname_record(
    writer: &mut PacketWriter,
    cache: &Cache,
    id: EntryId,
    section: Section,
    now: i64,
    owner_offset: Option<u16>,
) -> Result<Option<CnameTarget>, WireError> {
    if !cache.is_valid(id, now) {
        return Ok(None);
    }
    let entry = cache.get(id).expect("valid handle refers to an entry");
    if entry.record.kind != Kind::Cname || entry.record.negative {
        return Ok(None);
    }
    let end = super::wire::validate_name(&entry.record.data, 0, 0)?;
    if end != entry.record.data.len() {
        return Err(WireError::InvalidName);
    }
    let Some(target) = entry.cname_target() else {
        return Ok(None);
    };
    let ttl = entry.reply_ttl(now, cache.policy());
    if let Some(offset) = owner_offset {
        writer.record_at(section, offset, 5, 1, ttl, &entry.record.data)?;
    } else {
        writer.record(section, &entry.record.name, 5, 1, ttl, &entry.record.data)?;
    }
    Ok(Some(target))
}

/// Append the SOA authority retained with a cached negative entry.
///
/// `rfc1035.c::answer_request` emits this RR only for a negative record that
/// was created from an upstream SOA.  A no-SOA `--neg-ttl` fallback therefore
/// has no authority section.  The SOA's own remaining TTL is independent of
/// the negative cache expiry (which is `min(SOA TTL, SOA MINIMUM)`).
pub fn append_negative_authority(
    writer: &mut PacketWriter,
    cache: &mut Cache,
    id: EntryId,
    now: i64,
) -> Result<bool, WireError> {
    if !cache.is_valid(id, now) {
        return Ok(false);
    }
    let entry = cache.get(id).expect("valid handle refers to an entry");
    if !entry.record.negative {
        return Ok(false);
    }
    let Some(authority_name) = entry.negative_authority_name().cloned() else {
        return Ok(false);
    };
    // Generic lookup intentionally returns all F_RR types, as cache.c does;
    // filter the exact SOA RR before appending it.
    let soa_ids = cache.lookup(&authority_name, &[Kind::Generic(6)], now, false);
    for soa_id in soa_ids {
        if cache
            .get(soa_id)
            .is_some_and(|entry| entry.record.kind == Kind::Generic(6))
        {
            return append_positive_record(writer, cache, soa_id, Section::Authority, now, None);
        }
    }
    Ok(false)
}

#[cfg(test)]
#[path = "cache_reply_tests.rs"]
mod tests;
