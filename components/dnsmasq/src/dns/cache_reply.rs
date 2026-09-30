//! Write a selected positive forward-cache record into a caller-owned packet.
//!
//! References: `rfc1035.c::crec_ttl` (1654–1686), address record output
//! (2100–2170) and generic record output (2283–2347). This helper does not
//! decide whether a query can be answered from cache. The caller owns RRset
//! selection, CNAME traversal, negative answers/SOA, query flags, and EDNS.

use super::cache::{Cache, EntryId, Kind};
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
pub fn append_positive_record(
    writer: &mut PacketWriter,
    cache: &Cache,
    id: EntryId,
    section: Section,
    now: i64,
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
        Kind::Cname | Kind::NxDomain => return Ok(false),
    };
    writer.record(
        section,
        &entry.record.name,
        rrtype,
        1,
        entry.reply_ttl(now, cache.policy()),
        &entry.record.data,
    )?;
    Ok(true)
}

/// Append one cached CNAME and return its still-live target handle. The
/// caller follows that handle to emit the terminal CNAME/A/AAAA chain.
pub fn append_cname_record(
    writer: &mut PacketWriter,
    cache: &Cache,
    id: EntryId,
    section: Section,
    now: i64,
) -> Result<Option<EntryId>, WireError> {
    if !cache.is_valid(id, now) {
        return Ok(None);
    }
    let entry = cache.get(id).expect("valid handle refers to an entry");
    if entry.record.kind != Kind::Cname || entry.record.negative {
        return Ok(None);
    }
    let (_, end) = super::wire::decode_name(&entry.record.data, 0, 0)?;
    if end != entry.record.data.len() {
        return Err(WireError::InvalidName);
    }
    let Some(target) = entry.cname_target() else {
        return Ok(None);
    };
    writer.record(
        section,
        &entry.record.name,
        5,
        1,
        entry.reply_ttl(now, cache.policy()),
        &entry.record.data,
    )?;
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
    cache: &Cache,
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
    let Some(authority) = entry.negative_authority() else {
        return Ok(false);
    };
    let ttl = (i128::from(authority.expires) - i128::from(now)).clamp(0, u32::MAX as i128) as u32;
    let ttl = if cache.policy().max_reply_ttl == 0 {
        ttl
    } else {
        ttl.min(cache.policy().max_reply_ttl)
    };
    writer.record(
        Section::Authority,
        &authority.name,
        6,
        1,
        ttl,
        &authority.data,
    )?;
    Ok(true)
}

#[cfg(test)]
#[path = "cache_reply_tests.rs"]
mod tests;
