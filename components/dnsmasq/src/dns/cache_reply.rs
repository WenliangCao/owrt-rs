//! Wire synthesis for records selected from the forward cache.
//!
//! This is deliberately a small boundary between [`super::cache::Cache`] and
//! a daemon.  It does not parse upstream packets, manufacture SOA records, or
//! decide whether a response is cacheable.  A caller supplies the question
//! and response flags; this module only performs cache lookup, remaining-TTL
//! projection, and bounded RR writing.

use super::cache::{Cache, EntryId, Kind};
use super::wire::{Name, PacketWriter, Section, WireError};

/// Input needed to build one cache answer.
#[derive(Debug, Clone, Copy)]
pub struct CacheQuery<'a> {
    pub name: &'a Name,
    pub qtype: u16,
    pub qclass: u16,
    pub id: u16,
    pub base_flags: u16,
    pub now: i64,
    pub limit: usize,
    pub round_robin: bool,
}

/// Build an answer from records currently present in `cache`.
///
/// `base_flags` is the response flag template owned by the caller (for
/// example, RA/CD policy).  The QR bit is added here and the RCODE is set to
/// NXDOMAIN when a cached name-wide marker is selected.  `None` means no
/// cache entry matched this question, so the caller should forward it.
///
/// CNAME expansion is bounded to ten links, matching the cache's CNAME
/// extraction limit.  NODATA records and negative SOA metadata are not
/// synthesized here: a negative RR makes the query cacheable/answerable but
/// contributes no answer RR, while SOA authority construction remains a
/// caller responsibility.
pub fn answer_from_cache(
    cache: &mut Cache,
    query: CacheQuery<'_>,
) -> Result<Option<Vec<u8>>, WireError> {
    let CacheQuery {
        name,
        qtype,
        qclass,
        id,
        base_flags,
        now,
        limit,
        round_robin,
    } = query;
    if qclass != 1 {
        return Ok(None);
    }

    let mut ids = if qtype == 255 {
        cache.lookup(
            name,
            &[
                Kind::Ipv4,
                Kind::Ipv6,
                Kind::Cname,
                Kind::Generic(255),
                Kind::NxDomain,
            ],
            now,
            round_robin,
        )
    } else {
        cache.lookup_question(name, kind_for_type(qtype), now, round_robin)
    };

    // An A/AAAA/etc question still needs the alias RR before its terminal
    // target.  Keep exact lookup semantics in Cache::lookup and add CNAMEs at
    // this integration boundary where the question type is known.
    if qtype != 5 && qtype != 255 {
        for cname in cache.lookup(name, &[Kind::Cname], now, round_robin) {
            if !ids.contains(&cname) {
                ids.push(cname);
            }
        }
    }
    if ids.is_empty() {
        return Ok(None);
    }

    let nxdomain = ids.iter().any(|entry_id| {
        cache
            .get(*entry_id)
            .is_some_and(|entry| entry.record.kind == Kind::NxDomain)
    });
    let mut writer = PacketWriter::new(
        id,
        base_flags | 0x8000 | if nxdomain { 3 } else { 0 },
        limit,
    )?;
    writer.question(name, qtype, qclass)?;
    let policy = cache.policy();
    let mut emitted = false;
    let mut truncated = false;
    let mut visited = Vec::new();
    {
        let mut render = RenderState {
            cache,
            writer: &mut writer,
            qtype,
            now,
            policy,
            visited: &mut visited,
        };
        for entry_id in ids {
            if !nxdomain && render.cache.get(entry_id).is_some() {
                match append_entry(&mut render, entry_id, 0)? {
                    AppendOutcome::Added => emitted = true,
                    AppendOutcome::Noop => {}
                    AppendOutcome::Full { emitted: before } => {
                        emitted |= before;
                        truncated = true;
                        break;
                    }
                }
            }
        }
    }

    // A stale/missing target can leave only an NXDOMAIN marker or a negative
    // RR.  It is still an answerable cache result, but it has no answer RRs.
    if !emitted && !nxdomain && ids_have_negative(cache, &visited) {
        emitted = true;
    }
    if !emitted && !nxdomain && !truncated {
        return Ok(None);
    }
    Ok(Some(writer.finish()))
}

fn kind_for_type(qtype: u16) -> Kind {
    match qtype {
        1 => Kind::Ipv4,
        28 => Kind::Ipv6,
        5 => Kind::Cname,
        type_ => Kind::Generic(type_),
    }
}

fn type_for_kind(kind: Kind) -> Option<u16> {
    match kind {
        Kind::Ipv4 => Some(1),
        Kind::Ipv6 => Some(28),
        Kind::Cname => Some(5),
        Kind::Generic(type_) => Some(type_),
        Kind::NxDomain => None,
    }
}

struct RenderState<'a> {
    cache: &'a Cache,
    writer: &'a mut PacketWriter,
    qtype: u16,
    now: i64,
    policy: super::cache::Policy,
    visited: &'a mut Vec<EntryId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppendOutcome {
    Noop,
    Added,
    Full { emitted: bool },
}

fn append_entry(
    state: &mut RenderState<'_>,
    id: EntryId,
    depth: usize,
) -> Result<AppendOutcome, WireError> {
    if depth > 10 || state.visited.contains(&id) {
        return Ok(AppendOutcome::Noop);
    }
    let Some(entry) = state.cache.get(id) else {
        return Ok(AppendOutcome::Noop);
    };
    state.visited.push(id);
    if entry.record.negative {
        return Ok(AppendOutcome::Noop);
    }
    let Some(type_) = type_for_kind(entry.record.kind) else {
        return Ok(AppendOutcome::Noop);
    };
    let cname = type_ == 5;
    if cname {
        if let Err(error) = state.writer.record(
            Section::Answer,
            &entry.record.name,
            type_,
            1,
            entry.reply_ttl(state.now, state.policy),
            &entry.record.data,
        ) {
            return match error {
                WireError::Full => Ok(AppendOutcome::Full { emitted: false }),
                error => Err(error),
            };
        }
        let Some(target) = entry.cname_target() else {
            return Ok(AppendOutcome::Added);
        };
        if state.qtype == 5 {
            return Ok(AppendOutcome::Added);
        }
        return match append_entry(state, target, depth + 1)? {
            AppendOutcome::Full { .. } => Ok(AppendOutcome::Full { emitted: true }),
            AppendOutcome::Noop | AppendOutcome::Added => Ok(AppendOutcome::Added),
        };
    }
    if state.qtype != 255 && type_ != state.qtype {
        return Ok(AppendOutcome::Noop);
    }
    if let Err(error) = state.writer.record(
        Section::Answer,
        &entry.record.name,
        type_,
        1,
        entry.reply_ttl(state.now, state.policy),
        &entry.record.data,
    ) {
        return match error {
            WireError::Full => Ok(AppendOutcome::Full { emitted: false }),
            error => Err(error),
        };
    }
    Ok(AppendOutcome::Added)
}

// A negative NODATA record is selected by lookup_question but has no wire RR.
// Keep this check separate from CNAME traversal so the caller can distinguish
// a cache hit from a forward miss without exposing Cache's internal slots.
fn ids_have_negative(cache: &Cache, visited: &[EntryId]) -> bool {
    visited
        .iter()
        .any(|id| cache.get(*id).is_some_and(|entry| entry.record.negative))
}

#[cfg(test)]
#[path = "cache_reply_tests.rs"]
mod tests;
