//! Bounded DNS wire primitives, traced to patched dnsmasq 2.93.
//!
//! See docs/dnsmasq/DNS_SOURCE_MAP.md. Skipping a name deliberately differs
//! from decoding one: dnsmasq accepts obsolete bitstring labels while skipping,
//! and does not follow compression pointers until a name is actually needed.

use std::ops::Range;

pub const HEADER_LEN: usize = 12;
pub const MAX_NAME_LEN: usize = 255;
pub const TYPE_OPT: u16 = 41;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    LabelType,
    NameTooLong,
    PointerLoop,
    InvalidName,
    RecordTooLong,
    Full,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WireError {}

fn end(packet: &[u8], start: usize, length: usize) -> Result<usize, WireError> {
    let end = start.checked_add(length).ok_or(WireError::Truncated)?;
    if end > packet.len() {
        return Err(WireError::Truncated);
    }
    Ok(end)
}

fn u16_at(packet: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([packet[at], packet[at + 1]])
}

fn u32_at(packet: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(packet[at..at + 4].try_into().unwrap())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authorities: u16,
    pub additionals: u16,
}

impl Header {
    pub fn parse(packet: &[u8]) -> Result<Self, WireError> {
        end(packet, 0, HEADER_LEN)?;
        Ok(Self {
            id: u16_at(packet, 0),
            flags: u16_at(packet, 2),
            questions: u16_at(packet, 4),
            answers: u16_at(packet, 6),
            authorities: u16_at(packet, 8),
            additionals: u16_at(packet, 10),
        })
    }

    pub fn write(self, packet: &mut [u8]) -> Result<(), WireError> {
        end(packet, 0, HEADER_LEN)?;
        for (chunk, value) in packet[..HEADER_LEN].as_chunks_mut::<2>().0.iter_mut().zip([
            self.id,
            self.flags,
            self.questions,
            self.answers,
            self.authorities,
            self.additionals,
        ]) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        Ok(())
    }

    pub fn opcode(self) -> u8 {
        ((self.flags >> 11) & 15) as u8
    }

    pub fn rcode(self) -> u8 {
        (self.flags & 15) as u8
    }
}

/// An uncompressed wire name including its root terminator.
/// Binary labels are preserved; this is intentionally not a UTF-8 string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name(Vec<u8>);

impl Name {
    pub(super) fn into_wire_buffer(self) -> Vec<u8> { self.0 }

    pub fn root() -> Self {
        Self(vec![0])
    }

    /// Parse a plain dotted name. Escape syntax belongs to the config parser.
    pub fn from_ascii(name: &str) -> Result<Self, WireError> {
        if !name.is_ascii() {
            return Err(WireError::InvalidName);
        }
        Self::from_dotted_bytes(name.as_bytes())
    }

    /// A plain dotted byte name, e.g. a hostname restored from a lease file.
    /// Labels need not be UTF-8. Escape syntax is not interpreted here.
    pub fn from_dotted_bytes(name: &[u8]) -> Result<Self, WireError> {
        let name = name.strip_suffix(b".").unwrap_or(name);
        if name.is_empty() {
            return Ok(Self::root());
        }
        let mut wire = Vec::with_capacity(name.len() + 2);
        for label in name.split(|c| *c == b'.') {
            if label.is_empty() || label.len() > 63 {
                return Err(WireError::InvalidName);
            }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label);
        }
        wire.push(0);
        if wire.len() > MAX_NAME_LEN {
            return Err(WireError::NameTooLong);
        }
        Ok(Self(wire))
    }

    pub fn as_wire(&self) -> &[u8] {
        &self.0
    }

    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }

    pub fn canonical_wire(&self) -> Vec<u8> {
        // Length bytes are at most 63 and cannot be ASCII uppercase.
        self.0.to_ascii_lowercase()
    }

    /// Length of the escaped byte string without constructing a temporary.
    pub(super) fn dnsmasq_bytes_len(&self) -> usize {
        let mut result = self.0.len().saturating_sub(2);
        let mut pos = 0;
        while self.0[pos] != 0 {
            let length = self.0[pos] as usize;
            result += self.0[pos + 1..pos + 1 + length]
                .iter()
                .filter(|&&byte| matches!(byte, 0 | 1 | b'.'))
                .count();
            pos += length + 1;
        }
        result
    }

    /// Narrow plain-question constructor: no pointers or trailing bytes.
    /// Validate first, then copy once into the existing bounded name scratch.
    pub(super) fn from_uncompressed_reusing(wire: &[u8], scratch: &mut Vec<u8>) -> Option<Self> {
        validate_uncompressed_name(wire).ok()?;
        scratch.clear();
        scratch.extend_from_slice(wire);
        Some(Self(std::mem::take(scratch)))
    }

    /// dnsmasq's internal escaped byte string, without its C NUL terminator.
    pub fn dnsmasq_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.0.len().saturating_sub(2));
        let mut pos = 0;
        while self.0[pos] != 0 {
            let length = self.0[pos] as usize;
            if pos != 0 {
                result.push(b'.');
            }
            for &byte in &self.0[pos + 1..pos + 1 + length] {
                if matches!(byte, 0 | 1 | b'.') {
                    result.extend_from_slice(&[1, byte + 1]);
                } else {
                    result.push(byte);
                }
            }
            pos += length + 1;
        }
        result
    }
}

/// Follow compression pointers, preserving the cursor after the first pointer.
/// `extra` bytes must remain after that cursor, not after the pointed-to name.
pub fn decode_name(packet: &[u8], start: usize, extra: usize) -> Result<(Name, usize), WireError> {
    let mut wire = Vec::with_capacity(32);
    let next = walk_name(
        packet,
        start,
        extra,
        |label| wire.extend_from_slice(label),
        |_, _| {},
    )?;
    Ok((Name(wire), next))
}

/// Report pointers whose encoding could be affected by ASCII case changes.
pub(super) fn decode_name_with_aliasing(
    packet: &[u8],
    start: usize,
    extra: usize,
) -> Result<(Name, usize, bool), WireError> {
    let mut wire = Vec::with_capacity(32);
    let mut backward = false;
    let mut case_sensitive_offset = false;
    let next = walk_name(
        packet,
        start,
        extra,
        |label| wire.extend_from_slice(label),
        |at, target| {
            backward |= target < at + 1;
            case_sensitive_offset |= packet[at].is_ascii_alphabetic();
        },
    )?;
    Ok((Name(wire), next, backward && case_sensitive_offset))
}

/// Reuse a normal UDP owner's name allocation. On failure the caller keeps
/// the partial scratch; only a successful walk creates a valid owned Name.
pub(super) fn decode_name_reusing(
    packet: &[u8], start: usize, extra: usize, scratch: &mut Vec<u8>,
) -> Result<(Name, usize), WireError> {
    scratch.clear();
    if scratch.capacity() < 32 {
        scratch.reserve(32);
    }
    let next = walk_name(
        packet,
        start,
        extra,
        |label| scratch.extend_from_slice(label),
        |_, _| {},
    )?;
    Ok((Name(std::mem::take(scratch)), next))
}

/// Check the same expanded name and cursor as `decode_name` without keeping
/// its labels. Unlike `skip_name`, this follows pointers and rejects unsupported
/// label types. Writers use it when only the validity of an existing owner is
/// needed; no temporary name allocation or label copy is required.
pub(super) fn validate_name(packet: &[u8], start: usize, extra: usize) -> Result<usize, WireError> {
    walk_name(packet, start, extra, |_| {}, |_, _| {})
}

/// Validate a name and report whether case changes could affect pointer bytes.
pub(super) fn validate_name_may_alias(packet: &[u8], start: usize) -> Result<bool, WireError> {
    let mut backward = false;
    let mut case_sensitive_offset = false;
    walk_name(
        packet,
        start,
        0,
        |_| {},
        |at, target| {
            backward |= target < at + 1;
            case_sensitive_offset |= packet[at].is_ascii_alphabetic();
        },
    )?;
    Ok(backward && case_sensitive_offset)
}

/// Check a self-contained owner before copying it into a different packet.
/// Compression offsets belong to their original packet and cannot be copied.
fn validate_uncompressed_name(wire: &[u8]) -> Result<(), WireError> {
    if wire.len() > MAX_NAME_LEN {
        return Err(WireError::NameTooLong);
    }
    let mut pos = 0;
    loop {
        match *wire.get(pos).ok_or(WireError::Truncated)? {
            0 if pos + 1 == wire.len() => return Ok(()),
            0 => return Err(WireError::InvalidName),
            length @ 1..=63 => pos += 1 + usize::from(length),
            _ => return Err(WireError::LabelType),
        }
    }
}

fn walk_name(
    packet: &[u8],
    start: usize,
    extra: usize,
    mut label: impl FnMut(&[u8]),
    mut pointer: impl FnMut(usize, usize),
) -> Result<usize, WireError> {
    let mut pos = start;
    let mut resume = None;
    let mut hops = 0;
    let mut expanded = 0;
    loop {
        end(packet, pos, 1)?;
        let length = packet[pos];
        pos += 1;
        match length {
            0 => {
                let next = resume.unwrap_or(pos);
                end(packet, next, extra)?;
                label(&[0]);
                return Ok(next);
            }
            1..=63 => {
                let label_end = end(packet, pos, length as usize)?;
                expanded += length as usize + 1;
                if expanded >= MAX_NAME_LEN {
                    return Err(WireError::NameTooLong);
                }
                label(&packet[pos - 1..label_end]);
                pos = label_end;
            }
            192..=255 => {
                end(packet, pos, 1)?;
                let target = (((length & 63) as usize) << 8) | packet[pos] as usize;
                resume.get_or_insert(pos + 1);
                pointer(pos, target);
                hops += 1;
                if hops > 255 {
                    return Err(WireError::PointerLoop);
                }
                pos = target;
            }
            _ => return Err(WireError::LabelType),
        }
    }
}

/// Locate the end of the encoded name without dereferencing pointers.
pub fn skip_name(packet: &[u8], mut pos: usize, extra: usize) -> Result<usize, WireError> {
    loop {
        end(packet, pos, 1)?;
        let length = packet[pos];
        pos += 1;
        match length {
            0 => break,
            1..=63 => pos = end(packet, pos, length as usize)?,
            65 => {
                end(packet, pos, 1)?;
                let bits = packet[pos] as usize;
                pos = end(
                    packet,
                    pos + 1,
                    if bits == 0 { 32 } else { bits.div_ceil(8) },
                )?;
            }
            192..=255 => {
                pos = end(packet, pos, 1)?;
                break;
            }
            _ => return Err(WireError::LabelType),
        }
    }
    end(packet, pos, extra)?;
    Ok(pos)
}

pub fn skip_questions(packet: &[u8]) -> Result<usize, WireError> {
    let header = Header::parse(packet)?;
    let mut pos = HEADER_LEN;
    for _ in 0..header.questions {
        pos = skip_name(packet, pos, 4)? + 4;
    }
    Ok(pos)
}

pub fn skip_records(packet: &[u8], mut pos: usize, count: u32) -> Result<usize, WireError> {
    for _ in 0..count {
        let fixed = skip_name(packet, pos, 10)?;
        pos = end(packet, fixed + 10, u16_at(packet, fixed + 8) as usize)?;
    }
    Ok(pos)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub class: u16,
    pub start: usize,
    pub end: usize,
}

impl Question {
    pub fn parse(packet: &[u8], start: usize) -> Result<Self, WireError> {
        let (name, fixed) = decode_name(packet, start, 4)?;
        Ok(Self {
            name,
            qtype: u16_at(packet, fixed),
            class: u16_at(packet, fixed + 2),
            start,
            end: fixed + 4,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RecordRef<'a> {
    packet: &'a [u8],
    pub start: usize,
    pub fixed: usize,
    pub end: usize,
    pub rrtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

impl<'a> RecordRef<'a> {
    pub fn parse(packet: &'a [u8], start: usize) -> Result<Self, WireError> {
        let fixed = skip_name(packet, start, 10)?;
        let finish = end(packet, fixed + 10, u16_at(packet, fixed + 8) as usize)?;
        Ok(Self {
            packet,
            start,
            fixed,
            end: finish,
            rrtype: u16_at(packet, fixed),
            class: u16_at(packet, fixed + 2),
            ttl: u32_at(packet, fixed + 4),
            rdata: &packet[fixed + 10..finish],
        })
    }

    pub fn name(&self) -> Result<Name, WireError> {
        decode_name(self.packet, self.start, 10).map(|(name, _)| name)
    }

    /// Decode a name embedded in RDATA, checking its encoded bytes fit RDLEN.
    /// A compression target may lie outside RDATA, as required by DNS.
    pub fn rdata_name(&self, offset: usize) -> Result<(Name, usize), WireError> {
        if offset >= self.rdata.len() {
            return Err(WireError::Truncated);
        }
        let (name, next) = decode_name(self.packet, self.fixed + 10 + offset, 0)?;
        if next > self.end {
            return Err(WireError::Truncated);
        }
        Ok((name, next - self.fixed - 10))
    }

    /// Remove compression from the RR types described by dnsmasq's rrfilter_desc.
    /// This is the cache-copy representation, not a validator for every RR type.
    /// Unknown types (including SVCB/HTTPS) retain opaque RDATA bytes.
    pub fn canonical_rdata(&self) -> Result<Vec<u8>, WireError> {
        // 0 denotes a name; other values denote fixed bytes before the next name.
        let descriptor = name_descriptor(self.rrtype);
        let mut result = Vec::with_capacity(self.rdata.len());
        let mut offset = 0;
        for &part in descriptor {
            if part == 0 {
                let (name, next) = self.rdata_name(offset)?;
                result.extend_from_slice(&name.canonical_wire());
                offset = next;
            } else {
                let next = (offset + part).min(self.rdata.len());
                result.extend_from_slice(&self.rdata[offset..next]);
                offset = next;
            }
        }
        let remainder = &self.rdata[offset..];
        if result
            .len()
            .checked_add(remainder.len())
            .is_none_or(|len| len > u16::MAX as usize)
        {
            // The C cache stores this size in u16 and silently wraps. Such a
            // record cannot be encoded as DNS RDATA; never cache a prefix of it.
            return Err(WireError::RecordTooLong);
        }
        result.extend_from_slice(remainder);
        Ok(result)
    }
}

/// `rrfilter.c::rrfilter_desc`: zero denotes a domain; nonzero entries skip
/// fixed bytes. Unknown RDATA stays opaque, including newer uncompressed types.
pub(crate) fn name_descriptor(rrtype: u16) -> &'static [usize] {
    match rrtype {
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 30 | 39 => &[0],
        6 | 14 | 17 => &[0, 0],
        15 | 18 | 21 | 36 => &[2, 0],
        24 => &[18, 0],
        26 => &[2, 0, 0],
        33 => &[6, 0],
        _ => &[],
    }
}

/// Structural section ranges; unknown RDATA is left opaque and borrowed.
/// No allocation is based on the packet's untrusted count fields.
#[derive(Debug)]
pub struct Message<'a> {
    pub packet: &'a [u8],
    pub header: Header,
    pub questions: Range<usize>,
    pub answers: Range<usize>,
    pub authorities: Range<usize>,
    pub additionals: Range<usize>,
    pub end: usize,
}

impl<'a> Message<'a> {
    pub fn parse(packet: &'a [u8]) -> Result<Self, WireError> {
        let header = Header::parse(packet)?;
        let qend = skip_questions(packet)?;
        let aend = skip_records(packet, qend, header.answers.into())?;
        let nend = skip_records(packet, aend, header.authorities.into())?;
        let finish = skip_records(packet, nend, header.additionals.into())?;
        Ok(Self {
            packet,
            header,
            questions: HEADER_LEN..qend,
            answers: qend..aend,
            authorities: aend..nend,
            additionals: nend..finish,
            end: finish,
        })
    }

    pub fn records(&self, section: Section) -> Records<'a> {
        let (start, remaining) = match section {
            Section::Answer => (self.answers.start, self.header.answers),
            Section::Authority => (self.authorities.start, self.header.authorities),
            Section::Additional => (self.additionals.start, self.header.additionals),
        };
        Records {
            packet: self.packet,
            pos: start,
            remaining,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

#[derive(Clone, Debug)]
pub struct Records<'a> {
    packet: &'a [u8],
    pos: usize,
    remaining: u16,
}

impl<'a> Records<'a> {
    /// Validate one complete section independently of later sections. Return
    /// its borrowed iterator and the first byte following it. A cloned
    /// iterator can replay this validated immutable section without copying
    /// records or requiring an unrelated Additional section to be complete.
    pub fn parse_section(
        packet: &'a [u8],
        start: usize,
        count: u16,
    ) -> Result<(Self, usize), WireError> {
        end(packet, start, 0)?;
        let end = skip_records(packet, start, u32::from(count))?;
        Ok((
            Self {
                packet,
                pos: start,
                remaining: count,
            },
            end,
        ))
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = RecordRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        // Message::parse already checked each record and the backing slice is immutable.
        let record = RecordRef::parse(self.packet, self.pos).ok()?;
        self.pos = record.end;
        self.remaining -= 1;
        Some(record)
    }
}

#[derive(Debug, Clone)]
pub struct EdnsRef<'a> {
    pub record: RecordRef<'a>,
    pub is_last: bool,
}

impl<'a> EdnsRef<'a> {
    pub fn udp_size(&self, configured: u16) -> u16 {
        // Preserve the order of dnsmasq receive_query's two conditions.
        if self.record.class > configured {
            configured
        } else {
            self.record.class.max(512)
        }
    }

    pub fn version(&self) -> u8 {
        (self.record.ttl >> 16) as u8
    }
    pub fn extended_rcode(&self) -> u8 {
        (self.record.ttl >> 24) as u8
    }
    pub fn dnssec_ok(&self) -> bool {
        self.record.ttl & 0x8000 != 0
    }

    pub fn options(&self) -> EdnsOptions<'a> {
        EdnsOptions {
            remaining: self.record.rdata,
            failed: false,
        }
    }
}

#[derive(Debug)]
pub struct EdnsOptions<'a> {
    remaining: &'a [u8],
    failed: bool,
}

impl<'a> Iterator for EdnsOptions<'a> {
    type Item = Result<(u16, &'a [u8]), WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }
        if self.remaining.len() < 4 {
            self.failed = true;
            return Some(Err(WireError::Truncated));
        }
        let code = u16_at(self.remaining, 0);
        let length = u16_at(self.remaining, 2) as usize;
        if length > self.remaining.len() - 4 {
            self.failed = true;
            return Some(Err(WireError::Truncated));
        }
        let data = &self.remaining[4..4 + length];
        self.remaining = &self.remaining[4 + length..];
        Some(Ok((code, data)))
    }
}

/// Result retains signed-query information even when there is no OPT record.
#[derive(Debug)]
pub struct EdnsScan<'a> {
    pub opt: Option<EdnsRef<'a>>,
    pub signed: bool,
}

/// Mirrors find_pseudoheader including last-OPT selection and TSIG placement.
/// `detect_signed=false` follows its normal question-skipping path.
pub fn find_pseudoheader(packet: &[u8], detect_signed: bool) -> Result<EdnsScan<'_>, WireError> {
    let header = Header::parse(packet)?;
    let mut scan = EdnsScan {
        opt: None,
        signed: false,
    };
    let mut pos = HEADER_LEN;
    if detect_signed {
        if header.opcode() == 0 {
            for _ in 0..header.questions {
                let fixed = skip_name(packet, pos, 4)?;
                if u16_at(packet, fixed) == 249 && u16_at(packet, fixed + 2) == 1 {
                    scan.signed = true;
                }
                pos = fixed + 4;
            }
            // The TKEY scan has already advanced to the section cursor.
        }
    } else {
        pos = skip_questions(packet)?;
    }
    if header.additionals == 0 {
        return Ok(scan);
    }
    pos = match skip_records(
        packet,
        pos,
        u32::from(header.answers) + u32::from(header.authorities),
    ) {
        Ok(pos) => pos,
        Err(_) => return Ok(scan),
    };
    for index in 0..header.additionals {
        let record = match RecordRef::parse(packet, pos) {
            Ok(record) => record,
            Err(_) => {
                // C returns NULL if any later additional RR is truncated,
                // even when an earlier OPT was complete. Signed-query state
                // already discovered in the questions remains observable.
                scan.opt = None;
                return Ok(scan);
            }
        };
        pos = record.end;
        let is_last = index == header.additionals - 1;
        if record.rrtype == TYPE_OPT {
            scan.opt = Some(EdnsRef { record, is_last });
        } else if detect_signed && is_last && record.rrtype == 250 && record.class == 255 {
            scan.signed = true;
        }
    }
    Ok(scan)
}

/// A response builder with atomic record append. Caller chooses section order.
/// RDATA must be self-contained or use offsets into this very packet.
#[derive(Debug)]
pub struct PacketWriter {
    packet: Vec<u8>,
    limit: usize,
    header: Header,
    truncated: bool,
}

impl PacketWriter {
    pub fn new(id: u16, flags: u16, limit: usize) -> Result<Self, WireError> {
        Self::with_buffer(id, flags, limit, Vec::new())
    }

    pub(crate) fn with_buffer(
        id: u16, flags: u16, limit: usize, mut packet: Vec<u8>,
    ) -> Result<Self, WireError> {
        if limit < HEADER_LEN {
            return Err(WireError::Full);
        }
        let header = Header {
            id,
            flags,
            ..Header::default()
        };
        packet.clear();
        packet.reserve_exact(limit.min(128));
        packet.resize(HEADER_LEN, 0);
        header.write(&mut packet)?;
        Ok(Self {
            packet,
            limit: limit.min(u16::MAX as usize),
            header,
            truncated: false,
        })
    }

    pub fn question(&mut self, name: &Name, qtype: u16, class: u16) -> Result<usize, WireError> {
        if self.header.answers != 0 || self.header.authorities != 0 || self.header.additionals != 0
        {
            return Err(WireError::InvalidName);
        }
        self.ensure(name.0.len() + 4)?;
        let count = self
            .header
            .questions
            .checked_add(1)
            .ok_or(WireError::Full)?;
        let offset = self.packet.len();
        self.packet.extend_from_slice(name.as_wire());
        self.packet.extend_from_slice(&qtype.to_be_bytes());
        self.packet.extend_from_slice(&class.to_be_bytes());
        self.header.questions = count;
        Ok(offset)
    }

    pub fn record(
        &mut self,
        section: Section,
        name: &Name,
        rrtype: u16,
        class: u16,
        ttl: u32,
        data: &[u8],
    ) -> Result<(), WireError> {
        self.append_record(section, name.as_wire(), rrtype, class, ttl, data)
    }

    /// Append a validated, uncompressed owner name supplied by a caller that
    /// needs an owner different from the question (for example a CNAME target
    /// address).  Keeping validation here preserves the same atomic append
    /// boundary as `record` without exposing `Name`'s internal representation.
    ///
    /// # Errors
    /// Rejects malformed, compressed, overlong or trailing owner bytes. Record
    /// size, section ordering and packet limits follow [`Self::record`].
    pub fn record_wire(
        &mut self,
        section: Section,
        owner: &[u8],
        rrtype: u16,
        class: u16,
        ttl: u32,
        data: &[u8],
    ) -> Result<(), WireError> {
        validate_uncompressed_name(owner)?;
        self.append_record(section, owner, rrtype, class, ttl, data)
    }

    pub fn record_at(
        &mut self,
        section: Section,
        name_offset: u16,
        rrtype: u16,
        class: u16,
        ttl: u32,
        data: &[u8],
    ) -> Result<(), WireError> {
        if name_offset >= 0x4000 || usize::from(name_offset) >= self.packet.len() {
            return Err(WireError::InvalidName);
        }
        validate_name(&self.packet, name_offset.into(), 0)?;
        self.append_record(
            section,
            &(0xc000 | name_offset).to_be_bytes(),
            rrtype,
            class,
            ttl,
            data,
        )
    }

    /// Offset at which the next successfully appended question or RR starts.
    /// Callers can retain known name locations without rescanning the packet.
    pub fn position(&self) -> usize {
        self.packet.len()
    }

    fn ensure(&self, added: usize) -> Result<(), WireError> {
        if added > self.limit - self.packet.len() {
            Err(WireError::Full)
        } else {
            Ok(())
        }
    }

    fn append_record(
        &mut self,
        section: Section,
        name: &[u8],
        rrtype: u16,
        class: u16,
        ttl: u32,
        data: &[u8],
    ) -> Result<(), WireError> {
        if data.len() > u16::MAX as usize {
            return Err(WireError::RecordTooLong);
        }
        if self.truncated || self.ensure(name.len() + 10 + data.len()).is_err() {
            self.truncated = true;
            self.header.flags |= 0x0200;
            return Err(WireError::Full);
        }
        let count = match section {
            Section::Answer => {
                if self.header.authorities != 0 || self.header.additionals != 0 {
                    return Err(WireError::InvalidName);
                }
                &mut self.header.answers
            }
            Section::Authority => {
                if self.header.additionals != 0 {
                    return Err(WireError::InvalidName);
                }
                &mut self.header.authorities
            }
            Section::Additional => &mut self.header.additionals,
        };
        let next_count = count.checked_add(1).ok_or(WireError::Full)?;
        self.packet.extend_from_slice(name);
        self.packet.extend_from_slice(&rrtype.to_be_bytes());
        self.packet.extend_from_slice(&class.to_be_bytes());
        self.packet.extend_from_slice(&ttl.to_be_bytes());
        self.packet
            .extend_from_slice(&(data.len() as u16).to_be_bytes());
        self.packet.extend_from_slice(data);
        *count = next_count;
        Ok(())
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.header
            .write(&mut self.packet)
            .expect("writer retains DNS header");
        self.packet
    }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
