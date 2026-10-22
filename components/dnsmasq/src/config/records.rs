//! Local record configuration from option.c:2335-2373,4971-5251.
use super::{Directive, EncodedArg, Error, META};
use std::cell::RefCell;
use std::collections::HashMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cname {
    pub alias: Vec<u8>,
    pub target: Vec<u8>,
    pub ttl: Option<u32>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawRecord {
    pub name: Vec<u8>,
    pub rr_type: u16,
    pub data: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtrRecord {
    pub name: Vec<u8>,
    /// None encodes the DNS root target (rfc1035.c:1931,1600), not NODATA.
    pub target: Option<Vec<u8>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MxRecord {
    pub name: Vec<u8>,
    pub target: Option<Vec<u8>>,
    pub preference: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SrvRecord {
    pub name: Vec<u8>,
    pub target: Option<Vec<u8>>,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NaptrRecord {
    pub name: Vec<u8>,
    pub order: u16,
    pub preference: u16,
    pub flags: Option<Vec<u8>>,
    pub services: Option<Vec<u8>>,
    pub regexp: Option<Vec<u8>>,
    pub replacement: Option<Vec<u8>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MailRecord {
    Mx(usize),
    Srv(usize),
}

#[derive(Clone, Debug, Default)]
pub struct RecordConfig {
    /// Declaration order; all public name fields retain their original case.
    pub cnames: Vec<Cname>,
    pub txt: Vec<RawRecord>,
    pub ptr: Vec<PtrRecord>,
    pub mx: Vec<MxRecord>,
    pub srv: Vec<SrvRecord>,
    pub naptr: Vec<NaptrRecord>,
    raw: Vec<RawRecord>,
    // Sorted distinct types, not a second record collection. Keep writes
    // together so a query can skip unrelated raw records without scanning.
    raw_types: Vec<u16>,
    pub mx_target: Option<Vec<u8>>,
    pub local_mx: bool,
    pub self_mx: bool,
    hostname_finalized: bool,
    // C keeps MX and SRV in one newest-first list. Answering SRV moves its
    // first matching entry to the global tail; TCP clones inherit this order.
    mail_order: RefCell<Vec<MailRecord>>,
}

fn canon(arg: &EncodedArg) -> Result<Vec<u8>, Error> {
    let bytes = arg.decoded();
    if bytes.is_empty() {
        return Ok(bytes);
    }
    crate::hosts::canonicalise(&bytes).ok_or(Error("bad record name"))
}
fn integer(arg: &EncodedArg) -> Result<u32, Error> {
    arg.decoded().iter().try_fold(0u32, |value, &c| {
        if !c.is_ascii_digit() {
            return Err(Error("bad integer"));
        }
        // The image's musl atoi keeps the low 32 bits. Reproduce those
        // observed values without signed-overflow undefined behavior.
        Ok(value.wrapping_mul(10).wrapping_add(u32::from(c - b'0')))
    })
}
fn uint16(arg: &EncodedArg) -> Result<u16, Error> {
    integer(arg)?
        .try_into()
        .map_err(|_| Error("integer exceeds 65535"))
}
fn optional(arg: &EncodedArg) -> Option<Vec<u8>> {
    let bytes = arg.decoded();
    (!bytes.is_empty()).then_some(bytes)
}
fn sized(data: Vec<u8>) -> Result<Vec<u8>, Error> {
    if data.len() > usize::from(u16::MAX) {
        return Err(Error("record data exceeds DNS wire length"));
    }
    Ok(data)
}
// C allocates the complete RR/TXT backing bytes, then stores their length in
// txt_record.len (u16). CAA is different: its allocation uses that narrowed
// length before memcpy, so retain sized()'s safe rejection for that path.
fn narrowed(mut data: Vec<u8>) -> Vec<u8> {
    data.truncate(usize::from(data.len() as u16));
    data
}
fn ascii_key(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(u8::to_ascii_lowercase).collect()
}

/// parse_hex(..., maxlen=-1, wildcard_mask=NULL, mac_type=NULL) from util.c:612.
/// Keep the in-place wildcard quirk: '*' advances output without writing it,
/// so that byte retains initialized input data. No uninitialized memory used.
fn hex_data(argument: &EncodedArg) -> Result<Vec<u8>, Error> {
    let mut bytes = argument.encoded().to_vec();
    let mut input = 0;
    let mut output = 0;
    loop {
        let end = bytes[input..]
            .iter()
            .position(|&c| matches!(c, b':' | b'-' | b' '))
            .map(|n| input + n)
            .unwrap_or(bytes.len());
        if bytes[input..end]
            .iter()
            .any(|c| !c.is_ascii_hexdigit() && *c != b'*')
        {
            return Err(Error("bad RR hex data"));
        }
        let token = bytes[input..end].to_vec();
        if end < bytes.len() {
            bytes[end] = 0;
        }
        if token == b"*" {
            output += 1;
        } else {
            for pair in token.chunks(2) {
                if pair.contains(&b'*') {
                    return Err(Error("bad RR hex data"));
                }
                let mut value = 0u8;
                for &c in pair {
                    value = value * 16
                        + (c as char).to_digit(16).ok_or(Error("bad RR hex data"))? as u8;
                }
                bytes[output] = value;
                output += 1;
            }
        }
        if end == bytes.len() {
            break;
        }
        input = end + 1;
    }
    bytes.truncate(output);
    Ok(narrowed(bytes))
}

impl RecordConfig {
    pub fn raw_records(&self) -> &[RawRecord] {
        &self.raw
    }

    pub(crate) fn has_raw_type(&self, rr_type: u16) -> bool {
        self.raw_types.binary_search(&rr_type).is_ok()
    }

    fn push_raw(&mut self, record: RawRecord) {
        if let Err(index) = self.raw_types.binary_search(&record.rr_type) {
            self.raw_types.insert(index, record.rr_type);
        }
        // Preserve declaration order, including across different types: ANY
        // answers emit this list in reverse, just like C's prepended list.
        self.raw.push(record);
    }

    /// Called after the shared arity/repetition validation.
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"cname" => {
                let fields = argument.ok_or(Error("missing parameter"))?.split(b',');
                if fields.len() < 2 {
                    return Err(Error("bad CNAME"));
                }
                let last = fields.len() - 1;
                let ttl =
                    if fields.len() > 2 && fields[last].decoded().iter().all(u8::is_ascii_digit) {
                        Some(integer(&fields[last])?)
                    } else {
                        None
                    };
                let target_index = if ttl.is_some() { last - 1 } else { last };
                let target = canon(&fields[target_index])?;
                for field in &fields[..target_index] {
                    let alias = canon(field)?;
                    if self
                        .cnames
                        .iter()
                        .any(|entry| entry.alias.eq_ignore_ascii_case(&alias))
                    {
                        return Err(Error("duplicate CNAME"));
                    }
                    self.cnames.push(Cname {
                        alias,
                        target: target.clone(),
                        ttl,
                    });
                }
            }
            b"ptr-record" => {
                let (name, target) = argument.ok_or(Error("missing parameter"))?.split_once(b',');
                self.ptr.push(PtrRecord {
                    name: canon(&name)?,
                    target: target.as_ref().map(canon).transpose()?,
                });
            }
            b"txt-record" => {
                let (name, text) = argument.ok_or(Error("missing parameter"))?.split_once(b',');
                let mut data = vec![0u8];
                let mut count = 0;
                if let Some(text) = text {
                    for &byte in text.encoded() {
                        if byte == b',' || data[count] == 255 {
                            count = data.len();
                            data.push(0);
                            if byte == b',' {
                                continue;
                            }
                        }
                        data.push(META.get(usize::from(byte)).copied().unwrap_or(byte));
                        data[count] += 1;
                    }
                }
                self.txt.push(RawRecord {
                    name: canon(&name)?,
                    rr_type: 16,
                    data: narrowed(data),
                });
            }
            b"dns-rr" => {
                let (name, rest) = argument.ok_or(Error("missing parameter"))?.split_once(b',');
                let (rr_type, data) = rest.ok_or(Error("bad RR record"))?.split_once(b',');
                self.push_raw(RawRecord {
                    name: canon(&name)?,
                    rr_type: integer(&rr_type)? as u16,
                    data: data.as_ref().map(hex_data).transpose()?.unwrap_or_default(),
                });
            }
            b"caa-record" => {
                let mut rest = argument.ok_or(Error("missing parameter"))?.clone();
                let mut fields = Vec::new();
                for _ in 0..3 {
                    let (field, tail) = rest.split_once(b',');
                    fields.push(field);
                    rest = tail.ok_or(Error("bad CAA record"))?;
                }
                let flags = integer(&fields[1])? as u8;
                let tag = fields[2].decoded();
                let mut data = vec![flags, tag.len() as u8];
                data.extend(tag);
                data.extend(rest.decoded());
                self.push_raw(RawRecord {
                    name: canon(&fields[0])?,
                    rr_type: 257,
                    data: sized(data)?,
                });
            }
            b"mx-host" => {
                let (name, rest) = argument.ok_or(Error("missing parameter"))?.split_once(b',');
                let (target, preference) = match rest {
                    Some(rest) => {
                        let (target, preference) = rest.split_once(b',');
                        (
                            Some(canon(&target)?),
                            preference.as_ref().map(uint16).transpose()?.unwrap_or(1),
                        )
                    }
                    None => (None, 1),
                };
                let record = MxRecord {
                    name: canon(&name)?,
                    target,
                    preference,
                };
                self.mail_order
                    .get_mut()
                    .insert(0, MailRecord::Mx(self.mx.len()));
                self.mx.push(record);
            }
            b"mx-target" => {
                self.mx_target = Some(canon(argument.ok_or(Error("missing parameter"))?)?)
            }
            b"localmx" => self.local_mx = true,
            b"selfmx" => self.self_mx = true,
            b"srv-host" => {
                let (name, target) = argument.ok_or(Error("missing parameter"))?.split_once(b',');
                let mut record = SrvRecord {
                    name: canon(&name)?,
                    target: None,
                    port: 1,
                    priority: 0,
                    weight: 0,
                };
                if let Some(target) = target {
                    let (target, port) = target.split_once(b',');
                    record.target = Some(canon(&target)?);
                    if let Some(port) = port {
                        let (port, priority) = port.split_once(b',');
                        record.port = uint16(&port)?;
                        if let Some(priority) = priority {
                            let (priority, weight) = priority.split_once(b',');
                            record.priority = uint16(&priority)?;
                            if let Some(weight) = weight {
                                record.weight = uint16(&weight)?;
                            }
                        }
                    }
                }
                self.mail_order
                    .get_mut()
                    .insert(0, MailRecord::Srv(self.srv.len()));
                self.srv.push(record);
            }
            b"naptr-record" => {
                let mut rest = argument.ok_or(Error("missing parameter"))?.clone();
                let mut fields = Vec::new();
                for _ in 0..5 {
                    let (field, tail) = rest.split_once(b',');
                    fields.push(field);
                    rest = tail.ok_or(Error("bad NAPTR record"))?;
                }
                let (regexp, replacement) = rest.split_once(b',');
                self.naptr.push(NaptrRecord {
                    name: canon(&fields[0])?,
                    order: uint16(&fields[1])?,
                    preference: uint16(&fields[2])?,
                    flags: optional(&fields[3]),
                    services: optional(&fields[4]),
                    regexp: optional(&regexp),
                    replacement: replacement.as_ref().map(canon).transpose()?,
                });
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// C read_opts needs gethostname for this branch even when every MX
    /// target was explicit. The caller supplies the platform hostname and
    /// handles its I/O failure before reporting --test success.
    pub fn needs_hostname(&self) -> bool {
        !self.hostname_finalized
            && (self.local_mx
                || !self.mx.is_empty()
                || !self.srv.is_empty()
                || self.mx_target.is_some())
    }

    /// option.c:6214-6248. Keep this system dependency separate from parsing.
    pub fn finalize_mx(&mut self, hostname: &[u8]) {
        if !self.needs_hostname() {
            return;
        }
        let own_mx = self
            .mx
            .iter()
            .any(|record| record.name.eq_ignore_ascii_case(hostname));
        if (self.mx_target.is_some() || self.local_mx) && !own_mx {
            self.mail_order
                .get_mut()
                .insert(0, MailRecord::Mx(self.mx.len()));
            self.mx.push(MxRecord {
                name: hostname.to_vec(),
                target: None,
                preference: 0,
            });
        }
        self.hostname_finalized = true;
        let default = self.mx_target.get_or_insert_with(|| hostname.to_vec());
        for record in &mut self.mx {
            if record.target.is_none() {
                record.target = Some(default.clone());
            }
        }
    }

    /// Current C MX/SRV linked-list order, before a query mutates it.
    pub(crate) fn mail_order(&self) -> Vec<MailRecord> {
        self.mail_order.borrow().clone()
    }

    pub(crate) fn rotate_srv(&self, name: &[u8]) {
        let mut order = self.mail_order.borrow_mut();
        if let Some(at) = order.iter().position(|entry| match entry {
            MailRecord::Srv(index) => self.srv[*index].name.eq_ignore_ascii_case(name),
            MailRecord::Mx(_) => false,
        }) {
            let first = order.remove(at);
            order.push(first);
        }
    }

    /// option.c:6139-6190 does a quadratic alias-target pointer construction
    /// followed by loop detection. This index plus iterative graph walk is
    /// linear expected time and cannot overflow the call stack on a long chain.
    pub fn cname_loop_alias(&self) -> Option<&[u8]> {
        let index: HashMap<Vec<u8>, usize> = self
            .cnames
            .iter()
            .enumerate()
            .map(|(i, record)| (ascii_key(&record.alias), i))
            .collect();
        let next: Vec<Option<usize>> = self
            .cnames
            .iter()
            .map(|record| index.get(&ascii_key(&record.target)).copied())
            .collect();
        let mut state = vec![0u8; self.cnames.len()];
        // C prepends declarations and reports the first traversal root, even
        // when that alias points into a later cycle.
        for start in (0..state.len()).rev() {
            let mut node = Some(start);
            while let Some(current) = node {
                if state[current] == 1 {
                    return Some(&self.cnames[start].alias);
                }
                if state[current] == 2 {
                    break;
                }
                state[current] = 1;
                node = next[current];
            }
            node = Some(start);
            while let Some(current) = node {
                if state[current] != 1 {
                    break;
                }
                state[current] = 2;
                node = next[current];
            }
        }
        None
    }

    pub fn validate_cnames(&self) -> Result<(), Error> {
        if self.cname_loop_alias().is_some() {
            Err(Error("CNAME loop"))
        } else {
            Ok(())
        }
    }

    /// Call once after the default domain has been obtained, including a
    /// domain=# resolver search directive. TTL None remains a live inheritance
    /// from the final local-ttl rather than copying an early partial value.
    pub fn finalize(&mut self, domain: Option<&[u8]>) -> Result<(), Error> {
        self.validate_cnames()?;
        if let Some(domain) = domain {
            for record in &mut self.srv {
                if record.name.iter().filter(|&&c| c == b'.').count() == 1 {
                    let mut name = record.name.clone();
                    name.push(b'.');
                    name.extend_from_slice(domain);
                    record.name = crate::hosts::canonicalise(&name)
                        .ok_or(Error("bad SRV name after domain appended"))?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{dns::DnsConfig, lex_line, validate_directive, OccurrenceTracker, Origin};

    fn apply(config: &mut RecordConfig, text: &[u8]) -> Result<bool, Error> {
        let directive = lex_line(text)?.unwrap();
        validate_directive(&directive)?;
        config.apply(&directive)
    }

    #[test]
    fn image_record_integer_widths_wrap_before_field_checks() {
        let mut config = RecordConfig::default();
        apply(&mut config, b"dns-rr=test,4294967296,ab").unwrap();
        assert_eq!(config.raw[0].rr_type, 0);
        apply(
            &mut config,
            format!("caa-record=test,{},t,v", "9".repeat(64)).as_bytes(),
        )
        .unwrap();
        assert_eq!(config.raw[1].data[0], 255);
        apply(
            &mut config,
            b"naptr-record=test,4294967296,4294967297,f,s,r,.",
        )
        .unwrap();
        assert_eq!((config.naptr[0].order, config.naptr[0].preference), (0, 1));
        assert!(apply(&mut config, b"naptr-record=test,2147483648,1,f,s,r,.").is_err());
    }

    #[test]
    fn record_lengths_follow_safe_backing_allocation_boundaries() {
        let mut config = RecordConfig::default();
        apply(
            &mut config,
            format!("dns-rr=test,65401,{}", "ab".repeat(65537)).as_bytes(),
        )
        .unwrap();
        assert_eq!(config.raw[0].data, [0xab]);
        apply(
            &mut config,
            format!("txt-record=test,{}", "a".repeat(65280)).as_bytes(),
        )
        .unwrap();
        assert!(config.txt[0].data.is_empty());
        apply(
            &mut config,
            format!("caa-record=test,256,{},v", "t".repeat(256)).as_bytes(),
        )
        .unwrap();
        assert_eq!(&config.raw[1].data[..2], &[0, 0]);
        assert_eq!(config.raw[1].data.len(), 259);
        // C allocates u16(total), then overflows it with full strings here.
        assert!(apply(
            &mut config,
            format!("caa-record=test,0,t,{}", "v".repeat(65533)).as_bytes()
        )
        .is_err());
    }

    #[test]
    fn cname_aliases_case_insensitive_duplicate_and_loop() {
        let mut config = RecordConfig::default();
        apply(&mut config, b"cname=a.test,b.test,target.test,30").unwrap();
        assert_eq!(config.cnames.len(), 2);
        assert_eq!(config.cnames[0].ttl, Some(30));
        assert!(apply(&mut config, b"cname=A.test,other.test").is_err());
        apply(&mut config, b"cname=target.test,a.test").unwrap();
        assert!(config.validate_cnames().is_err());
        let mut config = RecordConfig::default();
        for index in 0..1000 {
            apply(
                &mut config,
                format!("cname=n{index}.test,n{}.test", index + 1).as_bytes(),
            )
            .unwrap();
        }
        config.validate_cnames().unwrap();
    }

    #[test]
    fn txt_character_strings_preserve_quoted_commas_and_255_byte_split() {
        let mut config = RecordConfig::default();
        apply(&mut config, b"txt-record=test,\"a,b\", c,,").unwrap();
        assert_eq!(config.txt[0].data, b"\x03a,b\x02 c\x00\x00");
        let mut line = b"txt-record=test,".to_vec();
        line.extend(vec![b'x'; 256]);
        apply(&mut config, &line).unwrap();
        assert_eq!(config.txt[1].data[0], 255);
        assert_eq!(&config.txt[1].data[256..], b"\x01x");
        apply(&mut config, b"txt-record=empty").unwrap();
        assert_eq!(config.txt[2].data, [0]);
    }

    #[test]
    fn generic_hex_caa_and_optional_ptr_keep_wire_values() {
        let mut config = RecordConfig::default();
        apply(&mut config, b"dns-rr=test,65536,a:bcd:ef").unwrap();
        assert_eq!(config.raw[0].rr_type, 0);
        assert_eq!(config.raw[0].data, [0x0a, 0xbc, 0x0d, 0xef]);
        apply(&mut config, b"dns-rr=test,65400,ab:*:cd").unwrap();
        assert_eq!(config.raw[1].data, [0xab, b'b', 0xcd]);
        apply(&mut config, b"caa-record=test,256,issue,ca.test,extra").unwrap();
        assert_eq!(config.raw[2].data, b"\x00\x05issueca.test,extra");
        apply(&mut config, b"ptr-record=example.test").unwrap();
        assert_eq!(config.ptr[0].target, None);
        assert!(apply(&mut config, b"dns-rr=test,1,\"abcd\"").is_err());
    }

    #[test]
    fn raw_type_presence_tracks_both_directives_and_cloned_config() {
        let mut config = RecordConfig::default();
        for line in [
            b"dns-rr=test,65401,abcd".as_slice(),
            b"dns-rr=test,1,c0000201",
            b"caa-record=test,0,issue,ca.test",
            b"dns-rr=test,65401,1234",
            b"dns-rr=test,257,0005697373756563612e74657374",
        ] {
            apply(&mut config, line).unwrap();
        }
        let snapshot = config.clone();
        apply(
            &mut config,
            b"dns-rr=test,28,00000000000000000000000000000001",
        )
        .unwrap();
        assert!(apply(&mut config, b"dns-rr=test,29,not-hex").is_err());
        for (records, types) in [
            (&snapshot, &[1, 257, 65401][..]),
            (&config, &[1, 28, 257, 65401][..]),
        ] {
            for rr_type in [0, 1, 16, 28, 29, 255, 257, 65401, 65535] {
                assert_eq!(records.has_raw_type(rr_type), types.contains(&rr_type));
                assert_eq!(
                    records.has_raw_type(rr_type),
                    records
                        .raw_records()
                        .iter()
                        .any(|record| record.rr_type == rr_type)
                );
            }
        }
        assert_eq!(snapshot.raw_records().len(), 5);
        assert_eq!(config.raw_records().len(), 6);
    }

    #[test]
    fn rejected_mx_name_cannot_leave_an_invalid_runtime_index() {
        let mut config = RecordConfig::default();
        let invalid = format!("mx-host={}.test,target.test", "x".repeat(64));
        assert!(apply(&mut config, invalid.as_bytes()).is_err());
        assert!(config.mail_order().is_empty());
        apply(&mut config, b"mx-host=valid.test,target.test").unwrap();
        assert_eq!(config.mail_order(), [MailRecord::Mx(0)]);
    }

    #[test]
    fn mx_srv_naptr_defaults_and_final_domain() {
        let mut config = RecordConfig::default();
        apply(&mut config, b"mx-host=test").unwrap();
        assert_eq!(config.mx[0].target, None);
        assert_eq!(config.mx[0].preference, 1);
        assert!(config.needs_hostname());
        config.finalize_mx(b"gateway.test");
        assert_eq!(
            config.mx[0].target.as_deref(),
            Some(b"gateway.test".as_slice())
        );
        apply(&mut config, b"srv-host=_sip._tcp,target.test").unwrap();
        assert_eq!(config.srv[0].port, 1);
        config.finalize(Some(b"lan")).unwrap();
        assert_eq!(config.srv[0].name, b"_sip._tcp.lan");
        apply(
            &mut config,
            b"naptr-record=test,10,20,u,E2U+sip,\"!^.*$!sip:info@example.test!\",.",
        )
        .unwrap();
        assert_eq!(config.naptr[0].replacement, Some(Vec::new()));
        assert_eq!(
            config.naptr[0].regexp.as_deref(),
            Some(b"!^.*$!sip:info@example.test!".as_slice())
        );
    }

    #[test]
    #[ignore = "requires DNSMASQ_C_REFERENCE pointing to exact C 2.93 build"]
    fn local_record_acceptance_matches_c() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let reference = std::env::var_os("DNSMASQ_C_REFERENCE").expect("DNSMASQ_C_REFERENCE");
        let cases = [
            "cname=a.test,b.test",
            "cname=a.test,b.test,target.test,30",
            "cname=a.test",
            "cname=a.test,A.test",
            "cname=a.test,b.test\ncname=b.test,a.test",
            "cname=a.test,target.test\ncname=A.test,other.test",
            "cname=a.test,target.test,",
            "ptr-record=example.test",
            "ptr-record=example.test,target.test",
            "ptr-record=",
            "txt-record=test",
            "txt-record=test,\"a,b\", c,,",
            "txt-record=test,\"unterminated",
            "dns-rr=test,1",
            "dns-rr=test,65400,a:bcd:ef",
            "dns-rr=test,65400,ab:*:cd",
            "dns-rr=test,65536,abcd",
            "dns-rr=test,1,\"abcd\"",
            "dns-rr=test,1,az",
            "dns-rr=test,1,a*b",
            "dns-rr=test",
            "dns-rr=test,1,",
            "caa-record=test,0,issue,ca.test",
            "caa-record=test,256,issue,ca.test,extra",
            "caa-record=test,0,issue",
            "caa-record=test,bad,issue,ca.test",
            "mx-host=test",
            "mx-host=test,target.test,10",
            "mx-host=test,target.test,65536",
            "mx-target=mail.test",
            "localmx",
            "selfmx",
            "srv-host=_sip._tcp,target.test",
            "domain=lan\nsrv-host=_sip._tcp,target.test,5060,10,20",
            "srv-host=service",
            "srv-host=service,target.test,65536",
            "srv-host=service,target.test,1,2,3,4",
            "naptr-record=test,10,20,u,E2U+sip,regexp",
            "naptr-record=test,10,20,u,E2U+sip,regexp,.",
            "naptr-record=test,10,20,u,E2U+sip",
            "naptr-record=test,65536,20,u,E2U+sip,regexp",
        ];
        let mut successes = 0;
        let mut failures = 0;
        for text in cases {
            let mut config = DnsConfig::default();
            let mut tracker = OccurrenceTracker::default();
            let rust = text
                .as_bytes()
                .split(|&c| c == b'\n')
                .try_for_each(|line| {
                    if let Some(directive) = lex_line(line)? {
                        let spec = validate_directive(&directive)?;
                        if tracker.record(spec, Origin::File)? && !config.apply(&directive)? {
                            return Err(Error("unhandled corpus option"));
                        }
                    }
                    Ok(())
                })
                .and_then(|_| config.finalize());
            let mut child = Command::new(&reference)
                .args(["--test", "--conf-file=-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
            let c = child.wait_with_output().unwrap();
            assert_eq!(
                rust.is_ok(),
                c.status.success(),
                "config {text:?}: Rust {rust:?}, C {}",
                String::from_utf8_lossy(&c.stderr)
            );
            if rust.is_ok() {
                successes += 1;
            } else {
                failures += 1;
            }
        }
        assert!(successes > 15 && failures > 5);
        eprintln!("Local record config C differential: {successes} accepted, {failures} rejected, {} matched", successes + failures);
    }
}
