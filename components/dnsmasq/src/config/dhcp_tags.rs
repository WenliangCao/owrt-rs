//! DHCP tag predicates and generators. These own configuration only; packet
//! tag lists borrow the rules and are discarded after each request.

use crate::config::{EncodedArg, Error};

/// One rule is a conjunction; repeated directives are alternatives. An empty
/// rule is the explicit, unconditional form of broadcast/ignore-names.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TagPredicate {
    tags: Vec<Vec<u8>>,
}

impl TagPredicate {
    pub fn from_tags(tags: Vec<Vec<u8>>) -> Self {
        Self { tags }
    }

    pub fn tags(&self) -> &[Vec<u8>] {
        &self.tags
    }
    /// A rule with no selector applies to every packet. A negated selector
    /// which happens to match an empty tag list is still conditional.
    pub fn is_unconditional(&self) -> bool {
        self.tags.is_empty()
    }

    pub(super) fn parse(argument: Option<&EncodedArg>) -> Result<Self, Error> {
        let mut tags = Vec::new();
        if let Some(argument) = argument {
            for value in argument.split(b',') {
                let prefixed =
                    value.encoded().starts_with(b"tag:") || value.encoded().starts_with(b"net:");
                let value = value.decoded();
                let tag = if prefixed { &value[4..] } else { &value };
                if tag.is_empty() {
                    return Err(Error("empty DHCP tag predicate"));
                }
                tags.push(tag.to_vec());
            }
        }
        Ok(Self { tags })
    }

    pub fn matches(&self, tags: &[&[u8]]) -> bool {
        // dhcp-common.c: match_netid; keep configuration independent of the
        // DHCP runtime so standalone configuration consumers can use it.
        self.tags.iter().all(|tag| {
            if let Some(negative) = tag.strip_prefix(b"!").or_else(|| tag.strip_prefix(b"#")) {
                !tags.contains(&negative)
            } else {
                tags.contains(&tag.as_slice())
            }
        })
    }

    /// C match_netid distinguishes untagged fallback from a matching rule.
    pub fn matches_with(&self, tags: &[&[u8]], allow_untagged: bool) -> bool {
        (allow_untagged || !self.tags.is_empty()) && self.matches(tags)
    }

    pub fn matches_wild(&self, tags: &[&[u8]]) -> bool {
        self.tags.iter().all(|tag| {
            let (negative, value) = match tag.first() {
                Some(b'!' | b'#') => (true, &tag[1..]),
                _ => (false, tag.as_slice()),
            };
            let found = tags.iter().any(|candidate| {
                value
                    .strip_suffix(b"*")
                    .map_or(*candidate == value, |prefix| candidate.starts_with(prefix))
            });
            found != negative
        })
    }
}

/// The observed OpenWrt include sets one tag for an exact client hostname.
/// Matching uses the full client name before rfc2131.c strips its domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpNameMatch {
    pub set_tag: Vec<u8>,
    name: Vec<u8>,
    prefix: bool,
}

impl DhcpNameMatch {
    pub(super) fn parse(argument: &EncodedArg) -> Result<Self, Error> {
        let (tag, name) = argument.split_once(b',');
        let mut name = name.ok_or(Error("error"))?.decoded();
        if name.is_empty() {
            return Err(Error("error"));
        }
        let prefix = name.last() == Some(&b'*');
        if prefix {
            name.pop();
        }
        let prefixed = tag.encoded().starts_with(b"set:");
        let value = tag.decoded();
        let set_tag = if prefixed { &value[4..] } else { &value };
        if set_tag.is_empty() {
            return Err(Error("empty DHCP name-match tag"));
        }
        Ok(Self {
            set_tag: set_tag.to_vec(),
            name,
            prefix,
        })
    }

    pub fn matches(&self, full_hostname: &[u8]) -> bool {
        if self.prefix {
            full_hostname
                .get(..self.name.len())
                .is_some_and(|part| self.name.eq_ignore_ascii_case(part))
        } else {
            self.name.eq_ignore_ascii_case(full_hostname)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagIf {
    pub filter: TagPredicate,
    pub set_tags: Vec<Vec<u8>>,
}

impl TagIf {
    pub fn parse(argument: &EncodedArg) -> Result<Self, Error> {
        let mut tags = Vec::new();
        let mut set_tags = Vec::new();
        for item in argument.split(b',') {
            let bytes = item.encoded();
            if bytes.len() < 5 {
                return Err(Error("bad tag-if"));
            }
            if bytes.starts_with(b"tag:") {
                tags.push(item.decoded()[4..].to_vec());
            } else if bytes.starts_with(b"set:") {
                set_tags.push(item.decoded()[4..].to_vec());
            } else {
                return Err(Error("bad tag-if"));
            }
        }
        if set_tags.is_empty() {
            return Err(Error("bad tag-if"));
        }
        Ok(Self {
            filter: TagPredicate::from_tags(tags),
            set_tags,
        })
    }

    /// Rules must be retained in declaration order (unlike most C lists).
    pub fn apply_all<'a>(rules: &'a [Self], tags: &mut Vec<&'a [u8]>) {
        for rule in rules {
            if rule.filter.matches_wild(tags) {
                tags.extend(rule.set_tags.iter().map(Vec::as_slice));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassKind {
    Vendor,
    User,
    Circuit,
    Remote,
    Subscriber,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpClass {
    pub set_tag: Vec<u8>,
    pub kind: ClassKind,
    pub enterprise: Option<u32>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpMac {
    pub set_tag: Vec<u8>,
    pub hardware: super::host::HardwareAddress,
}

impl DhcpMac {
    pub fn parse(argument: &EncodedArg) -> Result<Self, Error> {
        let (tag, address) = argument.split_once(b',');
        let tag = tag.decoded();
        let set_tag = tag.strip_prefix(b"set:").unwrap_or(&tag).to_vec();
        if set_tag.is_empty() {
            return Err(Error("empty DHCP MAC tag"));
        }
        let address = address.ok_or(Error("bad DHCP MAC rule"))?.decoded();
        let hardware =
            super::host::parse_hardware(&address, 16, true, true).map_err(|_| Error("error"))?;
        Ok(Self { set_tag, hardware })
    }

    pub fn matches(&self, kind: u32, address: &[u8]) -> bool {
        let hardware = &self.hardware;
        hardware.address.len() == address.len()
            && (hardware.kind == 0 || hardware.kind == kind)
            && hardware
                .address
                .iter()
                .zip(address)
                .enumerate()
                .all(|(at, (left, right))| {
                    hardware.wildcard_mask & (1 << (address.len() - at - 1)) != 0 || left == right
                })
    }
}

impl DhcpClass {
    pub fn parse(argument: &EncodedArg, kind: ClassKind) -> Result<Self, Error> {
        let (tag, value) = argument.split_once(b',');
        let value = value.ok_or(Error("error"))?;
        let mut enterprise = None;
        let value = if kind == ClassKind::Vendor && value.encoded().starts_with(b"enterprise:") {
            let (number, tail) = value.split_once(b',');
            enterprise = Some(super::integer(&number.encoded()[11..])?);
            match tail {
                Some(tail) => tail,
                None if enterprise != Some(0) => EncodedArg::command_line(b""),
                None => return Err(Error("bad DHCP class enterprise")),
            }
        } else {
            value
        };
        let tag = tag.decoded();
        let set_tag = tag.strip_prefix(b"set:").unwrap_or(&tag).to_vec();
        if set_tag.is_empty() {
            return Err(Error("empty DHCP class tag"));
        }
        let raw = value.encoded();
        let relay_hex = !matches!(kind, ClassKind::Vendor | ClassKind::User)
            && raw.contains(&b':')
            && raw.iter().any(u8::is_ascii_hexdigit)
            && raw.iter().all(|b| b.is_ascii_hexdigit() || *b == b':');
        let value = if relay_hex {
            super::host::parse_hardware(raw, usize::MAX, false, false)?.address
        } else {
            value.decoded()
        };
        Ok(Self {
            set_tag,
            kind,
            enterprise,
            value,
        })
    }

    /// The caller passes option 60/77, or the relevant option 82 suboption.
    /// In this nodhcpv6 C build enterprise metadata does not alter IPv4
    /// vendor-class matching (rfc2131.c uses option 60, not option 124).
    pub fn matches(&self, bytes: &[u8]) -> bool {
        if matches!(
            self.kind,
            ClassKind::Circuit | ClassKind::Remote | ClassKind::Subscriber
        ) {
            return bytes == self.value;
        }
        if self.kind == ClassKind::User {
            let mut at = 0;
            while at < bytes.len() {
                at += usize::from(bytes[at]) + 1;
            }
            if at == bytes.len() {
                // C zeroes the length octets, then performs a substring
                // search. Match that without changing the received packet.
                let mut normalized = bytes.to_vec();
                let mut at = 0;
                while at < bytes.len() {
                    normalized[at] = 0;
                    at += usize::from(bytes[at]) + 1;
                }
                return contains(&normalized, &self.value);
            }
        }
        contains(bytes, &self.value)
    }
}

fn contains(value: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || value.windows(needle.len()).any(|part| part == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;

    #[test]
    fn tag_predicates_keep_conjunction_negation_and_case() {
        let rule =
            TagPredicate::parse(Some(&EncodedArg::command_line(b"tag:lan,tag:!blocked"))).unwrap();
        assert!(rule.matches(&[b"lan"]));
        assert!(!rule.matches(&[b"LAN"]));
        assert!(!rule.matches(&[b"lan", b"blocked"]));
        assert!(!rule.matches(&[]));
        assert!(TagPredicate::parse(None).unwrap().matches(&[]));
        assert!(TagPredicate::parse(None).unwrap().is_unconditional());
        let negative = TagPredicate::parse(Some(&EncodedArg::command_line(b"tag:!known"))).unwrap();
        assert!(negative.matches(&[]));
        assert!(!negative.is_unconditional());
        let rule =
            TagPredicate::parse(Some(&EncodedArg::command_line(b"net:lan,#blocked"))).unwrap();
        assert!(rule.matches(&[b"lan"]));
        assert!(!rule.matches(&[b"lan", b"blocked"]));
        for value in [b"".as_slice(), b"tag:", b"lan,,other"] {
            assert!(TagPredicate::parse(Some(&EncodedArg::command_line(value))).is_err());
        }
        for value in [b"tag:!".as_slice(), b"#"] {
            assert!(TagPredicate::parse(Some(&EncodedArg::command_line(value)))
                .unwrap()
                .matches(&[b"ordinary"]));
        }
    }

    #[test]
    fn exact_hostname_tags_match_full_name_without_changing_tag_case() {
        let line = lex_line(b"dhcp-name-match=set:dhcp_bogus_hostname,wpad")
            .unwrap()
            .unwrap();
        let rule = DhcpNameMatch::parse(line.argument.as_ref().unwrap()).unwrap();
        assert_eq!(rule.set_tag, b"dhcp_bogus_hostname");
        assert!(rule.matches(b"WPAD"));
        assert!(!rule.matches(b"wpad.example"));
        assert!(!rule.matches(b"other"));
        for value in [b"set:tag".as_slice(), b"set:tag,", b"set:,wpad"] {
            assert!(DhcpNameMatch::parse(&EncodedArg::command_line(value)).is_err());
        }
        let prefix = DhcpNameMatch::parse(&EncodedArg::command_line(b"set:tag,wpad*")).unwrap();
        assert!(prefix.matches(b"WPAD.example"));
        assert!(!prefix.matches(b"wpa"));
        let all = DhcpNameMatch::parse(&EncodedArg::command_line(b"set:tag,*")).unwrap();
        assert!(all.matches(b"client"));
    }

    #[test]
    fn tag_if_is_ordered_and_only_it_expands_wildcards() {
        let rules = [
            TagIf::parse(&EncodedArg::command_line(
                b"tag:br-*,tag:!blocked,set:lan,set:second",
            ))
            .unwrap(),
            TagIf::parse(&EncodedArg::command_line(b"tag:lan,set:ready")).unwrap(),
        ];
        let mut tags: Vec<&[u8]> = vec![b"br-lan"];
        TagIf::apply_all(&rules, &mut tags);
        assert!(tags.contains(&b"ready".as_slice()));
        assert!(!TagPredicate::from_tags(vec![b"br-*".to_vec()]).matches(&tags));
        let mut blocked: Vec<&[u8]> = vec![b"br-lan", b"blocked"];
        TagIf::apply_all(&rules, &mut blocked);
        assert_eq!(blocked.len(), 2);
        assert!(!TagPredicate::default().matches_with(&[], false));
        assert!(TagPredicate::default().matches_with(&[], true));
    }

    #[test]
    fn classes_preserve_counted_user_strings_and_relay_exact_matching() {
        let user =
            DhcpClass::parse(&EncodedArg::command_line(b"set:desk,desk"), ClassKind::User).unwrap();
        assert!(user.matches(b"\x04desk\x06mobile"));
        assert!(user.matches(b"broken-desktop"));
        assert!(!user.matches(b"\x03des\x01k"));
        let relay = DhcpClass::parse(
            &EncodedArg::command_line(b"set:relay,01:02"),
            ClassKind::Circuit,
        )
        .unwrap();
        assert!(relay.matches(&[1, 2]));
        assert!(!relay.matches(&[0, 1, 2]));
        let vendor = DhcpClass::parse(
            &EncodedArg::command_line(b"set:vendor,enterprise:1234,desk"),
            ClassKind::Vendor,
        )
        .unwrap();
        assert_eq!(vendor.enterprise, Some(1234));
        assert!(vendor.matches(b"desktop"));
    }

    #[test]
    fn hardware_tag_mask_and_type_do_not_widen_exact_octets() {
        let rule =
            DhcpMac::parse(&EncodedArg::command_line(b"set:device,1-02:00:*:00:00:01")).unwrap();
        assert!(rule.matches(1, &[2, 0, 7, 0, 0, 1]));
        assert!(!rule.matches(6, &[2, 0, 7, 0, 0, 1]));
        assert!(!rule.matches(1, &[2, 1, 7, 0, 0, 1]));
    }
}
