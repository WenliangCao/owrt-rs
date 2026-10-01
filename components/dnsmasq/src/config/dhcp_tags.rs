//! Tag rules used by the OpenWrt-generated broadcast and hostname policies.

use crate::config::{EncodedArg, Error};

/// One rule is a conjunction; repeated directives are alternatives. An empty
/// rule is the explicit, unconditional form of broadcast/ignore-names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagPredicate {
    tags: Vec<Vec<u8>>,
}

impl TagPredicate {
    pub(super) fn parse(argument: Option<&EncodedArg>) -> Result<Self, Error> {
        let mut tags = Vec::new();
        if let Some(argument) = argument {
            for value in argument.split(b',') {
                let prefixed =
                    value.encoded().starts_with(b"tag:") || value.encoded().starts_with(b"net:");
                let value = value.decoded();
                let tag = if prefixed { &value[4..] } else { &value };
                if tag.is_empty() || matches!(tag, b"!" | b"#") {
                    return Err(Error("empty DHCP tag predicate"));
                }
                tags.push(tag.to_vec());
            }
        }
        Ok(Self { tags })
    }

    pub fn matches(&self, tags: &[&[u8]]) -> bool {
        // Reuse the existing C-qualified exact/negated tag predicate.
        crate::dhcp::allocation::match_tags(&self.tags, tags, true)
    }
}

/// The observed OpenWrt include sets one tag for an exact client hostname.
/// Matching uses the full client name before rfc2131.c strips its domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpNameMatch {
    pub set_tag: Vec<u8>,
    name: Vec<u8>,
}

impl DhcpNameMatch {
    pub(super) fn parse(argument: &EncodedArg) -> Result<Self, Error> {
        let (tag, name) = argument.split_once(b',');
        let name = name
            .ok_or(Error("DHCP name match requires a hostname"))?
            .decoded();
        if name.is_empty() {
            return Err(Error("DHCP name match requires a hostname"));
        }
        if name.ends_with(b"*") {
            return Err(Error("DHCP hostname prefix matching is not implemented"));
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
        })
    }

    pub fn matches(&self, full_hostname: &[u8]) -> bool {
        self.name.eq_ignore_ascii_case(full_hostname)
    }
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
        let rule =
            TagPredicate::parse(Some(&EncodedArg::command_line(b"net:lan,#blocked"))).unwrap();
        assert!(rule.matches(&[b"lan"]));
        assert!(!rule.matches(&[b"lan", b"blocked"]));
        for value in [b"".as_slice(), b"tag:", b"tag:!", b"lan,,other"] {
            assert!(TagPredicate::parse(Some(&EncodedArg::command_line(value))).is_err());
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
        for value in [
            b"set:tag".as_slice(),
            b"set:tag,",
            b"set:,wpad",
            b"set:tag,wpad*",
        ] {
            assert!(DhcpNameMatch::parse(&EncodedArg::command_line(value)).is_err());
        }
    }
}
