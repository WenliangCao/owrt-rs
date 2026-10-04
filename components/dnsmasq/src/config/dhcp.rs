//! Minimal typed DHCPv4 configuration for the local listener.
//!
//! The parser keeps the byte-oriented option boundary separate from the
//! state/runtime modules. Unsupported context selectors remain explicit
//! errors instead of silently producing a pool with different semantics.

use super::{validate_directive, Directive, Error};
use std::net::Ipv4Addr;

#[path = "dhcp_host.rs"]
mod host;
pub use host::{HardwareAddress, HostConfig};
#[path = "dhcp_host_files.rs"]
mod host_files;
pub use host_files::{FilePlanStep, HostFileError, HostFileErrorKind, HostFiles, HostReload};
#[path = "dhcp_options.rs"]
mod ordinary_options;
pub use ordinary_options::{
    option_filter, DhcpMatch, DhcpOption, Encapsulation, FilteredOptions, OptionValue,
};
#[path = "dhcp_tags.rs"]
mod tags;
pub use tags::{ClassKind, DhcpClass, DhcpMac, DhcpNameMatch, TagIf, TagPredicate};

/// A validated copy of only the DNS address-to-domain fields. Keeping these
/// fields in DnsConfig reuses its audited selector ordering and matching.
#[derive(Clone, Debug, Default)]
pub struct NameDomains(super::dns::DnsConfig);

impl NameDomains {
    pub fn new(config: &super::dns::DnsConfig) -> Result<Self, Error> {
        let mut domains = super::dns::DnsConfig::default();
        domains.domain_suffix.clone_from(&config.domain_suffix);
        domains
            .conditional_domains
            .clone_from(&config.conditional_domains);
        domains.validate_ready()?;
        Ok(Self(domains))
    }

    pub fn for_address(&self, address: Ipv4Addr) -> Option<&[u8]> {
        self.0
            .domain_for_address(address.into())
            .expect("NameDomains validates selectors at construction")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeConfig {
    pub kind: crate::dhcp::allocation::RangeKind,
    /// Tag set only after this address context has been selected.
    pub set_tag: Option<Vec<u8>>,
    pub filter: TagPredicate,
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    /// None asks the runtime to derive the netmask from the serving interface.
    pub netmask: Option<Ipv4Addr>,
    pub broadcast: Option<Ipv4Addr>,
    pub lease_time: u32,
    pub lease_time_explicit: bool,
}

/// Ordinary untagged boot metadata. Zero numeric next-server retains the
/// context's local address; a hosts name is resolved for each response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootConfig {
    pub filename: Option<Vec<u8>>,
    pub server_name: Option<Vec<u8>>,
    pub next_server: Ipv4Addr,
    pub next_server_name: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootEntry {
    pub filter: TagPredicate,
    pub config: BootConfig,
}

impl BootConfig {
    fn parse_fields(
        file: &super::EncodedArg,
        tail: Option<super::EncodedArg>,
    ) -> Result<Self, Error> {
        let (server, next) = tail
            .map(|tail| tail.split_once(b','))
            .map(|(server, next)| (Some(server), next))
            .unwrap_or_default();
        let string = |value: Vec<u8>| -> Result<Option<Vec<u8>>, Error> {
            if value.len() > 255 {
                return Err(Error("DHCP boot string exceeds one-byte option length"));
            }
            Ok((!value.is_empty()).then_some(value))
        };
        let (next_server, next_server_name) = match next.map(|value| value.decoded()) {
            Some(value) if !value.is_empty() => match ip(&value) {
                Ok(address) => (address, None),
                Err(_) => (Ipv4Addr::UNSPECIFIED, Some(value)),
            },
            _ => (Ipv4Addr::UNSPECIFIED, None),
        };
        Ok(Self {
            filename: string(file.decoded())?,
            server_name: string(server.map(|value| value.decoded()).unwrap_or_default())?,
            next_server,
            next_server_name,
        })
    }

    /// Parse the optional leading `tag:`/`net:` selectors used by
    /// `dhcp-boot`. Selectors are consumed before the ordinary three fields;
    /// the latter retain EncodedArg's quoted-comma behavior.
    fn parse_selected(argument: &super::EncodedArg) -> Result<(TagPredicate, Self), Error> {
        let mut selectors = Vec::new();
        let mut rest = argument.clone();
        loop {
            let (head, tail) = rest.split_once(b',');
            let bytes = head.encoded();
            let prefix_len = if bytes.starts_with(b"tag:") || bytes.starts_with(b"net:") {
                4
            } else {
                0
            };
            if prefix_len == 0 {
                return Ok((
                    TagPredicate::from_tags(selectors),
                    Self::parse_fields(&head, tail)?,
                ));
            }
            let value = head.decoded();
            let tag = &value[prefix_len..];
            // An empty selector has no usable C runtime representation.
            // Reject it here; never silently widen it to an untagged rule.
            if tag.is_empty() {
                return Err(Error("empty DHCP boot tag selector"));
            }
            selectors.push(tag.to_vec());
            rest = tail.ok_or(Error("DHCP boot selector requires boot fields"))?;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicFileKind {
    Hosts,
    Options,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicFileDirectory {
    pub kind: DynamicFileKind,
    pub path: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpConfig {
    pub pxe: super::dhcp_pxe::PxeConfig,
    pub relay: Vec<super::dhcp_relay::RelayRule>,
    pub ports: super::dhcp_relay::DhcpPorts,
    /// RFC4388 leasequery configuration. The parser is kept with the DHCP
    /// config, while query state and wire encoding stay in the DHCP module.
    pub lease_query: crate::dhcp::lease_query::LeaseQueryConfig,
    pub script: Option<Vec<u8>>,
    pub script_user: Option<Vec<u8>>,
    pub script_on_renewal: bool,
    /// Matches C's context-list order: the last configured range comes first.
    pub ranges: Vec<RangeConfig>,
    /// Last directive first, matching daemon->dhcp_conf.
    pub hosts: Vec<HostConfig>,
    /// Last configured path first, as in daemon->dhcp_hosts_file.
    pub host_files: Vec<Vec<u8>>,
    pub option_files: Vec<Vec<u8>>,
    /// Mixed hosts/options directories retain reverse declaration order.
    pub dynamic_dirs: Vec<DynamicFileDirectory>,
    /// Last configured first, including duplicates for C warning behavior.
    pub options: Vec<DhcpOption>,
    pub authoritative: bool,
    pub rapid_commit: bool,
    pub bootp_dynamic: bool,
    pub bootp_dynamic_tags: Vec<TagPredicate>,
    /// Last untagged directive wins, matching find_boot's reverse list.
    pub boot: Option<BootConfig>,
    /// All dhcp-boot directives in reverse declaration order. Tagged entries
    /// are selected after the request context is known; the untagged entry is
    /// retained in `boot` for compatibility with callers that only need the
    /// fallback configuration.
    pub boot_entries: Vec<BootEntry>,
    pub no_override: bool,
    pub sequential: bool,
    pub ignore_client_id: bool,
    pub fqdn_only: bool,
    pub read_ethers: bool,
    pub name_matches: Vec<DhcpNameMatch>,
    pub tag_if: Vec<TagIf>,
    pub classes: Vec<DhcpClass>,
    pub macs: Vec<DhcpMac>,
    pub matches: Vec<DhcpMatch>,
    pub ignore: Vec<TagPredicate>,
    pub generate_names: Vec<TagPredicate>,
    pub client_update: bool,
    pub ignore_names: Vec<TagPredicate>,
    pub force_broadcast: Vec<TagPredicate>,
    pub no_dhcp_interfaces: Vec<Option<Vec<u8>>>,
    pub no_ping: bool,
    /// Also controls the C early return for an ignored DISCOVER.
    pub quiet_dhcp: bool,
    pub log_dhcp: bool,
    pub lease_max: usize,
    pub lease_file: Option<Vec<u8>>,
    pub lease_read_only: bool,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            pxe: Default::default(),
            relay: Vec::new(),
            ports: Default::default(),
            lease_query: Default::default(),
            script: None,
            script_user: None,
            script_on_renewal: false,
            ranges: Vec::new(),
            hosts: Vec::new(),
            host_files: Vec::new(),
            option_files: Vec::new(),
            dynamic_dirs: Vec::new(),
            options: Vec::new(),
            authoritative: false,
            rapid_commit: false,
            bootp_dynamic: false,
            bootp_dynamic_tags: Vec::new(),
            boot: None,
            boot_entries: Vec::new(),
            no_override: false,
            sequential: false,
            ignore_client_id: false,
            fqdn_only: false,
            read_ethers: false,
            name_matches: Vec::new(),
            tag_if: Vec::new(),
            classes: Vec::new(),
            macs: Vec::new(),
            matches: Vec::new(),
            ignore: Vec::new(),
            generate_names: Vec::new(),
            client_update: false,
            ignore_names: Vec::new(),
            force_broadcast: Vec::new(),
            no_dhcp_interfaces: Vec::new(),
            no_ping: false,
            quiet_dhcp: false,
            log_dhcp: false,
            lease_max: 1000,
            lease_file: None,
            lease_read_only: false,
        }
    }
}

fn integer(bytes: &[u8]) -> Result<u32, Error> {
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error("bad DHCP integer"));
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .filter(|value| *value <= i32::MAX as u32)
            .ok_or(Error("DHCP integer exceeds defined C int range"))
    })
}

fn lease_time(bytes: &[u8]) -> Result<(u32, bool), Error> {
    if bytes.is_empty() {
        return Ok((3600, false));
    }
    // option.c accepts this IPv6 deprecation marker in the shared range
    // grammar.  The nodhcpv6 build has no corresponding runtime bit, so the
    // IPv4 context keeps its ordinary default lease and does not mark it as
    // an explicit duration.
    if bytes == b"deprecated" {
        return Ok((3600, false));
    }
    if bytes == b"infinite" {
        return Ok((u32::MAX, true));
    }
    let (digits, multiplier) = match bytes.last().copied() {
        Some(b's' | b'S') => (&bytes[..bytes.len() - 1], 1),
        Some(b'm' | b'M') => (&bytes[..bytes.len() - 1], 60),
        Some(b'h' | b'H') => (&bytes[..bytes.len() - 1], 3600),
        Some(b'd' | b'D') => (&bytes[..bytes.len() - 1], 86_400),
        Some(b'w' | b'W') => (&bytes[..bytes.len() - 1], 604_800),
        _ => (bytes, 1),
    };
    // C accepts a bare suffix: after stripping it, atoi("") is zero. Avoid
    // inventing semantics for inputs whose C int multiplication overflows.
    let value = if digits.is_empty() {
        0
    } else {
        integer(digits)?
    };
    value
        .checked_mul(multiplier)
        .filter(|value| *value <= i32::MAX as u32)
        .map(|value| (value.max(120), true))
        .ok_or(Error("DHCP lease time exceeds defined C int range"))
}

fn ip(bytes: &[u8]) -> Result<Ipv4Addr, Error> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(Error("bad DHCP IPv4 address"))
}

/// Match option.c's lexical probe used while peeling range selectors.
///
/// The C parser does not try `inet_pton` for every prefix-looking token.  It
/// first scans for a restricted address alphabet (`[0-9a-fA-F.: ]`) and only
/// treats a token outside that alphabet as a legacy/set or `tag:`/`net:`
/// selector.  This distinction matters for names such as `red` (a legacy
/// tag) versus address-shaped values such as `dead` or `1.2.3`, which must
/// reach the IPv4 parser and fail as a malformed range. An empty first field
/// also reaches the address parser; an explicit `set:` remains a selector.
fn range_address_lexeme(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| {
        byte.is_ascii_digit() || matches!(byte, b'a'..=b'f' | b'A'..=b'F' | b'.' | b':' | b' ')
    })
}

impl DhcpConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        if self.lease_query.apply(directive)? {
            return Ok(true);
        }
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"dhcp-relay" | b"dhcp-split-relay" => self.relay.insert(
                0,
                super::dhcp_relay::RelayRule::parse(
                    argument.ok_or(Error("missing parameter"))?,
                    directive.name == b"dhcp-split-relay",
                )?,
            ),
            b"dhcp-alternate-port" => {
                self.ports = super::dhcp_relay::DhcpPorts::parse(argument)?;
            }
            b"pxe-prompt" => {
                let prompt = self
                    .pxe
                    .parse_prompt(argument.ok_or(Error("missing parameter"))?)?;
                self.options.insert(
                    0,
                    DhcpOption {
                        code: 10,
                        value: OptionValue::Raw(prompt.data),
                        tags: prompt.tags,
                        encapsulation: Encapsulation::PxeVendor,
                        ..Default::default()
                    },
                );
            }
            b"pxe-service" => self
                .pxe
                .add_service(argument.ok_or(Error("missing parameter"))?)?,
            b"dhcp-pxe-vendor" => self
                .pxe
                .add_vendors(argument.ok_or(Error("missing parameter"))?)?,
            b"dhcp-authoritative" => self.authoritative = true,
            b"dhcp-rapid-commit" => self.rapid_commit = true,
            b"dhcp-option" | b"dhcp-option-force" | b"dhcp-option-pxe" => {
                let option = DhcpOption::parse_mode(
                    argument.ok_or(Error("missing parameter"))?,
                    directive.name == b"dhcp-option-force",
                    directive.name == b"dhcp-option-pxe",
                )?;
                self.options.insert(0, option);
            }
            b"dhcp-no-override" => self.no_override = true,
            b"dhcp-boot" => {
                let (filter, boot) =
                    BootConfig::parse_selected(argument.ok_or(Error("missing parameter"))?)?;
                self.boot_entries.insert(
                    0,
                    BootEntry {
                        filter: filter.clone(),
                        config: boot.clone(),
                    },
                );
                if filter.is_unconditional() {
                    self.boot = Some(boot);
                }
            }
            b"bootp-dynamic" => {
                if argument.is_none() {
                    self.bootp_dynamic = true;
                } else {
                    self.bootp_dynamic_tags
                        .insert(0, TagPredicate::parse(argument)?);
                }
            }
            b"dhcp-sequential-ip" => self.sequential = true,
            b"dhcp-ignore-clid" => self.ignore_client_id = true,
            b"dhcp-fqdn" => self.fqdn_only = true,
            b"read-ethers" => self.read_ethers = true,
            b"tag-if" => self
                .tag_if
                .push(TagIf::parse(argument.ok_or(Error("missing parameter"))?)?),
            b"dhcp-mac" => self.macs.insert(
                0,
                DhcpMac::parse(argument.ok_or(Error("missing parameter"))?)?,
            ),
            b"dhcp-match" => self.matches.insert(
                0,
                DhcpMatch::parse(argument.ok_or(Error("missing parameter"))?)?,
            ),
            b"dhcp-vendorclass" | b"dhcp-userclass" | b"dhcp-circuitid" | b"dhcp-remoteid"
            | b"dhcp-subscrid" => {
                let kind = match directive.name.as_slice() {
                    b"dhcp-vendorclass" => ClassKind::Vendor,
                    b"dhcp-userclass" => ClassKind::User,
                    b"dhcp-circuitid" => ClassKind::Circuit,
                    b"dhcp-remoteid" => ClassKind::Remote,
                    _ => ClassKind::Subscriber,
                };
                self.classes.insert(
                    0,
                    DhcpClass::parse(argument.ok_or(Error("missing parameter"))?, kind)?,
                );
            }
            b"dhcp-ignore" => self.ignore.insert(0, TagPredicate::parse(argument)?),
            b"dhcp-generate-names" => self
                .generate_names
                .insert(0, TagPredicate::parse(argument)?),
            b"dhcp-client-update" => self.client_update = true,
            b"dhcp-name-match" => {
                let rule = DhcpNameMatch::parse(argument.ok_or(Error("missing parameter"))?)?;
                self.name_matches.insert(0, rule);
            }
            b"dhcp-ignore-names" => {
                self.ignore_names.insert(0, TagPredicate::parse(argument)?);
            }
            b"dhcp-broadcast" => {
                self.force_broadcast
                    .insert(0, TagPredicate::parse(argument)?);
            }
            b"no-dhcp-interface" | b"no-dhcpv4-interface" => {
                for value in argument.ok_or(Error("missing parameter"))?.split(b',') {
                    let value = value.decoded();
                    self.no_dhcp_interfaces
                        .insert(0, (!value.is_empty()).then_some(value));
                }
            }
            b"no-ping" => self.no_ping = true,
            b"quiet-dhcp" => self.quiet_dhcp = true,
            b"log-dhcp" => self.log_dhcp = true,
            b"leasefile-ro" => self.lease_read_only = true,
            b"dhcp-leasefile" | b"dhcp-lease" => {
                let value = argument.ok_or(Error("missing parameter"))?.decoded();
                self.lease_file = (!value.is_empty()).then_some(value);
            }
            b"dhcp-lease-max" => {
                self.lease_max = integer(&argument.ok_or(Error("missing parameter"))?.decoded())
                    .map_err(|_| Error("error"))? as usize
            }
            b"dhcp-range" => {
                let argument = argument.ok_or(Error("missing parameter"))?;
                let parts = argument.split(b',');
                let mut set_tag = None;
                let mut filters = Vec::new();
                let mut first = 0;
                while first < parts.len() && !range_address_lexeme(parts[first].encoded()) {
                    let bytes = parts[first].encoded();
                    if bytes.starts_with(b"tag:") || bytes.starts_with(b"net:") {
                        if bytes.len() > 4 {
                            filters.push(parts[first].decoded()[4..].to_vec());
                        }
                    } else {
                        if set_tag.is_some() {
                            return Err(Error("only one tag allowed"));
                        }
                        let value = parts[first].decoded();
                        let tag = if bytes.starts_with(b"set:") {
                            value[4..].to_vec()
                        } else {
                            value
                        };
                        set_tag = (!tag.is_empty()).then_some(tag);
                    }
                    first += 1;
                }
                let filter = TagPredicate::from_tags(filters);
                let parts = &parts[first..];
                if parts.len() < 2 || parts.len() > 5 {
                    return Err(Error("bad DHCP range"));
                }
                // option.c does not unhide quoted metacharacters for ranges.
                let mut start = ip(parts[0].encoded())?;
                use crate::dhcp::allocation::RangeKind;
                let (kind, mut end) = match parts[1].encoded() {
                    b"static" => (RangeKind::Static, start),
                    b"proxy" => (RangeKind::Proxy, start),
                    value => (RangeKind::Dynamic, ip(value)?),
                };
                if start > end {
                    std::mem::swap(&mut start, &mut end);
                }
                let mut netmask = None;
                let mut broadcast = None;
                let mut leasepos = 2;
                if let Some(mask) = parts.get(2).and_then(|part| ip(part.encoded()).ok()) {
                    if (u32::from(start) & u32::from(mask)) != (u32::from(end) & u32::from(mask)) {
                        return Err(Error("inconsistent DHCP range"));
                    }
                    netmask = Some(mask);
                    leasepos = 3;
                    if let Some(address) = parts.get(3).and_then(|part| ip(part.encoded()).ok()) {
                        broadcast = Some(address);
                        leasepos = 4;
                    }
                }
                if parts.len() > leasepos + 1 {
                    return Err(Error("bad DHCP range"));
                }
                let (duration, explicit) = match parts.get(leasepos) {
                    Some(part) => lease_time(part.encoded())?,
                    None => (3600, false),
                };
                self.ranges.insert(
                    0,
                    RangeConfig {
                        kind,
                        set_tag,
                        filter,
                        start,
                        end,
                        netmask,
                        broadcast,
                        lease_time: duration,
                        lease_time_explicit: explicit,
                    },
                );
            }
            b"dhcp-host" => {
                let host =
                    HostConfig::parse(argument.ok_or(Error("missing parameter"))?, &self.hosts)?;
                self.hosts.insert(0, host);
            }
            b"dhcp-hostsfile" | b"dhcp-optsfile" => {
                let value = argument.ok_or(Error("missing parameter"))?.decoded();
                if directive.name == b"dhcp-hostsfile" {
                    self.host_files.insert(0, value);
                } else {
                    self.option_files.insert(0, value);
                }
            }
            b"dhcp-hostsdir" | b"dhcp-optsdir" => {
                self.dynamic_dirs.insert(
                    0,
                    DynamicFileDirectory {
                        kind: if directive.name == b"dhcp-hostsdir" {
                            DynamicFileKind::Hosts
                        } else {
                            DynamicFileKind::Options
                        },
                        path: argument.ok_or(Error("missing parameter"))?.decoded(),
                    },
                );
            }
            b"dhcp-script" => {
                self.script = Some(argument.ok_or(Error("missing parameter"))?.decoded());
            }
            b"dhcp-scriptuser" => {
                self.script_user = Some(argument.ok_or(Error("missing parameter"))?.decoded());
            }
            b"script-on-renewal" => self.script_on_renewal = true,
            b"dhcp-reply-delay" => {
                return Err(Error(
                    "DHCP option is parsed but runtime wiring is not complete",
                ));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn validate_ready(&self) -> Result<(), Error> {
        // A parsed range can omit its mask. Serving-interface discovery and
        // runtime capability checks belong to the listener's admission gate.
        Ok(())
    }

    /// The caller supplies the expanded tags at C's ACK hostname-policy point.
    /// Configured/static names remain authoritative and bypass this policy.
    pub fn ignore_client_name(&self, tags: &[&[u8]]) -> bool {
        self.ignore_names.iter().any(|rule| rule.matches(tags))
    }

    /// `do_options` evaluates broadcast against the original request tags,
    /// before adding the chosen range's context tag for option selection.
    pub fn force_broadcast_for(&self, tags: &[&[u8]]) -> bool {
        self.force_broadcast.iter().any(|rule| rule.matches(tags))
    }

    pub fn validate_dns_config(&self, config: &super::dns::DnsConfig) -> Result<(), Error> {
        if self.fqdn_only && config.domain_suffix.is_none() {
            return Err(Error(
                "there must be a default domain when --dhcp-fqdn is set",
            ));
        }
        Ok(())
    }

    /// rfc2131.c::find_boot first scans every tagged entry, then falls back
    /// to an untagged entry. Both passes retain reverse declaration order.
    pub fn boot_for(&self, tags: &[&[u8]]) -> Option<&BootConfig> {
        self.boot_entries
            .iter()
            .find(|entry| entry.filter.matches_with(tags, false))
            .map(|entry| &entry.config)
            .or(self.boot.as_ref())
    }

    /// dhcp-common.c find_config's ordinary selector passes: all client IDs
    /// before any exact MAC. The caller supplies the selected context chain;
    /// restoration uses a predicate which accepts every configured address.
    pub fn find_host(
        &self,
        client_id: Option<&[u8]>,
        hardware_type: u32,
        hardware_address: Option<&[u8]>,
        in_context: impl Fn(Ipv4Addr) -> bool,
    ) -> Option<usize> {
        self.find_host_tagged(
            client_id,
            hardware_type,
            hardware_address,
            None,
            &[],
            in_context,
        )
    }

    pub fn find_host_tagged(
        &self,
        client_id: Option<&[u8]>,
        hardware_type: u32,
        hardware_address: Option<&[u8]>,
        hostname: Option<&[u8]>,
        tags: &[&[u8]],
        in_context: impl Fn(Ipv4Addr) -> bool,
    ) -> Option<usize> {
        // find_config does the complete selector search for tagged rules
        // before allowing untagged rules, not one pass per selector globally.
        for allow_untagged in [false, true] {
            let eligible = |host: &HostConfig| {
                host.address.is_none_or(&in_context)
                    && host.filter.matches_with(tags, allow_untagged)
            };
            if let Some(id) = client_id {
                if let Some(index) = self.hosts.iter().position(|host| {
                    eligible(host)
                        && host.client_id.as_deref().is_some_and(|configured| {
                            configured == id || (id.first() == Some(&0) && configured == &id[1..])
                        })
                }) {
                    return Some(index);
                }
            }
            if let Some(address) = hardware_address {
                if let Some(index) = self.hosts.iter().position(|host| {
                    eligible(host) && host.matches_hardware(hardware_type, address)
                }) {
                    return Some(index);
                }
            }
            if let Some(name) = hostname {
                if let Some(index) = self.hosts.iter().position(|host| {
                    eligible(host)
                        && host
                            .hostname
                            .as_deref()
                            .is_some_and(|configured| configured.eq_ignore_ascii_case(name))
                }) {
                    return Some(index);
                }
            }
            if let Some(address) = hardware_address {
                let mut best = None;
                let mut score = 0;
                for (index, host) in self
                    .hosts
                    .iter()
                    .enumerate()
                    .filter(|(_, host)| eligible(host))
                {
                    let candidate = host.wildcard_score(hardware_type, address);
                    if candidate > score {
                        score = candidate;
                        best = Some(index);
                    }
                }
                if best.is_some() {
                    return best;
                }
            }
        }
        None
    }

    /// Target Linux CLI default from config.h. OpenWrt init passes its own
    /// explicit /tmp/dhcp.leases path; experiments must pass a private path.
    pub fn lease_path(&self) -> &[u8] {
        self.lease_file
            .as_deref()
            .unwrap_or(b"/var/lib/misc/dnsmasq.leases")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;

    #[test]
    fn scoped_bootp_permission_is_never_widened_to_global() {
        for line in [
            b"bootp-dynamic=tag:known".as_slice(),
            b"bootp-dynamic=known",
        ] {
            let mut config = DhcpConfig::default();
            assert!(config.apply(&lex_line(line).unwrap().unwrap()).unwrap());
            assert!(!config.bootp_dynamic);
            assert_eq!(config.bootp_dynamic_tags.len(), 1);
            assert!(config.bootp_dynamic_tags[0].matches(&[b"known"]));
            assert!(!config.bootp_dynamic_tags[0].matches(&[]));
        }
        assert!(DhcpConfig::default()
            .apply(&lex_line(b"bootp-dynamic=").unwrap().unwrap())
            .is_err());
        let mut config = DhcpConfig::default();
        assert!(config
            .apply(&lex_line(b"bootp-dynamic").unwrap().unwrap())
            .unwrap());
        assert!(config.bootp_dynamic);
        for option in [
            "dhcp-authoritative",
            "dhcp-ignore-clid",
            "dhcp-sequential-ip",
            "no-ping",
            "quiet-dhcp",
            "leasefile-ro",
        ] {
            let line = format!("{option}=tag:known");
            assert!(config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .is_err());
        }
    }

    #[test]
    fn leasefile_alias_readonly_and_c_defaults() {
        let mut config = DhcpConfig::default();
        assert_eq!(config.lease_max, 1000); // config.h MAXLEASES, option.c:5978.
        assert_eq!(config.lease_path(), b"/var/lib/misc/dnsmasq.leases");
        let error = config
            .apply(&lex_line(b"dhcp-lease-max=word").unwrap().unwrap())
            .unwrap_err();
        assert_eq!(error.0, "error");
        for value in [
            b"dhcp-lease=/private/example.leases".as_slice(),
            b"leasefile-ro",
            b"dhcp-lease-max=",
        ] {
            assert!(config.apply(&lex_line(value).unwrap().unwrap()).unwrap());
        }
        assert_eq!(config.lease_path(), b"/private/example.leases");
        assert!(config.lease_read_only);
        assert_eq!(config.lease_max, 0);
        config
            .apply(&lex_line(b"dhcp-leasefile=").unwrap().unwrap())
            .unwrap();
        assert_eq!(config.lease_path(), b"/var/lib/misc/dnsmasq.leases");
    }

    #[test]
    fn parses_basic_ipv4_range_and_duration() {
        let directive = lex_line(b"dhcp-range=192.0.2.10,192.0.2.20,12h")
            .unwrap()
            .unwrap();
        let mut config = DhcpConfig::default();
        assert!(config.apply(&directive).unwrap());
        assert_eq!(config.ranges[0].lease_time, 43_200);
        assert_eq!(config.ranges[0].start, Ipv4Addr::new(192, 0, 2, 10));
    }

    fn parse(value: &str) -> Result<RangeConfig, Error> {
        let line = format!("dhcp-range={value}");
        let directive = lex_line(line.as_bytes())?.unwrap();
        let mut config = DhcpConfig::default();
        config.apply(&directive)?;
        Ok(config.ranges.remove(0))
    }

    #[test]
    fn tagged_range_filters_preserve_c_empty_selector_semantics() {
        let range = parse("tag:known,net:lan,192.0.2.10,192.0.2.20").unwrap();
        assert_eq!(range.filter.tags(), &[b"known".to_vec(), b"lan".to_vec()]);
        assert!(range.filter.matches(&[b"known", b"lan"]));
        assert!(!range.filter.matches(&[b"known"]));
        // option.c:'F' deliberately ignores empty tag:/net: selectors.
        assert!(parse("tag:,192.0.2.10,192.0.2.20")
            .unwrap()
            .filter
            .is_unconditional());
        assert!(parse("net:,192.0.2.10,192.0.2.20")
            .unwrap()
            .filter
            .is_unconditional());
    }

    #[test]
    fn range_prefix_scan_preserves_legacy_tags_but_rejects_address_shaped_tokens() {
        for tag in ["red", "lan"] {
            let range = parse(&format!("{tag},192.0.2.10,192.0.2.20")).unwrap();
            assert_eq!(range.set_tag.as_deref(), Some(tag.as_bytes()));
        }
        let quoted = parse("\"set:red\",192.0.2.10,192.0.2.20").unwrap();
        assert_eq!(quoted.set_tag.as_deref(), Some(b"set:red".as_slice()));
        // option.c's restricted scan sends these tokens to the IPv4 parser;
        // they are not silently widened into legacy tags.
        for token in ["", "dead", "1234", "1.2.3", "2001:db8::1"] {
            assert!(
                parse(&format!("{token},192.0.2.10,192.0.2.20")).is_err(),
                "{token}"
            );
        }
    }

    // Expected fields below come from exact option.c read_opts state, retained
    // in tools/dnsmasq/dhcp_config_diff.py's independent C corpus.
    #[test]
    fn ordinary_boot_fields_and_last_directive_match_c() {
        let mut config = DhcpConfig::default();
        for line in [
            b"dhcp-boot=old.img,old.test,192.0.2.1".as_slice(),
            b"dhcp-boot=\"synthetic,one.img\",\"boot,name\",192.0.2.2",
            b"dhcp-no-override",
        ] {
            config.apply(&lex_line(line).unwrap().unwrap()).unwrap();
        }
        assert_eq!(
            config.boot,
            Some(BootConfig {
                filename: Some(b"synthetic,one.img".to_vec()),
                server_name: Some(b"boot,name".to_vec()),
                next_server: Ipv4Addr::new(192, 0, 2, 2),
                next_server_name: None,
            })
        );
        assert!(config.no_override);
        for name in ["boot.test", "BOOT.test.", "192.0.2.2,extra"] {
            let line = format!("dhcp-boot=file,,{name}");
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
            // option.c preserves this field rather than canonicalising it.
            assert_eq!(
                config.boot.as_ref().unwrap().next_server_name.as_deref(),
                Some(name.as_bytes())
            );
        }
        for line in [
            "dhcp-boot=tag:known,tag:uefi,file,boot.test,192.0.2.3",
            "dhcp-boot=net:lan,net:trusted,recovery.img,,192.0.2.4",
        ] {
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
        }
        assert!(config.options.is_empty());
        assert!(config.boot_entries.iter().any(|entry| {
            entry.filter.tags() == [b"known".to_vec(), b"uefi".to_vec()]
                && entry.config.filename.as_deref() == Some(b"file".as_slice())
        }));
        let before = config.clone();
        assert!(config
            .apply(&lex_line(b"dhcp-boot=tag:known").unwrap().unwrap())
            .is_err());
        assert_eq!(config, before);
        config
            .apply(&lex_line(b"dhcp-boot=,,0.0.0.0").unwrap().unwrap())
            .unwrap();
        assert_eq!(
            config.boot,
            Some(BootConfig {
                filename: None,
                server_name: None,
                next_server: Ipv4Addr::UNSPECIFIED,
                next_server_name: None,
            })
        );
    }

    #[test]
    fn tagged_boot_selection_uses_context_tags_and_untagged_fallback() {
        let mut config = DhcpConfig::default();
        for line in [
            b"dhcp-boot=fallback.img,,192.0.2.1".as_slice(),
            b"dhcp-boot=tag:known,known.img,known.test,192.0.2.2".as_slice(),
            b"dhcp-boot=tag:known,latest.img,latest.test,192.0.2.3".as_slice(),
            b"dhcp-boot=fallback.img,,192.0.2.1".as_slice(),
        ] {
            config.apply(&lex_line(line).unwrap().unwrap()).unwrap();
        }
        assert_eq!(
            config.boot_for(&[b"known"]),
            Some(&BootConfig {
                filename: Some(b"latest.img".to_vec()),
                server_name: Some(b"latest.test".to_vec()),
                next_server: Ipv4Addr::new(192, 0, 2, 3),
                next_server_name: None,
            })
        );
        assert_eq!(
            config.boot_for(&[b"other"]).unwrap().filename.as_deref(),
            Some(b"fallback.img".as_slice())
        );
    }

    #[test]
    fn range_defaults_reverse_bounds_and_broadcast_match_c() {
        let defaults = parse("192.0.2.20,192.0.2.10").unwrap();
        assert_eq!(defaults.start, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(defaults.end, Ipv4Addr::new(192, 0, 2, 20));
        assert_eq!(defaults.netmask, None);
        assert_eq!(defaults.broadcast, None);
        assert_eq!(defaults.lease_time, 3600);
        assert!(!defaults.lease_time_explicit);

        let explicit = parse("192.0.2.10,192.0.2.20,255.255.255.0,192.0.2.255,12h").unwrap();
        assert_eq!(explicit.netmask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(explicit.broadcast, Some(Ipv4Addr::new(192, 0, 2, 255)));
        assert_eq!(explicit.lease_time, 43_200);
        assert!(explicit.lease_time_explicit);
    }

    #[test]
    fn lease_units_floor_empty_and_infinite_match_c() {
        for (input, expected, explicit) in [
            ("", 3600, false),
            ("0", 120, true),
            ("119S", 120, true),
            ("121s", 121, true),
            ("1m", 120, true),
            ("2M", 120, true),
            ("1H", 3600, true),
            ("1D", 86_400, true),
            ("1W", 604_800, true),
            ("h", 120, true),
            ("infinite", u32::MAX, true),
            ("deprecated", 3600, false),
        ] {
            let range = parse(&format!("192.0.2.10,192.0.2.20,{input}")).unwrap();
            assert_eq!(
                (range.lease_time, range.lease_time_explicit),
                (expected, explicit)
            );
        }
        assert!(lease_time(b"2147483648").is_err());
        assert!(lease_time(b"2147483647w").is_err());
    }

    #[test]
    fn explicit_mask_checks_network_without_inventing_a_default() {
        assert!(parse("192.0.2.10,198.51.100.20").is_ok());
        assert!(parse("192.0.2.10,198.51.100.20,255.255.255.0").is_err());
        assert!(parse("192.0.2.10,192.0.2.20,255.255.255.255").is_err());
        assert_eq!(
            parse("192.0.2.10,198.51.100.20,0.0.0.0").unwrap().netmask,
            Some(Ipv4Addr::UNSPECIFIED)
        );
        assert!(parse("192.0.2.10,192.0.2.20,255.0.255.0").is_ok());
    }

    #[test]
    fn generated_lan_tags_keep_context_and_hostname_policies_separate() {
        let mut config = DhcpConfig::default();
        assert!(!config.read_ethers);
        for line in [
            b"dhcp-range=set:lan,192.0.2.100,192.0.2.149,255.255.255.0,12h".as_slice(),
            b"dhcp-broadcast=tag:needs-broadcast",
            b"dhcp-ignore-names=tag:dhcp_bogus_hostname",
            b"dhcp-name-match=set:dhcp_bogus_hostname,localhost",
            b"dhcp-name-match=set:dhcp_bogus_hostname,wpad",
            b"no-dhcp-interface=wan,guest",
            b"read-ethers",
        ] {
            assert!(config.apply(&lex_line(line).unwrap().unwrap()).unwrap());
        }
        assert_eq!(config.ranges[0].set_tag.as_deref(), Some(b"lan".as_slice()));
        assert!(config.read_ethers);
        assert_eq!(config.ranges[0].lease_time, 43_200);
        let tags: Vec<_> = config
            .name_matches
            .iter()
            .filter(|rule| rule.matches(b"WPAD"))
            .map(|rule| rule.set_tag.as_slice())
            .collect();
        assert!(config.ignore_client_name(&tags));
        assert!(!config.ignore_client_name(&[b"lan"]));
        assert!(config.force_broadcast_for(&[b"needs-broadcast"]));
        assert!(!config.force_broadcast_for(&tags));
        assert_eq!(
            config.no_dhcp_interfaces,
            [Some(b"guest".to_vec()), Some(b"wan".to_vec())]
        );
        let before = config.clone();
        for line in [
            b"dhcp-range=set:a,set:b,192.0.2.1,192.0.2.2".as_slice(),
            b"dhcp-name-match=set:tag,",
            b"dhcp-ignore-names=tag:",
        ] {
            assert!(config.apply(&lex_line(line).unwrap().unwrap()).is_err());
            assert_eq!(config, before);
        }
    }

    #[test]
    fn leasequery_configuration_keeps_acl_and_enable_bit() {
        let mut config = DhcpConfig::default();
        for line in [b"leasequery".as_slice(), b"leasequery=192.0.2.0/24"] {
            assert!(config.apply(&lex_line(line).unwrap().unwrap()).unwrap());
        }
        assert!(config.lease_query.enabled);
        assert_eq!(config.lease_query.allowed_sources.len(), 1);
        assert!(config.lease_query.allows("192.0.2.44".parse().unwrap()));
        assert!(!config.lease_query.allows("198.51.100.44".parse().unwrap()));
    }

    #[test]
    fn static_and_proxy_ranges_reuse_the_subnet_context() {
        use crate::dhcp::allocation::RangeKind;
        for (mode, kind) in [("static", RangeKind::Static), ("proxy", RangeKind::Proxy)] {
            let mut config = DhcpConfig::default();
            let line =
                format!("dhcp-range=tag:client,set:pool,192.0.2.0,{mode},255.255.255.0,600s");
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
            let range = &config.ranges[0];
            assert_eq!(range.kind, kind);
            assert_eq!(range.start, range.end);
            assert_eq!(range.netmask, Some(Ipv4Addr::new(255, 255, 255, 0)));
            assert_eq!(range.lease_time, 600);
            assert_eq!(range.set_tag.as_deref(), Some(b"pool".as_slice()));
            assert!(range.filter.matches(&[b"client"]));
            assert!(!range.filter.matches(&[]));
        }
    }

    #[test]
    fn rejects_extra_fields_and_quoted_ipv4_addresses() {
        for input in [
            "192.0.2.10,192.0.2.20,1h,2h",
            "192.0.2.10,192.0.2.20,,1h",
            "\"192.0.2.10\",192.0.2.20",
            "192.0.2.10,192.0.2.20,\"12h\"",
        ] {
            assert!(parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn fqdn_only_requires_a_default_domain() {
        let mut config = DhcpConfig::default();
        config
            .apply(&lex_line(b"dhcp-fqdn").unwrap().unwrap())
            .unwrap();
        assert!(config.fqdn_only);
        let mut dns = super::super::dns::DnsConfig::default();
        assert_eq!(
            config.validate_dns_config(&dns),
            Err(Error(
                "there must be a default domain when --dhcp-fqdn is set"
            ))
        );
        dns.domain_suffix = Some(b"example.test".to_vec());
        assert!(config.validate_dns_config(&dns).is_ok());
    }

    #[test]
    fn ranges_follow_c_context_order_and_rejection_is_atomic() {
        let mut config = DhcpConfig::default();
        for line in [
            b"dhcp-range=192.0.2.10,192.0.2.20".as_slice(),
            b"dhcp-range=198.51.100.10,198.51.100.20",
        ] {
            config.apply(&lex_line(line).unwrap().unwrap()).unwrap();
        }
        assert_eq!(config.ranges[0].start, Ipv4Addr::new(198, 51, 100, 10));
        assert_eq!(config.ranges[1].start, Ipv4Addr::new(192, 0, 2, 10));
        let before = config.clone();
        assert!(config
            .apply(
                &lex_line(b"dhcp-range=192.0.2.10,192.0.2.20,bad")
                    .unwrap()
                    .unwrap()
            )
            .is_err());
        assert_eq!(config, before);
    }
}
