//! Typed DNS configuration derived from option.c, domain-match.c and domain.c.
//! Parsing does not activate features. In particular, hostname upstreams and
//! interface-derived domains need platform resolution before startup.
#[cfg(unix)]
#[path = "dns_endpoints.rs"]
pub mod endpoints;
#[cfg(target_os = "linux")]
#[path = "dns_lookup.rs"]
pub mod lookup;

use super::{validate_directive, Directive, EncodedArg, Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPattern {
    pub suffix: Vec<u8>,
    pub wildcard: bool,
    /// A wildcard written as *.example.test keeps the leading dot and
    /// therefore requires a label boundary. *example.test is a character
    /// suffix and also matches badexample.test, as in domain-match.c.
    pub wildcard_dot: bool,
    pub dotless: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerHost {
    Address(IpAddr),
    /// Must be resolved with C's AI_ADDRCONFIG/SOCK_DGRAM semantics before
    /// --test success. Retaining syntax here does not complete resolution.
    Name(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceBinding {
    pub address: Option<IpAddr>,
    pub interface: Option<Vec<u8>>,
    /// An explicit @source defaults to port 0, not the global query-port.
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerEndpoint {
    pub host: ServerHost,
    pub port: u16,
    pub scope: Option<Vec<u8>>,
    /// Validated at directive consumption; preserves the original interface index.
    pub scope_id: Option<u32>,
    /// None inherits the final global query-port.
    pub source: Option<SourceBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleTarget {
    Upstream(ServerEndpoint),
    DefaultResolvers,
    LocalOnly,
    Literal(IpAddr),
    ZeroAddresses,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerRule {
    pub domain: DomainPattern,
    pub target: RuleTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRecord {
    /// Declaration order is significant: the first name owns the PTR record.
    pub names: Vec<Vec<u8>>,
    pub address4: Option<Ipv4Addr>,
    pub address6: Option<Ipv6Addr>,
    /// None inherits the final local-ttl, including a later CLI/file override.
    pub ttl: Option<u32>,
}

/// option.c's static IPv4 doctor rule, already in its evaluation order when
/// stored in DnsConfig::aliases. Preserve host bits and C's zero-end sentinel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AliasConfig {
    pub from: Ipv4Addr,
    pub end: Ipv4Addr,
    pub to: Ipv4Addr,
    pub mask: Ipv4Addr,
}

/// option.c's bogus/ignore address selector. Preserve host bits; matching masks
/// at runtime. Separate from the packet policy so configuration probes stay
/// independent of DNS transport and wire modules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixConfig {
    pub address: IpAddr,
    pub prefix: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainSelector {
    Range4 {
        start: Ipv4Addr,
        end: Ipv4Addr,
    },
    Prefix6 {
        address: Ipv6Addr,
        prefix: u8,
    },
    /// C leaves prefixlen=0 for this syntax and therefore matches /0 in
    /// domain.c:255-280. Keep the input explicit until independent C runtime
    /// reproduction settles whether to retain or correct that defect.
    Range6 {
        start: Ipv6Addr,
        end: Ipv6Addr,
    },
    Interface(Option<Vec<u8>>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalDomain {
    pub domain: Vec<u8>,
    pub selector: DomainSelector,
}

#[derive(Clone, Debug)]
pub struct DnsConfig {
    pub records: super::records::RecordConfig,
    pub edns: super::edns::EdnsConfig,
    pub interface_records: super::interface_records::InterfaceRecordConfig,
    pub synth_domains: super::synth_domain::SynthConfig,
    /// Declaration order. A lookup must apply domain-match.c priorities, not
    /// pick the first suffix match (specificity and RR family both matter).
    pub rules: Vec<ServerRule>,
    pub listen_addresses: Vec<IpAddr>,
    pub auth: super::auth::AuthConfig,
    pub interfaces: Vec<Option<Vec<u8>>>,
    pub excluded_interfaces: Vec<Option<Vec<u8>>>,
    pub resolv_files: Vec<PathBuf>,
    pub servers_file: Option<PathBuf>,
    pub addn_hosts: Vec<Option<PathBuf>>,
    pub hosts_dirs: Vec<Option<PathBuf>>,
    pub host_records: Vec<HostRecord>,
    /// Newest declaration first. A doctor consumer must not reverse this again.
    pub aliases: Vec<AliasConfig>,
    pub bogus_addresses: Vec<PrefixConfig>,
    pub ignore_addresses: Vec<PrefixConfig>,
    /// Additional cacheable RR types; 255 selects all types in extraction.
    /// CNAME and ANY queries retain their special insertion rules.
    pub cache_rr: Vec<u16>,
    /// RR types elided from forwarded upstream and dynamic-cache answers. The
    /// list preserves declaration order (newest first), matching option.c's
    /// rrlist; configured/hosts/DHCP local answers bypass this policy.
    pub filter_rr: Vec<u16>,
    pub filter_win2k: bool,
    pub loop_detect: bool,
    pub domain_suffix: Option<Vec<u8>>,
    pub domain_from_resolv: bool,
    /// Newest declaration first, matching C's cond_domain linked list.
    pub conditional_domains: Vec<ConditionalDomain>,
    pub domain_interfaces: std::sync::Arc<super::domains::DomainInterfaces>,
    pub no_hosts: bool,
    pub no_resolv: bool,
    pub no_poll: bool,
    pub clear_on_reload: bool,
    pub expand_hosts: bool,
    pub bind_interfaces: bool,
    pub bind_dynamic: bool,
    pub local_service_net: bool,
    pub local_service_host: bool,
    pub domain_needed: bool,
    pub bogus_priv: bool,
    pub strict_order: bool,
    pub all_servers: bool,
    pub no_negative_cache: bool,
    pub no_round_robin: bool,
    pub stop_rebind: bool,
    pub rebind_localhost_ok: bool,
    pub rebind_domains: Vec<Vec<u8>>,
    pub localise_queries: bool,
    pub proxy_dnssec: bool,
    pub no_0x20_encode: bool,
    pub do_0x20_encode: bool,
    resolv_default: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            records: super::records::RecordConfig::default(),
            edns: super::edns::EdnsConfig::default(),
            interface_records: super::interface_records::InterfaceRecordConfig::default(),
            synth_domains: super::synth_domain::SynthConfig::default(),
            rules: Vec::new(),
            listen_addresses: Vec::new(),
            auth: Default::default(),
            interfaces: Vec::new(),
            excluded_interfaces: Vec::new(),
            resolv_files: vec![PathBuf::from("/etc/resolv.conf")],
            servers_file: None,
            addn_hosts: Vec::new(),
            hosts_dirs: Vec::new(),
            host_records: Vec::new(),
            aliases: Vec::new(),
            bogus_addresses: Vec::new(),
            ignore_addresses: Vec::new(),
            cache_rr: Vec::new(),
            filter_rr: Vec::new(),
            filter_win2k: false,
            loop_detect: false,
            domain_suffix: None,
            domain_from_resolv: false,
            conditional_domains: Vec::new(),
            domain_interfaces: Default::default(),
            no_hosts: false,
            no_resolv: false,
            no_poll: false,
            clear_on_reload: false,
            expand_hosts: false,
            bind_interfaces: false,
            bind_dynamic: false,
            local_service_net: false,
            local_service_host: false,
            domain_needed: false,
            bogus_priv: false,
            strict_order: false,
            all_servers: false,
            no_negative_cache: false,
            no_round_robin: false,
            stop_rebind: false,
            rebind_localhost_ok: false,
            rebind_domains: Vec::new(),
            localise_queries: false,
            proxy_dnssec: false,
            no_0x20_encode: false,
            do_0x20_encode: false,
            resolv_default: true,
        }
    }
}

fn numeric(bytes: &[u8]) -> Result<u32, Error> {
    bytes.iter().try_fold(0u32, |n, &c| {
        if !c.is_ascii_digit() {
            return Err(Error("bad integer"));
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u32::from(c - b'0')))
            .filter(|&n| n <= i32::MAX as u32)
            .ok_or(Error("integer exceeds defined C int range"))
    })
}
fn port(bytes: &[u8]) -> Result<u16, Error> {
    let value = bytes.iter().try_fold(0u32, |n, c| {
        if !c.is_ascii_digit() {
            return Err(Error("bad port"));
        }
        Ok(n.wrapping_mul(10).wrapping_add(u32::from(c - b'0')))
    })?;
    u16::try_from(value as i32).map_err(|_| Error("bad port"))
}
fn ip(bytes: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}
fn canon(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    crate::hosts::canonicalise(bytes).ok_or(Error("bad domain name"))
}
fn fields(bytes: &[u8], delimiter: u8) -> Vec<Vec<u8>> {
    EncodedArg::command_line(bytes)
        .split(delimiter)
        .into_iter()
        .map(|part| part.0)
        .collect()
}
fn optional_bytes(bytes: Vec<u8>) -> Option<Vec<u8>> {
    (!bytes.is_empty()).then_some(bytes)
}

fn address_prefix(argument: &EncodedArg) -> Result<PrefixConfig, Error> {
    // Unlike aliases, C unhides the whole argument before splitting the slash.
    let argument = EncodedArg::command_line(&argument.decoded());
    let (address, prefix) = argument.split_once(b'/');
    let address = ip(address.encoded()).ok_or(Error("error"))?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        // C numeric_check accepts an empty string and atoi gives zero.
        Some(prefix) => numeric(prefix.encoded()).map_err(|_| Error("error"))?,
        None => width,
    };
    if prefix > width {
        return Err(Error("error"));
    }
    Ok(PrefixConfig {
        address,
        prefix: prefix as u8,
    })
}

fn alias(argument: &EncodedArg) -> Result<AliasConfig, Error> {
    let missing = Error("missing address in alias");
    let range_error = Error("invalid alias range");
    let v4 = |bytes: &[u8]| match ip(bytes) {
        Some(IpAddr::V4(address)) => Some(address),
        _ => None,
    };
    let (source, tail) = argument.split_once(b',');
    let tail = tail.ok_or_else(|| missing.clone())?;
    // C leaves the first field encoded, but unhides the complete tail before
    // finding the mask comma. A quoted comma in the tail is therefore real.
    let (target, mask) = EncodedArg::command_line(&tail.decoded()).split_once(b',');
    let (source, end) = source.split_once(b'-');
    let from = v4(source.encoded()).ok_or_else(|| missing.clone())?;
    let to = v4(target.encoded()).ok_or_else(|| missing.clone())?;
    let mask = match mask {
        Some(mask) => v4(&mask.decoded()).ok_or(missing)?,
        None => Ipv4Addr::BROADCAST,
    };
    let end = match end {
        Some(end) => {
            let end = v4(end.encoded()).ok_or_else(|| range_error.clone())?;
            if from > end
                || (u32::from(from) & u32::from(mask)) != (u32::from(end) & u32::from(mask))
            {
                return Err(range_error);
            }
            end
        }
        None => Ipv4Addr::UNSPECIFIED,
    };
    Ok(AliasConfig {
        from,
        end,
        to,
        mask,
    })
}
fn path(argument: Option<&EncodedArg>) -> Option<PathBuf> {
    let bytes = argument?.decoded();
    if bytes.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        Some(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

fn pattern(bytes: &[u8], dotless: bool) -> Result<DomainPattern, Error> {
    let mut suffix = bytes;
    let mut wildcard = false;
    let mut wildcard_dot = false;
    if suffix.first() == Some(&b'.') {
        while suffix.first() == Some(&b'.') {
            suffix = &suffix[1..];
        }
    } else if suffix.first() == Some(&b'*') {
        suffix = &suffix[1..];
        wildcard = !suffix.is_empty();
        wildcard_dot = wildcard && suffix.first() == Some(&b'.');
    }
    Ok(DomainPattern {
        // add_update_server reports canonicalisation failures through the
        // generic option parser error, unlike other named-record parsers.
        suffix: canon(suffix).map_err(|_| Error("error"))?,
        wildcard,
        wildcard_dot,
        dotless,
    })
}

pub fn parse_endpoint(bytes: &[u8]) -> Result<ServerEndpoint, Error> {
    let at = fields(bytes, b'@');
    if at.len() > 3 {
        return Err(Error("interface can only be specified once"));
    }
    if at.len() == 3 && at[1].contains(&b'#') {
        return Err(Error("bad port"));
    }
    let server = fields(&at[0], b'#');
    if server.len() > 2 {
        return Err(Error("bad port"));
    }
    let server_port = if server.len() == 2 {
        port(&server[1])?
    } else {
        53
    };
    let scope = fields(&server[0], b'%');
    if scope.len() > 2 {
        return Err(Error("bad interface name"));
    }
    let host = match ip(&scope[0]) {
        Some(address) => ServerHost::Address(address),
        None => ServerHost::Name(scope[0].clone()),
    };
    let scope = if matches!(host, ServerHost::Address(IpAddr::V4(_))) {
        None
    } else {
        scope.get(1).cloned()
    };
    let source = if at.len() >= 2 {
        // C first extracts #port from the entire source substring, before
        // splitting the optional second @ (interface@source).
        let source_index = at.len() - 1;
        let source_parts = fields(&at[source_index], b'#');
        if source_parts.len() > 2 {
            return Err(Error("bad port"));
        }
        let source_port = if source_parts.len() == 2 {
            port(&source_parts[1])?
        } else {
            0
        };
        let address = ip(&source_parts[0]);
        let interface = if at.len() == 3 {
            if address.is_none() {
                return Err(Error("interface can only be specified once"));
            }
            Some(at[1].iter().copied().take(15).collect())
        } else if address.is_none() {
            Some(source_parts[0].iter().copied().take(15).collect())
        } else {
            None
        };
        if let (ServerHost::Address(server), Some(source)) = (&host, address) {
            if server.is_ipv4() != source.is_ipv4() {
                return Err(Error(if server.is_ipv4() {
                    "cannot use IPv4 server address with IPv6 source address"
                } else {
                    "cannot use IPv6 server address with IPv4 source address"
                }));
            }
        }
        Some(SourceBinding {
            address,
            interface,
            port: source_port,
        })
    } else {
        None
    };
    Ok(ServerEndpoint {
        host,
        port: server_port,
        scope,
        scope_id: None,
        source,
    })
}

pub fn parse_rules(option: &[u8], argument: &EncodedArg) -> Result<Vec<ServerRule>, Error> {
    let bytes = argument.decoded();
    let (domains, endpoint, explicit) = if let Some(rest) = bytes.strip_prefix(b"/") {
        let mut parts = fields(rest, b'/');
        // slice.split always yields at least one field, including an empty tail.
        let endpoint = parts.pop().unwrap();
        if parts.is_empty() {
            parts.push(endpoint.clone());
        }
        (parts, endpoint, true)
    } else {
        (vec![Vec::new()], bytes, false)
    };
    let target = if endpoint.is_empty() {
        RuleTarget::LocalOnly
    } else if option == b"address" {
        if endpoint == b"#" {
            RuleTarget::ZeroAddresses
        } else {
            RuleTarget::Literal(ip(&endpoint).ok_or(Error("Bad address in --address"))?)
        }
    } else if endpoint == b"#" {
        RuleTarget::DefaultResolvers
    } else {
        RuleTarget::Upstream(parse_endpoint(&endpoint)?)
    };
    domains
        .into_iter()
        .map(|domain| {
            let dotless = explicit && domain.is_empty();
            let domain = if domain == b"#" { &[][..] } else { &domain };
            Ok(ServerRule {
                domain: pattern(domain, dotless)?,
                target: target.clone(),
            })
        })
        .collect()
}

/// Reverse-domain expansion from option.c:1140-1305. Partial octets/nibbles
/// expand to the minimal set of suffix rules covering the CIDR prefix.
pub fn reverse_patterns(address: IpAddr, prefix: u8) -> Result<Vec<DomainPattern>, Error> {
    let (digits, width, unit, suffix): (Vec<u8>, u8, u8, &[u8]) = match address {
        IpAddr::V4(address) => (address.octets().to_vec(), 32, 8, b"in-addr.arpa"),
        IpAddr::V6(address) => (
            address
                .octets()
                .into_iter()
                .flat_map(|byte| [byte >> 4, byte & 15])
                .collect(),
            128,
            4,
            b"ip6.arpa",
        ),
    };
    if prefix == 0 || prefix > width {
        return Err(Error(if width == 32 {
            "bad IPv4 prefix length"
        } else {
            "bad IPv6 prefix length"
        }));
    }
    let count = usize::from(prefix.div_ceil(unit));
    let rem = prefix % unit;
    let variants = if rem == 0 { 1 } else { 1usize << (unit - rem) };
    let mut significant = digits[..count].to_vec();
    significant[count - 1] &= !((variants - 1) as u8);
    let mut patterns = Vec::with_capacity(variants);
    for delta in 0..variants {
        let mut name = Vec::new();
        for (index, &digit) in significant.iter().enumerate().rev() {
            let digit = digit + if index + 1 == count { delta as u8 } else { 0 };
            if unit == 8 {
                // An IPv4 octet needs at most three ASCII digits. Avoid an
                // allocated formatting buffer for every reverse-name label.
                if digit >= 100 {
                    name.push(b'0' + digit / 100);
                }
                if digit >= 10 {
                    name.push(b'0' + digit / 10 % 10);
                }
                name.push(b'0' + digit % 10);
            } else {
                name.push(b"0123456789abcdef"[usize::from(digit)]);
            }
            name.push(b'.');
        }
        name.extend_from_slice(suffix);
        patterns.push(DomainPattern {
            suffix: name,
            wildcard: false,
            wildcard_dot: false,
            dotless: false,
        });
    }
    Ok(patterns)
}

fn host_record(argument: &EncodedArg) -> Result<HostRecord, Error> {
    let parts = argument.split(b',');
    if parts.len() < 2 {
        return Err(Error("Bad host-record"));
    }
    let mut record = HostRecord {
        names: Vec::new(),
        address4: None,
        address6: None,
        ttl: None,
    };
    for part in parts {
        if part.encoded().iter().all(u8::is_ascii_digit) {
            // host-record uses the full on-wire u32 TTL in the image. Its
            // all-ones value becomes C's -1 sentinel and inherits local-ttl.
            let ttl = part.encoded().iter().try_fold(0u32, |value, digit| {
                value
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u32::from(digit - b'0')))
                    .ok_or(Error("host-record TTL exceeds unsigned 32-bit range"))
            })?;
            record.ttl = (ttl != u32::MAX).then_some(ttl);
        } else if let Some(address) = ip(part.encoded()) {
            match address {
                IpAddr::V4(address) => record.address4 = Some(address),
                IpAddr::V6(address) => record.address6 = Some(address),
            }
        } else {
            record.names.push(canon(&part.decoded())?);
        }
    }
    Ok(record)
}

impl DnsConfig {
    /// dnsmasq.c warns only for an explicitly supplied non-null resolver list.
    pub fn has_explicit_resolv_file(&self) -> bool {
        !self.resolv_default && !self.resolv_files.is_empty()
    }

    /// Startup loader boundary only. C resolves at each directive, before
    /// --test returns and before later files or scripts execute.
    #[cfg(unix)]
    pub fn apply_resolved(&mut self, directive: &Directive) -> Result<bool, Error> {
        let begin = self.rules.len();
        let consumed = self.apply(directive)?;
        if self.rules.len() != begin {
            let added = self.rules.split_off(begin);
            let expanded = endpoints::resolve_rules(&added, directive.name == b"rev-server");
            self.rules.extend(expanded.rules);
            if let Some(error) = expanded.error {
                return Err(error);
            }
        }
        Ok(consumed)
    }

    /// Return false for an option owned by another/unimplemented subsystem.
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        if self.auth.apply(directive)? {
            return Ok(true);
        }
        // Required-argument arms below follow validate_directive; optional
        // arms keep their explicit Option handling instead of assuming a value.
        let arg = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"synth-domain" => {
                self.synth_domains.apply(directive)?;
            }
            b"interface-name" | b"dynamic-host" => {
                self.interface_records.apply(directive)?;
            }
            b"server" | b"local" | b"address" => self
                .rules
                .extend(parse_rules(&directive.name, arg.unwrap())?),
            b"rev-server" => self.reverse_server(arg.unwrap())?,
            b"listen-address" => {
                let addresses: Result<Vec<_>, _> = arg
                    .unwrap()
                    .split(b',')
                    .iter()
                    .map(|a| ip(&a.decoded()).ok_or(Error("bad address")))
                    .collect();
                for address in addresses? {
                    self.listen_addresses.insert(0, address);
                }
            }
            b"interface" | b"except-interface" => {
                let target = if directive.name == b"interface" {
                    &mut self.interfaces
                } else {
                    &mut self.excluded_interfaces
                };
                for value in arg.unwrap().split(b',') {
                    target.insert(0, optional_bytes(value.decoded()));
                }
            }
            b"resolv-file" => {
                let name = path(arg);
                if self.resolv_default {
                    self.resolv_files.clear();
                    if let Some(name) = name {
                        self.resolv_files.push(name);
                    }
                    self.resolv_default = false;
                } else if let Some(name) = name {
                    self.resolv_files.insert(0, name);
                }
            }
            b"servers-file" => self.servers_file = path(arg),
            b"addn-hosts" => self.addn_hosts.insert(0, path(arg)),
            b"hostsdir" => self.hosts_dirs.insert(0, path(arg)),
            b"host-record" => self.host_records.push(host_record(arg.unwrap())?),
            b"alias" => self.aliases.insert(0, alias(arg.unwrap())?),
            b"bogus-nxdomain" => self
                .bogus_addresses
                .insert(0, address_prefix(arg.unwrap())?),
            b"ignore-address" => self
                .ignore_addresses
                .insert(0, address_prefix(arg.unwrap())?),
            b"cache-rr" => {
                for field in arg.unwrap().split(b',') {
                    self.cache_rr
                        .insert(0, super::rrtypes::parse(&field.decoded())?);
                }
            }
            b"filter-A" => self.filter_rr.insert(0, 1),
            b"filterwin2k" => self.filter_win2k = true,
            b"dns-loop-detect" => self.loop_detect = true,
            b"filter-AAAA" => self.filter_rr.insert(0, 28),
            b"filter-rr" => {
                for field in arg.unwrap().split(b',') {
                    self.filter_rr
                        .insert(0, super::rrtypes::parse(&field.decoded())?);
                }
            }
            b"domain" | b"domain-suffix" => {
                self.domain(arg.unwrap()).map_err(|error| match error.0 {
                    "bad domain address" | "bad domain local marker" | "bad integer" => {
                        Error("error")
                    }
                    _ => error,
                })?
            }
            b"local-service" => match arg.map(EncodedArg::encoded) {
                None | Some(b"net") => self.local_service_net = true,
                Some(b"host") => self.local_service_host = true,
                _ => return Err(Error("error")),
            },
            b"rebind-domain-ok" => {
                let bytes = arg.unwrap().decoded();
                let domains = fields(bytes.strip_prefix(b"/").unwrap_or(&bytes), b'/');
                for (index, domain) in domains.iter().enumerate() {
                    if index != 0 && domain.is_empty() {
                        break;
                    }
                    self.rebind_domains.insert(0, canon(domain)?);
                }
            }
            b"no-hosts" => self.no_hosts = true,
            b"no-resolv" => self.no_resolv = true,
            b"no-poll" => self.no_poll = true,
            b"clear-on-reload" => self.clear_on_reload = true,
            b"expand-hosts" => self.expand_hosts = true,
            b"bind-interfaces" => self.bind_interfaces = true,
            b"bind-dynamic" => self.bind_dynamic = true,
            b"domain-needed" => self.domain_needed = true,
            b"bogus-priv" => self.bogus_priv = true,
            b"strict-order" => self.strict_order = true,
            b"all-servers" => self.all_servers = true,
            b"no-negcache" => self.no_negative_cache = true,
            b"no-round-robin" => self.no_round_robin = true,
            b"stop-dns-rebind" => self.stop_rebind = true,
            b"rebind-localhost-ok" => self.rebind_localhost_ok = true,
            b"localise-queries" => self.localise_queries = true,
            b"proxy-dnssec" => self.proxy_dnssec = true,
            b"no-0x20-encode" => self.no_0x20_encode = true,
            b"do-0x20-encode" => self.do_0x20_encode = true,
            _ => {
                if self.edns.apply(directive)? {
                    return Ok(true);
                }
                return self.records.apply(directive);
            }
        }
        Ok(true)
    }

    fn reverse_server(&mut self, argument: &EncodedArg) -> Result<(), Error> {
        let (range, server) = EncodedArg(argument.decoded()).split_once(b',');
        let (address, prefix) = range.split_once(b'/');
        let address = ip(address.encoded()).ok_or(Error("error"))?;
        // C invalid numeric prefix falls back to the complete address width.
        let width = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix.as_ref() {
            Some(prefix) if prefix.encoded().iter().all(u8::is_ascii_digit) => {
                numeric(prefix.encoded())?
            }
            _ => width,
        };
        if prefix > width || prefix == 0 {
            return Err(Error(if width == 32 {
                "bad IPv4 prefix length"
            } else {
                "bad IPv6 prefix length"
            }));
        }
        let target = match server {
            None => RuleTarget::LocalOnly,
            Some(server) if server.encoded() == b"#" => RuleTarget::DefaultResolvers,
            Some(server) => RuleTarget::Upstream(parse_endpoint(server.encoded())?),
        };
        for domain in reverse_patterns(address, prefix as u8)? {
            self.rules.push(ServerRule {
                domain,
                target: target.clone(),
            });
        }
        Ok(())
    }

    fn domain(&mut self, argument: &EncodedArg) -> Result<(), Error> {
        let (name, tail) = argument.split_once(b',');
        let domain = canon(&name.decoded())?;
        let Some(tail) = tail else {
            if name.encoded() == b"#" {
                self.domain_from_resolv = true;
            } else {
                self.domain_suffix = Some(domain);
            }
            return Ok(());
        };
        // C decodes the whole tail before parsing range commas/slashes.
        let mut parts = vec![name];
        parts.extend(fields(&tail.decoded(), b',').into_iter().map(EncodedArg));
        let selector = fields(&parts[1].decoded(), b'/');
        let selector = if selector.len() == 2 {
            let prefix = super::domains::image_prefix_length(&selector[1])?;
            let address = ip(&selector[0]).ok_or(Error("bad domain address"))?;
            // A negative IPv6 prefix makes C is_same_net6 call memcmp with
            // a negative byte count cast to size_t; reject that unsafe input.
            if prefix < 0 && address.is_ipv6() {
                return Err(Error("bad prefix length"));
            }
            if parts.len() > 2 {
                if parts.len() != 3 || parts[2].encoded() != b"local" {
                    return Err(Error("bad domain local marker"));
                }
                // Prefix zero is valid for domain=; C ignores the reverse
                // helper's rejection of zero while still adding the domain.
                if prefix > 0 {
                    let prefix: u8 = prefix.try_into().map_err(|_| Error("bad prefix length"))?;
                    for domain in reverse_patterns(address, prefix)? {
                        self.rules.push(ServerRule {
                            domain,
                            target: RuleTarget::LocalOnly,
                        });
                    }
                }
                self.rules.push(ServerRule {
                    domain: pattern(&domain, false)?,
                    target: RuleTarget::LocalOnly,
                });
            }
            match address {
                IpAddr::V4(address) => {
                    if prefix > 32 {
                        return Err(Error("bad prefix length"));
                    }
                    let mask = u32::MAX.wrapping_shl(32u32.wrapping_sub(prefix as u32));
                    let start = u32::from(address) & mask;
                    DomainSelector::Range4 {
                        start: start.into(),
                        end: (start | !mask).into(),
                    }
                }
                IpAddr::V6(address) => {
                    if prefix > 128 {
                        return Err(Error("bad prefix length"));
                    }
                    DomainSelector::Prefix6 {
                        address,
                        prefix: prefix as u8,
                    }
                }
            }
        } else if selector.len() != 1 {
            return Err(Error("bad prefix length"));
        } else {
            match ip(&selector[0]) {
                Some(IpAddr::V4(start)) => {
                    let end = if parts.len() > 2 {
                        match ip(&parts[2].decoded()) {
                            Some(IpAddr::V4(end)) => end,
                            _ => return Err(Error("bad domain address")),
                        }
                    } else {
                        start
                    };
                    DomainSelector::Range4 { start, end }
                }
                Some(IpAddr::V6(start)) => {
                    let end = if parts.len() > 2 {
                        match ip(&parts[2].decoded()) {
                            Some(IpAddr::V6(end)) => end,
                            _ => return Err(Error("bad domain address")),
                        }
                    } else {
                        start
                    };
                    DomainSelector::Range6 { start, end }
                }
                None => DomainSelector::Interface(optional_bytes(selector[0].clone())),
            }
        };
        self.conditional_domains
            .insert(0, ConditionalDomain { domain, selector });
        Ok(())
    }

    /// Cross-option checks performed by C before --test success. Resolver
    /// search-domain reading and interface population still need caller I/O.
    pub fn finalize(&mut self) -> Result<(), Error> {
        self.records.finalize(self.domain_suffix.as_deref())?;
        if !self.no_resolv && self.no_poll && self.resolv_files.len() > 1 {
            return Err(Error("only one resolv.conf file allowed in no-poll mode."));
        }
        if self.domain_from_resolv && (self.no_resolv || self.resolv_files.len() != 1) {
            return Err(Error(
                "must have exactly one resolv.conf to read domain from.",
            ));
        }
        if !self.interfaces.is_empty()
            || !self.excluded_interfaces.is_empty()
            || !self.listen_addresses.is_empty()
            || self.auth.server_present
        {
            self.local_service_net = false;
            self.local_service_host = false;
        } else if self.local_service_host && !self.local_service_net {
            self.interfaces.push(None);
            self.bind_interfaces = true;
        }
        Ok(())
    }

    /// Finalize the gethostname-dependent MX defaults before startup or --test.
    /// C uses the OS hostname as-is: domain-suffix is only applied to SRV owners.
    pub fn finalize_hostname(&mut self, hostname: &[u8]) -> Result<(), Error> {
        let hostname = hostname.split(|&byte| byte == 0).next().unwrap_or_default();
        if hostname.len() > 502 {
            return Err(Error("host-name exceeds DNS configuration buffer"));
        }
        self.records.finalize_mx(hostname);
        Ok(())
    }

    pub fn needs_domain_interfaces(&self) -> bool {
        self.conditional_domains
            .iter()
            .any(|entry| matches!(entry.selector, DomainSelector::Interface(Some(_))))
    }

    /// Address-specific suffix selection from domain.c:218-302. Interface
    /// subnets use the owner-published enumeration; explicit IPv6 ranges
    /// retain the image prefixlen=0 comparison.
    pub fn domain_for_address(&self, address: IpAddr) -> Result<Option<&[u8]>, Error> {
        for entry in &self.conditional_domains {
            let matches = match (&entry.selector, address) {
                (DomainSelector::Range4 { start, end }, IpAddr::V4(address)) => {
                    address >= *start && address <= *end
                }
                (
                    DomainSelector::Prefix6 {
                        address: prefix_address,
                        prefix,
                    },
                    IpAddr::V6(address),
                ) => {
                    let shift = 128u8.checked_sub(*prefix).ok_or(Error("bad prefix length"))?;
                    let mask = u128::MAX.checked_shl(u32::from(shift)).unwrap_or(0);
                    u128::from(address) & mask == u128::from(*prefix_address) & mask
                }
                (DomainSelector::Interface(Some(interface)), _) => {
                    self.domain_interfaces.matches(interface, address)
                }
                (DomainSelector::Interface(None), IpAddr::V4(address)) => address.is_unspecified(),
                (DomainSelector::Range6 { .. }, IpAddr::V6(_)) => true,
                _ => false,
            };
            if matches {
                return Ok(Some(&entry.domain));
            }
        }
        Ok(self.domain_suffix.as_deref())
    }

    /// Guard platform-dependent inputs and features without a live consumer.
    /// Callers may replace the corresponding guard only when equivalent
    /// resolution/consumption is connected; they must not silently skip it.
    pub fn validate_ready(&self) -> Result<(), Error> {
        // These fields are also constructible through the public Rust API.
        // NameDomains relies on this check before making selector lookup infallible.
        if self.conditional_domains.iter().any(|entry| {
            matches!(entry.selector, DomainSelector::Prefix6 { prefix, .. } if prefix > 128)
        }) {
            return Err(Error("bad prefix length"));
        }
        for rule in &self.rules {
            if let RuleTarget::Upstream(server) = &rule.target {
                if matches!(server.host, ServerHost::Name(_)) {
                    return Err(Error("upstream hostname resolution not implemented"));
                }
                if server.scope.is_some()
                    && server.scope_id.is_none()
                    && matches!(server.host, ServerHost::Address(IpAddr::V6(_)))
                {
                    return Err(Error("upstream scope validation not implemented"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ipv6_selector_is_validated_before_name_domain_lookup() {
        let address = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let mut config = DnsConfig {
            conditional_domains: vec![ConditionalDomain {
                domain: b"example.test".to_vec(),
                selector: DomainSelector::Prefix6 { address, prefix: 129 },
            }],
            ..Default::default()
        };
        assert_eq!(config.validate_ready(), Err(Error("bad prefix length")));
        assert!(crate::config::dhcp::NameDomains::new(&config).is_err());
        assert_eq!(config.domain_for_address(address.into()), Err(Error("bad prefix length")));
        config.conditional_domains[0].selector = DomainSelector::Prefix6 { address, prefix: 128 };
        let domains = crate::config::dhcp::NameDomains::new(&config).unwrap();
        // The /128 only applies to this exact address and cannot match IPv4.
        assert_eq!(config.domain_for_address(address.into()), Ok(Some(b"example.test".as_slice())));
        assert_eq!(domains.for_address(Ipv4Addr::LOCALHOST), None);
    }

    use crate::config::{lex_line, OccurrenceTracker, Origin};

    fn apply(config: &mut DnsConfig, input: &[u8]) -> Result<bool, Error> {
        config.apply(&lex_line(input)?.ok_or(Error("empty test directive"))?)
    }

    #[test]
    fn host_record_ttl_preserves_full_wire_width_and_inheritance_sentinel() {
        let mut config = DnsConfig::default();
        for (ttl, expected) in [
            (2147483647u32, Some(2147483647)),
            (2147483648, Some(2147483648)),
            (u32::MAX, None),
        ] {
            apply(
                &mut config,
                format!("host-record=ttl.test,192.0.2.1,{ttl}").as_bytes(),
            )
            .unwrap();
            assert_eq!(config.host_records.last().unwrap().ttl, expected);
        }
        assert!(apply(&mut config, b"host-record=ttl.test,192.0.2.1,4294967296").is_err());
    }

    #[test]
    fn alias_rules_retain_runtime_evaluation_order() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"alias=192.0.2.10,198.51.100.20").unwrap();
        apply(&mut config, b"alias=192.0.2.0,203.0.113.99,255.255.255.0").unwrap();
        assert_eq!(
            config.aliases[0].to,
            "203.0.113.99".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(config.aliases[1].mask, Ipv4Addr::BROADCAST);
        assert!(config.finalize().is_ok());
        assert!(config.validate_ready().is_ok());
    }

    #[test]
    fn rr_filter_options_share_c_rrlist_parsing() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"filter-A").unwrap();
        apply(&mut config, b"filter-AAAA").unwrap();
        apply(&mut config, b"filter-rr=MX,257,ANY").unwrap();
        assert_eq!(config.filter_rr, vec![255, 257, 15, 28, 1]);
        assert!(apply(&mut config, b"filter-rr=not-a-type").is_err());
        apply(&mut config, b"filter-rr=").unwrap();
        assert_eq!(config.filter_rr[0], 0);
        apply(&mut config, b"cache-rr=TXT,").unwrap();
        assert_eq!(config.cache_rr, vec![0, 16]);
    }

    #[test]
    fn domain_rule_syntax_retains_specificity_family_and_default_markers() {
        let mut config = DnsConfig::default();
        apply(
            &mut config,
            b"server=/example.test/.other.test/192.0.2.1#5353",
        )
        .unwrap();
        assert_eq!(config.rules[0].domain.suffix, b"example.test");
        assert_eq!(config.rules[1].domain.suffix, b"other.test");
        assert!(matches!(
            config.rules[0].target,
            RuleTarget::Upstream(ServerEndpoint { port: 5353, .. })
        ));
        apply(&mut config, b"server=//192.0.2.2").unwrap();
        assert!(config.rules[2].domain.dotless);
        apply(&mut config, b"server=/#/#").unwrap();
        assert!(!config.rules[3].domain.dotless);
        assert_eq!(config.rules[3].target, RuleTarget::DefaultResolvers);
        apply(&mut config, b"address=/*example.test/#").unwrap();
        assert!(config.rules[4].domain.wildcard);
        assert!(!config.rules[4].domain.wildcard_dot);
        apply(&mut config, b"address=/*.example.test/#").unwrap();
        assert!(config.rules[5].domain.wildcard);
        assert!(config.rules[5].domain.wildcard_dot);
        assert_eq!(config.rules[5].domain.suffix, b".example.test");
        assert_eq!(config.rules[4].target, RuleTarget::ZeroAddresses);
        apply(&mut config, b"local=/example.test/").unwrap();
        assert_eq!(config.rules[6].target, RuleTarget::LocalOnly);
        apply(&mut config, b"address=/example.test/2001:db8::1").unwrap();
        assert_eq!(
            config.rules[7].target,
            RuleTarget::Literal("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn source_binding_and_unresolved_platform_inputs_are_explicit() {
        let server = parse_endpoint(b"192.0.2.1#5353@eth0@192.0.2.2#5300").unwrap();
        assert_eq!(
            server.source,
            Some(SourceBinding {
                address: Some("192.0.2.2".parse().unwrap()),
                interface: Some(b"eth0".to_vec()),
                port: 5300
            })
        );
        assert!(parse_endpoint(b"192.0.2.1@2001:db8::1").is_err());
        assert!(parse_endpoint(b"192.0.2.1@eth0#12@192.0.2.2").is_err());
        assert_eq!(
            parse_endpoint(b"2001:db8::1%eth0").unwrap().scope,
            Some(b"eth0".to_vec())
        );
        let mut config = DnsConfig::default();
        apply(&mut config, b"server=upstream.test").unwrap();
        assert!(config.validate_ready().is_err());
    }

    #[test]
    fn server_domain_label_limit_uses_the_c_generic_diagnostic() {
        for option in ["address", "server", "local"] {
            let accepted = format!("{option}=/{}/192.0.2.1", "a".repeat(63));
            let rejected = format!("{option}=/{}/192.0.2.1", "a".repeat(64));
            let mut config = DnsConfig::default();
            apply(&mut config, accepted.as_bytes()).unwrap();
            assert_eq!(apply(&mut config, rejected.as_bytes()), Err(Error("error")));
        }
    }

    #[test]
    fn reverse_labels_cover_all_octets_and_nibbles() {
        for digit in 0..=u8::MAX {
            let address = IpAddr::V4(Ipv4Addr::new(digit, digit, digit, digit));
            let patterns = reverse_patterns(address, 32).unwrap();
            assert_eq!(patterns.len(), 1);
            assert_eq!(
                patterns[0].suffix,
                format!("{digit}.{digit}.{digit}.{digit}.in-addr.arpa").as_bytes()
            );
        }
        for digit in 0..16u8 {
            let address = IpAddr::V6(std::net::Ipv6Addr::from([digit * 17; 16]));
            let patterns = reverse_patterns(address, 128).unwrap();
            assert_eq!(patterns.len(), 1);
            let expected = format!("{digit:x}.").repeat(32) + "ip6.arpa";
            assert_eq!(patterns[0].suffix, expected.as_bytes());
        }
    }

    #[test]
    fn reverse_partial_prefixes_and_address_domain_selection() {
        let domains = reverse_patterns("192.0.2.0".parse().unwrap(), 23).unwrap();
        assert_eq!(
            domains
                .iter()
                .map(|p| p.suffix.as_slice())
                .collect::<Vec<_>>(),
            [
                b"2.0.192.in-addr.arpa".as_slice(),
                b"3.0.192.in-addr.arpa".as_slice()
            ]
        );
        let domains = reverse_patterns("2001:db8::".parse().unwrap(), 31).unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].suffix, b"8.b.d.0.1.0.0.2.ip6.arpa");
        assert_eq!(domains[1].suffix, b"9.b.d.0.1.0.0.2.ip6.arpa");
        assert!(reverse_patterns("192.0.2.0".parse().unwrap(), 0).is_err());
        let mut config = DnsConfig::default();
        apply(&mut config, b"rev-server=192.0.2.0/23,192.0.2.53").unwrap();
        assert_eq!(config.rules.len(), 2);
        apply(&mut config, b"domain=lan").unwrap();
        apply(&mut config, b"domain=lab,192.0.2.0/24").unwrap();
        apply(&mut config, b"domain=v6,2001:db8::/32").unwrap();
        assert_eq!(
            config
                .domain_for_address("192.0.2.3".parse().unwrap())
                .unwrap(),
            Some(b"lab".as_slice())
        );
        assert_eq!(
            config
                .domain_for_address("198.51.100.1".parse().unwrap())
                .unwrap(),
            Some(b"lan".as_slice())
        );
        assert_eq!(
            config
                .domain_for_address("2001:db8::1".parse().unwrap())
                .unwrap(),
            Some(b"v6".as_slice())
        );
    }

    #[test]
    fn resolver_replacement_and_local_service_finalization() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"resolv-file=").unwrap();
        assert!(config.resolv_files.is_empty());
        apply(&mut config, b"resolv-file=/tmp/one").unwrap();
        apply(&mut config, b"resolv-file=/tmp/two").unwrap();
        assert_eq!(
            config.resolv_files,
            [PathBuf::from("/tmp/two"), PathBuf::from("/tmp/one")]
        );
        apply(&mut config, b"no-poll").unwrap();
        assert!(config.finalize().is_err());
        apply(&mut config, b"no-resolv").unwrap();
        config.finalize().unwrap();
        let mut config = DnsConfig::default();
        apply(&mut config, b"local-service=host").unwrap();
        config.finalize().unwrap();
        assert_eq!(config.interfaces, [None]);
        assert!(config.bind_interfaces);
        let mut config = DnsConfig::default();
        apply(&mut config, b"local-service").unwrap();
        apply(&mut config, b"listen-address=127.0.0.1,::1").unwrap();
        config.finalize().unwrap();
        assert!(!config.local_service_net);
        assert_eq!(
            config.listen_addresses,
            [
                "::1".parse::<IpAddr>().unwrap(),
                "127.0.0.1".parse().unwrap()
            ]
        );
    }

    #[test]
    fn host_record_keeps_ptr_name_order_and_encoded_type_inference() {
        let mut config = DnsConfig::default();
        apply(
            &mut config,
            b"host-record=First.test,alias.test,192.0.2.1,2001:db8::1,30",
        )
        .unwrap();
        let record = &config.host_records[0];
        assert_eq!(
            record.names,
            [b"First.test".to_vec(), b"alias.test".to_vec()]
        );
        assert_eq!(record.address4, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(record.address6, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(record.ttl, Some(30));
        apply(&mut config, b"host-record=\"192.0.2.1\",\"123\",192.0.2.2").unwrap();
        assert_eq!(
            config.host_records[1].names,
            [b"192.0.2.1".to_vec(), b"123".to_vec()]
        );
        assert_eq!(config.host_records[1].ttl, None);
    }

    #[test]
    fn conditional_domains_and_interface_rules_retain_state() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"domain=lan").unwrap();
        apply(&mut config, b"domain=lab,192.0.2.1/24").unwrap();
        apply(&mut config, b"domain=v6,2001:db8::/32").unwrap();
        assert_eq!(config.domain_suffix, Some(b"lan".to_vec()));
        assert_eq!(
            config.conditional_domains[1].selector,
            DomainSelector::Range4 {
                start: "192.0.2.0".parse().unwrap(),
                end: "192.0.2.255".parse().unwrap()
            }
        );
        apply(&mut config, b"domain=lab,192.0.2.0/24,local").unwrap();
        assert_eq!(config.rules.len(), 2);
        assert!(apply(&mut config, b"dynamic-host=example.test,192.0.2.1,eth0").unwrap());
        assert_eq!(config.interface_records.rules.len(), 1);
        assert_eq!(config.interface_records.rules[0].interface, b"eth0");
        apply(&mut config, b"domain=interface,eth0").unwrap();
        assert!(config.validate_ready().is_ok());
        assert!(config.needs_domain_interfaces());
        assert_eq!(
            config
                .domain_for_address("192.0.2.9".parse().unwrap())
                .unwrap(),
            Some(b"lab".as_slice())
        );
    }

    #[test]
    #[ignore = "requires DNSMASQ_C_REFERENCE pointing to exact C 2.93 build"]
    fn dns_config_acceptance_matches_c() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let reference = std::env::var_os("DNSMASQ_C_REFERENCE").expect("DNSMASQ_C_REFERENCE");
        let cases = [
            "server=192.0.2.1",
            "server=/test/192.0.2.1#5353",
            "server=//192.0.2.1",
            "server=/#/#",
            "server=/a.test/b.test/#",
            "local=/test/",
            "local=",
            "address=/test/192.0.2.1",
            "address=/#/#",
            "address=/*test/2001:db8::1",
            "address=/test/not-an-ip",
            "address=/test/",
            "address=",
            "server=192.0.2.1#65536",
            "server=192.0.2.1@192.0.2.2#5300",
            "server=192.0.2.1@eth0@192.0.2.2#5300",
            "server=192.0.2.1@2001:db8::1",
            "server=2001:db8::1@192.0.2.1",
            "server=192.0.2.1@eth0#12@192.0.2.2",
            "listen-address=127.0.0.1,::1",
            "listen-address=bad",
            "listen-address=",
            "interface=",
            "interface=eth0,eth1*",
            "except-interface=eth0",
            "local-service",
            "local-service=host",
            "local-service=",
            "local-service=bad",
            "local-service=\"net\"",
            "local-service\ninterface=eth0",
            "resolv-file=",
            "no-poll\nresolv-file=/tmp/a\nresolv-file=/tmp/b",
            "no-resolv\nno-poll\nresolv-file=/tmp/a\nresolv-file=/tmp/b",
            "host-record=a.test,192.0.2.1,60",
            "host-record=a.test,b.test,2001:db8::1",
            "host-record=a.test",
            "host-record=a.test,",
            "host-record=\"192.0.2.1\",192.0.2.2",
            "domain=lan",
            "domain=lab,192.0.2.1/24",
            "domain=lab,192.0.2.1,192.0.2.20",
            "domain=lab,192.0.2.1/33",
            "domain=lab,2001:db8::/129",
            "domain=lab,2001:db8::/32",
            "domain=lab,eth0",
            "no-hosts\nexpand-hosts",
            "rebind-domain-ok=/a.test/b.test/",
            "proxy-dnssec",
            "bind-dynamic\nlocal-service",
            "rev-server=192.0.2.0/23,192.0.2.53",
            "rev-server=2001:db8::/31,#",
            "rev-server=192.0.2.1/invalid,#",
            "rev-server=192.0.2.0/0,#",
            "domain=lab,192.0.2.0/24,local",
            "domain=v6,2001:db8::/32,local",
            "domain=lab,192.0.2.0/24,bad",
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
        assert!(successes > 20 && failures > 5);
        eprintln!(
            "DNS config C differential: {successes} accepted, {failures} rejected, {} matched",
            successes + failures
        );
    }
}
