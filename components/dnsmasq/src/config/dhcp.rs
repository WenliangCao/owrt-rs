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
pub use host_files::{HostFileError, HostFileErrorKind, HostFiles, HostReload};

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
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    /// None asks the runtime to derive the netmask from the serving interface.
    pub netmask: Option<Ipv4Addr>,
    pub broadcast: Option<Ipv4Addr>,
    pub lease_time: u32,
    pub lease_time_explicit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpConfig {
    /// Matches C's context-list order: the last configured range comes first.
    pub ranges: Vec<RangeConfig>,
    /// Last directive first, matching daemon->dhcp_conf.
    pub hosts: Vec<HostConfig>,
    /// Last configured path first, as in daemon->dhcp_hosts_file.
    pub host_files: Vec<Vec<u8>>,
    pub authoritative: bool,
    pub bootp_dynamic: bool,
    pub sequential: bool,
    pub ignore_client_id: bool,
    pub no_ping: bool,
    /// Also controls the C early return for an ignored DISCOVER.
    pub quiet_dhcp: bool,
    pub lease_max: usize,
    pub lease_file: Option<Vec<u8>>,
    pub lease_read_only: bool,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            ranges: Vec::new(),
            hosts: Vec::new(),
            host_files: Vec::new(),
            authoritative: false,
            bootp_dynamic: false,
            sequential: false,
            ignore_client_id: false,
            no_ping: false,
            quiet_dhcp: false,
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

impl DhcpConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"dhcp-authoritative" => self.authoritative = true,
            b"bootp-dynamic" => {
                // option.c:4664-4701 stores optional tag predicates. Until
                // they reach the BOOTP caller, only the no-argument global
                // form is supported; never widen scoped permission.
                if argument.is_some() {
                    return Err(Error("BOOTP dynamic tag selectors are not implemented"));
                }
                self.bootp_dynamic = true;
            }
            b"dhcp-sequential-ip" => self.sequential = true,
            b"dhcp-ignore-clid" => self.ignore_client_id = true,
            b"no-ping" => self.no_ping = true,
            b"quiet-dhcp" => self.quiet_dhcp = true,
            b"leasefile-ro" => self.lease_read_only = true,
            b"dhcp-leasefile" | b"dhcp-lease" => {
                let value = argument.ok_or(Error("missing parameter"))?.decoded();
                self.lease_file = (!value.is_empty()).then_some(value);
            }
            b"dhcp-lease-max" => {
                self.lease_max =
                    integer(&argument.ok_or(Error("missing parameter"))?.decoded())? as usize
            }
            b"dhcp-range" => {
                let argument = argument.ok_or(Error("missing parameter"))?;
                let parts = argument.split(b',');
                if parts.len() < 2 || parts.len() > 5 {
                    return Err(Error("bad DHCP range"));
                }
                // option.c does not unhide quoted metacharacters for ranges.
                let mut start = ip(parts[0].encoded())?;
                let mut end = ip(parts[1].encoded())?;
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
            b"dhcp-hostsfile" => {
                let value = argument.ok_or(Error("missing parameter"))?.decoded();
                if value.is_empty() || value == b"-" {
                    return Err(Error("DHCP hosts file requires a nonempty file path"));
                }
                self.host_files.insert(0, value);
            }
            b"dhcp-option"
            | b"dhcp-option-force"
            | b"dhcp-boot"
            | b"dhcp-vendorclass"
            | b"dhcp-userclass"
            | b"dhcp-match"
            | b"dhcp-name-match"
            | b"dhcp-ignore"
            | b"dhcp-hostsdir"
            | b"dhcp-optsfile"
            | b"dhcp-optsdir"
            | b"dhcp-script"
            | b"dhcp-scriptuser"
            | b"dhcp-fqdn"
            | b"dhcp-client-update"
            | b"dhcp-rapid-commit"
            | b"dhcp-reply-delay" => {
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
        let eligible = |host: &HostConfig| host.address.is_none_or(&in_context);
        client_id
            .and_then(|id| {
                self.hosts.iter().position(|host| {
                    eligible(host)
                        && host.client_id.as_deref().is_some_and(|configured| {
                            configured == id || (id.first() == Some(&0) && configured == &id[1..])
                        })
                })
            })
            .or_else(|| {
                hardware_address.and_then(|address| {
                    self.hosts.iter().position(|host| {
                        eligible(host) && host.matches_hardware(hardware_type, address)
                    })
                })
            })
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
            b"bootp-dynamic=",
        ] {
            let mut config = DhcpConfig::default();
            assert!(config.apply(&lex_line(line).unwrap().unwrap()).is_err());
            assert!(!config.bootp_dynamic);
        }
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

    // Expected fields below come from exact option.c read_opts state, retained
    // in tools/dnsmasq/dhcp_config_diff.py's independent C corpus.
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
    fn rejects_extra_fields_quotes_and_unimplemented_selectors() {
        for input in [
            "192.0.2.10,192.0.2.20,1h,2h",
            "192.0.2.10,192.0.2.20,,1h",
            "\"192.0.2.10\",192.0.2.20",
            "192.0.2.10,192.0.2.20,\"12h\"",
            "tag:known,192.0.2.10,192.0.2.20",
            "set:known,192.0.2.10,192.0.2.20",
            "192.0.2.10,static",
            "192.0.2.10,proxy",
        ] {
            assert!(parse(input).is_err(), "{input}");
        }
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
